// SPDX-License-Identifier: GPL-2.0
/*
 * uidbench - side-channel detector for the uidfake hook.
 *
 * Classes, all sampled in the same round so drift and frequency changes cancel:
 *
 *   H1  getpriority(PRIO_USER, hidden1)      hooked, policy hit
 *   H2  getpriority(PRIO_USER, hidden2)      hooked, policy hit   (null pair vs
 * H1) AB  getpriority(PRIO_USER, absent)       hooked, policy miss C1
 * getpriority(PRIO_PROCESS, dead pid)  NOT hooked: pid hash miss -> ESRCH C2
 * ioprio_get(IOPRIO_WHO_PROCESS, dead) NOT hooked
 *
 * C1 is the "similar sized call": same syscall, same shape (entry + one hash
 * lookup that misses + ESRCH), but it never reaches find_user(), so our hook is
 * not on it. C2 is a second, different-syscall baseline.
 *
 * Each sample is a block of K calls, timed and divided by K, so the clock's own
 * overhead and its granularity are amortised by K.
 *
 * Reported per class: n, mean ns/call, sd. Then:
 *   - paired (same round) deltas H1-AB, H1-H2, H1-C1 with mean, sd, paired t;
 *   - Welch t for H1 vs AB (the primary test), H1 vs H2 (the noise floor), H1
 * vs C1;
 *   - the number of paired samples an attacker needs for one 5 sigma decision,
 *     (5*sd/delta)^2, which is what decides whether a difference is
 * exploitable;
 *   - the ratio mean(H1)/mean(C1) as a sanity check that the two calls really
 * are of similar size. The two paths are not isomorphic, so this one is
 * reported with a deliberately loose band and only warns.
 *
 * Run it as one of the app uids that hide (the caller of a lookup must be an
 * app uid for the policy to match at all), for example from a probe app, or
 * with run-as.
 *
 *   uidbench --hidden 10400,10401 --absent 10500 --rounds 200000 --block 64
 * --pin 4
 *
 * It can also be built as a shared library (-DUIDBENCH_LIB) and called from
 * inside an app: an app cannot exec a file from its data directory, and running
 * it as the shell uid would not match the policy, because only app uids (10000
 * + appid + user*100000) can be callers.
 *
 *   dlopen("libuidbench.so", RTLD_NOW); uidbench_main(argc, argv);
 */
#define _GNU_SOURCE
#include <errno.h>
#include <math.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_ioprio_get
#define SYS_ioprio_get 31
#endif

#define PRIO_PROCESS_NR 0
#define PRIO_USER_NR 2
#define IOPRIO_WHO_PROCESS 1

enum { CL_H1, CL_H2, CL_AB, CL_AB2, CL_C1, CL_C2, CL_N };

static const char *cl_name[] = {"H1 hidden1",      "H2 hidden2",
                                "AB absent ",      "AB2 absent2",
                                "C1 getprio(pid)", "C2 ioprio(pid)"};

static unsigned long cl_arg[CL_N];
static volatile long cl_sink;

static inline uint64_t now_ns(void) {
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* one block of calls of one class; returns nothing, accumulates into cl_sink */
static __attribute__((noinline)) void run_block(int cls, long k) {
  long i;
  long acc = 0;

  for (i = 0; i < k; i++) {
    switch (cls) {
    case CL_H1:
    case CL_H2:
    case CL_AB:
      acc += syscall(SYS_getpriority, PRIO_USER_NR, (int)cl_arg[cls]);
      break;
    case CL_C1:
      acc += syscall(SYS_getpriority, PRIO_PROCESS_NR, (int)cl_arg[cls]);
      break;
    default:
      acc += syscall(SYS_ioprio_get, IOPRIO_WHO_PROCESS, (int)cl_arg[cls]);
      break;
    }
  }
  cl_sink += acc;
}

static int cmp_d(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;

  return (x > y) - (x < y);
}

/* trimmed mean/sd: outliers from scheduling noise are cut off both tails */
struct stat_t {
  double mean, sd;
  size_t n;
};

static struct stat_t trimmed(const double *src, size_t n, double frac) {
  struct stat_t r = {0.0, 0.0, 0};
  double *c, s = 0.0;
  size_t lo, hi, i;

  if (!n)
    return r;
  c = malloc(n * sizeof(double));
  if (!c)
    return r;
  memcpy(c, src, n * sizeof(double));
  qsort(c, n, sizeof(double), cmp_d);
  lo = (size_t)((double)n * frac);
  hi = n - lo;
  if (hi <= lo + 1) {
    lo = 0;
    hi = n;
  }
  for (i = lo; i < hi; i++)
    s += c[i];
  r.n = hi - lo;
  r.mean = s / (double)r.n;
  s = 0.0;
  for (i = lo; i < hi; i++)
    s += (c[i] - r.mean) * (c[i] - r.mean);
  r.sd = r.n > 1 ? sqrt(s / (double)(r.n - 1)) : 0.0;
  free(c);
  return r;
}

/* how long k calls of getpriority(which, arg) take, in ns */
static double probe_ns(int which, unsigned long arg, long k) {
  uint64_t a, b;
  long i;

  a = now_ns();
  for (i = 0; i < k; i++)
    syscall(SYS_getpriority, which, (int)arg);
  b = now_ns();
  return k > 0 ? (double)(b - a) / (double)k : 0.0;
}

/* Give back the series when a run stops before the report is printed; the
 * pointers stay owned by the caller, so nothing is freed twice. */
static void free_series(double **v, double *d_ab, double *d_h2, double *d_c1,
                        double *d_ab2) {
  int i;

  for (i = 0; i < CL_N; i++) {
    free(v[i]);
    v[i] = NULL;
  }
  free(d_ab);
  free(d_h2);
  free(d_c1);
  free(d_ab2);
}

static void usage(const char *argv0) {
  fprintf(
      stderr,
      "usage: %s [--hidden A,B] [--absent UID] [--dead-pid N] [--rounds N]\n"
      "          [--block K] [--pin CPU] [--csv FILE] [--max-ns X]\n"
      "          [--min-samples N] [--ratio R]\n",
      argv0);
  exit(2);
}

int uidbench_main(int argc, char **argv) {
  double *v[CL_N] = {0};
  double *d_ab = NULL, *d_h2 = NULL, *d_c1 = NULL, *d_ab2 = NULL;
  unsigned long hidden1 = 0, hidden2 = 0, absent = 19999, dead = 0x7fffff00ul;
  long rounds = 20000, block = 256;
  int pin = -1, progress = -1, force = 0, i, n_absent = 0;
  unsigned long absent_list[8];
  const char *csv = NULL;
  double max_ns = 2.0, ratio_band = 1.35, warmfrac = 0.1, trim = 0.01;
  long r;
  double t0 = 0.0;
  long next = 0;

  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--hidden") && i + 1 < argc) {
      char *s = argv[++i], *c = strchr(s, ',');

      hidden1 = strtoul(s, NULL, 0);
      if (c)
        hidden2 = strtoul(c + 1, NULL, 0);
    } else if (!strcmp(argv[i], "--absent") && i + 1 < argc) {
      char *s = argv[++i], *tok, *save = NULL;

      for (tok = strtok_r(s, ",", &save); tok && n_absent < 8;
           tok = strtok_r(NULL, ",", &save))
        absent_list[n_absent++] = strtoul(tok, NULL, 0);
      if (n_absent)
        absent = absent_list[0];
    } else if (!strcmp(argv[i], "--dead-pid") && i + 1 < argc) {
      dead = strtoul(argv[++i], NULL, 0);
    } else if (!strcmp(argv[i], "--rounds") && i + 1 < argc) {
      rounds = strtol(argv[++i], NULL, 0);
    } else if (!strcmp(argv[i], "--block") && i + 1 < argc) {
      block = strtol(argv[++i], NULL, 0);
    } else if (!strcmp(argv[i], "--pin") && i + 1 < argc) {
      pin = (int)strtol(argv[++i], NULL, 0);
    } else if (!strcmp(argv[i], "--csv") && i + 1 < argc) {
      csv = argv[++i];
    } else if (!strcmp(argv[i], "--max-ns") && i + 1 < argc) {
      max_ns = strtod(argv[++i], NULL);
    } else if (!strcmp(argv[i], "--ratio") && i + 1 < argc) {
      ratio_band = strtod(argv[++i], NULL);
    } else if (!strcmp(argv[i], "--force")) {
      force = 1;
    } else if (!strcmp(argv[i], "--progress")) {
      progress = 1;
    } else if (!strcmp(argv[i], "--no-progress")) {
      progress = 0;
    } else {
      usage(argv[0]);
    }
  }
  if (!hidden1 || !hidden2) {
    fprintf(stderr, "uidbench: need --hidden A,B\n");
    return 2;
  }
  if (rounds < 100 || block < 1)
    usage(argv[0]);
  if (!n_absent) {
    absent_list[0] = absent;
    absent_list[1] = absent - 1;
    n_absent = 2;
  }
  if (progress < 0)
    progress = isatty(2);

  if (pin >= 0) {
    unsigned long mask = 1ul << pin;

    if (syscall(SYS_sched_setaffinity, 0, sizeof(mask), &mask))
      fprintf(stderr, "uidbench: pin to cpu %d failed: %s\n", pin,
              strerror(errno));
  }

  cl_arg[CL_H1] = hidden1;
  cl_arg[CL_H2] = hidden2;
  cl_arg[CL_C1] = dead;
  cl_arg[CL_C2] = dead;

  for (i = 0; i < CL_N; i++) {
    v[i] = calloc((size_t)rounds, sizeof(double));
    if (!v[i]) {
      fprintf(stderr, "uidbench: out of memory\n");
      free_series(v, d_ab, d_h2, d_c1, d_ab2);
      return 1;
    }
  }
  d_ab = calloc((size_t)rounds, sizeof(double));
  d_h2 = calloc((size_t)rounds, sizeof(double));
  d_c1 = calloc((size_t)rounds, sizeof(double));
  d_ab2 = calloc((size_t)rounds, sizeof(double));

  /* sanity probe: a hidden uid that exists and is not hooked takes the 'uid
   * exists' path, which walks every process (measured 674 us against 0.45 us)
   * and ruins the run */
  {
    double base_ns = probe_ns(PRIO_PROCESS_NR, dead, 200);

    if (probe_ns(PRIO_USER_NR, hidden1, 200) > 4.0 * base_ns && !force) {
      fprintf(stderr,
              "uidbench: hidden uid %lu takes the slow 'uid exists' path.\n"
              "  Add this process's uid (%d) to the policy's caller list, or "
              "load the "
              "policy. (--force overrides)\n",
              hidden1, (int)getuid());
      free_series(v, d_ab, d_h2, d_c1, d_ab2);
      return 3;
    }
    for (i = 0; i < n_absent; i++) {
      if (probe_ns(PRIO_USER_NR, absent_list[i], 8) > 4.0 * base_ns) {
        fprintf(stderr,
                "uidbench: absent uid %lu exists in the kernel; "
                "pick one that is neither installed nor hidden\n",
                absent_list[i]);
        if (!force) {
          free_series(v, d_ab, d_h2, d_c1, d_ab2);
          return 3;
        }
      }
    }
  }

  fprintf(
      stderr, "uidbench: %ld rounds x %ld calls x %d classes = %.3g syscalls\n",
      rounds, block, (int)CL_N, (double)rounds * (double)block * (double)CL_N);

  for (i = 0; i < CL_N; i++)
    run_block(i, block * 16);

  for (r = 0; r < rounds; r++) {
    cl_arg[CL_AB] =
        absent_list[(int)((unsigned long)r % (unsigned long)n_absent)];
    cl_arg[CL_AB2] =
        absent_list[(int)(((unsigned long)r + 1) % (unsigned long)n_absent)];
    t0 = (double)now_ns();
    for (i = 0; i < CL_N; i++) {
      int cls = (int)(((unsigned long)r + (unsigned long)i) % CL_N);
      uint64_t a = now_ns();

      run_block(cls, block);
      v[cls][r] = (double)(now_ns() - a) / (double)block;
    }
    d_ab[r] = v[CL_H1][r] - v[CL_AB][r];
    d_h2[r] = v[CL_H1][r] - v[CL_H2][r];
    d_c1[r] = v[CL_H1][r] - v[CL_C1][r];
    d_ab2[r] = v[CL_AB][r] - v[CL_AB2][r];
    if (progress && r >= next) {
      double el = ((double)now_ns() - t0) / 1e9;
      double frac = (double)(r + 1) / (double)rounds;

      fprintf(stderr,
              "\r  %5.1f%%  %ld/%ld rounds  %.0fs elapsed  eta %.0fs      ",
              frac * 100.0, r + 1, rounds, el,
              frac > 0 ? el / frac * (1.0 - frac) : 0.0);
      next = r + (rounds / 100 > 0 ? rounds / 100 : 1);
    }
  }
  if (progress)
    fprintf(stderr, "\r  100.0%%  %ld/%ld rounds done\n", rounds, rounds);

  {
    struct stat_t h1, h2, ab, c1, dab, dab2, dh2, dc1;
    size_t n, warm = (size_t)((double)rounds * warmfrac);
    double tab2, th2, ratio;

    n = (size_t)rounds - warm;
    h1 = trimmed(v[CL_H1] + warm, n, trim);
    h2 = trimmed(v[CL_H2] + warm, n, trim);
    ab = trimmed(v[CL_AB] + warm, n, trim);
    c1 = trimmed(v[CL_C1] + warm, n, trim);
    dab = trimmed(d_ab + warm, n, trim);
    dab2 = trimmed(d_ab2 + warm, n, trim);
    dh2 = trimmed(d_h2 + warm, n, trim);
    dc1 = trimmed(d_c1 + warm, n, trim);
    tab2 = dab2.sd > 0 ? dab2.mean / (dab2.sd / sqrt((double)dab2.n)) : 0.0;
    th2 = dh2.sd > 0 ? dh2.mean / (dh2.sd / sqrt((double)dh2.n)) : 0.0;

    printf("uidbench: hidden %lu,%lu  absent %d uid(s)  dead pid %lu  rounds "
           "%ld  block %ld"
           "%s%d\n",
           hidden1, hidden2, n_absent, dead, rounds, block,
           pin >= 0 ? "  pin " : "", pin);
    printf(
        "  warmup %.0f%% dropped, %.1f%% trimmed per tail, %zu samples used\n",
        warmfrac * 100.0, trim * 100.0, dab.n);
    printf("\n  class              n        mean ns   sd ns\n");
    printf("  %-18s %-8zu %8.2f %8.2f\n", cl_name[CL_H1], h1.n, h1.mean, h1.sd);
    printf("  %-18s %-8zu %8.2f %8.2f\n", cl_name[CL_H2], h2.n, h2.mean, h2.sd);
    printf("  %-18s %-8zu %8.2f %8.2f\n", cl_name[CL_AB], ab.n, ab.mean, ab.sd);
    printf("\n  paired deltas (same round, trimmed)\n");
    printf("    H1 - AB  : %+7.3f ns  sd %6.2f  t %8.2f   <- signal (hidden vs "
           "absent)\n",
           dab.mean, dab.sd,
           tab2 * 0 +
               (dab.sd > 0 ? dab.mean / (dab.sd / sqrt((double)dab.n)) : 0.0));
    printf("    AB - AB2 : %+7.3f ns  sd %6.2f  t %8.2f   <- reference: plain "
           "uid spread\n",
           dab2.mean, dab2.sd, tab2);
    printf(
        "    H1 - H2  : %+7.3f ns  sd %6.2f  t %8.2f   <- hidden vs hidden\n",
        dh2.mean, dh2.sd, th2);
    printf("    H1 - C1  : %+7.3f ns  sd %6.2f  t %8.2f   <- hooked vs "
           "unhooked path\n",
           dc1.mean, dc1.sd,
           dc1.sd > 0 ? dc1.mean / (dc1.sd / sqrt((double)dc1.n)) : 0.0);

    ratio = c1.mean > 0 ? h1.mean / c1.mean : 0.0;
    printf("\n  similar-size sanity   mean(H1)/mean(C1) = %.3f   (band %.2f, "
           "loose by design)\n",
           ratio, ratio_band);
    printf("  signal / reference ratio : %.3f  (<< 1 means the hook hides "
           "inside the natural\n"
           "                                       uid-to-uid spread of "
           "find_user())\n",
           fabs(dab2.mean) > 0 ? fabs(dab.mean) / fabs(dab2.mean) : 0.0);

    printf("\n  verdict\n");
    printf("    signal H1-AB    : %+.3f ns   95%% CI %+.3f .. %+.3f  (sem %.3f "
           "ns)\n",
           dab.mean, dab.mean - 1.96 * dab.sd / sqrt((double)dab.n),
           dab.mean + 1.96 * dab.sd / sqrt((double)dab.n),
           dab.sd / sqrt((double)dab.n));
    printf("    reference AB-AB2: %+.3f ns  sd %.3f ns  (3 sigma = %.3f ns)\n",
           dab2.mean, dab2.sd, 3.0 * dab2.sd);
    printf("    hidden vs absent   : %s  (|signal| %.3f vs tolerances "
           "3sd=%.3f, %.3f ns)\n",
           (fabs(dab.mean) <= 3.0 * dab2.sd || fabs(dab.mean) <= max_ns)
               ? "PASS"
               : "FAIL",
           dab.mean, 3.0 * dab2.sd, max_ns);
    printf("    exploitable        : %s\n",
           (fabs(dab.mean) <= 3.0 * dab2.sd || fabs(dab.mean) <= max_ns)
               ? "no"
               : "YES");
    printf("    similar-size ratio : %s  (%.3f vs band %.2f) [loose]\n",
           (ratio <= ratio_band && ratio >= 1.0 / ratio_band) ? "ok" : "WARN",
           ratio, ratio_band);

    if (csv) {
      FILE *f = fopen(csv, "w");

      if (f) {
        fprintf(f, "round,H1,H2,AB,C1,dH1_AB,dH1_H2,dH1_C1,dAB_AB2\n");
        for (r = 0; r < rounds; r++)
          fprintf(f, "%ld,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n", r,
                  v[CL_H1][r], v[CL_H2][r], v[CL_AB][r], v[CL_C1][r], d_ab[r],
                  d_h2[r], d_c1[r], d_ab2[r]);
        fclose(f);
        printf("\n  raw samples written to %s\n", csv);
      }
    }
    fflush(stdout);

    free_series(v, d_ab, d_h2, d_c1, d_ab2);
    return (fabs(dab.mean) <= 3.0 * dab2.sd || fabs(dab.mean) <= max_ns) ? 0
                                                                         : 1;
  }
}

#ifndef UIDBENCH_LIB
int main(int argc, char **argv) { return uidbench_main(argc, argv); }
#endif

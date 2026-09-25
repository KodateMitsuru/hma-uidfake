// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/ioprio.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uidgid.h>

#include "uidfake.h"

#ifndef PRIO_USER
#define PRIO_USER 2
#endif
#ifndef IOPRIO_WHO_USER
#define IOPRIO_WHO_USER 3
#endif

/* syscall params：which=regs[0]，who=regs[1] */
#define ARG_WHICH 0
#define ARG_WHO 1

struct kr_state {
  struct pt_regs* uregs;
  u32 orig_who;
  u8 active;
};

static void hook_rewrite(struct pt_regs* regs, u32 which_val,
                         struct kr_state* st) {
  struct pt_regs* uregs = (struct pt_regs*)regs->regs[0];
  s32 who;
  u32 repl = 0;

  st->uregs = uregs;
  st->active = 0;
  st->orig_who = 0;
  if (!uregs) return;

  if ((u32)uregs->regs[ARG_WHICH] != which_val) return;

  st->orig_who = (u32)uregs->regs[ARG_WHO];
  who = (s32)st->orig_who;

  if (who > 0) {
    uid_t caller = __kuid_val(current_fsuid());
    uid_t target = (uid_t)who;

    if (target != 0 && caller != target) repl = policy_lookup(caller, target);
  }

  {
    u32 orig = st->orig_who;
    u32 val;

    /*
     * use asm to keep the comparison and selection in one instruction to
     * avoid side-channel attack.
     */
    asm("cmp\t%w[r], #0\n\tcsel\t%w[v], %w[r], %w[o], ne"
        : [v] "=r"(val)
        : [r] "r"(repl), [o] "r"(orig)
        : "cc");

    uregs->regs[ARG_WHO] = val;
  }
  st->active = 1;
}

/* Destination for the branchless restore when the wrapped syscall gave us no pt_regs. */
static struct pt_regs g_scratch_regs;

/*
 * The restore must not branch on data either: `active` is 0 for the syscalls whose
 * `which` we do not care about, and that must never turn into a hit-vs-miss branch.
 * Store unconditionally and pick the value with csel -- `active` 0 means "write the
 * value that is already there", which for a real pt_regs is a no-op store.
 */
static void hook_restore(struct kr_state* st) {
  struct pt_regs* dst = st->uregs ? st->uregs : &g_scratch_regs;
  u32 cur = (u32)dst->regs[ARG_WHO];
  u32 val;

  asm("cmp\t%w[f], #0\n\tcsel\t%w[v], %w[o], %w[c], ne"
      : [v] "=r"(val)
      : [f] "r"((u32)st->active), [o] "r"(st->orig_who), [c] "r"(cur)
      : "cc");

  dst->regs[ARG_WHO] = val;
}

#define DEFINE_HOOK(i)                                                        \
  static int entry_##i(struct kretprobe_instance* ri, struct pt_regs* regs) { \
    hook_rewrite(regs, g_hooks[i].which, (struct kr_state*)ri->data);         \
    return 0;                                                                 \
  }                                                                           \
  static int ret_##i(struct kretprobe_instance* ri, struct pt_regs* regs) {   \
    hook_restore((struct kr_state*)ri->data);                                 \
    return 0;                                                                 \
  }

struct syshook {
  const char* name;
  u32 which;
  struct kretprobe kr;
  int (*entry)(struct kretprobe_instance*, struct pt_regs*);
  int (*ret)(struct kretprobe_instance*, struct pt_regs*);
};

static struct syshook g_hooks[] = {
    {"__arm64_sys_getpriority", PRIO_USER},
    {"__arm64_sys_setpriority", PRIO_USER},
    {"__arm64_sys_ioprio_get", IOPRIO_WHO_USER},
    {"__arm64_sys_ioprio_set", IOPRIO_WHO_USER},
};
#define NHOOKS ((int)ARRAY_SIZE(g_hooks))

DEFINE_HOOK(0)
DEFINE_HOOK(1)
DEFINE_HOOK(2)
DEFINE_HOOK(3)

static void bind_handlers(void) {
  g_hooks[0].entry = entry_0;
  g_hooks[0].ret = ret_0;
  g_hooks[1].entry = entry_1;
  g_hooks[1].ret = ret_1;
  g_hooks[2].entry = entry_2;
  g_hooks[2].ret = ret_2;
  g_hooks[3].entry = entry_3;
  g_hooks[3].ret = ret_3;
}

int hooks_install(void) {
  int n = 0, ret, i;

  bind_handlers();

  for (i = 0; i < NHOOKS; i++) {
    struct syshook* h = &g_hooks[i];

    memset(&h->kr, 0, sizeof(h->kr));
    h->kr.kp.symbol_name = h->name;
    h->kr.entry_handler = h->entry;
    h->kr.handler = h->ret;
    h->kr.data_size = sizeof(struct kr_state);
    /*
     * If the instance pool is exhausted the entry handler is not called, that
     * call is not rewritten and the real priority leaks (the kernel's hit path
     * is about 1000x slower than a miss). 512 leaves plenty of room for these
     * non-blocking syscalls.
     */
    h->kr.maxactive = 512;

    ret = register_kretprobe(&h->kr);
    if (ret < 0) {
      pr_warn("uidfake: kretprobe %s failed: %d\n", h->name, ret);
      continue;
    }
    pr_info("uidfake: %s (which=%u)\n", h->name, h->which);
    n++;
  }

  return n;
}

void hooks_remove(void) {
  int i;

  for (i = 0; i < NHOOKS; i++) unregister_kretprobe(&g_hooks[i].kr);
}

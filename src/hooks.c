// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/ioprio.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/user.h>
#include <linux/uidgid.h>

#include "uidfake.h"

/* find_user(kuid_t uid) takes the uid in the argument register x0. */
#define ARG_UID 0

/*
 * The probe sits on find_user() rather than on the syscall entry, for a reason that only
 * shows when you look at what is observable:
 *
 *  - __arm64_sys_getpriority() and friends keep the arguments in the syscall's pt_regs,
 *    and arm64 has no separate in-register entry (there is no __do_sys_ or __se_sys_
 *    symbol on arm64 -- the body is inlined into the __arm64_sys_ wrapper). Rewriting
 *    argument there leaves the tampered value sitting in pt_regs for the whole syscall,
 *    where /proc/<tid>/syscall, ptrace register reads and syscall-exit stops can see it.
 *
 *  - find_user() is the first place the uid exists as a plain register argument, and it
 *    is exported. Substituting the uid here leaves the syscall's own pt_regs untouched:
 *    external observers only ever see the original argument and there is nothing to
 *    restore, so no return handler is needed at all.
 *
 * Coverage: getpriority(PRIO_USER), setpriority(PRIO_USER), ioprio_get(IOPRIO_WHO_USER)
 * and ioprio_set(IOPRIO_WHO_USER) all call find_user() for their uid branch, while their
 * pid/pgrp branches never do -- so the pid paths stay untouched without a `which` check.
 *
 * The caller then runs its own "user does not exist" path: find_user() returns NULL and
 * the syscall takes its miss branch (`if (!user) goto out_unlock`), exactly like a uid
 * that really does not exist.
 */
static int hook_pre(struct kprobe *kp, struct pt_regs *regs) {
  u64 orig = regs->regs[ARG_UID];
  u32 target = (u32)orig;
  u32 caller = (u32)__kuid_val(current_fsuid());
  u32 repl = 0;
  u64 cand, val;

  /*
   * Callers that are system/root uids never take part in hiding (policy_lookup also
   * short circuits for them), and a lookup for the caller's own uid is left alone.
   */
  if (caller != target) repl = policy_lookup(caller, target);

  /* replacement in the low 32 bits, the upper half of the register left untouched */
  cand = (orig & ~0xffffffffULL) | (u64)repl;

  /* one cmp + csel: hit and miss execute the same instruction stream */
  asm("cmp\t%w[r], #0\n\tcsel\t%[v], %[c], %[o], ne"
      : [v] "=r"(val)
      : [r] "r"(repl), [c] "r"(cand), [o] "r"(orig)
      : "cc");

  regs->regs[ARG_UID] = val;
  return 0;
}

static struct kprobe g_user_probe;

int hooks_install(void) {
  int ret;

  memset(&g_user_probe, 0, sizeof(g_user_probe));
  g_user_probe.symbol_name = "find_user";
  g_user_probe.pre_handler = hook_pre;

  ret = register_kprobe(&g_user_probe);
  if (ret < 0) {
    pr_warn("uidfake: kprobe find_user failed: %d\n", ret);
    return 0;
  }

  pr_info("uidfake: find_user (uid in x%u)\n", ARG_UID);
  return 1;
}

void hooks_remove(void) { unregister_kprobe(&g_user_probe); }

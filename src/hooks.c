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
 * The probe sits on find_user(kuid_t uid), uid in x0:
 *  - __arm64_sys_* has no separate entry symbol (the body is inlined), and rewriting the
 *    argument in pt_regs would leave the tampered value visible to /proc/<tid>/syscall and
 *    ptrace for the whole syscall;
 *  - find_user() is the first place the uid exists as a plain register, is exported, and is
 *    called by the uid branches of getpriority/setpriority/ioprio_get/ioprio_set only;
 *  - nothing has to be restored afterwards, so there is no kretprobe.
 * The caller then takes its own "no such user" path, exactly like for an absent uid.
 */

static int hook_pre(struct kprobe *kp, struct pt_regs *regs) {
  u64 orig = regs->regs[ARG_UID];
  u32 target = (u32)orig;
  u32 caller = (u32)__kuid_val(current_fsuid());
  u32 repl = 0;
  u64 cand, val;

  /* one consult for every query, so a caller always pays the same price */
  repl = policy_lookup(caller, target);

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

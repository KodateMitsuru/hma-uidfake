// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/ioprio.h>
#include <linux/kernel.h>

#include <linux/module.h>
#include <linux/resource.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/user.h>
#include <linux/uidgid.h>

#include "uidfake.h"

/* one translation unit with the policy: policy_lookup() is on the hot path and the compiler
 * can then inline it into the syscall wrappers instead of paying a call for every query */
#include "policy.c"

#define ARG_UID 0	/* find_user(kuid_t uid): uid in x0 */
#define ARG_WHO 1	/* getpriority/setpriority/ioprio_get/ioprio_set: (which, who, ...) */

/* syscall_fn_t is not declared for every KMI the module builds against */
typedef long (*uidfake_syscall_t)(const struct pt_regs *);

struct hook_entry {
	unsigned nr;
	uidfake_syscall_t ours;
	uidfake_syscall_t orig;
};

/*
 * Only data is patched, never an instruction: the syscall table entries are indirect calls, so
 * there is no branch range to worry about (a module region is farther from the image than a bl
 * can reach), no BTI landing pad and no PAC prologue. A wrapper never touches the task's
 * pt_regs either -- it copies it, substitutes the uid in the copy and runs the real wrapper
 * with that, so find_user() fails exactly like for a uid that does not exist while
 * /proc/<tid>/syscall, ptrace and the syscall-exit stop keep seeing the original argument.
 *
 * This is the mechanism KernelSU uses. Fallback: if the table cannot be resolved or patched,
 * the verified sys_call_table patch is the only hook.
 */

asmlinkage long uidfake_getpriority(const struct pt_regs *regs);
asmlinkage long uidfake_setpriority(const struct pt_regs *regs);
asmlinkage long uidfake_ioprio_get(const struct pt_regs *regs);
asmlinkage long uidfake_ioprio_set(const struct pt_regs *regs);

static struct hook_entry g_hook[] = {
	{ __NR_getpriority, uidfake_getpriority, NULL },
	{ __NR_setpriority, uidfake_setpriority, NULL },
	{ __NR_ioprio_get, uidfake_ioprio_get, NULL },
	{ __NR_ioprio_set, uidfake_ioprio_set, NULL },
};

/*
 * AArch32 binaries go through compat_sys_call_table with the ARM (EABI) numbers. They are
 * stable ABI constants: getpriority/setpriority are 141/140 in both tables, ioprio is not
 * (314/315 here against 31/30 in the 64-bit generic table).
 */
#ifdef CONFIG_COMPAT
#define NR32_GETPRIORITY 141
#define NR32_SETPRIORITY 140
#define NR32_IOPRIO_SET  314
#define NR32_IOPRIO_GET  315

asmlinkage long uidfake32_getpriority(const struct pt_regs *regs);
asmlinkage long uidfake32_setpriority(const struct pt_regs *regs);
asmlinkage long uidfake32_ioprio_get(const struct pt_regs *regs);
asmlinkage long uidfake32_ioprio_set(const struct pt_regs *regs);

static struct hook_entry g_chook[] = {
	{ NR32_GETPRIORITY, uidfake32_getpriority, NULL },
	{ NR32_SETPRIORITY, uidfake32_setpriority, NULL },
	{ NR32_IOPRIO_GET, uidfake32_ioprio_get, NULL },
	{ NR32_IOPRIO_SET, uidfake32_ioprio_set, NULL },
};
#endif

/*
 * Substitute the uid argument when the policy hides it, then run the real wrapper.
 *
 * Only the argument registers are copied: the generated __arm64_sys_* wrappers read exactly
 * regs[0..2] (which/who/prio) and never pass the pt_regs on, so the rest of the copy is never
 * touched. The copy is unconditional and the substituted value is selected with csel, so a
 * hidden uid and a uid that does not exist execute the same instruction stream -- only the
 * register value differs. The task's own pt_regs is never modified, so /proc/<tid>/syscall,
 * ptrace and the syscall-exit stop keep seeing the original argument.
 */
static asmlinkage long uid_hook(const struct pt_regs *regs, unsigned which_user,
				uidfake_syscall_t orig)
{
	struct pt_regs copy;
	u32 repl;

	copy.regs[0] = regs->regs[0];
	copy.regs[1] = regs->regs[1];
	copy.regs[2] = regs->regs[2];
	if ((u32)regs->regs[0] != which_user)
		return orig(regs);

	repl = policy_lookup_fast((u32)__kuid_val(current_fsuid()), (u32)regs->regs[ARG_WHO]);
	copy.regs[ARG_WHO] = repl ? (u64)repl : regs->regs[ARG_WHO];
	return orig(&copy);
}

asmlinkage long uidfake_getpriority(const struct pt_regs *regs)
{
	return uid_hook(regs, PRIO_USER, g_hook[0].orig);
}

asmlinkage long uidfake_setpriority(const struct pt_regs *regs)
{
	return uid_hook(regs, PRIO_USER, g_hook[1].orig);
}

asmlinkage long uidfake_ioprio_get(const struct pt_regs *regs)
{
	return uid_hook(regs, IOPRIO_WHO_USER, g_hook[2].orig);
}

asmlinkage long uidfake_ioprio_set(const struct pt_regs *regs)
{
	return uid_hook(regs, IOPRIO_WHO_USER, g_hook[3].orig);
}

#ifdef CONFIG_COMPAT
asmlinkage long uidfake32_getpriority(const struct pt_regs *regs)
{
	return uid_hook(regs, PRIO_USER, g_chook[0].orig);
}

asmlinkage long uidfake32_setpriority(const struct pt_regs *regs)
{
	return uid_hook(regs, PRIO_USER, g_chook[1].orig);
}

asmlinkage long uidfake32_ioprio_get(const struct pt_regs *regs)
{
	return uid_hook(regs, IOPRIO_WHO_USER, g_chook[2].orig);
}

asmlinkage long uidfake32_ioprio_set(const struct pt_regs *regs)
{
	return uid_hook(regs, IOPRIO_WHO_USER, g_chook[3].orig);
}
#endif

/* ---- table patching ---- */

static uidfake_syscall_t *main_table;
#ifdef CONFIG_COMPAT
static uidfake_syscall_t *compat_table;
#endif

static unsigned patch_entries(uidfake_syscall_t *table, struct hook_entry *e, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		uidfake_syscall_t *slot = &table[e[i].nr];

		e[i].orig = slot[0];
		if (uidfake_patch_text(slot, &e[i].ours, sizeof(uidfake_syscall_t), true) ||
		    slot[0] != e[i].ours) {
			pr_warn("uidfake: patching syscall %u failed\n", e[i].nr);
			return 0;
		}
	}
	return n;
}

static void unpatch_entries(uidfake_syscall_t *table, struct hook_entry *e, unsigned n)
{
	unsigned i;

	if (!table)
		return;
	for (i = 0; i < n; i++) {
		if (e[i].orig)
			uidfake_patch_text(&table[e[i].nr], &e[i].orig,
					   sizeof(uidfake_syscall_t), true);
		e[i].orig = NULL;
	}
}

static int patch_tables(void)
{
	unsigned long table = uidfake_lookup("sys_call_table");
	unsigned n;

	if (!table || uidfake_patch_init())
		return -ENOENT;
	pr_info("uidfake: sys_call_table=%px locator check: find_user=%px linked=%px\n",
		(void *)table, (void *)uidfake_lookup("find_user"), (void *)find_user);

	main_table = (uidfake_syscall_t *)table;
	n = patch_entries(main_table, g_hook, ARRAY_SIZE(g_hook));
	if (n != ARRAY_SIZE(g_hook)) {
		unpatch_entries(main_table, g_hook, ARRAY_SIZE(g_hook));
		return -EIO;
	}
	pr_info("uidfake: %u uid syscall(s) hooked in sys_call_table\n", n);

#ifdef CONFIG_COMPAT
	table = uidfake_lookup("compat_sys_call_table");
	if (table) {
		compat_table = (uidfake_syscall_t *)table;
		n = patch_entries(compat_table, g_chook, ARRAY_SIZE(g_chook));
		if (n != ARRAY_SIZE(g_chook)) {
			unpatch_entries(compat_table, g_chook, ARRAY_SIZE(g_chook));
			pr_warn("uidfake: 32-bit compat table not hooked; 32-bit callers are uncovered\n");
		} else {
			pr_info("uidfake: %u uid syscall(s) hooked in compat_sys_call_table\n", n);
		}
	}
#endif
	return 0;
}

int hooks_install(void)
{
	/* the sys_call_table patch is the only hook now: no kprobe fallback */
	if (!patch_tables())
		return 1;

	pr_warn("uidfake: could not hook sys_call_table, no hook installed\n");
	return 0;
}

void hooks_remove(void)
{
	/* nothing was patched means nothing to tear down: there is no fallback */
	if (!main_table)
		return;

	unpatch_entries(main_table, g_hook, ARRAY_SIZE(g_hook));
#ifdef CONFIG_COMPAT
	unpatch_entries(compat_table, g_chook, ARRAY_SIZE(g_chook));
	compat_table = NULL;
#endif
	main_table = NULL;
}
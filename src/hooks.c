// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ioprio.h>
#include <linux/kernel.h>
#include <linux/version.h>

#include <linux/module.h>
#include <linux/resource.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uidgid.h>
#include <linux/user.h>

#include <trace/hooks/syscall_check.h>

#include "uidfake.h"

/* The window is closed from the query path too (see uidfake_close_pending). */
void uidfake_tag_close(void);

/* one translation unit with the policy: its query is on the hot path and the compiler
 * can then inline it into the syscall wrappers instead of paying a call for every query */
#include "policy.c"

#define ARG_UID 0 /* find_user(kuid_t uid): uid in x0 */
#define ARG_WHO 1 /* getpriority/setpriority/ioprio_get/ioprio_set: (which, who, ...) */

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

/* The id setters: declared here because the tables below already use them. */
static asmlinkage long uidfake_setuid(const struct pt_regs *regs);
static asmlinkage long uidfake_setreuid(const struct pt_regs *regs);
static asmlinkage long uidfake_setresuid(const struct pt_regs *regs);
static asmlinkage long uidfake_setgid(const struct pt_regs *regs);
static asmlinkage long uidfake_setregid(const struct pt_regs *regs);
static asmlinkage long uidfake_setresgid(const struct pt_regs *regs);

/* Names an isolated child when it opens its app's apk; registered as a vendor hook. */
static void uidfake_file_open(void *data, const struct file *file);

static asmlinkage long uidfake32_setuid(const struct pt_regs *regs);
static asmlinkage long uidfake32_setreuid(const struct pt_regs *regs);
static asmlinkage long uidfake32_setresuid(const struct pt_regs *regs);
static asmlinkage long uidfake32_setgid(const struct pt_regs *regs);
static asmlinkage long uidfake32_setregid(const struct pt_regs *regs);
static asmlinkage long uidfake32_setresgid(const struct pt_regs *regs);

static struct hook_entry g_hook[] = {
    {__NR_getpriority, uidfake_getpriority, NULL}, {__NR_setpriority, uidfake_setpriority, NULL},
    {__NR_ioprio_get, uidfake_ioprio_get, NULL},   {__NR_ioprio_set, uidfake_ioprio_set, NULL},
    {__NR_setuid, uidfake_setuid, NULL},	   {__NR_setreuid, uidfake_setreuid, NULL},
    {__NR_setresuid, uidfake_setresuid, NULL},	   {__NR_setgid, uidfake_setgid, NULL},
    {__NR_setregid, uidfake_setregid, NULL},	   {__NR_setresgid, uidfake_setresgid, NULL},
};

/*
 * AArch32 binaries go through compat_sys_call_table with the ARM (EABI) numbers. They are
 * stable ABI constants: getpriority/setpriority are 141/140 in both tables, ioprio is not
 * (314/315 here against 31/30 in the 64-bit generic table).
 */
#ifdef CONFIG_COMPAT
#define NR32_GETPRIORITY 141
#define NR32_SETPRIORITY 140
#define NR32_IOPRIO_SET 314
#define NR32_IOPRIO_GET 315
#define NR32_SETUID 23
#define NR32_SETGID 46
#define NR32_SETREUID 70
#define NR32_SETREGID 71
#define NR32_SETRESUID 164
#define NR32_SETRESGID 170
#define NR32_OPENAT 322

asmlinkage long uidfake32_getpriority(const struct pt_regs *regs);
asmlinkage long uidfake32_setpriority(const struct pt_regs *regs);
asmlinkage long uidfake32_ioprio_get(const struct pt_regs *regs);
asmlinkage long uidfake32_ioprio_set(const struct pt_regs *regs);

static struct hook_entry g_chook[] = {
    {NR32_GETPRIORITY, uidfake32_getpriority, NULL},
    {NR32_SETPRIORITY, uidfake32_setpriority, NULL},
    {NR32_IOPRIO_GET, uidfake32_ioprio_get, NULL},
    {NR32_IOPRIO_SET, uidfake32_ioprio_set, NULL},
    {NR32_SETUID, uidfake32_setuid, NULL},
    {NR32_SETREUID, uidfake32_setreuid, NULL},
    {NR32_SETRESUID, uidfake32_setresuid, NULL},
    {NR32_SETGID, uidfake32_setgid, NULL},
    {NR32_SETREGID, uidfake32_setregid, NULL},
    {NR32_SETRESGID, uidfake32_setresgid, NULL},
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
/*
 * The ten syscalls hooked here take three arguments at most, and the generated __arm64_sys_*
 * wrappers read exactly those argument registers -- so the substituted call is handed a three
 * register object instead of a whole pt_regs. The full struct made the compiler zero 312 bytes on
 * every hooked call (a memset call, not three stores), and it pushed the frame over the size that
 * turns the stack canary on. The copy stays unconditional, so a hidden uid and a uid that does not
 * exist still execute the same instruction stream.
 */
struct uidfake_args {
	u64 regs[3];
};

static asmlinkage long uid_hook(const struct pt_regs *regs, unsigned which_user,
				uidfake_syscall_t orig)
{
	struct uidfake_args args;
	u32 repl;

	args.regs[0] = regs->regs[0];
	args.regs[1] = regs->regs[1];
	args.regs[2] = regs->regs[2];
	if ((u32)regs->regs[0] != which_user)
		return orig(regs);

	repl = policy_query((u32)regs->regs[ARG_WHO]);
	args.regs[ARG_WHO] = repl ? (u64)repl : regs->regs[ARG_WHO];
	return orig((const struct pt_regs *)&args);
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

/* ---- naming an isolated child from the apk it opens ---- */

static bool uidfake_tag_pending(void)
{
	return (READ_ONCE(task_thread_info(current)->flags) & UF_TAG_PENDING) != 0;
}

/*
 * The identity belongs to the process, not to the thread that happened to open the apk: every
 * thread carries its own thread_info, and a sibling thread is exactly where a later query comes
 * from. Threads created afterwards inherit the tag from whoever created them.
 */
static noinline void uidfake_tag_group(u32 tag)
{
	struct task_struct *t;

	rcu_read_lock();
	for_each_thread(current, t)
	{
		const unsigned long flags = READ_ONCE(task_thread_info(t)->flags);
		const unsigned long next =
		    (flags & ~((UF_TAG_MASK << UF_TAG_SHIFT) | UF_TAG_PENDING)) |
		    ((unsigned long)tag << UF_TAG_SHIFT);

		if (next != flags)
			WRITE_ONCE(task_thread_info(t)->flags, next);
	}
	rcu_read_unlock();
}

static noinline void uidfake_tag_verify(u32 tag)
{
	if (!uidfake_tag_pending())
		return;
	uidfake_tag_group(tag);
	pr_info("uidfake: iso uid %u belongs to app %u, from the apk it opened\n",
		(u32)__kuid_val(current_fsuid()), (u32)tag - 1u + UF_APP_MIN);
}

/*
 * The window is over and no apk named this one: it is an app without rules and it answers as one.
 * Saying so once is enough -- this is a normal outcome, not a failure.
 */
noinline void uidfake_tag_close(void)
{
	static unsigned logged;

	uidfake_tag_group(0);
	if (logged < 4 && UF_DEBUG_ON()) {
		logged++;
		pr_info("uidfake: iso uid %u reached its own code, no rule names it\n",
			(u32)__kuid_val(current_fsuid()));
	}
}

/*
 * Called from do_dentry_open() for every file a task opens -- openat, openat2, creat, all of
 * them -- with the struct file already filled in. It is the vendor hook AOSP keeps for exactly
 * this (include/trace/hooks/syscall_check.h: "a mechanism for vendor modules to hook and extend
 * functionality"), so the module no longer needs an entry in sys_call_table to see opens.
 *
 * The first thing checked is one bit of the task's flags, so a process that is not waiting for a
 * name pays an AND here and nothing else.
 */
/*
 * The app's code directory is what the helper registers, so an open of anything inside it -- the
 * apk, a vdex, an odex, a library -- names the app as soon as the directory is reached. The walk is
 * one or two levels (the same for every artifact) and only runs while a child is still unnamed.
 * Nothing that may or may not exist has to be listed, and the first file of the app's own code that
 * is opened ends the wait either way: a hit names the app, no hit means it has no rules.
 */
#define UF_DIR_DEPTH 4

/*
 * The app's code directory is what the helper registers, so an open of anything inside it -- the
 * apk, a vdex, an odex, a library -- names the app as soon as the directory is reached. The walk is
 * one or two levels (the same for every artifact) and only runs while a child is still unnamed.
 */
#define UF_DIR_DEPTH 4

static noinline void uidfake_close_unheard(const struct file *file, u32 dev, int depth)
{
	static unsigned logged;

	if (logged >= 6)
		return;
	logged++;
	pr_info("uidfake: no rule: %s in %s/%s (ino %lu dev %u) depth %d\n", current->comm,
		file->f_path.dentry->d_parent->d_name.name, file->f_path.dentry->d_name.name,
		(unsigned long)file_inode(file)->i_ino, dev, depth);
}

static void uidfake_file_open(void *data, const struct file *file)
{
	const struct inode *inode = file_inode(file);
	const struct dentry *dentry;
	u32 tag = 0;
	int depth = 0;

	(void)data;
	if (!uidfake_tag_pending())
		return;

	/*
	 * Only an open that lands on the filesystem an app's code lives on says anything at all:
	 * while the framework sets the process up it reads properties, /proc, /dev and /system, and
	 * those are none of our business. Without this gate the very first property read would end
	 * the wait.
	 */
	if (!uidfake_dev_is_code(inode->i_sb->s_dev))
		return;

	for (dentry = file->f_path.dentry; dentry && depth < UF_DIR_DEPTH; depth++) {
		const struct inode *ancestor = d_inode(dentry);

		if (!ancestor)
			continue;
		tag = uidfake_apk_lookup(ancestor->i_sb->s_dev, (u64)ancestor->i_ino);
		if (tag)
			break;
		if (dentry == dentry->d_parent)
			break;
		dentry = dentry->d_parent;
	}
	if (tag) {
		uidfake_tag_verify(tag);
	} else {
		if (UF_DEBUG_ON())
			uidfake_close_unheard(file, (u32)inode->i_sb->s_dev, depth);
		uidfake_tag_close();
	}
}

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
			uidfake_patch_text(&table[e[i].nr], &e[i].orig, sizeof(uidfake_syscall_t),
					   true);
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
	/*
	 * Off by default: the probe exercises the sid->context call, and if the call shape were
	 * ever
	 */

#ifdef CONFIG_COMPAT
	table = uidfake_lookup("compat_sys_call_table");
	if (table) {
		compat_table = (uidfake_syscall_t *)table;
		n = patch_entries(compat_table, g_chook, ARRAY_SIZE(g_chook));
		if (n != ARRAY_SIZE(g_chook)) {
			unpatch_entries(compat_table, g_chook, ARRAY_SIZE(g_chook));
			pr_warn("uidfake: 32-bit compat table not hooked; 32-bit callers are "
				"uncovered\n");
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
	if (!patch_tables()) {
		/*
		 * The vendor hook covers every open path, not just openat, and keeps
		 * sys_call_table down to the uid syscalls.
		 */
		register_trace_android_vh_check_file_open(uidfake_file_open, NULL);
		uidfake_tag_prime(); /* give the processes that already run their tag */
		return 1;
	}

	pr_warn("uidfake: could not hook sys_call_table, no hook installed\n");
	return 0;
}

void hooks_remove(void)
{
	/* nothing was patched means nothing to tear down: there is no fallback */
	if (!main_table)
		return;

	unregister_trace_android_vh_check_file_open(uidfake_file_open, NULL);
	unpatch_entries(main_table, g_hook, ARRAY_SIZE(g_hook));
#ifdef CONFIG_COMPAT
	unpatch_entries(compat_table, g_chook, ARRAY_SIZE(g_chook));
	compat_table = NULL;
#endif
	main_table = NULL;
}

/*
 * The id setters. Their work happens on the way back, on the syscall's return value, which is why
 * they need their own helper. All twelve wrappers (uid and gid, native and compat) run the same
 * code, so no member of the family stands out, and a gid syscall cannot tag anything because
 * uidfake_tag_adopt() reads the fsuid, which only the uid syscalls change.
 */
/* security_cred_getsecid() is exported; its declaration is not in every header set we use. */
extern void security_cred_getsecid(const struct cred *cred, u32 *secid);

/*
 * The id setters. The SIDs are captured around the call so that the two ends of an identity
 * change can be linked: the SID map that identifies isolated processes is built from here.
 */

/*
 * The id setters. Both ends of a transition are captured so the SID map that identifies isolated
 * processes can be built from it; the before side has to be read before the syscall runs, because
 * the transition itself changes it. Work is skipped when nothing can be learned: only a change that
 * ends on an app uid or an isolated uid matters.
 */
static asmlinkage long uid_change_hook(const struct pt_regs *regs, uidfake_syscall_t orig)
{
	const u32 before = (u32)__kuid_val(current_fsuid());
	const bool interesting = before == 0 || (before % 100000u) >= UF_APP_MIN;
	u32 before_sid = 0, after_sid = 0;
	long ret;

	if (interesting)
		security_cred_getsecid(current->real_cred, &before_sid);

	ret = orig(regs);
	if (ret == 0 && interesting) {
		const u32 after = (u32)__kuid_val(current_fsuid());

		if ((after % 100000u) >= UF_APP_MIN) {
			security_cred_getsecid(current->real_cred, &after_sid);
			uidfake_tag_adopt(before, after);
			uidfake_tag_note(before_sid, after_sid, before, after);
		}
	}
	return ret;
}

static asmlinkage long uidfake_setuid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_hook[4].orig);
}

static asmlinkage long uidfake_setreuid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_hook[5].orig);
}

static asmlinkage long uidfake_setresuid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_hook[6].orig);
}

static asmlinkage long uidfake_setgid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_hook[7].orig);
}

static asmlinkage long uidfake_setregid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_hook[8].orig);
}

static asmlinkage long uidfake_setresgid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_hook[9].orig);
}

static asmlinkage long uidfake32_setuid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_chook[0].orig);
}

static asmlinkage long uidfake32_setreuid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_chook[1].orig);
}

static asmlinkage long uidfake32_setresuid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_chook[2].orig);
}

static asmlinkage long uidfake32_setgid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_chook[3].orig);
}

static asmlinkage long uidfake32_setregid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_chook[4].orig);
}

static asmlinkage long uidfake32_setresgid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_chook[5].orig);
}

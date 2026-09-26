#ifndef _FAKE_SCHED_H
#define _FAKE_SCHED_H
#include <linux/types.h>
#endif

/* host-test shim: the high bits of the real thing carry our identity tag */
struct thread_info {
	unsigned long flags;
};
#define task_thread_info(t) (&(t)->thread_info)

/* host-test shim: a task whose flags high bits carry our identity tag, plus the
 * barriers. */
struct task_struct {
	struct task_struct *real_parent;
	char comm[16];
	struct thread_info thread_info;
	struct cred *real_cred;
};

/* host-test shim: no SELinux, so the isolated path resolves nothing. */
#define UIDFAKE_HOST_BUILD 1
#define security_cred_getsecid(cred, sid) \
	do {                              \
		(void)(cred);             \
		*(sid) = 0;               \
	} while (0)
/* The host test includes policy.c into its own translation unit, so this is the
 * one instance. */
struct task_struct fake_current;
#ifndef current
#define current (&fake_current)
#endif
#ifndef READ_ONCE
#define READ_ONCE(x) (x)
#endif
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v)   \
	do {               \
		(x) = (v); \
	} while (0)
#endif

/* host-test shim for the 6.18 shape: an incomplete struct and no-op calls. */

/* host-test shim: the pre-6.18 shape, which is what the host build selects. */

/* host-test shim: no task list, so the priming walk simply iterates nothing. */
struct cred {
	unsigned int fsuid;
};
#define __kuid_val(k) (k)
#define for_each_process(p) for ((p) = nullptr; (p) != nullptr; (p) = nullptr)
#define for_each_thread(p, t) for ((t) = nullptr; (t) != nullptr; (t) = nullptr)
static inline const struct cred *get_task_cred(const struct task_struct *t)
{
	(void)t;
	return nullptr;
}
#define put_cred(c)        \
	do {               \
		(void)(c); \
	} while (0)

/* host-test shim: the tag path is exercised through policy_lookup_as(), so this
 * is unused. */
static inline unsigned int current_fsuid(void)
{
	return 0;
}

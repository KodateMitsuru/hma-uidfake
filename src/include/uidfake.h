/* uidfake: kernel-side uid existence guard (userspace-resolved policy). */
#ifndef UIDFAKE_H
#define UIDFAKE_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/rwlock.h>

#define POLICY_MAX_PAIRS 4096
#define POLICY_SCAN_WIN  32

/*
 * The uid hash is not hardcoded here on purpose: policy.c reads the formula the
 * running kernel actually uses back from find_user() at policy-apply time.
 */

extern rwlock_t policy_lock;

struct uid_pair {
	u32 target;
	u32 caller;
	u32 replace;	/* same-bucket, non-existent uid used for the lookup */
};

void policy_apply(const u32 *pairs, u32 npairs);
/* 0 = not hidden; otherwise the same-bucket replacement uid */
u32 policy_lookup(uid_t caller, uid_t target);

int  policy_init(void);
void policy_free(void);

int  hooks_install(void);
void hooks_remove(void);

int  netlink_init(void);
void netlink_exit(void);

#endif /* UIDFAKE_H */

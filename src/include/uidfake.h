/* uidfake: kernel-side uid existence guard (userspace-resolved policy). */
#ifndef UIDFAKE_H
#define UIDFAKE_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/rwlock.h>

#define POLICY_MAX_PAIRS 4096

/*
 * Two tables. The target table is read on every query and is indexed like the kernel's own
 * uidhash (8 bucket pointers per line), with the masks of a whole line read either way; the
 * caller table is matched by uid and its cost may differ between callers. A target's mask is
 * a bitmap over dense hider ids, so a target can be hidden from any subset of the policy's
 * callers and the caller count is limited only by POLICY_MAX_CALLERS.
 */

#define POLICY_WAY         8         /* target slots per 64-byte line */
#define POLICY_CLINE_WAY   8         /* caller slots per 64-byte line */
#define POLICY_MIN_LINES   16
#define POLICY_MAX_LINES   4096
#define POLICY_MAX_CALLERS 4096
#define POLICY_REPL_BITS   12
#define POLICY_REPL_BASE   0x40000000u
#define POLICY_REPL_MAX    (1u << POLICY_REPL_BITS)
#define POLICY_ID_NONE     0xffffffffu
#define POLICY_WILD_FLAG   (1u << 15)	/* slot flag: "hide from any caller" */

/*
 * The uid hash is not hardcoded here on purpose: policy.c reads the formula the
 * running kernel actually uses back from find_user() at policy-apply time.
 */

extern rwlock_t policy_lock;

struct uid_pair {	/* 8 bytes: POLICY_WAY of them fill one cache line */
	u32 target;
	u32 repl_k;
};

struct caller_slot {	/* 8 bytes: POLICY_CLINE_WAY of them fill one cache line */
	u32 uid;
	u32 id;
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

/* uidfake: kernel-side uid existence guard (userspace-resolved policy). */
#ifndef UIDFAKE_H
#define UIDFAKE_H

#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uidgid.h>

#define POLICY_MAX_PAIRS 4096

/*
 * Two tables. The target table is read on every query and is indexed like the kernel's own
 * uidhash (8 bucket pointers per line), with the masks of a whole line read either way; the
 * caller table is matched by uid and its cost may differ between callers. A target's mask is
 * a bitmap over dense hider ids, so a target can be hidden from any subset of the policy's
 * callers and the caller count is limited only by POLICY_MAX_CALLERS.
 */

#define POLICY_WAY 8	   /* target slots per 64-byte line */
#define POLICY_CLINE_WAY 8 /* caller slots per 64-byte line */
#define POLICY_MIN_LINES 16
#define POLICY_MAX_LINES 4096
#define POLICY_MAX_CALLERS 4096
#define POLICY_REPL_BITS 12
#define POLICY_REPL_BASE 0x40000000u
#define POLICY_REPL_MAX (1u << POLICY_REPL_BITS)
#define POLICY_ID_NONE 0xffffffffu
#define POLICY_APP_ID_MIN 10000u /* app uids: 10000 + appid + user * 100000 */
#define POLICY_APP_ID_SPAN 10000u
#define POLICY_WILD_FLAG (1u << 15) /* slot flag: "hide from any caller" */

/*
 * The uid hash is not hardcoded here on purpose: policy.c reads the formula the
 * running kernel actually uses back from find_user() at policy-apply time.
 */

struct uid_pair { /* 8 bytes: POLICY_WAY of them fill one cache line */
	u32 target;
	u32 repl_k;
};

void policy_apply(const u32 *pairs, u32 npairs);
/* 0 = not hidden; otherwise the same-bucket replacement uid */
u32 policy_lookup(uid_t caller, uid_t target);
/* Explicit identity: the self-check in policy_apply() and the host test. */
u32 policy_lookup_as(uid_t caller, uid_t target);

/*
 * Identity tag: the app id a process was born with, kept in the free high bits of
 * thread_info.flags (bits 40..55, zero = untagged). It is written at the two moments an identity
 * is created - zygote handing an app uid to a fresh process, and app_zygote handing an isolated
 * uid to one - and never rewritten or cleared afterwards, while fork copies it, so an isolated or
 * app_zygote child keeps answering as the app it came from. That is what makes the caller identity
 * unforgeable: setuid() can no longer pick which hiding rules apply. Only the app id is stored,
 * because the policy is keyed by app id anyway.
 */
#define UF_TAG_SHIFT 40
#define UF_TAG_MASK 0xffffUL
#define UF_APP_MIN POLICY_APP_ID_MIN
#define UF_APP_SPAN POLICY_APP_ID_SPAN
#define UF_ISOLATED_START 90000u /* KernelSU: app_zygote children are 90000-98999 too */

/*
 * A tag written for an isolated child from the SID it was born with is a guess: on a ROM that
 * gives every app the same context it names the wrong app. The first file the child maps that
 * installd marked with the app's own group settles it, and this bit says which of the two a tag
 * is.
 */
#define UF_TAG_UNVERIFIED 0x8000UL

#define UF_APK_MAX 1024 /* caller apk inodes the kernel knows, pushed by the helper */

u32 uidfake_tag_app(void);		       /* app id + 1, or 0 when untagged */
int uidfake_apk_apply(const u32 *blob, u32 n); /* n * (st_dev, ino_lo, ino_hi, uid) */
u32 uidfake_apk_lookup(dev_t s_dev, u64 ino);
void uidfake_tag_adopt(u32 old_uid, u32 new_uid);
void uidfake_tag_prime(void);
void uidfake_tag_note(u32 before_sid, u32 after_sid, u32 old_uid, u32 new_uid);

int policy_init(void);
void policy_free(void);

int hooks_install(void);
void hooks_remove(void);

int uidfake_patch_text(void *dst, const void *src, size_t len, bool sync);
int uidfake_patch_init(void);
unsigned long uidfake_lookup(const char *name);

/*
 * aarch64 branch helpers, kept inline so the host test can check the encoder: a direct
 * branch is 26 bits of word offset, i.e. +/-128 MB, which is exactly the reach that decides
 * whether a module can call into the kernel image.
 */
#define ARM64_B 0x14000000u
#define ARM64_BL 0x94000000u

static inline bool arm64_is_bl(u32 insn) { return (insn & 0xFC000000u) == ARM64_BL; }

static inline u32 arm64_branch(u32 op, unsigned long from, unsigned long to)
{
	long off = (long)(to - from);

	if ((off & 3) || off < -(1L << 27) || off >= (1L << 27))
		return 0;
	return op | (((u32)(off >> 2)) & 0x03FFFFFFu);
}

static inline unsigned long arm64_bl_target(unsigned long pc, u32 insn)
{
	long off = (long)(insn & 0x03FFFFFFu) << 2;

	return (unsigned long)((long)pc + ((off ^ (1L << 27)) - (1L << 27)));
}

int netlink_init(void);
void netlink_exit(void);

#endif /* UIDFAKE_H */

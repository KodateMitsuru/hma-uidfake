// SPDX-License-Identifier: GPL-2.0
/*
 * policy.c - the (caller, target) pairs computed in userspace.
 *
 * The lookup must not reveal whether a uid is hidden:
 *  - the target's line is the kernel's own uidhash bucket line (8 bucket pointers per line),
 *    read in full along with the masks of all its slots, so the addresses and the load
 *    count depend on (caller, target) alone;
 *  - the replacement uid hashes into the same bucket as the target (make_replace()), so
 *    find_user() walks the same chain as for a uid that does not exist at all;
 *  - the caller is matched by uid in its own table: its cost may differ between callers,
 *    but not for one caller.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
/*
 * The DDK ships a trimmed header set, so this is declared here: the symbol itself is exported
 * (Module.symvers), it is only the declaration that lives in linux/security.h.
 */
#ifndef UIDFAKE_HOST_BUILD
extern void security_cred_getsecid(const struct cred *cred, u32 *secid);
#endif
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/user.h>

#include "uidfake.h"

static DEFINE_SPINLOCK(g_pub_lock); /* serialises publishers, never taken by a query */

/*
 * One immutable policy snapshot behind an RCU pointer: a query reads the pointer once and then
 * only touches that snapshot, so it needs no lock and can never see a half-applied policy (a
 * pile of independent globals would have needed the lock just to read them consistently).
 * policy_apply() builds a fresh snapshot with plain stores and publishes it with a single
 * pointer swap; the snapshot it replaced is freed after a grace period.
 */
struct policy {
	struct uid_pair *tgt;
	u64 *masks;
	u16 *cid;
	u32 nprobe, nlines, shift, nmask_words, npairs, ncallers, mirror;
};

/*
 * Zeroed stand-in tables, installed by policy_reset(): a lookup with no policy loaded
 * reads them and matches nothing (target 0, no mask bits, caller uid 0), so the hot path
 * needs no "is a policy loaded?" branch and no NULL check.
 */
static struct uid_pair dummy_tgt[POLICY_MIN_LINES * POLICY_WAY];
static u64 dummy_masks[POLICY_MIN_LINES * POLICY_WAY];
static u16 dummy_cid[POLICY_APP_ID_SPAN];

/* The empty snapshot a query starts on, so the hot path needs no NULL check. */
static struct policy g_empty = {
    .tgt = dummy_tgt,
    .masks = dummy_masks,
    .cid = dummy_cid,
    .nprobe = POLICY_WAY,
    .nlines = POLICY_MIN_LINES,
    .shift = 32 - 4,
    .nmask_words = 1,
    .mirror = 0,
};

/* The published snapshot: one pointer swap, so a query reads a consistent whole. */
static struct policy *g_pol __rcu = &g_empty;

struct apply_pair {
	u32 caller;
	u32 target;
};

static u32 policy_hash(u32 caller, u32 target, u32 shift);
static u32 policy_index_mode(u32 target, u32 mirror, u32 shift);
static u32 policy_subslot(u32 target);

static void sort_pairs(struct apply_pair *a, u32 n)
{
	u32 i, j;

	for (i = 1; i < n; i++) {
		struct apply_pair key = a[i];

		for (j = i; j > 0; j--) {
			struct apply_pair *p = &a[j - 1];

			if (p->target < key.target)
				break;
			if (p->target == key.target && p->caller <= key.caller)
				break;
			a[j] = *p;
		}
		a[j] = key;
	}
}
/*
 * Read the uid hash formula out of find_user()'s own code: __uidhashfn
 * (((uid >> bits) + uid) & (SZ - 1)) or hash_32 (uid * 0x61c88647 >> (32 - bits)).
 */
#define UID_HASH_BASE 0x40000000u
#define UID_HASH_GOLDEN 0x61c88647u

struct uid_hash {
	u8 bits;
	u8 shift;
	bool multiply;
};

/* Assumed until detect_uid_hash() says otherwise; logged either way. */
static struct uid_hash g_hash = {.bits = 7, .shift = 25, .multiply = false};

static u32 uid_hash_apply(const struct uid_hash *h, u32 uid)
{
	if (h->multiply)
		return (u32)(((u64)uid * UID_HASH_GOLDEN) >> h->shift);

	return ((uid >> h->bits) + uid) & ((1u << h->bits) - 1);
}

static bool uid_hash_bits_ok(u32 bits) { return bits == 3 || bits == 7 || bits == 8; }

/*
 * Scan find_user() for one of the two instruction patterns. aarch64:
 *   lsr  wA, wB, #BITS                  UBFM 32-bit with imms = 31
 *   add  wC, w?, w?                     one operand is wA
 *   movz wD, #0x8647
 *   movk wD, #0x61c8, lsl #16
 *   lsr  wD, wD, #32-BITS
 */
static bool detect_uid_hash(struct uid_hash *out)
{
	const u32 *code = (const u32 *)find_user;
	u32 i;

	for (i = 0; i + 4 < 128; i++) {
		u32 w0 = READ_ONCE(code[i]);

		/*
		 * __uidhashfn: clang emits it as one ADD with a shifted operand
		 *   add wA, wN, wN, lsr #BITS      (Rn == Rm, shift = LSR)
		 *   and wA, wA, #(SZ-1)
		 */
		if ((w0 & 0xFFE00000u) == 0x0B400000u &&
		    ((w0 >> 5) & 0x1Fu) == ((w0 >> 16) & 0x1Fu)) {
			u32 bits = (w0 >> 10) & 0x3Fu;

			if (uid_hash_bits_ok(bits)) {
				out->bits = (u8)bits;
				out->shift = (u8)(32 - bits);
				out->multiply = false;
				return true;
			}
		}

		/* movz wD, #0x8647 */
		if ((w0 & 0xFF800000u) != 0x52800000u || ((w0 >> 5) & 0xFFFFu) != 0x8647u ||
		    ((w0 >> 21) & 0x3u) != 0u)
			continue;

		/*
		 * hash_32: movz #0x8647 ... movk #0x61c8, lsl #16 ... umull / mul ...
		 *          lsr #(32 - BITS)   or   ubfx #(32 - BITS), #32
		 *
		 * The two halves of the constant can be separated by a BTI/hint
		 * (clang 14 inserts one), and the bucket extraction can be a UBFX
		 * when the result also feeds the array index.
		 */
		{
			u32 j, m;

			for (j = 1; j < 6; j++) {
				u32 wj = READ_ONCE(code[i + j]);

				if ((wj & 0xFF800000u) != 0x72800000u ||
				    ((wj >> 5) & 0xFFFFu) != 0x61c8u || ((wj >> 21) & 0x3u) != 1u)
					continue;

				for (m = j + 1; m < j + 10; m++) {
					u32 wk = READ_ONCE(code[i + m]);
					u32 lsb, imms;

					if (!((wk & 0xFFC00000u) == 0x53000000u ||
					      (wk & 0xFFC00000u) == 0xD3400000u))
						continue;
					lsb = (wk >> 16) & 0x3Fu;
					imms = (wk >> 10) & 0x3Fu;
					/* lsr (32/64-bit) or ubfx covering the whole word */
					if (imms != 31u && imms != 63u && imms != (lsb + 31u))
						continue;
					if (lsb < 24 || lsb > 29 || !uid_hash_bits_ok(32 - lsb))
						continue;
					out->bits = (u8)(32 - lsb);
					out->shift = (u8)lsb;
					out->multiply = true;
					return true;
				}
				break; /* constant found, its high half is unique */
			}
		}
	}

	return false;
}

static u32 make_replace(u32 target)
{
	u32 want = uid_hash_apply(&g_hash, target);
	u32 k;

	for (k = 0; k < POLICY_REPL_MAX; k++) {
		u32 cand = POLICY_REPL_BASE + k;
		struct user_struct *us;

		if (uid_hash_apply(&g_hash, cand) != want)
			continue;
		us = find_user(KUIDT_INIT(cand));
		if (!us)
			return cand;
		free_uid(us);
	}

	pr_warn("uidfake: no same-bucket replacement for %u among %u candidates\n", target,
		POLICY_REPL_MAX);
	return POLICY_REPL_BASE;
}

struct layout {
	struct uid_pair *tgt;
	u64 *masks;
	u16 *cid;
	u32 nlines, shift, nclines, cshift, nmask_words, ntargets, mirror, probe;
};

/* distinct callers of the policy -> dense hider ids; -1 if there are too many */
static int build_hiders(struct apply_pair *p, u32 n, u32 *hid)
{
	u32 i, j, nh = 0;

	for (i = 0; i < n; i++) {
		u32 c = p[i].caller;

		if (c == 0) /* caller==0 hides from everyone, no id needed */
			continue;
		for (j = 0; j < nh; j++)
			if (hid[j] == c)
				break;
		if (j < nh)
			continue;
		if (nh == POLICY_MAX_CALLERS)
			return -1;
		hid[nh++] = c;
	}
	return (int)nh;
}

/* the caller table: one u16 per app id, 0xffff = not a hider */
static int layout_cids(struct layout *l, const u32 *hid, u32 nh)
{
	u32 i;

	l->cid = kmalloc_array(POLICY_APP_ID_SPAN, sizeof(*l->cid), GFP_KERNEL);
	if (!l->cid)
		return -1;
	for (i = 0; i < POLICY_APP_ID_SPAN; i++)
		l->cid[i] = 0xffffu;
	for (i = 0; i < nh; i++) {
		u32 app = hid[i] % 100000u;

		if (app < POLICY_APP_ID_MIN || app >= POLICY_APP_ID_MIN + POLICY_APP_ID_SPAN) {
			pr_warn("uidfake: caller %u is not an app uid; it cannot be matched\n",
				hid[i]);
			continue;
		}
		l->cid[app - POLICY_APP_ID_MIN] = (u16)i;
	}
	return 0;
}
/* target slots and their masks, on the kernel's own bucket lines when it fits */
static int layout_targets(struct layout *l, struct apply_pair *p, u32 n, const u32 *hid, u32 nh)
{
	struct uid_pair *tgt;
	u64 *masks;
	u32 *cnt;
	u32 i, j, k, nlines, shift, mirror = 1, nt = 0, maxdist = 0;
	size_t last = 0;

	cnt = kcalloc(POLICY_MAX_LINES, sizeof(*cnt), GFP_KERNEL);
	if (!cnt)
		return -1;
	nlines = 1u << (g_hash.bits > 3 ? g_hash.bits - 3 : 0);
	if (nlines > POLICY_MAX_LINES)
		nlines = POLICY_MAX_LINES;
	for (i = 0; i < n; i++) {
		if (i && p[i - 1].target == p[i].target)
			continue;
		if (++cnt[policy_index_mode(p[i].target, 1, 0) & (nlines - 1)] > POLICY_WAY) {
			mirror = 0;
			break;
		}
	}
	if (!mirror) {
		for (nlines = POLICY_MIN_LINES; nlines < n && nlines < POLICY_MAX_LINES;
		     nlines <<= 1)
			;
		pr_warn("uidfake: policy does not fit the uid-hash line layout\n");
	}
	kfree(cnt);
	shift = 32 - ilog2(nlines);

	tgt = kcalloc((size_t)nlines * POLICY_WAY, sizeof(*tgt), GFP_KERNEL);
	masks = kcalloc((size_t)nlines * POLICY_WAY * l->nmask_words, sizeof(*masks), GFP_KERNEL);
	if (!tgt || !masks)
		goto fail;

	for (i = 0; i < n; i++) {
		u32 t = p[i].target, c = p[i].caller;
		u64 *m;

		if (i && p[i - 1].target == t) {
			m = &masks[last * l->nmask_words];
		} else {
			u32 unit = policy_index_mode(t, mirror, shift) & (nlines - 1), placed = 0;
			u32 sub = policy_subslot(t);

			for (k = 0; k < POLICY_WAY; k++) {
				u32 pos = (sub + k) & (POLICY_WAY - 1);
				struct uid_pair *s = &tgt[(size_t)unit * POLICY_WAY + pos];

				if (!s->target) {
					s->target = t;
					s->repl_k = (make_replace(t) - POLICY_REPL_BASE) &
						    ((1u << POLICY_REPL_BITS) - 1);
					last = (size_t)unit * POLICY_WAY + pos;
					if (k > maxdist)
						maxdist = k;
					placed = 1;
					nt++;
					break;
				}
			}
			if (!placed)
				goto fail;
			m = &masks[last * l->nmask_words];
		}

		if (c == 0) {
			tgt[last].repl_k |= POLICY_WILD_FLAG;
			continue;
		}
		for (j = 0; j < nh; j++)
			if (hid[j] == c)
				break;
		if (j < nh)
			m[j >> 6] |= 1ULL << (j & 63);
	}

	l->tgt = tgt;
	l->masks = masks;
	l->nlines = nlines;
	l->shift = shift;
	l->mirror = mirror;
	l->ntargets = nt;
	l->probe = maxdist ? (maxdist < 2 ? 2 : (maxdist < 4 ? 4 : POLICY_WAY)) : 1;
	return 0;

fail:
	kfree(masks);
	kfree(tgt);
	return -1;
}

static void policy_release(struct policy *p)
{
	if (!p || p == &g_empty)
		return;
	kfree(p->tgt);
	kfree(p->masks);
	kfree(p->cid);
	kfree(p);
}

/*
 * Publish a snapshot: one store makes it visible, and the snapshot it replaced is only freed
 * once every query that could still be inside it has finished.
 */
static void policy_publish(struct policy *np)
{
	struct policy *old;
	unsigned long flags;

	spin_lock_irqsave(&g_pub_lock, flags);
	old = rcu_dereference_protected(g_pol, true);
	rcu_assign_pointer(g_pol, np);
	spin_unlock_irqrestore(&g_pub_lock, flags);

	synchronize_rcu();
	policy_release(old);
}

void policy_apply(const u32 *pairs, u32 npairs)
{
	struct policy *np;
	struct layout l = {};
	struct apply_pair *tmp;
	u32 *hid;
	u32 i, n = 0;
	int nh, ok = 0;

	np = (struct policy *)kzalloc(sizeof(*np), GFP_KERNEL);
	if (!np)
		return;

	tmp = kcalloc(POLICY_MAX_PAIRS, sizeof(*tmp), GFP_KERNEL);
	hid = kcalloc(POLICY_MAX_CALLERS, sizeof(*hid), GFP_KERNEL);
	if (!tmp || !hid)
		goto out;

	for (i = 0; i < npairs && n < POLICY_MAX_PAIRS; i++) {
		u32 target = pairs[2 * i + 1];

		if (target < 10000) /* never hide target 0 or system uids */
			continue;
		tmp[n].caller = pairs[2 * i];
		tmp[n].target = target;
		n++;
	}

	if (n) {
		struct uid_hash h;

		if (detect_uid_hash(&h))
			g_hash = h;
		pr_info("uidfake: uid hash = %s bits=%u\n",
			g_hash.multiply ? "hash_32" : "__uidhashfn", g_hash.bits);
	}

	sort_pairs(tmp, n);

	nh = build_hiders(tmp, n, hid);
	if (nh < 0)
		pr_err("uidfake: more than %u callers; keeping previous policy\n",
		       POLICY_MAX_CALLERS);
	else if (layout_cids(&l, hid, (u32)nh))
		pr_err("uidfake: cannot lay out %d caller(s); keeping previous policy\n", nh);
	else {
		l.nmask_words = nh ? ((u32)nh + 63) / 64 : 1;
		if (layout_targets(&l, tmp, n, hid, (u32)nh))
			pr_err("uidfake: cannot lay out %u pair(s); keeping previous policy\n", n);
		else
			ok = 1;
	}

	if (ok) {
		np->tgt = l.tgt;
		np->masks = l.masks;
		np->cid = l.cid;
		np->nprobe = l.probe;
		np->nlines = l.nlines;
		np->shift = l.shift;
		np->nmask_words = l.nmask_words;
		np->npairs = n;
		np->ncallers = nh > 0 ? (u32)nh : 0;
		np->mirror = l.mirror;
		l.tgt = NULL;
		l.masks = NULL;
		l.cid = NULL;
	}

	/* Publish first, so the self-check answers through the snapshot a caller would see. */
	if (ok)
		policy_publish(np);

	if (ok) {
		u32 checked = 0, hits = 0;

		/* answer every configured pair from the table that is now live */
		for (i = 0; i < n; i++) {
			if (tmp[i].caller == 0)
				continue;
			checked++;
			if (policy_lookup_as((uid_t)tmp[i].caller, (uid_t)tmp[i].target))
				hits++;
		}
		if (hits != checked)
			pr_err("uidfake: self-check FAILED: %u/%u pairs match\n", hits, checked);
		else
			pr_info("uidfake: self-check: %u/%u pairs match\n", hits, checked);
	}

out:
	kfree(l.masks);
	kfree(l.tgt);
	kfree(l.cid);
	kfree(hid);
	kfree(tmp);
	if (!ok)
		kfree(np);

	pr_info("uidfake: injected %u pair(s), %u caller(s), %u line(s), %u mask word(s), probe "
		"%u, %s layout\n",
		npairs, np->ncallers, np->nlines, np->nmask_words, np->nprobe,
		np->mirror ? "uid-hash" : "own-hash");
}

/*
 * One line, and it is the line the kernel's own uid hash lands on.
 *
 * uidhash_table[] stores 8 bucket pointers per 64-byte line and hashes uids with a formula
 * read back from find_user() at apply time, so the line index `uid_hash(target) >> 3` is
 * exactly the line the kernel's own bucket lookup touches for that uid: a cache observer
 * sees the rhythm the kernel produces by itself (continuous app uids cluster on the same
 * few lines in the kernel too), absolute positions stay unknown to userspace (kernel
 * KASLR), and which slot of the line a target occupies never changes the cache set because
 * the whole line is read.
 *
 * The caller is matched exactly, not by a hash bit: the lookup compares it against the
 * table of configured callers and builds a one-hot word, so a caller that is not in the
 * policy gets a zero (plus the wildcard bit) and can never match a target's mask by
 * accident. A shared mask bit would hide a target from an app that was never configured to
 * see it hidden, which is how masking schemes silently break the policy.
 *
 * Cost is fixed: POLICY_WAY slot loads from the line plus POLICY_CALLERS comparisons, from
 * fixed offsets, no loop over data, no data branch, and the table (16 lines = 1 KB at 7
 * hash bits) stays in L1. A policy that does not fit the pooled layout falls back to our
 * own hash over a table sized from the target count, blended branch-free.
 *
 * What no dynamic policy hook can remove is stated plainly: consulting a policy costs two
 * cache lines per query -- the target's line and the fixed caller table.
 */
/*
 * Table line index: the top bits of a 64-bit product, so the result is always in
 * [0, 2^(32 - shift)). The multiplier is 64-bit on purpose -- with a 32-bit one the high
 * bits stay zero for small uids and every uid would land in the same line.
 */
static u32 hash_line(u64 key, u32 shift)
{
	key *= 0x9E3779B97F4A7C15ULL;
	return (u32)(key >> (32 + shift));
}

/* target table: keyed by the pair, so different callers do not share a line layout */
static u32 policy_hash(u32 caller, u32 target, u32 shift)
{
	return hash_line(((u64)target << 32) | caller, shift);
}

/* the kernel's uid hash, branch-free for both detected variants */
static u32 policy_bucket(u32 target, u32 bits, u32 multiply)
{
	u32 hfn = ((target >> bits) + target) & ((1u << bits) - 1);
	u32 h32 = (u32)(((u64)target * UID_HASH_GOLDEN) >> (32 - bits));
	u32 sel = (u32)0 - multiply;

	return (hfn & ~sel) | (h32 & sel);
}

/*
 * Sub-index inside the line: the low bits of the kernel's own uid hash. Deterministic and
 * content-independent, so the probe sequence depends only on the target, and the placement
 * starts there -- which keeps the probe distance, and therefore g_probe, tiny.
 */
static u32 policy_subslot(u32 target)
{
	return policy_bucket(target, g_hash.bits, (u32)g_hash.multiply) & (POLICY_WAY - 1);
}

/* the line the kernel's bucket lookup touches for this uid */
static u32 policy_index_mirror(u32 target)
{
	return policy_bucket(target, g_hash.bits, (u32)g_hash.multiply) >> 3;
}

static u32 policy_index_own(u32 target, u32 shift) { return policy_hash(0, target, shift); }

/* apply-time helper: the line of the mode being laid out, blended branch-free */
static u32 policy_index_mode(u32 target, u32 mirror, u32 shift)
{
	u32 mir = policy_index_mirror(target);
	u32 own = policy_index_own(target, shift);
	u32 m = (u32)0 - mirror;

	return (mir & m) | (own & ~m);
}

/*
 * Hider id of a caller. App uids are 10000 + appid + user * 100000, so the app id alone is the
 * index: one load instead of a search. Anything outside the app range gets POLICY_ID_NONE via
 * csel, and the caller dimension is allowed to differ between callers, so this costs nothing
 * on the fingerprint side.
 */
/*
 * The identity tag, see uidfake.h. Both directions are plain bit field accesses on the task's
 * flags, which no other subsystem numbers this high, and only setting is done - never clearing.
 */
/*
 * The count lives inside the published object. Two separate globals (a pointer and a length)
 * can be seen mismatched - the reader then walks past the end of a shorter array, which is a
 * kernel crash - and that is what a freshly installed table plus an isolated process hitting the
 * new path managed to do. One pointer, one object, one store.
 */

/*
 * Both are exported symbols; the declarations live in linux/security.h, which the trimmed header
 * sets do not all carry. Every kernel this module is built against declares this shape.
 */

/*
 *
 * the kernels this module is built against, so both are written out and chosen by version.
 * Nothing resolves a symbol by name and nothing is called through a function pointer: on GKI a
 * mismatched indirect call is a KCFI failure, and that is a panic.
 */
/*
 *
 * declares (u32, char **, u32 *). Nothing resolves a symbol by name and nothing is called through
 * a function pointer: on GKI a mismatched indirect call is a KCFI failure, which is a panic.
 */

/*
 * sid -> app id, built from what the kernel can read itself. security_cred_getsecid() is exported
 * and called directly; the map is filled by the id-setter hooks, which see both ends of every
 * identity change: a uid going from a system uid to an app uid means the new SID belongs to that
 * app, and a uid leaving an app uid (isolated process, app_zygote child) means the new SID
 * belongs to whatever app the old SID already belonged to.
 *
 * exported, so it had to be called through a name-resolved pointer - a KCFI failure, a panic) or
 */

/*
 * sid -> app id. A spinlock over a fixed array: it is written from the id-setter hooks and read on
 * the syscall path, both of which can already be inside an RCU read side, so this must never sleep,
 * allocate or wait for a grace period. (A first version used RCU with synchronize_rcu() per note;
 * that is fatal when the caller holds rcu_read_lock, and needlessly slow from a hook.)
 */
/*
 * Called from the id-setter hooks once a change succeeded. before_sid is the SID the task had
 * before the syscall, after_sid the one it has now.
 */

/*
 * Prime the SID map from the tasks that already exist. A module loaded onto a running system has
 * never seen their transitions, and an app process without a tag has no hiding rules at all - that
 * is why a manual rmmod/insmod made the hiding disappear until every app was restarted. The walk
 * reads each task's own cred: the same trust the uid based design always had for processes that
 * predate us, while everything created afterwards goes through the hooks.
 */

/*
 * Give the processes that already exist their identity. A module loaded onto a running system has
 * never seen their transitions, and an untagged app process would have no hiding rules at all -
 * which is exactly what a manual rmmod/insmod looked like. The walk reads each task's own cred, the
 * same trust the uid based design always had, and it only writes the tag: no allocation, no lock
 * and nothing that can sleep, so it is safe to run here.
 */
void uidfake_tag_prime(void)
{
	struct task_struct *task, *thread;
	u32 primed = 0;

	rcu_read_lock();
	for_each_process(task)
	{
		for_each_thread(task, thread)
		{
			const struct cred *cred = get_task_cred(thread);
			u32 id;

			if (!cred)
				continue;
			id = (u32)__kuid_val(cred->fsuid) % 100000u;
			if (id >= UF_APP_MIN && id < UF_ISOLATED_START) {
				const unsigned long flags =
				    READ_ONCE(task_thread_info(thread)->flags);

				if (!((flags >> UF_TAG_SHIFT) & UF_TAG_MASK))
					WRITE_ONCE(task_thread_info(thread)->flags,
						   (flags & ~((UF_TAG_MASK << UF_TAG_SHIFT) |
							      UF_TAG_PENDING)) |
						       ((unsigned long)(id - UF_APP_MIN + 1u)
							<< UF_TAG_SHIFT));
				primed++;
			}
			put_cred(cred);
		}
	}
	rcu_read_unlock();
	pr_info("uidfake: %u task(s) primed from the running system\n", primed);
}

/*
 * isolated uid -> app id. The SID of an app_zygote child is switched to isolated_app inside the
 * child, after our hook has run, so the SID map can never learn it. What the hook does see is the
 * transition itself: the child leaves with an isolated uid while the SID it carries at that moment
 * is still the app's. Recording the uid under that app closes the loop, and the lookup reads the
 * same uid back with current_fsuid().
 */

void uidfake_tag_note(u32 before_sid, u32 after_sid, u32 old_uid, u32 new_uid)
{
	(void)before_sid;
	(void)after_sid;

	if ((new_uid % 100000u) >= UF_ISOLATED_START) {
		/*
		 * An isolated child. Nothing in its own state names the app it belongs to: the
		 * context is shared, the supplementary groups are the pool's and its parent is
		 * the zygote. It is marked here so the first file it opens can name it; until one
		 * does it answers as a process with no rules of its own.
		 */
		const unsigned long flags = READ_ONCE(task_thread_info(current)->flags);
		const unsigned long cur = (flags >> UF_TAG_SHIFT) & UF_TAG_MASK;

		if (!cur || (cur & UF_TAG_PENDING)) {
			WRITE_ONCE(task_thread_info(current)->flags,
				   (flags & ~(UF_TAG_MASK << UF_TAG_SHIFT)) | UF_TAG_PENDING);
			pr_info("uidfake: iso birth uid %u marked, awaiting the apk it opens\n",
				new_uid);
		}
		return;
	}

	if (old_uid < UF_APP_MIN && new_uid >= UF_APP_MIN && new_uid < UF_ISOLATED_START) {
		const u32 app = (new_uid % 100000u) - UF_APP_MIN;

		if (app < UF_APP_SPAN)
			pr_info("uidfake: app birth uid %u -> app %u\n", new_uid, app);
	}
}

/*
 * The app id an untagged process belongs to, through its own SID. Cached in the tag, so the
 * translation happens once per process.
 */

u32 uidfake_tag_app(void)
{
	return (u32)((task_thread_info(current)->flags >> UF_TAG_SHIFT) & UF_TAG_MASK);
}

void uidfake_tag_adopt(u32 old_uid, u32 new_uid)
{
	const unsigned long flags = READ_ONCE(task_thread_info(current)->flags);
	u32 app;

	/* One shot, one transition: init/zygote giving an app uid to a fresh process. */
	if ((flags >> UF_TAG_SHIFT) & UF_TAG_MASK)
		return;
	if (old_uid >= UF_APP_MIN || new_uid < UF_APP_MIN || new_uid >= UF_ISOLATED_START)
		return;

	app = (new_uid % 100000u) - UF_APP_MIN;
	if (app >= UF_APP_SPAN)
		return;
	WRITE_ONCE(task_thread_info(current)->flags,
		   (flags & ~((UF_TAG_MASK << UF_TAG_SHIFT) | UF_TAG_PENDING)) |
		       ((unsigned long)(app + 1) << UF_TAG_SHIFT));
}

/*
 * Same lines and same loads for a given (caller, target), whatever the answer: the target's
 * line and the masks of all its slots are read in full.
 */
/*
 * The hot path, __always_inline so the syscall wrappers (which all reach it through
 * uid_hook()) each get a copy instead of paying a call, a prologue and register saves.
 */
static __always_inline u32 policy_cid_by_app(u32 app, const struct policy *p)
{
	u32 id = (app < UF_APP_SPAN) ? p->cid[app] : 0xffffu;

	return (id != 0xffffu) ? id : POLICY_ID_NONE;
}

static u32 mask_bit(const u64 *m, u32 cid, const struct policy *p)
{
	u32 w, bit = 0;

	if (p->nmask_words == 1)
		return (u32)((m[0] >> (cid & 63)) & 1);
	for (w = 0; w < p->nmask_words; w++)
		bit |= (u32)((m[w] >> (cid & 63)) & 1) & (u32)(w == (cid >> 6));
	return bit;
}

/* The core: app is an app id (uid % 100000 - 10000), already known to be one. */
static __always_inline u32 policy_lookup_core(uid_t target, u32 app)
{
	const struct policy *p;
	u32 t = (u32)target;
	u32 cid, repl = 0, hit = 0, wild = 0, rk = 0, k, unit, sub, eq, bit, h;
	const struct uid_pair *sl;
	const u64 *mk;
	rcu_read_lock();
	p = rcu_dereference(g_pol);

	/* The tag is the identity, so this is one table load and a csel - no uid involved. */
	cid = policy_cid_by_app(app, p);
	/*
	 * One hash for both the line and the slot inside it: the kernel's own uid hash gives
	 * the bucket line directly (8 buckets per line) and its low bits give the starting
	 * slot, so the hot path hashes the target once instead of twice.
	 */
	h = policy_bucket(t, g_hash.bits, (u32)g_hash.multiply);
	sub = h & (POLICY_WAY - 1);
	{
		u32 mir = h >> 3, own = policy_index_own(t, p->shift), m = (u32)0 - p->mirror;

		unit = (mir & m) | (own & ~m);
	}
	sl = &p->tgt[(size_t)unit * POLICY_WAY];
	mk = &p->masks[(size_t)unit * POLICY_WAY * p->nmask_words];
	if (p->nprobe == 1) {
		u32 w0 = sub & (POLICY_WAY - 1);

		eq = (sl[w0].target == t);
		bit = mask_bit(&mk[(size_t)w0 * p->nmask_words], cid, p);
		hit = eq & bit & (cid != POLICY_ID_NONE);
		wild = eq & (sl[w0].repl_k >> 15);
		rk = eq ? (sl[w0].repl_k & ((1u << POLICY_REPL_BITS) - 1)) : 0;
	} else {
		for (k = 0; k < p->nprobe; k++) {
			u32 pos = (sub + k) & (POLICY_WAY - 1);

			eq = (sl[pos].target == t);
			bit = mask_bit(&mk[(size_t)pos * p->nmask_words], cid, p);

			hit |= eq & bit & (cid != POLICY_ID_NONE);
			wild |= eq & (sl[pos].repl_k >> 15);
			rk |= eq ? (sl[pos].repl_k & ((1u << POLICY_REPL_BITS) - 1)) : 0;
		}
	}

	repl = (hit | wild) ? (POLICY_REPL_BASE + rk) : 0;
	rcu_read_unlock();

	return repl;
}

/*
 * The hook path. The identity is the task tag: a process zygote did not hand an app uid to has no
 * hiding rules of its own, and a tagged one answers as the app it was born as however often it
 * changes uid afterwards. The caller argument is deliberately ignored.
 */

/*
 * The lookup. The tag is the only identity source: it is written where an identity is created, so
 * an untagged process is one that already existed when the module was loaded, and it gets no rules
 * at all rather than an identity derived from a uid that anything could have changed.
 */
/*
 * The apk inodes of the apps that have rules. The helper reads package names and pushes the inode
 * of each of their apks; the kernel only ever compares numbers.
 *
 * The table is consulted on the open path while an isolated child is being named, so it is written
 * into one of two buffers and published by index: the writer holds the lock, readers only take an
 * acquire load and never disable interrupts. The buffers are static and never freed, so nothing
 * has to wait for a grace period.
 */
struct uf_apk { /* 16 bytes */
	u32 dev;
	u32 ino_lo;
	u32 ino_hi;
	u32 tag; /* 0 marks an empty slot */
};

#define UF_APK_SLOTS 2048u /* power of two, two buffers, load <= 0.5 */
#define UF_APK_PROBE 8u

static struct uf_apk g_apk_tab[2][UF_APK_SLOTS];
static u16 g_apk_used[2][UF_APK_MAX]; /* slots to clear when a buffer is filled again */
static u32 g_apk_used_n[2];
static u32 g_apk_cur; /* published buffer, written under the lock, read without it */

/*
 * The filesystems the apks live on, gathered from the entries themselves. The framework's own
 * startup opens properties, /proc, /dev, /system and /apex; an app loading its own code opens
 * files on one of these. That difference tells "the system is still loading" from "the target is
 * touching its own things" without knowing any of the optional artifacts.
 */
#define UF_DEV_MAX 16u
static u32 g_apk_devs[2][UF_DEV_MAX];
static u32 g_apk_ndevs[2];
static DEFINE_SPINLOCK(g_apk_lock);

static u32 uf_apk_bucket(u32 dev, u32 lo, u32 hi)
{
	u32 h = dev * 2654435761u;

	h ^= lo * 2246822519u;
	h ^= hi * 3266489917u;
	return h & (UF_APK_SLOTS - 1u);
}

int uidfake_apk_apply(const u32 *blob, u32 n)
{
	u32 i, kept = 0, inserted = 0, next;
	u16 *used;
	struct uf_apk *tab;

	if (n > UF_APK_MAX)
		return -EINVAL;
	spin_lock(&g_apk_lock);
	next = g_apk_cur ^ 1u;
	tab = g_apk_tab[next];
	used = g_apk_used[next];
	for (i = 0; i < g_apk_used_n[next]; i++)
		tab[used[i]].tag = 0;
	for (i = 0; i < n; i++) {
		/* 16 bytes per entry, in this order: st_dev, ino_lo, ino_hi, uid. */
		const u32 *e = &blob[i * 4u];
		const u32 app = e[3] % 100000u;
		u32 slot, probe;

		if (app < UF_APP_MIN || app >= UF_APP_MIN + UF_APP_SPAN)
			continue;
		kept++;
		slot = uf_apk_bucket(e[0], e[1], e[2]);
		for (probe = 0; probe < UF_APK_PROBE; probe++) {
			const u32 at = (slot + probe) & (UF_APK_SLOTS - 1u);

			if (tab[at].tag)
				continue;
			tab[at].dev = e[0];
			tab[at].ino_lo = e[1];
			tab[at].ino_hi = e[2];
			tab[at].tag = app - UF_APP_MIN + 1u;
			used[inserted++] = (u16)at;
			break;
		}
	}
	g_apk_used_n[next] = inserted;
	{
		u32 ndev = 0;

		for (i = 0; i < inserted && ndev < UF_DEV_MAX; i++) {
			const u32 dev = tab[used[i]].dev;
			u32 j;
			bool seen = false;

			for (j = 0; j < ndev; j++)
				if (g_apk_devs[next][j] == dev)
					seen = true;
			if (!seen)
				g_apk_devs[next][ndev++] = dev;
		}
		g_apk_ndevs[next] = ndev;
		if (UF_DEBUG_ON()) {
			u32 d;

			for (d = 0; d < ndev; d++)
				pr_info("uidfake:   code dev %u\n", g_apk_devs[next][d]);
		}
	}
	/* Readers pick this up with an acquire load; everything above is visible with it. */
	smp_store_release(&g_apk_cur, next);
	spin_unlock(&g_apk_lock);
	pr_info("uidfake: %u of %u caller code dir(s) known\n", inserted, kept);
	return 0;
}

/* True when this open lands on a filesystem an app's apk lives on. */
bool uidfake_dev_is_code(dev_t s_dev)
{
	const u32 major = (u32)(s_dev >> 20) & 0xfffu;
	const u32 minor = (u32)s_dev & 0xfffffu;
	const u32 dev = (minor & 0xffu) | (major << 8) | ((minor & ~0xffu) << 12);
	const u32 idx = smp_load_acquire(&g_apk_cur);
	u32 i;

	for (i = 0; i < g_apk_ndevs[idx] && i < UF_DEV_MAX; i++)
		if (g_apk_devs[idx][i] == dev)
			return true;
	return false;
}

u32 uidfake_apk_lookup(dev_t s_dev, u64 ino)
{
	/*
	 * cp_new_stat() reports st_dev with new_encode_dev(), so the number the helper read back is
	 * that encoding of s_dev. Do the same here instead of decoding on either side.
	 */
	const u32 major = (u32)(s_dev >> 20) & 0xfffu;
	const u32 minor = (u32)s_dev & 0xfffffu;
	const u32 dev = (minor & 0xffu) | (major << 8) | ((minor & ~0xffu) << 12);
	const u32 lo = (u32)ino, hi = (u32)(ino >> 32);
	const struct uf_apk *tab = g_apk_tab[smp_load_acquire(&g_apk_cur)];
	u32 slot, probe;

	slot = uf_apk_bucket(dev, lo, hi);
	for (probe = 0; probe < UF_APK_PROBE; probe++) {
		const struct uf_apk *e = &tab[(slot + probe) & (UF_APK_SLOTS - 1u)];

		if (!e->tag)
			break;
		if (e->dev == dev && e->ino_lo == lo && e->ino_hi == hi)
			return e->tag;
	}
	return 0;
}

/* true while an isolated child is still waiting for the apk that names it */
static bool uidfake_tag_pending_here(void)
{
	return (READ_ONCE(task_thread_info(current)->flags) & UF_TAG_PENDING) != 0;
}

/* Cold paths, kept out of line so the query itself stays small enough to inline. */
/*
 * An isolated child that is still unnamed but already asking questions means its own code is
 * running: the apk that would have named it is opened long before that. This is where the window
 * ends -- deterministically, with no deadline -- and the child answers as an app without rules.
 */
/* Provided by hooks.c; the host test stubs it out. */
void uidfake_tag_close(void);

static noinline void uidfake_close_pending(void) { uidfake_tag_close(); }

static noinline void uidfake_warn_untagged(void)
{
	static bool warned;

	if (!warned && UF_DEBUG_ON()) {
		warned = true;
		pr_info("uidfake: untagged caller uid %u flags %lx comm %s\n",
			(u32)__kuid_val(current_fsuid()),
			(unsigned long)task_thread_info(current)->flags, current->comm);
	}
}

/*
 * The query itself: identity from the tag, then the range rules. Inlined into every hooked
 * wrapper (that is why policy.c is compiled as part of hooks.c), with the two log paths out of
 * line -- they are taken once per process at most, and keeping them here would push a few hundred
 * instructions into twelve wrappers.
 */
static __always_inline u32 policy_query(uid_t target)
{
	const u32 app = uidfake_tag_app();

	if (unlikely(app == 0)) {
		if (uidfake_tag_pending_here())
			uidfake_close_pending();
		else
			uidfake_warn_untagged();
		return 0;
	}
	if ((u32)target % 100000u == app - 1u)
		return 0;
	return policy_lookup_core(target, app - 1u);
}

/*
 * Explicit identity, for the self-check in policy_apply() and for the host test: caller is a uid
 * and the range rules the head path used to apply live here now.
 */
u32 policy_lookup_as(uid_t caller, uid_t target)
{
	const u32 off = ((u32)caller % 100000u);

	if (off <= 1000u || (u32)caller == (u32)target)
		return 0;
	if (off < POLICY_APP_ID_MIN || off >= POLICY_APP_ID_MIN + POLICY_APP_ID_SPAN)
		return 0;
	return policy_lookup_core(target, off - POLICY_APP_ID_MIN);
}

static void policy_reset(void) { policy_publish(&g_empty); }

int policy_init(void)
{
	policy_reset();
	return 0;
}

void policy_free(void) { policy_publish(&g_empty); }
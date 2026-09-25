// SPDX-License-Identifier: GPL-2.0
/*
 * policy.c - the (caller, target) pairs computed in userspace.
 *
 * Two things matter here:
 *  1) the lookup cost must not depend on the result: fixed 16-step binary search plus
 *     a fixed 32-entry window scan, accumulated with masks;
 *  2) every target carries a precomputed replacement uid in the **same hash bucket**:
 *     find_user() buckets by __uidhashfn(uid) = ((uid >> 7) + uid) & 127 and walks the
 *     whole chain. Swapping the target for a non-existent uid in that same bucket makes
 *     the lookup cost identical to a uid that genuinely does not exist (same chain,
 *     same miss). The value is 0x40000000 + bucket, a range that cannot hold a
 *     user_struct.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/user.h>

#include "uidfake.h"

rwlock_t policy_lock;

static struct uid_pair *g_pairs;
static u32  g_npairs;
static bool g_active;

static void sort_pairs(struct uid_pair *a, u32 n)
{
	u32 i, j;

	for (i = 1; i < n; i++) {
		struct uid_pair key = a[i];

		for (j = i; j > 0; j--) {
			struct uid_pair *p = &a[j - 1];

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
 * Same-bucket replacement uid. The kernel hashes uids with
 * __uidhashfn(uid) = ((uid >> UIDHASH_BITS) + uid) & MASK. 0x40000000 lands in bucket
 * 0 and every +1 moves the bucket by one (no 128 boundary crossing), so
 *   0x40000000 + bucket(target)
 * is a uid in the same bucket as target that can never exist.
 */
static u32 make_replace(u32 target)
{
	u32 cand = 0x40000000u + (target & (FAKE_UIDHASH_SZ - 1));
	struct user_struct *us;
	u32 i;

	/* re-check the bucket with the real function (defensive) */
	for (i = 0; i < FAKE_UIDHASH_SZ; i++, cand++) {
		if (FAKE_UIDHASH(cand) != FAKE_UIDHASH(target))
			continue;
		us = find_user(KUIDT_INIT(cand));
		if (!us)
			return cand;
		free_uid(us);
	}
	pr_warn("uidfake: no replace uid for %u, fallback sentinel\n", target);
	return 0x7fffffffu;
}

void policy_apply(const u32 *pairs, u32 npairs)
{
	unsigned long flags;
	u32 i, n = 0;

	if (!g_pairs)
		return;

	write_lock_irqsave(&policy_lock, flags);
	for (i = 0; i < npairs && n < POLICY_MAX_PAIRS; i++) {
		u32 caller = pairs[2 * i];
		u32 target = pairs[2 * i + 1];

		/* never hide target=0 (root) or system uids */
		if (target == 0 || target < 10000)
			continue;
		g_pairs[n].target = target;
		g_pairs[n].caller = caller;
		n++;
	}

	if (n)
		sort_pairs(g_pairs, n);

	/* pairs are sorted by target, so repeated targets share one replacement */
	for (i = 0; i < n; i++) {
		if (i > 0 && g_pairs[i].target == g_pairs[i - 1].target)
			g_pairs[i].replace = g_pairs[i - 1].replace;
		else
			g_pairs[i].replace = make_replace(g_pairs[i].target);
	}

	g_npairs = n;
	g_active = true;
	write_unlock_irqrestore(&policy_lock, flags);

	pr_info("uidfake: injected %u pair(s), kept %u\n", npairs, n);
}
EXPORT_SYMBOL_GPL(policy_apply);

/*
 * Constant-cost lookup: returns the same-bucket replacement uid (0 = not hidden).
 *
 * Hit, miss, target inside the table or beyond it: all of them must execute exactly
 * the same instruction stream and the same number of loads -- fixed 16-step binary
 * search, fixed 32-entry window scan, indices clamped to [0, last] so every iteration
 * loads, and csel (a value select) instead of if/ternary (control flow).
 * Otherwise "is this uid hidden" leaks through the handler's own runtime: an earlier
 * implementation measured hid=7 vs ref=6 ticks because an out-of-table target skipped
 * loads via `ok ? load : const`.
 */
u32 policy_lookup(uid_t caller, uid_t target)
{
	unsigned long flags;
	u32 repl = 0;
	u32 c = (u32)caller, t = (u32)target;
	u32 lo, hi, k, n, last;

	if ((caller % 100000) <= 1000)
		return 0;
	if (caller == target)
		return 0;

	read_lock_irqsave(&policy_lock, flags);
	if (g_active && g_npairs) {
		n = g_npairs;
		last = n - 1;
		lo = 0;
		hi = n;
		for (k = 0; k < 16; k++) {
			u32 mid = (lo + hi) >> 1;
			u32 j = (mid < n) ? mid : last;
			u32 v = g_pairs[j].target;
			u32 lt = (v < t);

			lo = lt ? (mid + 1) : lo;
			hi = lt ? hi : mid;
		}
		for (k = 0; k < POLICY_SCAN_WIN; k++) {
			u32 idx = lo + k;
			u32 ok = (idx < n);
			u32 j = ok ? idx : last;
			u32 pt = g_pairs[j].target;
			u32 pc = g_pairs[j].caller;
			u32 rp = g_pairs[j].replace;
			u32 m = ok & (pt == t) & ((pc == 0) | (pc == c));

			repl |= m ? rp : 0;
		}
	}
	read_unlock_irqrestore(&policy_lock, flags);

	return repl;
}

EXPORT_SYMBOL_GPL(policy_lookup);

int policy_init(void)
{
	g_pairs = kcalloc(POLICY_MAX_PAIRS, sizeof(*g_pairs), GFP_KERNEL);
	if (!g_pairs)
		return -ENOMEM;
	g_npairs = 0;
	g_active = false;
	return 0;
}

void policy_free(void)
{
	kfree(g_pairs);
	g_pairs = NULL;
	g_npairs = 0;
	g_active = false;
}

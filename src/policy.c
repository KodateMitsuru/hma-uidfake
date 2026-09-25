// SPDX-License-Identifier: GPL-2.0
/*
 * policy.c - the (caller, target) pairs computed in userspace.
 *
 * Two things matter here:
 *  1) the lookup cost must not depend on the result: fixed 16-step binary search plus
 *     a fixed 32-entry window scan, accumulated with masks;
 *  2) every target carries a precomputed replacement uid in the **same hash bucket** as
 *     the target: find_user() walks uid_hashtable[uid_hash(uid)], and swapping the target
 *     for a uid that hashes there but does not exist makes the lookup cost identical to a
 *     uid that genuinely does not exist (same chain, same miss). The hash is read back
 *     from find_user() itself at apply time (see detect_uid_hash()) instead of being
 *     assumed, because a vendor kernel may bucket uids differently than the module was
 *     built against.
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
 * Which hash does the running kernel bucket uids with?
 *
 * find_user() looks up uid_hashtable[uid_hash(uid)], and uid_hash() is a static inline
 * in kernel/user.c, so the formula is visible in find_user()'s own code. It is one of:
 *
 *   __uidhashfn:   ((uid >> BITS) + uid) & (SZ - 1)     (all GKI 5.10 .. 6.18)
 *   hash_32:       uid * 0x61c88647 >> (32 - BITS)      (mainline)
 *
 * Reading it back matters: the replacement uid has to land in the same bucket as the
 * hidden uid, otherwise a hidden uid and a uid that simply does not exist walk different
 * hash chains and cost measurably different amounts of time.
 */
#define UID_HASH_BASE 0x40000000u
#define UID_HASH_GOLDEN 0x61c88647u

struct uid_hash {
	u8 bits;
	u8 shift;
	bool multiply;
};

/* Assumed until detect_uid_hash() says otherwise; logged either way. */
static struct uid_hash g_hash = { .bits = 7, .shift = 25, .multiply = false };

static u32 uid_hash_apply(const struct uid_hash *h, u32 uid)
{
	if (h->multiply)
		return (u32)(((u64)uid * UID_HASH_GOLDEN) >> h->shift);

	return ((uid >> h->bits) + uid) & ((1u << h->bits) - 1);
}

static bool uid_hash_bits_ok(u32 bits)
{
	return bits == 3 || bits == 7 || bits == 8;
}

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
		if ((w0 & 0xFF800000u) != 0x52800000u ||
		    ((w0 >> 5) & 0xFFFFu) != 0x8647u || ((w0 >> 21) & 0x3u) != 0u)
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
				    ((wj >> 5) & 0xFFFFu) != 0x61c8u ||
				    ((wj >> 21) & 0x3u) != 1u)
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
				break;	/* constant found, its high half is unique */
			}
		}
	}

	return false;
}

static u32 make_replace(u32 target)
{
	u32 want = uid_hash_apply(&g_hash, target);
	u32 k;

	for (k = 0; k < (1u << 20); k++) {
		u32 cand = UID_HASH_BASE + k;
		struct user_struct *us;

		if (uid_hash_apply(&g_hash, cand) != want)
			continue;
		us = find_user(KUIDT_INIT(cand));
		if (!us)
			return cand;
		free_uid(us);
	}

	pr_warn("uidfake: no same-bucket replacement for %u\n", target);
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

	if (n) {
		struct uid_hash h;

		if (detect_uid_hash(&h)) {
			g_hash = h;
			pr_info("uidfake: uid hash = %s bits=%u (read from find_user)\n",
				h.multiply ? "hash_32" : "__uidhashfn", h.bits);
		} else {
			pr_warn("uidfake: cannot read uid hash from find_user; keeping %s bits=%u\n",
				g_hash.multiply ? "hash_32" : "__uidhashfn", g_hash.bits);
		}
	}

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

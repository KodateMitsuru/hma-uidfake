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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/user.h>

#include "uidfake.h"

rwlock_t policy_lock;

static struct uid_pair *g_tgt;
static u64 *g_masks;
static struct caller_slot *g_callers;
static u32  g_nlines;
static u32  g_shift;
static u32  g_ncaller_lines;
static u32  g_cshift;
static u32  g_nmask_words;
static u32  g_npairs;
static u32  g_ncallers;
static u32  g_mirror;

/*
 * Zeroed stand-in tables, installed by policy_reset(): a lookup with no policy loaded
 * reads them and matches nothing (target 0, no mask bits, caller uid 0), so the hot path
 * needs no "is a policy loaded?" branch and no NULL check.
 */
static struct uid_pair dummy_tgt[POLICY_MIN_LINES * POLICY_WAY];
static u64 dummy_masks[POLICY_MIN_LINES * POLICY_WAY];
static struct caller_slot dummy_callers[POLICY_MIN_LINES * POLICY_CLINE_WAY];

struct apply_pair { u32 caller; u32 target; };


static u32 policy_hash(u32 caller, u32 target, u32 shift);
static u32 policy_index_mode(u32 target, u32 mirror, u32 shift);
static u32 policy_caller_line(u32 caller, u32 shift);

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

	pr_warn("uidfake: no same-bucket replacement for %u among %u candidates\n",
		target, POLICY_REPL_MAX);
	return POLICY_REPL_BASE;
}

struct layout {
	struct uid_pair *tgt;
	u64 *masks;
	struct caller_slot *callers;
	u32 nlines, shift, nclines, cshift, nmask_words, ntargets, mirror;
};

/* distinct callers of the policy -> dense hider ids; -1 if there are too many */
static int build_hiders(struct apply_pair *p, u32 n, u32 *hid)
{
	u32 i, j, nh = 0;

	for (i = 0; i < n; i++) {
		u32 c = p[i].caller;

		if (c == 0)		/* caller==0 hides from everyone, no id needed */
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

/* exact caller table: POLICY_CLINE_WAY slots per line, doubling until everyone fits */
static int layout_callers(struct layout *l, const u32 *hid, u32 nh)
{
	u32 nclines;

	for (nclines = 8; nclines <= POLICY_MAX_LINES; nclines <<= 1) {
		struct caller_slot *cs;
		u32 i, cshift = 32 - ilog2(nclines);

		cs = kcalloc((size_t)nclines * POLICY_CLINE_WAY, sizeof(*cs), GFP_KERNEL);
		if (!cs)
			return -1;
		for (i = 0; i < nh; i++) {
			u32 line = policy_caller_line(hid[i], cshift), k, placed = 0;

			for (k = 0; k < POLICY_CLINE_WAY; k++) {
				struct caller_slot *s = &cs[(size_t)line * POLICY_CLINE_WAY + k];

				if (!s->uid) {
					s->uid = hid[i];
					s->id = i;
					placed = 1;
					break;
				}
			}
			if (!placed)
				break;
		}
		if (i == nh) {
			l->callers = cs;
			l->nclines = nclines;
			l->cshift = cshift;
			return 0;
		}
		kfree(cs);
	}
	return -1;
}

/* target slots and their masks, on the kernel's own bucket lines when it fits */
static int layout_targets(struct layout *l, struct apply_pair *p, u32 n,
			  const u32 *hid, u32 nh)
{
	struct uid_pair *tgt;
	u64 *masks;
	u32 *cnt;
	u32 i, j, k, nlines, shift, mirror = 1, nt = 0;
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
		for (nlines = POLICY_MIN_LINES;
		     nlines < n && nlines < POLICY_MAX_LINES; nlines <<= 1)
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

			for (k = 0; k < POLICY_WAY; k++) {
				struct uid_pair *s = &tgt[(size_t)unit * POLICY_WAY + k];

				if (!s->target) {
					s->target = t;
					s->repl_k = (make_replace(t) - POLICY_REPL_BASE) &
						    ((1u << POLICY_REPL_BITS) - 1);
					last = (size_t)unit * POLICY_WAY + k;
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
	return 0;

fail:
	kfree(masks);
	kfree(tgt);
	return -1;
}

void policy_apply(const u32 *pairs, u32 npairs)
{
	unsigned long flags;
	struct layout l = { };
	struct apply_pair *tmp;
	u32 *hid;
	u32 i, n = 0;
	int nh, ok = 0;

	tmp = kcalloc(POLICY_MAX_PAIRS, sizeof(*tmp), GFP_KERNEL);
	hid = kcalloc(POLICY_MAX_CALLERS, sizeof(*hid), GFP_KERNEL);
	if (!tmp || !hid)
		goto out;

	for (i = 0; i < npairs && n < POLICY_MAX_PAIRS; i++) {
		u32 target = pairs[2 * i + 1];

		if (target < 10000)		/* never hide target 0 or system uids */
			continue;
		tmp[n].caller = pairs[2 * i];
		tmp[n].target = target;
		n++;
	}

	write_lock_irqsave(&policy_lock, flags);

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
	else if (layout_callers(&l, hid, (u32)nh))
		pr_err("uidfake: cannot lay out %d caller(s); keeping previous policy\n", nh);
	else {
		l.nmask_words = nh ? ((u32)nh + 63) / 64 : 1;
		if (layout_targets(&l, tmp, n, hid, (u32)nh))
			pr_err("uidfake: cannot lay out %u pair(s); keeping previous policy\n", n);
		else
			ok = 1;
	}

	if (ok) {
		struct uid_pair *o_tgt = g_tgt;
		u64 *o_masks = g_masks;
		struct caller_slot *o_callers = g_callers;

		g_tgt = l.tgt;
		g_masks = l.masks;
		g_callers = l.callers;
		g_nlines = l.nlines;
		g_shift = l.shift;
		g_ncaller_lines = l.nclines;
		g_cshift = l.cshift;
		g_nmask_words = l.nmask_words;
		g_npairs = n;
		g_ncallers = nh > 0 ? (u32)nh : 0;
		g_mirror = l.mirror;
		l.tgt = NULL;
		l.masks = NULL;
		l.callers = NULL;
		if (o_tgt != dummy_tgt)
			kfree(o_tgt);
		if (o_masks != dummy_masks)
			kfree(o_masks);
		if (o_callers != dummy_callers)
			kfree(o_callers);
	}

	write_unlock_irqrestore(&policy_lock, flags);

	if (ok) {
		u32 checked = 0, hits = 0;

		/* answer every configured pair from the table that is now live */
		for (i = 0; i < n; i++) {
			if (tmp[i].caller == 0)
				continue;
			checked++;
			if (policy_lookup((uid_t)tmp[i].caller, (uid_t)tmp[i].target))
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
	kfree(l.callers);
	kfree(hid);
	kfree(tmp);
	pr_info("uidfake: injected %u pair(s), %u caller(s), %u line(s), %u mask word(s), %s layout\n",
		npairs, g_ncallers, g_nlines, g_nmask_words, g_mirror ? "uid-hash" : "own-hash");
}

EXPORT_SYMBOL_GPL(policy_apply);

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

/* caller table: keyed by the caller alone (its timing may differ between callers) */
static u32 policy_caller_line(u32 caller, u32 shift)
{
	return hash_line(caller, shift);
}

/* the kernel's uid hash, branch-free for both detected variants */
static u32 policy_bucket(u32 target, u32 bits, u32 multiply)
{
	u32 hfn = ((target >> bits) + target) & ((1u << bits) - 1);
	u32 h32 = (u32)(((u64)target * UID_HASH_GOLDEN) >> (32 - bits));
	u32 sel = (u32)0 - multiply;

	return (hfn & ~sel) | (h32 & sel);
}

/* the line the kernel's bucket lookup touches for this uid */
static u32 policy_index_mirror(u32 target)
{
	return policy_bucket(target, g_hash.bits, (u32)g_hash.multiply) >> 3;
}

static u32 policy_index_own(u32 target, u32 shift)
{
	return policy_hash(0, target, shift);
}

/* apply-time helper: the line of the mode being laid out, blended branch-free */
static u32 policy_index_mode(u32 target, u32 mirror, u32 shift)
{
	u32 mir = policy_index_mirror(target);
	u32 own = policy_index_own(target, shift);
	u32 m = (u32)0 - mirror;

	return (mir & m) | (own & ~m);
}

/* hider id of a caller, or POLICY_ID_NONE if it hides nothing */
static u32 caller_id(u32 caller)
{
	const struct caller_slot *cs =
		&g_callers[(size_t)policy_caller_line(caller, g_cshift) * POLICY_CLINE_WAY];
	u32 k, id = POLICY_ID_NONE;

	for (k = 0; k < POLICY_CLINE_WAY; k++)
		if (cs[k].uid == caller)
			id = cs[k].id;
	return id;
}

/* the caller's bit in a mask: all words are read, the bit comes from the owning word */
static u32 mask_bit(const u64 *m, u32 cid)
{
	u32 w, bit = 0;

	for (w = 0; w < g_nmask_words; w++)
		bit |= (u32)((m[w] >> (cid & 63)) & 1) & (u32)(w == (cid >> 6));
	return bit;
}

/*
 * Same lines and same loads for a given (caller, target), whatever the answer: the target's
 * line and the masks of all its slots are read in full.
 */
u32 policy_lookup(uid_t caller, uid_t target)
{
	unsigned long flags;
	u32 c = (u32)caller, t = (u32)target;
	u32 cid, repl = 0, hit = 0, wild = 0, rk = 0, k, unit;
	const struct uid_pair *sl;
	const u64 *mk;

	if ((caller % 100000) <= 1000 || caller == target)
		return 0;

	read_lock_irqsave(&policy_lock, flags);
	cid = caller_id(c);
	unit = policy_index_mode(t, g_mirror, g_shift);
	sl = &g_tgt[(size_t)unit * POLICY_WAY];
	mk = &g_masks[(size_t)unit * POLICY_WAY * g_nmask_words];
	for (k = 0; k < POLICY_WAY; k++) {
		u32 eq = (sl[k].target == t);
		u32 bit = mask_bit(&mk[(size_t)k * g_nmask_words], cid);

		hit |= eq & bit & (cid != POLICY_ID_NONE);
		wild |= eq & (sl[k].repl_k >> 15);
		rk |= eq ? (sl[k].repl_k & ((1u << POLICY_REPL_BITS) - 1)) : 0;
	}
	repl = (hit | wild) ? (POLICY_REPL_BASE + rk) : 0;
	read_unlock_irqrestore(&policy_lock, flags);

	return repl;
}

EXPORT_SYMBOL_GPL(policy_lookup);

static void policy_reset(void)
{
	g_tgt = dummy_tgt;
	g_masks = dummy_masks;
	g_callers = dummy_callers;
	g_nlines = POLICY_MIN_LINES;
	g_shift = 32 - ilog2(POLICY_MIN_LINES);
	g_ncaller_lines = POLICY_MIN_LINES;
	g_cshift = g_shift;
	g_nmask_words = 1;
	g_npairs = 0;
	g_ncallers = 0;
	g_mirror = 0;
}

int policy_init(void)
{
	policy_reset();
	return 0;
}

void policy_free(void)
{
	if (g_tgt != dummy_tgt)
		kfree(g_tgt);
	if (g_masks != dummy_masks)
		kfree(g_masks);
	if (g_callers != dummy_callers)
		kfree(g_callers);
	policy_reset();
}
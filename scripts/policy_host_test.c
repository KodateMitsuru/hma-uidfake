/* Host test: compile the real policy.c against the scripts/hosttest shims and
 * check that the table reproduces its own policy exactly, at small and large
 * scale.
 */
#include "policy.c"
#include <stdio.h>

/* the host never logs anything, but the key has to exist for the linker */
struct static_key_false uidfake_debug_key;

/* the host has no isolated windows to close */
void uidfake_tag_close(void)
{
}

static u32 g_fail;
static u32 t_pairs[400 * 200 * 2];
static u32 t_np;
static u32 t_callers[400];
static u32 t_nc;

static int is_cfg(u32 c, u32 t)
{
	u32 k;

	for (k = 0; k < t_np; k += 2)
		if (t_pairs[k] == c && t_pairs[k + 1] == t)
			return 1;
	return 0;
}

static void check_sweep(const char *tag, u32 *pairs, u32 np, u32 *callers,
			u32 nc, u32 tlo, u32 thi)
{
	u32 i, j, unhidden = 0, fp = 0, cells = 0;

	policy_init();
	policy_apply(pairs, np / 2);
	for (i = 0; i < np; i += 2)
		if (pairs[i] &&
		    !policy_lookup_as((uid_t)pairs[i], (uid_t)pairs[i + 1]))
			unhidden++;
	for (i = 0; i < nc; i++) {
		for (j = tlo; j <= thi; j++) {
			int cfg = 0;
			u32 k2;

			for (k2 = 0; k2 < np; k2 += 2)
				if (pairs[k2] == callers[i] &&
				    pairs[k2 + 1] == j)
					cfg = 1;
			cells++;
			if (!cfg &&
			    policy_lookup_as((uid_t)callers[i], (uid_t)j))
				fp++;
		}
	}
	printf("%-22s pairs=%-5u callers=%-4u cells=%-7u unhidden=%u "
	       "false_positive=%u\n",
	       tag, np / 2, nc, cells, unhidden, fp);
	if (unhidden || fp)
		g_fail = 1;
}

int main(void)
{
	u32 callers[7] = { 10376, 10377, 10378, 10379, 10380, 10381, 10382 };
	u32 targets[19];
	static u32 pairs[7 * 19 * 2];
	u32 i, j, w = 0;
	static u32 big[4000 * 2];
	static u32 bigc[400];
	u32 bw = 0, bc = 0;

	for (i = 0; i < 19; i++)
		targets[i] = 10400 + i;
	for (i = 0; i < 19; i++)
		for (j = 0; j < 7; j++) {
			pairs[2 * w] = callers[j];
			pairs[2 * w + 1] = targets[i];
			w++;
		}
	check_sweep("device-like", pairs, w * 2, callers, 7, 10000, 14000);

	for (i = 0; i < 400; i++)
		bigc[bc++] = 10000 + i * 3; /* app uids live in 10000..19999 */
	for (i = 0; i < 100 && bw < 4000; i++)
		for (j = 0; j < 400 && bw < 4000; j++)
			if (((i * 7 + j * 13) % 40) ==
			    0) { /* ~10 of 400 callers per target */
				big[2 * bw] = bigc[j];
				big[2 * bw + 1] = 30000 + i;
				bw++;
			}
	check_sweep("uid-scale callers", big, bw * 2, bigc, bc, 30000, 30010);

	printf("%s\n", g_fail ? "FAIL" : "PASS");
	return g_fail;
}

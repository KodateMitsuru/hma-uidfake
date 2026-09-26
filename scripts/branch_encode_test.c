/* Host test for the branch encoder in uidfake.h: this is the one piece that
 * must be exactly right, because a wrong encode writes garbage into kernel
 * text.
 */
#include "uidfake.h"
#include <stdio.h>

static int fails;

static void expect_branch(unsigned long from, unsigned long to)
{
	u32 insn = arm64_branch(ARM64_BL, from, to);

	if (!insn) {
		printf("FAIL: encode %#lx -> %#lx returned 0\n", from, to);
		fails++;
		return;
	}
	if (!arm64_is_bl(insn)) {
		printf("FAIL: %#x is not a bl\n", insn);
		fails++;
		return;
	}
	if (arm64_bl_target(from, insn) != to) {
		printf("FAIL: round trip %#lx -> %#lx gave %#lx\n", from, to,
		       arm64_bl_target(from, insn));
		fails++;
	}
}

int main(void)
{
	/* module region is up to 128 MB below the kernel image: the boundary matters
   */
	unsigned long img = 0xffff800008000000UL; /* KIMAGE_VADDR */
	unsigned long modhi = img - 0x1000;
	unsigned long modlo = img - 0x07ff0000UL; /* just inside */
	unsigned long modout = img - 0x08000000UL; /* exactly 128 MB: out */
	unsigned long i;

	expect_branch(modhi, img);
	expect_branch(modlo, img);
	expect_branch(img, modhi);
	expect_branch(modhi, modhi + 0x100);
	for (i = 0; i < 2000; i++)
		expect_branch(0x1000 + i * 4096,
			      0x1000 + ((i * 7919) % 200000) * 4);
	if (arm64_branch(ARM64_BL, modout, img))
		printf("FAIL: exactly 128 MB accepted\n"), fails++;
	if (arm64_branch(ARM64_BL, modhi + 1, img))
		printf("FAIL: unaligned accepted\n"), fails++;
	u32 b = arm64_branch(ARM64_B, modhi, img);
	u32 bl = arm64_branch(ARM64_BL, modhi, img);

	if ((b & 0xFC000000u) != ARM64_B || (bl & 0xFC000000u) != ARM64_BL ||
	    (b & 0x03FFFFFFu) != (bl & 0x03FFFFFFu))
		printf("FAIL: B and BL must share the offset\n"), fails++;

	/* the two instructions the patcher relies on */
	if (arm64_is_bl(0x14000000u) || !arm64_is_bl(0x94000000u))
		printf("FAIL: bl detection\n"), fails++;

	printf("branch encoder: %s\n", fails ? "FAIL" : "PASS");
	return fails != 0;
}

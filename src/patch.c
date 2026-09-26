// SPDX-License-Identifier: GPL-2.0
/*
 * patch.c - write a few bytes into read-only kernel or module text.
 *
 * Kernel text is mapped read-only and the helpers that would normally make it
 * writable (set_memory_rw, text_poke) are not exported to modules. Instead the
 * physical page is translated through init_mm and mapped again writable with
 * vmap(); the instruction cache is cleaned afterwards and the synchronous path
 * stops all other CPUs, because one of them can be executing the very
 * instruction being replaced.
 *
 * The technique is the one every out-of-tree patcher on arm64 ends up using;
 * this is an independent implementation.
 */
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/vmalloc.h>

#include "uidfake.h"

static int probe_noop(struct kprobe *p, struct pt_regs *r)
{
	return 0;
}

/*
 * Look up a kernel symbol by name. kallsyms_lookup_name() is not exported to
 * modules, so its own address is obtained from a probe registered on it (kprobe
 * resolves .symbol_name through kallsyms internally) and unregistered
 * immediately -- nothing stays behind. This is how KernelSU resolves symbols
 * too.
 */
unsigned long uidfake_lookup(const char *name)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name",
			     .pre_handler = probe_noop };
	unsigned long (*fn)(const char *);

	if (register_kprobe(&kp))
		return 0;
	unregister_kprobe(&kp);
	fn = (void *)kp.addr;
	return fn ? fn(name) : 0;
}

/*
 * Symbols the patcher needs at run time. init_mm is not exported,
 * kimage_voffset/kallsyms are not either, so all of them go through the same
 * transient-probe resolver.
 */
static struct mm_struct *patch_mm;
static unsigned long *g_kimage_voffset;
static bool g_walk_warned;
static unsigned long *g_memstart_addr;

int uidfake_patch_init(void)
{
	patch_mm = (struct mm_struct *)uidfake_lookup("init_mm");
	g_kimage_voffset = (unsigned long *)uidfake_lookup("kimage_voffset");
	g_memstart_addr = (unsigned long *)uidfake_lookup("memstart_addr");
	pr_info("uidfake: init_mm=%px kimage_voffset=%px memstart_addr=%px\n",
		patch_mm, (void *)g_kimage_voffset, (void *)g_memstart_addr);
	return patch_mm ? 0 : -ENOENT;
}
struct patch_req {
	void *addr;
	const void *src;
	size_t len;
};

/*
 * The 4 KB page backing a kernel address, plus the offset inside it. Kernel
 * .rodata (where sys_call_table lives) is often mapped as a 2 MB block, and the
 * image as 1 GB blocks, so block mappings have to be resolved to the page
 * inside them instead of being rejected.
 */
static struct page *kernel_page(unsigned long addr, unsigned long *off)
{
	pgd_t *pgd = pgd_offset(patch_mm, addr);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	phys_addr_t phys;

	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return NULL;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return NULL;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;
	*off = offset_in_page(addr);
	if (pud_leaf(*pud)) {
		phys = (phys_addr_t)(pud_val(*pud) & ~(PUD_SIZE - 1)) +
		       (addr & (PUD_SIZE - 1));
		return pfn_to_page(phys >> PAGE_SHIFT);
	}
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;
	if (pmd_leaf(*pmd)) {
		phys = (phys_addr_t)(pmd_val(*pmd) & ~(PMD_SIZE - 1)) +
		       (addr & (PMD_SIZE - 1));
		return pfn_to_page(phys >> PAGE_SHIFT);
	}
	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte))
		return NULL;
	return pte_page(*pte);
}
/*
 * Cache maintenance inlined by hand: __builtin___clear_cache() lowers to a call
 * to
 * __clear_cache(), which the kernel does not export (the module would fail to
 * load with "Unknown symbol __clear_cache").
 */
static unsigned long cache_dline(void)
{
	unsigned long ctr;

	asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
	return 4UL << ((ctr >> 16) & 0xf);
}

static unsigned long cache_iline(void)
{
	unsigned long ctr;

	asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
	return 4UL << (ctr & 0xf);
}

static void cache_clean_inval(void *addr, size_t len)
{
	unsigned long start = (unsigned long)addr;
	unsigned long end = start + len;
	unsigned long dline = cache_dline();
	unsigned long iline = cache_iline();
	unsigned long p;

	for (p = start & ~(dline - 1); p < end; p += dline)
		asm volatile("dc cvau, %0" ::"r"(p) : "memory");
	dsb(ish);
	for (p = start & ~(iline - 1); p < end; p += iline)
		asm volatile("ic ivau, %0" ::"r"(p) : "memory");
	dsb(ish);
	isb();
}

/*
 * Physical address of a kernel image address without walking page tables: with
 * KASLR the image is offset by kimage_voffset, so pa = va - kimage_voffset.
 * Used when the walk cannot resolve the address, for instance because struct
 * mm_struct differs from the tree this module was built against.
 */
static phys_addr_t image_phys(unsigned long addr)
{
	if (g_kimage_voffset)
		return (phys_addr_t)(addr - *g_kimage_voffset);
	if (g_memstart_addr)
		return (phys_addr_t)(addr - (unsigned long)(KIMAGE_VADDR -
							    *g_memstart_addr));
	return 0;
}

static struct page *page_for(unsigned long addr, unsigned long *off)
{
	struct page *page = kernel_page(addr, off);
	phys_addr_t phys;

	if (page)
		return page;
	phys = image_phys(addr);
	if (!phys)
		return NULL;
	if (!g_walk_warned) {
		g_walk_warned = true;
		pr_info("uidfake: page table walk unusable (vendor mm_struct); using "
			"kimage_voffset\n");
	}
	return pfn_to_page(phys >> PAGE_SHIFT);
}

static int patch_do(void *arg)
{
	struct patch_req *r = arg;
	unsigned long off;
	struct page *page = page_for((unsigned long)r->addr, &off);
	void *alias;

	if (!page) {
		pr_warn("uidfake: no page for %px\n", r->addr);
		return -EFAULT;
	}
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!alias) {
		pr_warn("uidfake: vmap of %px failed\n", r->addr);
		return -ENOMEM;
	}
	memcpy(alias + off, r->src, r->len);
	/* the line is physically tagged, so cleaning through the alias covers the
   * target too */
	vunmap(alias);
	return 0;
}

int uidfake_patch_text(void *dst, const void *src, size_t len, bool sync)
{
	struct patch_req req = { .addr = dst, .src = src, .len = len };
	int ret;

	if (!len || (unsigned long)dst & 3 || len & 3)
		return -EINVAL;
	if (offset_in_page((unsigned long)dst) + len > PAGE_SIZE)
		return -EINVAL;

	ret = sync ? stop_machine(patch_do, &req, NULL) : patch_do(&req);
	if (ret)
		return ret;

	/* make the new instructions visible to every CPU */
	cache_clean_inval(dst, len);
	return 0;
}
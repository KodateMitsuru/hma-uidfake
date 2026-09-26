/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kmi_compat.h - only needed for kernel trees like android12-5.10.
 *
 * In that tree arch/arm64/include/asm/atomic_lse.h uses GCC style register-asm
 * variables (register unsigned long x0 asm("x0")), which clang cannot parse;
 * android13-5.10 onwards use operand constraints instead.
 *
 * -U on the command line does not work: clang processes every -D/-U first and
 * the -include files afterwards, so autoconf.h defines the macro again.
 * src/Makefile therefore -includes this file, which lands after autoconf.h, and
 * #undefs the macros to fall back to LL/SC atomics. Same semantics, only
 * affects the inlined code of this module, no ABI change.
 */
#ifndef UIDFAKE_KMI_COMPAT_H
#define UIDFAKE_KMI_COMPAT_H

#ifdef CONFIG_ARM64_LSE_ATOMICS
#undef CONFIG_ARM64_LSE_ATOMICS
#endif
#ifdef CONFIG_ARM64_USE_LSE_ATOMICS
#undef CONFIG_ARM64_USE_LSE_ATOMICS
#endif

/*
 * The same tree also declares the stack pointer as a GCC style global register
 * variable (register unsigned long current_stack_pointer asm("sp")), which
 * clang refuses outright:
 *
 *   arch/arm64/include/asm/stack_pointer.h:8:51: error: register 'sp'
 * unsuitable for global register variables on this target
 *
 * Later kernels wrap it in an inline asm helper instead, so that is what is
 * given here, and the header itself is skipped through its own guard.
 * Everything that reads it (asm/percpu.h, asm/perf_event.h, asm/processor.h)
 * reads it as a value, which is what the macro keeps working. src/Makefile
 * passes UIDFAKE_SP_REGISTER only where the register form is really present, so
 * a tree that already has the helper keeps it.
 */
#ifdef UIDFAKE_SP_REGISTER
#define __ASM_STACK_POINTER_H
static inline unsigned long uidfake_current_sp(void)
{
	unsigned long sp;

	asm("mov %0, sp" : "=r"(sp));
	return sp;
}
#define current_stack_pointer uidfake_current_sp()
#endif

/*
 * ...and arch/arm64/include/asm/kgdb.h writes one breakpoint with a GCC
 * constraint that clang only learned to accept in clang 14:
 *
 *   asm ("brk %0" : : "I" (KGDB_COMPILED_DBG_BRK_IMM));
 *
 * The same trees cannot be built with another compiler either (CONFIG_CFI_CLANG
 * and CONFIG_SHADOW_CALL_STACK both require the one the kernel was built with),
 * so the constraint is what gives: the header is skipped through its guard and
 * the instruction is written with a plain immediate, which is the same
 * encoding. Nothing in this module calls it; a header that reads it only has to
 * find it. src/Makefile passes UIDFAKE_KGDB_BRK for compilers that old.
 */
#ifdef UIDFAKE_KGDB_BRK
#define __ARM_KGDB_H
#include <asm/debug-monitors.h>
static inline void arch_kgdb_breakpoint(void)
{
	asm("brk %0" : : "i"(KGDB_COMPILED_DBG_BRK_IMM));
}
extern void kgdb_handle_bus_error(void);
extern int kgdb_fault_expected;
#endif

#endif /* UIDFAKE_KMI_COMPAT_H */

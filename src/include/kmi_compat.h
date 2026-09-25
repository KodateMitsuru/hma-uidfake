/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kmi_compat.h - only needed for kernel trees like android12-5.10.
 *
 * In that tree arch/arm64/include/asm/atomic_lse.h uses GCC style register-asm
 * variables (register unsigned long x0 asm("x0")), which clang cannot parse;
 * android13-5.10 onwards use operand constraints instead.
 *
 * -U on the command line does not work: clang processes every -D/-U first and the
 * -include files afterwards, so autoconf.h defines the macro again. src/Makefile
 * therefore -includes this file, which lands after autoconf.h, and #undefs the macros
 * to fall back to LL/SC atomics. Same semantics, only affects the inlined code of this
 * module, no ABI change.
 */
#ifndef UIDFAKE_KMI_COMPAT_H
#define UIDFAKE_KMI_COMPAT_H

#ifdef CONFIG_ARM64_LSE_ATOMICS
#undef CONFIG_ARM64_LSE_ATOMICS
#endif
#ifdef CONFIG_ARM64_USE_LSE_ATOMICS
#undef CONFIG_ARM64_USE_LSE_ATOMICS
#endif

#endif /* UIDFAKE_KMI_COMPAT_H */

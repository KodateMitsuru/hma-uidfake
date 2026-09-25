# kbuild fragment for the hma_uidfake module.
#
# Normally driven by CMake (which runs kbuild inside build/kmi/<kmi>/, a directory
# holding only symlinks to this source tree), but a manual build works too:
#   make -C <KDIR> ARCH=arm64 LLVM=1 M=$PWD/src modules

KDIR ?= /lib/modules/$(shell uname -r)/build

# abspath, not realpath: kbuild is invoked through a symlink staging directory, and
# realpath would resolve it back to the real source directory, writing objects there.
MDIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ODIR := $(MDIR)

# Kernel tree: srctree is the reliable one for a direct make, KDIR for the DDK flow.
KSRC  ?= $(or $(srctree),$(KDIR))
KMI   := $(notdir $(patsubst %/,%,$(KSRC)))

# Old trees (android12-5.10) have a GCC style register-asm atomic_lse.h that clang
# cannot parse. -U on the command line is useless (clang handles -D/-U first, then
# -include, so autoconf.h redefines the macro), hence a compatibility header that is
# -included after autoconf.h and drops the macros -- the module then falls back to
# LL/SC atomics, which is semantically equivalent.
LSE_HDR := $(shell grep -l 'unsigned long x0 asm' $(KSRC)/arch/arm64/include/asm/atomic_lse.h 2>/dev/null)
$(info uidfake: KMI=$(KMI) lse-workaround=$(if $(LSE_HDR),on,off))

ifeq ($(KMI),android17-6.18)
KBUILD_ARGS := M=$(MDIR) MO=$(ODIR)
else
KBUILD_ARGS := M=$(MDIR)
endif

obj-m += hma_uidfake.o
hma_uidfake-objs := main.o patch.o hooks.o  netlink.o

ifneq ($(LSE_HDR),)
ccflags-y += -include $(MDIR)/include/kmi_compat.h
endif
ccflags-y += -I$(MDIR)/include
ccflags-y += -I$(MDIR)
ccflags-y += -gz=none

# XDP Makefile
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
LLVMLLC ?= llc
PERL := perl

# Detect host architecture and map to BPF target arch name:
#   x86_64  → x86   (uname returns "x86_64", BPF macro expects "x86")
#   aarch64 → arm64 (uname returns "aarch64", BPF macro expects "arm64")
#   armv*   → arm
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/armv.*/arm/')

# Detect multiarch tuple for architecture-specific system headers.
# e.g. x86_64-linux-gnu on amd64, aarch64-linux-gnu on arm64.
# asm/types.h (pulled in by linux/bpf.h) lives under this path.
MULTIARCH ?= $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null)

# Kernel headers: generic path + arch-specific multiarch path
KERNEL_INCLUDE := -I/usr/include
ifneq ($(MULTIARCH),)
KERNEL_INCLUDE += -I/usr/include/$(MULTIARCH)
endif

# BPF flags
CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types

# Output files
OBJ := xdp_prog_kern.o
USER_PROG := xdp_prog_user

# Default target
all: $(OBJ) $(USER_PROG)

# Compile XDP kernel program
$(OBJ): xdp_prog_kern.c common/parsing_helpers.h common/rewrite_helpers.h
	$(CLANG) $(BPF_CFLAGS) $(CFLAGS) $(KERNEL_INCLUDE) -target bpf -c $< -o $@

# Compile user space program
$(USER_PROG): xdp_prog_user.c
	$(CLANG) $(CFLAGS) -o $@ $< -lelf -lbpf -lpcap

# Clean
clean:
	rm -f $(OBJ) $(USER_PROG)

.PHONY: all clean

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

# Kernel headers
KERNEL_INCLUDE := -I/usr/include

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
	$(CLANG) $(BPF_CFLAGS) $(CFLAGS) -target bpf -c $< -o $@

# Compile user space program
$(USER_PROG): xdp_prog_user.c
	$(CLANG) $(CFLAGS) -o $@ $< -lelf -lbpf -lpcap

# Clean
clean:
	rm -f $(OBJ) $(USER_PROG)

.PHONY: all clean

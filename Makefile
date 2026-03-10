# XDP IPIP Overlay Makefile
CLANG ?= clang

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/armv.*/arm/')
MULTIARCH ?= $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null)

KERNEL_INCLUDE := -I/usr/include
ifneq ($(MULTIARCH),)
KERNEL_INCLUDE += -I/usr/include/$(MULTIARCH)
endif

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types

OBJ := xdp_prog_kern.o
USER_PROG := xdp_prog_user

all: $(OBJ) $(USER_PROG)

$(OBJ): xdp_prog_kern.c common/parsing_helpers.h common/checksum_helpers.h common/xdp_maps.h
	$(CLANG) $(BPF_CFLAGS) $(CFLAGS) $(KERNEL_INCLUDE) -target bpf -c $< -o $@

$(USER_PROG): xdp_prog_user.c
	$(CLANG) $(CFLAGS) -o $@ $<

clean:
	rm -f $(OBJ) $(USER_PROG)

.PHONY: all clean

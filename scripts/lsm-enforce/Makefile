# scripts/lsm-enforce/Makefile
#
# Build + run the content-addressed exec enforcer demo.
#
# Prereqs (already present on the VM from the load test):
#     sudo apt install clang llvm libbpf-dev      # bpftool too
#
#     make           # build the BPF object + loader
#     make run       # build, then run the demo as root, approving sha256(/bin/true)
#     make clean

ARCH     := $(shell uname -m)
BPF_ARCH := $(subst x86_64,x86,$(subst aarch64,arm64,$(ARCH)))
CLANG    ?= clang
BPFTOOL  ?= bpftool

.PHONY: all run clean
all: enforce

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

enforce.bpf.o: enforce.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		-I. -I/usr/include/$(ARCH)-linux-gnu \
		-c enforce.bpf.c -o enforce.bpf.o

enforce.skel.h: enforce.bpf.o
	$(BPFTOOL) gen skeleton enforce.bpf.o > enforce.skel.h

enforce: loader.c enforce.skel.h
	$(CLANG) -g -O2 -I. loader.c -lbpf -o enforce

run: enforce
	sudo ./enforce $$(sha256sum /bin/true | awk '{print $$1}')

clean:
	rm -f vmlinux.h enforce.bpf.o enforce.skel.h enforce

# scripts/lsm-loadtest/Makefile
#
# Build + run the QuantmLayer BPF-LSM load test.
#
# Prereqs on the target VM (bpftool + cargo are already present per the probe;
# these are the gaps section H flagged):
#     sudo apt install clang llvm libbpf-dev
#
# Then:
#     make          # build everything
#     make run      # build + run as root
#     make clean

ARCH     := $(shell uname -m)
BPF_ARCH := $(subst x86_64,x86,$(subst aarch64,arm64,$(ARCH)))
CLANG    ?= clang
BPFTOOL  ?= bpftool

.PHONY: all run clean
all: loader

# Kernel type definitions for CO-RE, dumped from the running kernel's BTF.
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

probe.bpf.o: probe.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		-I. -I/usr/include/$(ARCH)-linux-gnu \
		-c probe.bpf.c -o probe.bpf.o

probe.skel.h: probe.bpf.o
	$(BPFTOOL) gen skeleton probe.bpf.o > probe.skel.h

loader: loader.c probe.skel.h
	$(CLANG) -g -O2 -I. loader.c -lbpf -o loader

run: loader
	sudo ./loader

clean:
	rm -f vmlinux.h probe.bpf.o probe.skel.h loader

#!/bin/sh
# scripts/ql-musl-build.sh
#
# QuantmLayer — Option A: build a FULLY STATIC x86_64 `ql` with the kernel exec
# wall, for locked cloud nodes (no glibc, no shared libelf/zlib) such as GKE
# Container-Optimized OS.
#
# The only source change this depends on is the cfg-gated libbpf-sys override in
# crates/ql-lsm/Cargo.toml (static-libelf + static-zlib for target_env="musl").
# This script just stands up an x86_64 Alpine build environment and runs the
# build, then proves the result is static.
#
# RUN ON: a fresh x86_64 Alpine system. Three equivalent ways:
#   (a) an x86_64 Alpine cloud VM (the rev 26/27 "stand up a builder" pattern):
#         doas sh scripts/ql-musl-build.sh        # or run as root
#   (b) Alpine in Docker on an x86_64 host:
#         docker run --rm -v "$PWD":/src -w /src alpine:3.21 \
#           sh scripts/ql-musl-build.sh
#   (c) CI, no local x86_64 needed: the `musl-static` GitHub Actions workflow
#         runs (b) on a native x86_64 runner and uploads the binary as an
#         artifact — the reproducible way to get an x86_64-BTF build.
#
# Must be x86_64 so /sys/kernel/btf/vmlinux and the produced binary are x86_64
# (the BPF object is CO-RE and relocates on the target kernel at load). Building
# under qemu emulation on an aarch64 host will compile and link (which is what
# proves the musl static-link works) but dumps aarch64 BTF — fine to de-risk the
# link, not ideal for a binary you intend to load on a specific x86_64 node.
#
# It changes NOTHING in your tree except target/ (cargo output).
set -eu

TARGET=x86_64-unknown-linux-musl

echo "== host: $(uname -m) $(uname -r)"
case "$(uname -m)" in
  x86_64) : ;;
  *) echo "NOTE: not x86_64 — see the qemu caveat in this script's header." >&2 ;;
esac

echo "== apk: build toolchain + BPF tooling + STATIC libelf/zlib"
# build-base/clang/llvm: compile libbpf + the BPF object. bpftool: dump vmlinux.h.
# elfutils-dev/zlib-dev: headers+libs the build-time libbpf links against.
# libelf-static/zlib-static: the .a files the final musl binary links statically.
# zstd-static: Alpine's libelf.a is built with zstd section compression, so it
#   references ZSTD_* and needs libzstd.a at static link time (the -lzstd below).
# argp-standalone: only needed if the static libelf pulls argp_* at final link
#   (usually not for prebuilt Alpine libelf; harmless to have present).
apk add --no-cache \
  build-base clang llvm pkgconf linux-headers \
  bpftool elfutils-dev zlib-dev \
  libelf-static zlib-static zstd-static argp-standalone \
  git curl

echo "== rust toolchain (rust-toolchain.toml pins 1.96.0; auto-installed)"
if apk add --no-cache rustup 2>/dev/null; then
  rustup-init -y --default-toolchain none
else
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain none
fi
# shellcheck disable=SC1091
. "$HOME/.cargo/env"

# Pre-dump and clean vmlinux.h to sidestep the 6.x duplicate-enum E0081 that
# libbpf-cargo otherwise passes through to rustc (the rev-26 fix). The _DEPRECATED
# aliases are unused by enforce.bpf.c and the object is CO-RE, so dropping them is
# link-safe. If BTF is unavailable, fall through and let build.rs dump it.
if [ -r /sys/kernel/btf/vmlinux ]; then
  echo "== pre-dump + clean vmlinux.h (sidesteps 6.x duplicate-enum E0081)"
  VMH=/tmp/ql-vmlinux.h
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMH"
  sed -i \
    -e '/BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,/d' \
    -e '/BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,/d' \
    "$VMH"
  export QL_VMLINUX_H="$VMH"
else
  echo "== /sys/kernel/btf/vmlinux not readable; build.rs will dump BTF itself"
fi

echo "== build: static musl ql with the kernel exec wall (--features lsm)"
# Build WITHOUT --target: on x86_64 Alpine the native target already is
# x86_64-unknown-linux-musl, and with no --target host==target so RUSTFLAGS also
# reaches BUILD SCRIPTS (the libbpf-cargo skeleton generator links libelf too).
# Passing --target would make Cargo treat this as cross-compiling and withhold
# RUSTFLAGS from the host build-script link, which is exactly where the libelf
# zstd symbols first surface.
#
# Do NOT force -C target-feature=+crt-static here: with no --target it would apply
# host-wide and break proc-macros (clap_derive etc.), which must be dynamic. The
# musl target already defaults to crt-static for executables, so the final `ql` is
# still fully static; rustc exempts proc-macros from that default but not from an
# explicit RUSTFLAGS override. We add only the static libzstd archive (named
# directly as -l:libzstd.a, so it links static without flipping the linker's
# -Bstatic/-Bdynamic mode and stays harmless on the proc-macro/dylib links this
# flag also passes through) to satisfy the ZSTD_* refs in Alpine's libelf.a.
#
# LIBBPF_SYS_LIBRARY_PATH tells libbpf-sys where the SYSTEM static libs live. With
# the static-libelf/static-zlib features it emits `rustc-link-lib=static=elf` /
# `static=z` but only auto-searches its own OUT_DIR (vendored libbpf), so rustc
# cannot find /usr/lib/libelf.a|libz.a without this. (The build-script graph found
# them via cc's default path; the normal graph's `static=` makes rustc do the
# lookup, and rustc does not search /usr/lib.)
export LIBBPF_SYS_LIBRARY_PATH=/usr/lib
RUSTFLAGS="-C link-arg=-l:libzstd.a" \
  cargo build -p ql-cli --features lsm --release

BIN="target/release/ql"
echo ""
echo "== result: $BIN"
ls -lh "$BIN"
echo "-- file (expect: ELF 64-bit ... x86-64 ... statically linked):"
file "$BIN"
echo "-- ldd (expect: 'not a dynamic executable'):"
ldd "$BIN" 2>&1 || true
echo "-- smoke:"
"$BIN" --version || true
echo ""
echo "DONE. Copy $BIN to the target node and run:  ./ql doctor"
echo "If the link still reports undefined symbols from libelf (e.g. argp_*, lzma,"
echo "or bz2), add the matching static archive by name and re-run, e.g.:"
echo "  RUSTFLAGS=\"-C link-arg=-l:libzstd.a -C link-arg=-l:liblzma.a\" \\"
echo "    cargo build -p ql-cli --features lsm --release"

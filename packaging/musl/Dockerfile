# packaging/musl/Dockerfile
#
# QuantmLayer — Option A static x86_64 musl `ql` builder, containerized.
#
# Produces a fully static `ql` (kernel exec wall included) for locked cloud nodes
# (GKE Container-Optimized OS, etc.). Build on an x86_64 Docker host so the BTF
# dumped for the BPF skeleton is x86_64; under buildx qemu on aarch64 it will
# still link (proving the musl static-link) but with aarch64 BTF.
#
# Usage (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f packaging/musl/Dockerfile \
#     --platform linux/amd64 -o type=local,dest=./dist .
#   # -> ./dist/ql  (static x86_64 musl binary)
#
# Or, to inspect interactively instead of exporting:
#   docker build -f packaging/musl/Dockerfile --platform linux/amd64 -t ql-musl .
#   docker run --rm ql-musl file /out/ql

FROM --platform=linux/amd64 alpine:3.21 AS build

RUN apk add --no-cache \
      build-base clang llvm pkgconf linux-headers \
      bpftool elfutils-dev zlib-dev \
      libelf-static zlib-static zstd-static argp-standalone \
      git curl rustup \
 && rustup-init -y --default-toolchain none
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /src
COPY . .

# build.rs dumps BTF from the build host. During `docker build` /sys/kernel/btf
# is the daemon host's; if it is unreadable, the build still proceeds and dumps
# at compile time. We apply the rev-26 enum-dedup only when BTF is present.
RUN set -eu; \
    if [ -r /sys/kernel/btf/vmlinux ]; then \
      bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/ql-vmlinux.h; \
      sed -i -e '/BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,/d' \
             -e '/BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,/d' \
             /tmp/ql-vmlinux.h; \
      export QL_VMLINUX_H=/tmp/ql-vmlinux.h; \
    fi; \
    RUSTFLAGS="-C link-arg=-l:libzstd.a" \
    LIBBPF_SYS_LIBRARY_PATH=/usr/lib \
      cargo build -p ql-cli --features lsm --release; \
    mkdir -p /out; cp target/release/ql /out/ql; \
    file /out/ql; ldd /out/ql 2>&1 || true

# Export stage: `-o type=local,dest=./dist` writes /out/ql to ./dist/ql.
FROM scratch AS export
COPY --from=build /out/ql /ql

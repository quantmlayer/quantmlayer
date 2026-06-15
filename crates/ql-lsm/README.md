# ql-lsm

Kernel-side **content-addressed exec enforcement** for QuantmLayer (Linux,
BPF-LSM). The userspace half (`ql-profile` + `ql learn`) produces a list of
approved SHA-256 digests; this crate loads a sleepable `BPF_LSM_CGROUP` program
onto the exec hook, fills a map with those digests, and attaches it to a cell's
cgroup. Any exec of a binary whose content isn't on the list is denied with
`EPERM`. Deny-by-default.

The BPF program is the one validated on real hardware in
[`scripts/lsm-enforce`](../../scripts/lsm-enforce) — `build.rs` compiles that
exact file, so the kernel logic and this loader can't drift.

```rust
use std::os::fd::AsRawFd;
let cgroup = std::fs::File::open("/sys/fs/cgroup/my-cell")?;
let _enforcer = ql_lsm::ExecEnforcer::attach(&profile, cgroup.as_raw_fd())?;
// enforcement is active until `_enforcer` is dropped
```

## Build

This crate is **excluded from the workspace** because it needs the eBPF
toolchain, so `make check` for the rest of the repo stays toolchain-free. Build
it directly:

```sh
sudo apt install clang libelf-dev zlib1g-dev pkgconf   # bpftool already present
cd crates/ql-lsm
cargo build
```

`libbpf-sys` vendors and statically links libbpf (hence libelf/zlib/pkgconf);
`build.rs` generates `vmlinux.h` from the host's BTF and compiles the BPF
program via `libbpf-cargo`.

## Status

The BPF program and the enforcement behavior are hardware-validated. This
loader is new and depends on the `libbpf-rs` 0.24 API; a few call sites are
annotated `API(libbpf-rs 0.24)` as the spots most likely to need a version
tweak. Cell integration (attaching automatically as part of `ql-enforce`'s
cell construction) is the next step.

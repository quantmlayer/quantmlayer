// crates/ql-lsm/build.rs
//
// Compiles the (already hardware-validated) BPF enforcer and generates a
// libbpf-rs skeleton. Single source of truth: the exact .bpf.c proven in
// scripts/lsm-enforce — we do not copy it, so the two can never drift.
//
// Build prerequisites on the host:  clang, bpftool, libelf-dev, zlib1g-dev,
// pkgconf (the last three are for the vendored libbpf that libbpf-sys builds).

use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;
use std::process::Command;

const BPF_SRC: &str = "../../scripts/lsm-enforce/enforce.bpf.c";

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));

    // Generate vmlinux.h from the build host's BTF (same step the Makefile runs).
    let vmlinux = out.join("vmlinux.h");
    let dump = Command::new("bpftool")
        .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
        .output()
        .expect("run `bpftool btf dump` (install bpftool / linux-tools)");
    assert!(
        dump.status.success(),
        "bpftool btf dump failed: {}",
        String::from_utf8_lossy(&dump.stderr)
    );
    std::fs::write(&vmlinux, &dump.stdout).expect("write vmlinux.h");

    // Compile the BPF object and generate the Rust skeleton into OUT_DIR.
    let skel = out.join("enforce.skel.rs");
    SkeletonBuilder::new()
        .source(BPF_SRC)
        .clang_args([format!("-I{}", out.display())]) // find the generated vmlinux.h
        .build_and_generate(&skel)
        .expect("compile BPF + generate skeleton (needs clang + libelf-dev/zlib1g-dev/pkgconf)");

    println!("cargo:rerun-if-changed={BPF_SRC}");
}

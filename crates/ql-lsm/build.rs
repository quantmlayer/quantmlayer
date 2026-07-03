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

    // Resolve vmlinux.h. By default, dump it from the build host's BTF (the same
    // step the Makefile runs). As an escape hatch, `QL_VMLINUX_H` may point at a
    // pre-dumped vmlinux.h to use instead — needed when the build host's BTF
    // generates a Rust-invalid skeleton (e.g. kernels whose BTF carries duplicate
    // enum discriminants like BPF_MAP_TYPE_CGROUP_STORAGE{,_DEPRECATED} = 19,
    // which libbpf-cargo passes through and rustc rejects with E0081). The BPF
    // object is CO-RE, so a header from slightly older BTF still loads on the
    // newer runtime kernel. When the var is unset, behavior is exactly as before.
    let vmlinux = out.join("vmlinux.h");
    println!("cargo:rerun-if-env-changed=QL_VMLINUX_H");
    match env::var("QL_VMLINUX_H") {
        Ok(path) if !path.is_empty() => {
            let bytes =
                std::fs::read(&path).unwrap_or_else(|e| panic!("read QL_VMLINUX_H={path}: {e}"));
            std::fs::write(&vmlinux, bytes).expect("write vmlinux.h");
            println!("cargo:rerun-if-changed={path}");
        }
        _ => {
            let dump = Command::new("bpftool")
                .args([
                    "btf",
                    "dump",
                    "file",
                    "/sys/kernel/btf/vmlinux",
                    "format",
                    "c",
                ])
                .output()
                .expect("run `bpftool btf dump` (install bpftool / linux-tools)");
            assert!(
                dump.status.success(),
                "bpftool btf dump failed: {}",
                String::from_utf8_lossy(&dump.stderr)
            );
            std::fs::write(&vmlinux, &dump.stdout).expect("write vmlinux.h");
        }
    }

    // Compile the BPF object and generate the Rust skeleton into OUT_DIR.
    let skel = out.join("enforce.skel.rs");
    SkeletonBuilder::new()
        .source(BPF_SRC)
        .clang_args([format!("-I{}", out.display())]) // find the generated vmlinux.h
        .build_and_generate(&skel)
        .expect("compile BPF + generate skeleton (needs clang + libelf-dev/zlib1g-dev/pkgconf)");

    println!("cargo:rerun-if-changed={BPF_SRC}");
}

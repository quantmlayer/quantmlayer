// crates/ql-lsm/examples/enforce_demo.rs
//
// Runtime proof that the Rust `ExecEnforcer` enforces — the Rust counterpart of
// scripts/lsm-enforce, exercising the exact `attach` path a real cell will use.
//
// Build as your user (build.rs needs the BPF toolchain), then run as root:
//     cargo build --example enforce_demo
//     sudo ./target/debug/examples/enforce_demo
//
// It approves the content digest of /bin/true, attaches the enforcer to a fresh
// cgroup, and execs three things *inside that cgroup*:
//   1. /bin/true                 — approved digest        -> ALLOWED
//   2. a byte-identical copy      — same content, new name -> ALLOWED
//   3. /bin/ls                   — not approved           -> DENIED (EPERM)

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use ql_lsm::ExecEnforcer;
use ql_profile::{ExecDigest, HashAlgo, Profile};
use sha2::{Digest, Sha256};

const CG: &str = "/sys/fs/cgroup/ql-lsm-demo";
const COPY: &str = "/var/tmp/ql-lsm-true-copy";

fn sha256_hex(path: &str) -> io::Result<String> {
    let bytes = fs::read(path)?;
    let out = Sha256::digest(bytes);
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
}

// Fork+exec `path` inside the demo cgroup. Ok(()) = ran (allowed);
// Err with EPERM = the enforcer denied the exec.
fn exec_in_cgroup(path: &str) -> io::Result<()> {
    let mut cmd = Command::new(path);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    // SAFETY: demo-grade. The process is single-threaded here, so allocating to
    // write our pid into cgroup.procs before exec (so the LSM hook governs this
    // exec) is safe between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            let pid = std::process::id();
            fs::write(format!("{CG}/cgroup.procs"), format!("{pid}\n"))
        });
    }
    let mut child = cmd.spawn()?; // Err(EPERM) here if the exec was denied
    child.wait()?;
    Ok(())
}

fn report(label: &str, got: &io::Result<()>, expect_allow: bool) {
    let (res, allowed) = match got {
        Ok(()) => ("ALLOWED", true),
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => ("DENIED", false),
        Err(e) => {
            println!("  [ERR ] {label}: {e}");
            return;
        }
    };
    let ok = allowed == expect_allow;
    println!("  [{}] {label} -> {res}", if ok { "PASS" } else { "FAIL" });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("== ql-lsm runtime enforcement demo ==");

    // Approve /bin/true by content.
    let hex = sha256_hex("/bin/true")?;
    println!("  approving sha256(/bin/true) = {hex}");
    let mut profile = Profile::default();
    profile.exec.enforce = true;
    profile
        .exec
        .allow_digests
        .push(ExecDigest::new(HashAlgo::Sha256, hex)?);

    // Fresh demo cgroup, opened to get an fd for attach.
    let _ = fs::create_dir(CG);
    let cgroup = fs::File::open(CG)?;

    // Attach the enforcer; it stays active until `enforcer` is dropped.
    let enforcer = ExecEnforcer::attach(&profile, cgroup.as_raw_fd())?;
    println!("  enforcer attached to {CG}\n");

    // Byte-identical copy: same digest, different path -> approved.
    fs::copy("/bin/true", COPY)?;

    println!("Execs inside the contained cgroup:");
    report("/bin/true (approved)", &exec_in_cgroup("/bin/true"), true);
    report("copy of /bin/true (same bytes)", &exec_in_cgroup(COPY), true);
    report("/bin/ls (NOT approved)", &exec_in_cgroup("/bin/ls"), false);

    // Cleanup: detach before removing the cgroup.
    drop(enforcer);
    let _ = fs::remove_file(COPY);
    let _ = fs::remove_dir(CG);
    println!("\nExpected: ALLOWED, ALLOWED, DENIED.");
    Ok(())
}

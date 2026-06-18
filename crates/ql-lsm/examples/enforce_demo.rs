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
// cgroup, and execs four things *inside that cgroup*:
//   1. /bin/true                 — approved digest        -> ALLOWED
//   2. a byte-identical copy      — same content, new name -> ALLOWED
//   3. /bin/true hello world      — approved binary, argv "hello" denied -> KILLED
//   4. /bin/ls                   — not approved           -> DENIED (EPERM)

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

use ql_lsm::ExecEnforcer;
use ql_profile::{ArgvDeny, ArgvRule, ExecDigest, HashAlgo, Profile};
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

// Fork+exec `path` inside the demo cgroup. Ok(status) = the exec was allowed
// and ran (a SIGKILL status means a post-commit argv-deny rule killed it);
// Err with EPERM = the enforcer denied the exec outright.
fn exec_in_cgroup(path: &str, args: &[&str]) -> io::Result<std::process::ExitStatus> {
    let mut cmd = Command::new(path);
    cmd.args(args).stdout(Stdio::null()).stderr(Stdio::null());
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
    child.wait()
}

/// What a given exec is expected to do.
enum Expect {
    /// Allowed by digest and ran to completion.
    Allowed,
    /// Denied at exec time (never started).
    Denied,
    /// Allowed by digest, then SIGKILLed post-commit by an argv-deny rule.
    Killed,
}

fn report(label: &str, got: &io::Result<std::process::ExitStatus>, expect: Expect) {
    let outcome = match got {
        Ok(st) if st.signal() == Some(libc::SIGKILL) => "KILLED",
        Ok(_) => "ALLOWED",
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => "DENIED",
        Err(e) => {
            println!("  [ERR ] {label}: {e}");
            return;
        }
    };
    let want = match expect {
        Expect::Allowed => "ALLOWED",
        Expect::Denied => "DENIED",
        Expect::Killed => "KILLED",
    };
    let ok = outcome == want;
    println!("  [{}] {label} -> {outcome}", if ok { "PASS" } else { "FAIL" });
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
        .push(ExecDigest::new(HashAlgo::Sha256, hex.clone())?);

    // Approve /bin/true by content, but deny one argv shape of it: any invocation
    // whose argv contains the element "hello". The binary stays allowed by
    // digest; this specific invocation is killed post-commit (Tier-1
    // detect-and-kill, single-token subset of the profile's argv_deny).
    profile.exec.argv_deny.push(ArgvRule {
        digest: ExecDigest::new(HashAlgo::Sha256, hex)?,
        deny: vec![ArgvDeny {
            all_of: vec!["hello".to_string()],
        }],
    });

    // Fresh demo cgroup, opened to get an fd for attach.
    let _ = fs::create_dir(CG);
    let cgroup = fs::File::open(CG)?;

    // Attach the enforcer; it stays active until `enforcer` is dropped.
    let enforcer = ExecEnforcer::attach(&profile, cgroup.as_raw_fd())?;
    println!("  enforcer attached to {CG}\n");

    // Byte-identical copy: same digest, different path -> approved.
    fs::copy("/bin/true", COPY)?;

    println!("Execs inside the contained cgroup:");
    report(
        "/bin/true (approved)",
        &exec_in_cgroup("/bin/true", &[]),
        Expect::Allowed,
    );
    report(
        "copy of /bin/true (same bytes)",
        &exec_in_cgroup(COPY, &[]),
        Expect::Allowed,
    );
    report(
        "/bin/true hello world (approved binary, denied argv)",
        &exec_in_cgroup("/bin/true", &["hello", "world"]),
        Expect::Killed,
    );
    report(
        "/bin/ls (NOT approved)",
        &exec_in_cgroup("/bin/ls", &[]),
        Expect::Denied,
    );

    // Show the kernel's exec audit stream: ground truth of what executed and
    // what content-addressing denied. Expect four records — true, the copy
    // (same digest), the hello-world run, and ls (denied).
    println!("\nKernel exec audit stream:");
    match enforcer.drain_events() {
        Ok(events) => {
            println!("  captured {} event(s)", events.len());
            for e in &events {
                let verdict = if e.allowed { "ALLOWED" } else { "DENIED" };
                let dg = e.digest_hex.as_deref().unwrap_or("<unhashed>");
                println!(
                    "  [{verdict}] ts={} comm={} pid={} digest={dg}",
                    e.ts_millis, e.comm, e.pid
                );
            }
        }
        Err(e) => eprintln!("  draining exec events failed: {e}"),
    }

    // Tier-1 committed-argv read + detect-and-kill: the sound argv each allowed
    // exec actually ran with, read post-commit from the new mm and correlated to
    // the content digest, with the kill flag set when an argv-deny rule matched.
    // Expect records for /bin/true, the copy, and the hello-world run (killed);
    // the denied ls never reached sched_process_exec.
    println!("\nKernel committed-argv stream:");
    match enforcer.drain_argv() {
        Ok(records) => {
            println!("  captured {} record(s)", records.len());
            for r in &records {
                let dg = &r.digest_hex[..r.digest_hex.len().min(16)];
                let tag = if r.killed { " [KILLED]" } else { "" };
                println!("  pid={} digest={dg}.. argv={:?}{tag}", r.pid, r.argv);
            }
        }
        Err(e) => eprintln!("  draining committed argv failed: {e}"),
    }

    // Cleanup: detach before removing the cgroup.
    drop(enforcer);
    let _ = fs::remove_file(COPY);
    let _ = fs::remove_dir(CG);
    println!("\nExpected: ALLOWED, ALLOWED, KILLED, DENIED.");
    Ok(())
}

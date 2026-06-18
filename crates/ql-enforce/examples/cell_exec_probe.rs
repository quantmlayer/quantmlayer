// crates/ql-enforce/examples/cell_exec_probe.rs
//
//! Slice 4b end-to-end: a real [`Cell`] with the Tier-2 exec wall enabled.
//!
//! Builds a cell whose profile allowlists `/bin/echo` by content digest, turns
//! on `with_exec_supervision`, and runs two commands through `Cell::run`:
//!   * `/bin/echo` — allowlisted   -> ALLOWED, runs, exits 0
//!   * `/bin/ls`   — not allowlisted -> DENIED (execve -> EACCES), exit 126
//!
//! Unlike `fd_transfer_probe.rs` (which proved the mechanism standalone), this
//! drives the actual cell fork path: the child installs the notify filter and
//! hands the listener to the parent via SCM_RIGHTS, and the parent supervises.
//!
//! Run (host and unprivileged container):
//! ```text
//! cargo run -p ql-enforce --example cell_exec_probe
//! docker run --rm -v "$PWD:/work" -w /work ubuntu:24.04 \
//!   /work/target/debug/examples/cell_exec_probe
//! ```

use ql_enforce::exec_supervisor::hash_file;
use ql_enforce::Cell;
use ql_profile::{ExecDigest, HashAlgo, Profile};

fn run_one(label: &str, allow_hex: &str, cmd: &[&str]) {
    let mut profile = Profile::default();
    // validate() requires a coding profile to allow ≥1 executable (path-based
    // ProcPolicy). The Tier-2 wall uses exec.allow_digests, not this list; this
    // entry only satisfies the validator for the minimal demo cell.
    profile.processes.allow_exec.push("/bin/echo".to_string());
    // The supervisor sources its allowlist from the profile's exec.allow_digests
    // (the enforce flag is irrelevant to it). One approved digest here.
    let digest = ExecDigest::new(HashAlgo::Sha256, allow_hex).expect("valid sha256 digest");
    profile.exec.allow_digests = vec![digest];

    let cell = Cell::builder(profile)
        .with_exec_supervision()
        .build()
        .expect("cell builds");

    let argv: Vec<String> = cmd.iter().map(|s| s.to_string()).collect();
    match cell.run(&argv) {
        Ok(0) => println!("[{label}] exit 0    ALLOWED + ran: {}", cmd.join(" ")),
        Ok(code) => println!("[{label}] exit {code}  DENIED / refused: {}", cmd.join(" ")),
        Err(e) => println!("[{label}] error: {e}"),
    }
}

fn main() {
    let echo = hash_file("/bin/echo").expect("hash /bin/echo");
    println!("== QuantmLayer cell exec-wall probe ==");
    println!("[*] allowlist: /bin/echo sha256={}...", &echo[..16]);
    run_one("echo", &echo, &["/bin/echo", "hi-from-cell"]);
    run_one("ls", &echo, &["/bin/ls", "/"]);
    println!("[+] done — echo should ALLOW (exit 0), ls should DENY (exit 126).");
}

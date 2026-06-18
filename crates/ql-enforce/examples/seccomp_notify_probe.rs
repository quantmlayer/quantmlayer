// crates/ql-enforce/examples/seccomp_notify_probe.rs
//
//! Tier-2 exec-wall probe — now a thin driver over `ql_enforce::ExecSupervisor`.
//!
//! Proves the library's seccomp-notify deny-by-digest core on a substrate:
//! approve a binary's digest, then watch an approved exec run (CONTINUE) and an
//! unapproved one fail (EACCES) — unprivileged, in a container if you run it
//! there. The mechanism lives in `exec_supervisor.rs`; this example only parses
//! args, seeds an allowlist, forks the target, and drives the serve loop.
//!
//! Allowlist: `--allow-path P` approves binary P's digest; `--allow-digest HEX`
//! approves a literal digest. With NO allow flags the target is auto-approved.
//! Fail-closed: anything not approved — incl. an unhashable binary — is denied.
//!
//! Run:
//! ```text
//! cargo run -p ql-enforce --example seccomp_notify_probe
//! cargo run -p ql-enforce --example seccomp_notify_probe -- \
//!   --allow-path /bin/echo -- /bin/ls /
//! ```
//! Inside a container:
//! ```text
//! docker run --rm -v "$PWD:/work" -w /work ubuntu:24.04 \
//!   /work/target/debug/examples/seccomp_notify_probe --allow-path /bin/echo -- /bin/ls /
//! ```

use ql_enforce::exec_supervisor::hash_file;
use ql_enforce::{Decision, ExecEvent, ExecSupervisor};
use std::collections::HashSet;
use std::ffi::CString;
use std::os::unix::io::AsRawFd;

struct Args {
    allow_paths: Vec<String>,
    allow_digests: Vec<String>,
    cmd: Vec<String>,
}

fn parse_args() -> Args {
    let mut allow_paths = Vec::new();
    let mut allow_digests = Vec::new();
    let mut cmd = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--allow-path" => allow_paths.push(it.next().expect("--allow-path needs a value")),
            "--allow-digest" => {
                allow_digests.push(it.next().expect("--allow-digest needs a value"))
            }
            "--" => {
                cmd.extend(it.by_ref());
                break;
            }
            _ => {
                cmd.push(a);
                cmd.extend(it.by_ref());
                break;
            }
        }
    }
    if cmd.is_empty() {
        cmd = vec![
            "/bin/echo".to_string(),
            "seccomp-notify exec wall: hello from inside the cell".to_string(),
        ];
    }
    Args {
        allow_paths,
        allow_digests,
        cmd,
    }
}

fn build_allowlist(args: &Args) -> HashSet<String> {
    let mut allow: HashSet<String> = HashSet::new();
    for d in &args.allow_digests {
        allow.insert(d.to_lowercase());
    }
    for p in &args.allow_paths {
        match hash_file(p) {
            Ok(d) => {
                println!("[*] approved --allow-path {p}");
                println!("    sha256={d}");
                allow.insert(d);
            }
            Err(e) => eprintln!("[!] cannot hash --allow-path {p}: {e}"),
        }
    }
    let explicit = !args.allow_paths.is_empty() || !args.allow_digests.is_empty();
    if !explicit {
        match hash_file(&args.cmd[0]) {
            Ok(d) => {
                println!(
                    "[*] no allowlist given; auto-approving target {}",
                    args.cmd[0]
                );
                println!("    sha256={d}");
                allow.insert(d);
            }
            Err(e) => eprintln!("[!] cannot hash target {}: {e}", args.cmd[0]),
        }
    }
    allow
}

fn main() {
    let args = parse_args();
    let sup = ExecSupervisor::new(build_allowlist(&args)).with_committed_argv(true);

    println!("== QuantmLayer Tier-2 proof: ExecSupervisor deny-by-digest ==");
    println!("[*] target command: {}", args.cmd.join(" "));

    // Build the child's argv BEFORE fork (no allocation in the child).
    let path_c = CString::new(args.cmd[0].as_str()).expect("nul in path");
    let argv_c: Vec<CString> = args
        .cmd
        .iter()
        .map(|s| CString::new(s.as_str()).expect("nul in arg"))
        .collect();
    let mut argv_p: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());

    let listener = match sup.install() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[!] install (seccomp NEW_LISTENER) failed: {e}");
            eprintln!("    This substrate cannot host the Tier-2 wall unprivileged.");
            std::process::exit(1);
        }
    };
    println!(
        "[+] listener installed (fd {}); filter inherited across fork",
        listener.as_raw_fd()
    );

    // SAFETY: fork; the child path touches only async-signal-safe calls (execvp).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("[!] fork failed: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
    if pid == 0 {
        // SAFETY: pointers come from CStrings kept alive in the parent frame.
        unsafe { libc::execvp(path_c.as_ptr(), argv_p.as_ptr()) };
        unsafe { libc::_exit(127) };
    }

    let mut on_event = |e: &ExecEvent| {
        match e.decision {
            Decision::Allow => println!("[+] ALLOW pid={:<7} path={}", e.pid, e.path),
            Decision::Deny => {
                println!(
                    "[-] DENY  pid={:<7} path={}  (execve -> EACCES)",
                    e.pid, e.path
                )
            }
        }
        match e.digest {
            Some(d) => println!("    sha256={d}"),
            None => println!("    sha256=<unhashable> (denied fail-closed)"),
        }
        // The whole point of this probe: pre-commit argv is read from the frozen
        // tracee's memory (racy); committed argv is read from /proc/<pid>/cmdline
        // after CONTINUE (sound). On an allowed, non-racing exec they match.
        println!("    argv(pre-commit)={:?}", e.argv);
        if e.committed_argv.is_empty() {
            println!("    argv(committed) =<none> (denied, too fast, or unconfirmed)");
        } else {
            println!("    argv(committed) ={:?}", e.committed_argv);
        }
    };

    loop {
        // SAFETY: WNOHANG reap; NULL status (we only need whether it was reaped).
        let reaped = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        let child_done = reaped == pid;
        let ready = listener.poll_ready(200).unwrap_or(false);
        if ready {
            if let Err(e) = sup.serve_one(&listener, &mut on_event) {
                eprintln!("[!] serve error: {e}");
                if child_done {
                    break;
                }
            }
        } else if child_done {
            break;
        }
    }

    println!("[+] child finished; ExecSupervisor exercised end-to-end.");
}

// crates/ql-enforce/examples/fd_transfer_probe.rs
//
//! fd-transfer probe — de-risks the corrected Tier-2 *cell* integration.
//!
//! The cell's parent runs a veth hook that execs `ip`, so the parent must NOT be
//! under the notify filter (it would intercept its own `ip` and deadlock). The
//! fix: the **child** installs the filter and hands the listener fd up to the
//! (unfiltered) parent, which supervises.
//!
//! The fd crosses via **SCM_RIGHTS** over a Unix socketpair. (An earlier draft
//! used `pidfd_getfd`, but that is blocked with EPERM in unprivileged Docker —
//! the default seccomp profile gates it behind CAP_SYS_PTRACE. SCM_RIGHTS needs
//! no such privilege and works in unprivileged containers.)
//!
//! Flow:
//!   parent: socketpair; fork
//!   child : install filter -> listener; send the fd via SCM_RIGHTS; wait "go";
//!           exec the agent (its execve is what the parent screens)
//!   parent: recv the fd via SCM_RIGHTS; signal "go"; serve the notify loop
//!
//! Run:
//! ```text
//! cargo run -p ql-enforce --example fd_transfer_probe -- --allow-path /bin/echo -- /bin/ls /
//! ```
//! Inside a container:
//! ```text
//! docker run --rm -v "$PWD:/work" -w /work ubuntu:24.04 \
//!   /work/target/debug/examples/fd_transfer_probe --allow-path /bin/echo -- /bin/ls /
//! ```

use ql_enforce::exec_supervisor::{hash_file, recv_fd, send_fd};
use ql_enforce::{Decision, ExecEvent, ExecSupervisor, Listener};
use std::collections::HashSet;
use std::ffi::CString;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

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
        cmd = vec!["/bin/echo".to_string(), "hello".to_string()];
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
                allow.insert(d);
            }
            Err(e) => eprintln!("[!] cannot hash --allow-path {p}: {e}"),
        }
    }
    let explicit = !args.allow_paths.is_empty() || !args.allow_digests.is_empty();
    if !explicit {
        if let Ok(d) = hash_file(&args.cmd[0]) {
            println!("[*] no allowlist; auto-approving target {}", args.cmd[0]);
            allow.insert(d);
        }
    }
    allow
}

fn main() {
    let args = parse_args();
    let allow = build_allowlist(&args);

    println!("== QuantmLayer SCM_RIGHTS fd-transfer probe: child installs, parent supervises ==");
    println!("[*] target command: {}", args.cmd.join(" "));

    let path_c = CString::new(args.cmd[0].as_str()).expect("nul in path");
    let argv_c: Vec<CString> = args
        .cmd
        .iter()
        .map(|s| CString::new(s.as_str()).expect("nul in arg"))
        .collect();
    let mut argv_p: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());

    let mut sv: [RawFd; 2] = [0; 2];
    // SAFETY: socketpair over a two-element array we own.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    if rc != 0 {
        eprintln!("[!] socketpair failed: {}", io::Error::last_os_error());
        std::process::exit(1);
    }
    let (parent_sock, child_sock) = (sv[0], sv[1]);

    // SAFETY: fork; child path uses only async-signal-safe-enough calls.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("[!] fork failed: {}", io::Error::last_os_error());
        std::process::exit(1);
    }

    if pid == 0 {
        // ---- child: install the filter, hand the fd up, then exec ----
        // SAFETY: close the parent's socket end.
        unsafe { libc::close(parent_sock) };
        let listener = match ExecSupervisor::new(HashSet::new()).install() {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[!] child: install failed: {e}");
                // SAFETY: terminate the child without running destructors.
                unsafe { libc::_exit(125) };
            }
        };
        if let Err(e) = send_fd(child_sock, listener.as_raw_fd()) {
            eprintln!("[!] child: send_fd failed: {e}");
            // SAFETY: terminate.
            unsafe { libc::_exit(125) };
        }
        let mut go = [0u8; 1];
        // SAFETY: wait for the parent's go/abort signal.
        let n = unsafe { libc::read(child_sock, go.as_mut_ptr().cast::<libc::c_void>(), 1) };
        if n != 1 {
            // SAFETY: parent aborted (EOF); do not exec.
            unsafe { libc::_exit(125) };
        }
        // listener fd is CLOEXEC, so the agent never inherits it.
        // SAFETY: exec the agent; on failure exit non-zero.
        unsafe { libc::execvp(path_c.as_ptr(), argv_p.as_ptr()) };
        unsafe { libc::_exit(127) };
    }

    // ---- parent: receive the fd, supervise (never filtered) ----
    // SAFETY: close the child's socket end.
    unsafe { libc::close(child_sock) };
    let listener = match recv_fd(parent_sock) {
        // SAFETY: fd is a valid notification fd this process now owns.
        Ok(fd) => unsafe { Listener::from_raw_fd(fd) },
        Err(e) => {
            eprintln!("[!] fd transfer (recv_fd) failed: {e}");
            // SAFETY: closing our socket signals abort (child sees EOF); reap.
            unsafe { libc::close(parent_sock) };
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            std::process::exit(1);
        }
    };
    println!(
        "[+] parent received listener fd {} via SCM_RIGHTS",
        listener.as_raw_fd()
    );

    // Signal the child it may exec now that we hold the listener.
    let go = [b'G'; 1];
    // SAFETY: write the go byte to the child.
    unsafe { libc::write(parent_sock, go.as_ptr().cast::<libc::c_void>(), 1) };

    let sup = ExecSupervisor::new(allow);
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
        if let Some(d) = e.digest {
            println!("    sha256={d}");
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

    println!("[+] child finished; SCM_RIGHTS fd-transfer + supervise proven end-to-end.");
}

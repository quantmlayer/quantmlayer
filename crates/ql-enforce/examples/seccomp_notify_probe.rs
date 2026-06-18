// crates/ql-enforce/examples/seccomp_notify_probe.rs
//
//! Tier-2 exec-wall PROOF HARNESS — seccomp user-notification, deny-by-digest.
//!
//! A *de-risking probe*, not the production wall. It answers two questions on a
//! given substrate: (1) can an unprivileged process install a
//! `SECCOMP_RET_USER_NOTIF` listener and intercept a child's `execve`, and
//! (2) can it ENFORCE a content-addressed allow/deny decision — letting an
//! approved binary run (CONTINUE) and failing an unapproved one (EACCES) — purely
//! in userspace. If a binary outside the allowlist is blocked from inside an
//! unprivileged container, the Tier-2 enforcement mechanism is proven and the real
//! `ql-enforce` module (profile wiring, audit, tier selection) is incremental.
//!
//! It still carries no policy *model* — the allowlist is a flat set of approved
//! sha256 digests. Do not grow profile logic in here; copy the proven core into
//! `ql-enforce` instead.
//!
//! Design: the PARENT sets no_new_privs, installs the filter with NEW_LISTENER
//! (so the listener fd lives in the parent), then forks. The child inherits the
//! filter; its execve is delivered to the parent's listener fd. No SCM_RIGHTS.
//!
//! Allowlist: `--allow-path P` hashes binary P and approves that digest;
//! `--allow-digest HEX` approves a literal digest. With NO allow flags, the
//! target binary is auto-approved (so the happy path runs out of the box).
//! Fail-closed: anything not approved — including a binary we cannot hash — is
//! denied.
//!
//! Run:
//! ```text
//! # happy path (auto-approves the target):
//! cargo run -p ql-enforce --example seccomp_notify_probe
//! # enforcement: approve echo, then try to run ls -> DENIED by digest
//! cargo run -p ql-enforce --example seccomp_notify_probe -- \
//!   --allow-path /bin/echo -- /bin/ls /
//! ```
//! Inside a container (the real test):
//! ```text
//! docker run --rm -v "$PWD:/work" -w /work ubuntu:24.04 \
//!   /work/target/debug/examples/seccomp_notify_probe --allow-path /bin/echo -- /bin/ls /
//! ```

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;

// ---- raw constants not exposed by libc -------------------------------------

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

// _IOWR('!', 0, struct seccomp_notif)        — see <linux/seccomp.h>
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
// _IOWR('!', 1, struct seccomp_notif_resp)
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
// _IOW('!', 2, __u64)
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;

const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// classic-BPF opcodes for the filter program
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64

// offsets into struct seccomp_data
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

// ---- kernel structs (not in libc) ------------------------------------------

#[repr(C)]
#[allow(dead_code)] // fields mirror the kernel ABI; some are kernel-written
struct SeccompDataRaw {
    nr: libc::c_int,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[allow(dead_code)] // fields mirror the kernel ABI; some are kernel-written
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompDataRaw,
}

#[repr(C)]
#[allow(dead_code)] // fields mirror the kernel ABI; some are kernel-written
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

// ---- filter construction ---------------------------------------------------

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jeq(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt,
        jf,
        k,
    }
}

/// Filter: notify on execve/execveat, allow everything else, kill on arch
/// mismatch (defends against a 32-bit compat trampoline).
fn build_filter() -> Vec<libc::sock_filter> {
    let nr_execve = libc::SYS_execve as u32;
    let nr_execveat = libc::SYS_execveat as u32;
    vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
        jeq(AUDIT_ARCH, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
        jeq(nr_execve, 2, 0),
        jeq(nr_execveat, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    ]
}

fn last_err() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// Install the notify filter on the current process and return the listener fd.
fn install_listener() -> std::io::Result<libc::c_int> {
    // SAFETY: standard prctl; no_new_privs lets an unprivileged process load a
    // seccomp filter without CAP_SYS_ADMIN.
    let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if nnp != 0 {
        return Err(last_err());
    }
    let filter = build_filter();
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: prog points to a live, correctly-sized filter for the duration of
    // the call; NEW_LISTENER makes seccomp() return the notification fd.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            std::ptr::addr_of!(prog),
        )
    };
    if fd < 0 {
        return Err(last_err());
    }
    Ok(fd as libc::c_int)
}

/// Is this notification still live (the syscall still blocked)?
fn notif_id_valid(fd: libc::c_int, id: u64) -> bool {
    // SAFETY: read-only ioctl over a u64 we own.
    let r = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, std::ptr::addr_of!(id)) };
    r == 0
}

// ---- hashing ---------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hash_reader(mut r: impl Read) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Hash a binary by path, in the caller's own view (used to seed the allowlist).
fn hash_path(path: &str) -> std::io::Result<String> {
    hash_reader(File::open(path)?)
}

/// Read the NUL-terminated path argument out of the stopped child's memory.
fn read_path(pid: u32, addr: u64) -> std::io::Result<String> {
    let mem = File::open(format!("/proc/{pid}/mem"))?;
    let mut buf = [0u8; libc::PATH_MAX as usize];
    let n = mem.read_at(&mut buf, addr)?;
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// Hash the file the child will exec, viewed through the child's own mount root
/// so a container path resolves correctly. The child is frozen in execve, so the
/// bytes cannot change underneath us here.
fn hash_target(pid: u32, path: &str) -> std::io::Result<String> {
    let candidate = if path.starts_with('/') {
        format!("/proc/{pid}/root{path}")
    } else {
        format!("/proc/{pid}/cwd/{path}")
    };
    let file = File::open(&candidate).or_else(|_| File::open(path))?;
    hash_reader(file)
}

// ---- notification handling -------------------------------------------------

/// Service one notification: hash the target, decide by digest, respond.
/// Approved -> CONTINUE (the real execve runs); otherwise EACCES (denied).
fn service(fd: libc::c_int, allow: &HashSet<String>) -> std::io::Result<()> {
    // SAFETY: zeroed is the required initial state for these all-integer structs
    // before NOTIF_RECV.
    let mut req: SeccompNotif = unsafe { std::mem::zeroed() };
    // SAFETY: req is a live, correctly-sized buffer for the RECV ioctl.
    let r = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, std::ptr::addr_of_mut!(req)) };
    if r != 0 {
        return Err(last_err());
    }

    // execve(path, ...) -> path is args[0]; execveat(dirfd, path, ...) -> args[1]
    let is_execveat = i64::from(req.data.nr) == libc::SYS_execveat;
    let path_addr = if is_execveat {
        req.data.args[1]
    } else {
        req.data.args[0]
    };
    let path = read_path(req.pid, path_addr).unwrap_or_else(|e| format!("<unreadable: {e}>"));

    // Fail-closed: a binary we cannot hash is never approved.
    let (approved, shown) = match hash_target(req.pid, &path) {
        Ok(d) => (allow.contains(&d), d),
        Err(e) => (false, format!("<hash failed: {e}>")),
    };

    if !notif_id_valid(fd, req.id) {
        eprintln!(
            "[!] notification {} expired before response (pid {})",
            req.id, req.pid
        );
        return Ok(());
    }

    if approved {
        println!("[+] ALLOW pid={:<7} path={path}", req.pid);
    } else {
        println!(
            "[-] DENY  pid={:<7} path={path}  (execve -> EACCES)",
            req.pid
        );
    }
    println!("    sha256={shown}");

    // SAFETY: zeroed response, then filled per the allow/deny decision.
    let mut resp: SeccompNotifResp = unsafe { std::mem::zeroed() };
    resp.id = req.id;
    if approved {
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; // val/error stay 0
    } else {
        resp.error = -libc::EACCES; // deny; flags stay 0 (do not continue)
    }
    // SAFETY: resp is a live, correctly-sized buffer for the SEND ioctl.
    let s = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, std::ptr::addr_of_mut!(resp)) };
    if s != 0 {
        eprintln!(
            "[!] NOTIF_SEND failed (likely child exited): {}",
            last_err()
        );
    }
    Ok(())
}

// ---- argument parsing ------------------------------------------------------

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
        match hash_path(p) {
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
        match hash_path(&args.cmd[0]) {
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
    let allow = build_allowlist(&args);

    println!("== QuantmLayer Tier-2 proof: seccomp-notify deny-by-digest ==");
    println!("[*] target command: {}", args.cmd.join(" "));
    println!("[*] allowlist holds {} approved digest(s)", allow.len());

    // Build the child's argv BEFORE fork (no allocation in the child).
    let path_c = CString::new(args.cmd[0].as_str()).expect("nul in path");
    let argv_c: Vec<CString> = args
        .cmd
        .iter()
        .map(|s| CString::new(s.as_str()).expect("nul in arg"))
        .collect();
    let mut argv_p: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());

    let fd = match install_listener() {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("[!] seccomp(NEW_LISTENER) failed: {e}");
            eprintln!("    This substrate cannot host the Tier-2 wall unprivileged.");
            std::process::exit(1);
        }
    };
    println!("[+] listener installed (fd {fd}); filter is inherited across fork");

    // SAFETY: fork; the child path touches only async-signal-safe calls (execvp).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("[!] fork failed: {}", last_err());
        std::process::exit(1);
    }
    if pid == 0 {
        // Child: exec the target. This execve is what the parent intercepts.
        // SAFETY: pointers come from CStrings kept alive in the parent frame.
        unsafe { libc::execvp(path_c.as_ptr(), argv_p.as_ptr()) };
        // Only reached if the kernel let the exec proceed and it still failed,
        // or the exec was denied (EACCES) — either way the child is done.
        unsafe { libc::_exit(127) };
    }

    // Parent: supervise. Drain notifications without blocking once the child is
    // gone.
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: WNOHANG reap; NULL status (we only need whether it was reaped).
        let reaped = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        let child_done = reaped == pid;

        // SAFETY: poll over one live pollfd, 200 ms timeout.
        let p = unsafe { libc::poll(std::ptr::addr_of_mut!(pfd), 1, 200) };
        if p > 0 && (pfd.revents & libc::POLLIN) != 0 {
            if let Err(e) = service(fd, &allow) {
                eprintln!("[!] service error: {e}");
                if child_done {
                    break;
                }
            }
        } else if child_done {
            break;
        }
    }

    println!("[+] child finished; Tier-2 deny-by-digest exercised end-to-end.");
}

// crates/ql-enforce/examples/seccomp_notify_probe.rs
//
//! Tier-2 exec-wall PROOF HARNESS — seccomp user-notification.
//!
//! This is a *de-risking probe*, not the production wall. Its only job is to
//! answer one question on a given substrate: can an unprivileged process install
//! a `SECCOMP_RET_USER_NOTIF` listener, intercept a child's `execve`, hash the
//! exact binary the kernel is about to run, and let it continue? If this prints a
//! correct sha256 from inside an unprivileged container, the Tier-2 mechanism is
//! proven and the real enforcement module (deny-by-digest, profile wiring, audit)
//! is incremental. If `seccomp(NEW_LISTENER)` fails here, we learn it on day one.
//!
//! Contract: intercept-hash-LOG-and-ALLOW. It carries NO policy and enforces
//! nothing — every exec is permitted. Do not grow policy logic in here; copy the
//! proven core into `ql-enforce` instead.
//!
//! Design: the PARENT sets no_new_privs, installs the filter with NEW_LISTENER
//! (so the listener fd lives in the parent), then forks. The child inherits the
//! filter; its execve is delivered to the parent's listener fd. No SCM_RIGHTS
//! fd-passing is required.
//!
//! Run (default execs `/bin/echo`):
//! ```text
//! cargo run -p ql-enforce --example seccomp_notify_probe
//! cargo run -p ql-enforce --example seccomp_notify_probe -- /bin/ls -l /
//! ```
//! Inside a container:
//! ```text
//! docker run --rm -v "$PWD:/work" -w /work ubuntu:24.04 \
//!   /work/target/debug/examples/seccomp_notify_probe /bin/echo hi
//! ```

use sha2::{Digest, Sha256};
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
    // SAFETY: standard prctl; turning on no_new_privs lets an unprivileged
    // process load a seccomp filter without CAP_SYS_ADMIN.
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
        // relative exec: resolve against the child's cwd
        format!("/proc/{pid}/cwd/{path}")
    };
    let mut file = File::open(&candidate).or_else(|_| File::open(path))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Service one notification: hash the target, log it, allow (CONTINUE).
fn service(fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: zeroed is a valid initial state for these all-integer structs; the
    // kernel requires the request struct be zeroed before NOTIF_RECV.
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

    let digest = match hash_target(req.pid, &path) {
        Ok(d) => d,
        Err(e) => format!("<hash failed: {e}>"),
    };

    if !notif_id_valid(fd, req.id) {
        eprintln!(
            "[!] notification {} expired before response (pid {})",
            req.id, req.pid
        );
        return Ok(());
    }

    println!("[+] exec intercepted  pid={:<7} path={path}", req.pid);
    println!("    sha256={digest}");
    println!("    verdict=ALLOW (proof harness enforces nothing)");

    // SAFETY: zeroed response, then filled; CONTINUE lets the real execve run.
    let mut resp: SeccompNotifResp = unsafe { std::mem::zeroed() };
    resp.id = req.id;
    resp.val = 0;
    resp.error = 0;
    resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    // SAFETY: resp is a live, correctly-sized buffer for the SEND ioctl.
    let s = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, std::ptr::addr_of_mut!(resp)) };
    if s != 0 {
        // A response can race the child dying; treat as non-fatal.
        eprintln!(
            "[!] NOTIF_SEND failed (likely child exited): {}",
            last_err()
        );
    }
    Ok(())
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd: Vec<String> = if argv.is_empty() {
        vec![
            "/bin/echo".to_string(),
            "seccomp-notify exec wall: hello from inside the cell".to_string(),
        ]
    } else {
        argv
    };

    println!("== QuantmLayer Tier-2 proof: seccomp-notify exec interception ==");
    println!("[*] target command: {}", cmd.join(" "));

    // Build the child's argv BEFORE fork (no allocation in the child).
    let path_c = CString::new(cmd[0].as_str()).expect("nul in path");
    let argv_c: Vec<CString> = cmd
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
            eprintln!("    (Try: is no_new_privs blocked? does the runtime drop seccomp?)");
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
        // Child: exec the target. This execve is what the parent will intercept.
        // SAFETY: pointers come from CStrings kept alive in the parent frame.
        unsafe { libc::execvp(path_c.as_ptr(), argv_p.as_ptr()) };
        // Only reached if exec failed.
        unsafe { libc::_exit(127) };
    }

    // Parent: supervise. Drain notifications without blocking forever once the
    // child is gone.
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
            if let Err(e) = service(fd) {
                eprintln!("[!] service error: {e}");
                if child_done {
                    break;
                }
            }
        } else if child_done {
            break;
        }
    }

    println!("[+] child finished; Tier-2 mechanism exercised end-to-end.");
}

// crates/ql-learn/src/trace.rs
//
//! The behavior tracer: run a command under `ptrace` and record what it does.
//!
//! This is the dynamic counterpart to Decap's static capability derivation —
//! instead of analyzing a binary, we watch a live agent and capture the
//! syscalls that reveal its real resource needs: `openat`/`open` (files, with
//! read vs write intent), `execve` (child programs), and `connect` (network
//! egress). Forked children are followed, so a tool that spawns a compiler or
//! a shell is observed in full.
//!
//! The tracer does **not** restrict anything — it runs the agent permissively
//! and only watches. The resulting [`Observation`] is then narrowed into a
//! least-privilege profile by [`crate::synth`].
//!
//! ## Architecture portability
//!
//! Syscall *numbers* are resolved through `libc::SYS_*`, which libc defines
//! correctly per target architecture, so the decoder is right on every arch we
//! build for. Only the register *layout* differs, and that is isolated in
//! [`read_regs`], which has an x86-64 and an aarch64 implementation. Syscall
//! argument *positions* (path in arg N, flags in arg M) are part of the Linux
//! syscall ABI and identical across these architectures, so the decode logic
//! itself is shared.

use crate::error::{LearnError, Result};
use crate::observation::Observation;
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::FileExt;

// open(2) flag bits (identical on x86-64 and aarch64).
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;

/// A decoded syscall entry: the syscall number plus its first six arguments,
/// in a register-layout-independent form.
struct Regs {
    nr: i64,
    args: [u64; 6],
}

/// Trace `command` (argv form) to completion, returning what it did.
pub fn trace(command: &[String]) -> Result<Observation> {
    if command.is_empty() {
        return Err(LearnError::Spawn("empty command".into()));
    }

    // SAFETY: in the child we only call traceme + execvp before handing control
    // to the new program; no shared Rust state is touched across the fork.
    match unsafe { fork() }.map_err(|e| LearnError::Spawn(e.to_string()))? {
        ForkResult::Child => {
            // Become traceable, then exec the agent. The kernel stops us at the
            // exec so the parent can attach options before any work happens.
            let _ = ptrace::traceme();
            // Redirect the agent's stdout onto stderr so that when `ql learn`
            // streams the synthesized profile to *its* stdout, the agent's own
            // output can't corrupt it. The agent still runs normally.
            unsafe { libc::dup2(2, 1) };
            let prog = CString::new(command[0].as_str()).unwrap_or_default();
            let argv: Vec<CString> = command
                .iter()
                .filter_map(|a| CString::new(a.as_str()).ok())
                .collect();
            let _ = execvp(&prog, &argv);
            // Only reached if exec failed.
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => supervise(child),
    }
}

/// Parent-side supervision loop: drive every traced process through its
/// syscall stops and record the interesting ones.
fn supervise(root: Pid) -> Result<Observation> {
    let mut obs = Observation::default();

    // Wait for the initial post-`traceme` stop, then set our trace options:
    // distinguish syscall stops (TRACESYSGOOD) and auto-attach children.
    waitpid(root, None).map_err(|e| LearnError::Trace(e.to_string()))?;
    let opts = Options::PTRACE_O_TRACESYSGOOD
        | Options::PTRACE_O_TRACEEXEC
        | Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_EXITKILL;
    ptrace::setoptions(root, opts).map_err(|e| LearnError::Trace(e.to_string()))?;

    // Per-pid state: are we at a syscall *entry* (true) or *exit* (false next)?
    let mut at_entry: HashMap<Pid, bool> = HashMap::new();
    at_entry.insert(root, true);
    let mut seen: HashSet<Pid> = HashSet::new();
    seen.insert(root);
    let _ = ptrace::syscall(root, None);

    // Drive every traced process until the last one exits. `waitpid` returns
    // an error (ECHILD) once there are no traced children left, ending the loop.
    while let Ok(status) = waitpid(Pid::from_raw(-1), None) {
        match status {
            WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) => {
                at_entry.remove(&pid);
                if at_entry.is_empty() {
                    break;
                }
            }
            WaitStatus::PtraceSyscall(pid) => {
                seen.insert(pid);
                let entry = at_entry.entry(pid).or_insert(true);
                if *entry {
                    if let Some(regs) = read_regs(pid) {
                        decode_entry(pid, &regs, &mut obs);
                    }
                }
                *entry = !*entry;
                let _ = ptrace::syscall(pid, None);
            }
            WaitStatus::PtraceEvent(pid, _, _) => {
                // fork/exec event: a new child may have appeared; it inherits
                // our options. Just keep everyone moving.
                seen.insert(pid);
                at_entry.entry(pid).or_insert(true);
                let _ = ptrace::syscall(pid, None);
            }
            WaitStatus::Stopped(pid, sig) => {
                // Signal-delivery stop. Swallow the ptrace artifacts; forward
                // anything the program genuinely received.
                seen.insert(pid);
                at_entry.entry(pid).or_insert(true);
                let inject = match sig {
                    Signal::SIGSTOP | Signal::SIGTRAP => None,
                    other => Some(other),
                };
                let _ = ptrace::syscall(pid, inject);
            }
            _ => {}
        }
    }

    obs.process_count = (seen.len() as u32).max(1);
    Ok(obs)
}

/// Read the syscall number and arguments for `pid` at a syscall-entry stop.
///
/// x86-64 exposes these via `PTRACE_GETREGS` (the syscall number in `orig_rax`,
/// arguments in `rdi, rsi, rdx, r10, r8, r9`).
#[cfg(target_arch = "x86_64")]
fn read_regs(pid: Pid) -> Option<Regs> {
    let r = ptrace::getregs(pid).ok()?;
    Some(Regs {
        nr: r.orig_rax as i64,
        args: [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9],
    })
}

/// Read the syscall number and arguments for `pid` at a syscall-entry stop.
///
/// aarch64 has no `PTRACE_GETREGS`; the register set is fetched via
/// `PTRACE_GETREGSET` with `NT_PRSTATUS`. The syscall number is in `x8`
/// (`regs[8]`) and the arguments in `x0..x5` (`regs[0..6]`).
#[cfg(target_arch = "aarch64")]
fn read_regs(pid: Pid) -> Option<Regs> {
    // PTRACE_GETREGSET (0x4204) with the NT_PRSTATUS (1) register set. Both are
    // architecture-independent ptrace constants; we hardcode them and go
    // through the raw `syscall` entry point so we don't depend on the exact
    // type of libc's `ptrace` wrapper (which varies across libc versions).
    const PTRACE_GETREGSET: libc::c_long = 0x4204;
    const NT_PRSTATUS: libc::c_long = 1;
    // SAFETY: we hand the kernel a correctly-sized buffer and check the return.
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: &mut regs as *mut _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
    };
    let res = unsafe {
        libc::syscall(
            libc::SYS_ptrace,
            PTRACE_GETREGSET,
            pid.as_raw() as libc::c_long,
            NT_PRSTATUS,
            &mut iov as *mut libc::iovec,
        )
    };
    if res != 0 {
        return None;
    }
    Some(Regs {
        nr: regs.regs[8] as i64,
        args: [
            regs.regs[0],
            regs.regs[1],
            regs.regs[2],
            regs.regs[3],
            regs.regs[4],
            regs.regs[5],
        ],
    })
}

/// Decode and record a single syscall *entry* for `pid`. Syscall numbers come
/// from `libc::SYS_*` (arch-correct); argument positions are ABI-stable.
fn decode_entry(pid: Pid, regs: &Regs, obs: &mut Observation) {
    let nr = regs.nr;
    obs.record_syscall(nr as u64, syscall_name(nr));

    if nr == libc::SYS_openat {
        if let Some(p) = read_cstr(pid, regs.args[1]) {
            obs.record_open(p.into(), is_write(regs.args[2]));
        }
    } else if nr == libc::SYS_openat2 {
        if let Some(p) = read_cstr(pid, regs.args[1]) {
            obs.record_open(p.into(), false);
        }
    } else if nr == libc::SYS_execve {
        if let Some(p) = read_cstr(pid, regs.args[0]) {
            obs.record_exec(p);
        }
    } else if nr == libc::SYS_execveat {
        if let Some(p) = read_cstr(pid, regs.args[1]) {
            obs.record_exec(p);
        }
    } else if nr == libc::SYS_connect {
        if let Some((ip, port)) = read_sockaddr(pid, regs.args[1], regs.args[2]) {
            obs.record_connect(ip, port);
        }
    } else {
        // x86-64 additionally has the legacy open(2)/creat(2); aarch64 routes
        // everything through openat and has no such syscalls.
        #[cfg(target_arch = "x86_64")]
        {
            if nr == libc::SYS_open {
                if let Some(p) = read_cstr(pid, regs.args[0]) {
                    obs.record_open(p.into(), is_write(regs.args[1]));
                }
            } else if nr == libc::SYS_creat {
                if let Some(p) = read_cstr(pid, regs.args[0]) {
                    obs.record_open(p.into(), true);
                }
            }
        }
    }
}

/// True if open(2) flags request any form of write access.
fn is_write(flags: u64) -> bool {
    (flags & (O_WRONLY | O_RDWR)) != 0 || (flags & O_CREAT) != 0
}

/// Read a NUL-terminated string from the tracee's memory at `addr`.
fn read_cstr(pid: Pid, addr: u64) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let mem = std::fs::File::open(format!("/proc/{}/mem", pid.as_raw())).ok()?;
    let mut buf = [0u8; 256];
    let n = mem.read_at(&mut buf, addr).ok()?;
    if n == 0 {
        return None;
    }
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// Read a `struct sockaddr` from the tracee and extract IP + port (v4/v6).
fn read_sockaddr(pid: Pid, addr: u64, len: u64) -> Option<(IpAddr, u16)> {
    if addr == 0 {
        return None;
    }
    let n = (len as usize).clamp(8, 28);
    let mem = std::fs::File::open(format!("/proc/{}/mem", pid.as_raw())).ok()?;
    let mut buf = [0u8; 28];
    let got = mem.read_at(&mut buf[..n], addr).ok()?;
    if got < 8 {
        return None;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    match family as i32 {
        libc::AF_INET => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            Some((IpAddr::V4(ip), port))
        }
        libc::AF_INET6 if got >= 24 => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[8..24]);
            Some((IpAddr::V6(Ipv6Addr::from(o)), port))
        }
        _ => None,
    }
}

/// Best-effort name for a syscall number, resolved through `libc::SYS_*` so it
/// is correct on every architecture. Unknown numbers get a generic label;
/// names are cosmetic (used only in the observation summary).
fn syscall_name(nr: i64) -> &'static str {
    if nr == libc::SYS_openat {
        return "openat";
    }
    if nr == libc::SYS_openat2 {
        return "openat2";
    }
    if nr == libc::SYS_execve {
        return "execve";
    }
    if nr == libc::SYS_execveat {
        return "execveat";
    }
    if nr == libc::SYS_connect {
        return "connect";
    }
    if nr == libc::SYS_socket {
        return "socket";
    }
    if nr == libc::SYS_clone {
        return "clone";
    }
    if nr == libc::SYS_ptrace {
        return "ptrace";
    }
    if nr == libc::SYS_mount {
        return "mount";
    }
    #[cfg(target_arch = "x86_64")]
    {
        if nr == libc::SYS_open {
            return "open";
        }
        if nr == libc::SYS_creat {
            return "creat";
        }
    }
    "other"
}

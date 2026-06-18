// crates/ql-enforce/src/exec_supervisor.rs
//
//! Tier-2 exec wall: a userspace **seccomp user-notification** supervisor.
//!
//! Where the BPF-LSM wall (Tier 1) enforces content-addressed execution in the
//! kernel, this wall enforces the same property from userspace and works on any
//! host with seccomp user-notification (kernel ≥5.0) — including unprivileged
//! containers where BPF-LSM is unavailable. It is the substrate-adaptive fallback
//! proven in `examples/seccomp_notify_probe.rs`.
//!
//! Unlike an [`crate::Enforcer`] (apply-once in the child), this is a long-lived
//! **supervisor**: the parent installs the notify filter and keeps the listener
//! fd; the contained child inherits the filter; every `execve` the child makes is
//! delivered to the parent, which hashes the resolved binary and allows
//! (`CONTINUE`) or denies (`EACCES`) by digest.
//!
//! This module is the reusable core. Cell wiring, profile-sourced allowlists, and
//! audit records are layered on top in later slices; here the allowlist is a flat
//! set of lowercase-hex sha256 digests and the caller drives the serve loop.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::os::unix::io::RawFd;

use ql_profile::{ExecPolicy, HashAlgo, Profile};

// ---- raw constants not exposed by libc -------------------------------------

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

// _IOWR('!', 0, struct seccomp_notif)
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
// _IOWR('!', 1, struct seccomp_notif_resp)
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
// _IOW('!', 2, __u64)
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;

const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

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

// ---- public types ----------------------------------------------------------

/// The verdict for one intercepted `execve`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Let the real `execve` proceed (CONTINUE).
    Allow,
    /// Fail the `execve` with `EACCES`.
    Deny,
}

/// What the supervisor decided about one exec, reported to the caller's callback
/// (e.g. to write an audit record). Borrows for the duration of the callback.
pub struct ExecEvent<'a> {
    /// Pid of the execing process, in the supervisor's pid namespace.
    pub pid: u32,
    /// The path the child passed to `execve` (as read from its memory).
    pub path: &'a str,
    /// sha256 hex of the resolved binary, or `None` if it could not be hashed.
    pub digest: Option<&'a str>,
    /// The verdict.
    pub decision: Decision,
}

/// An owned seccomp notification fd. Closes on drop.
pub struct Listener {
    fd: RawFd,
}

impl Listener {
    /// Block up to `timeout_ms` for a notification to be ready. `Ok(true)` means
    /// a subsequent `serve_one` will not block.
    pub fn poll_ready(&self, timeout_ms: i32) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll over one live pollfd we own.
        let p = unsafe { libc::poll(std::ptr::addr_of_mut!(pfd), 1, timeout_ms) };
        if p < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(p > 0 && (pfd.revents & libc::POLLIN) != 0)
    }
}

impl std::os::unix::io::AsRawFd for Listener {
    /// The raw listener fd (for the caller to `poll`/select on).
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // SAFETY: we own this fd; closing it once on drop is correct.
        unsafe { libc::close(self.fd) };
    }
}

/// A userspace content-addressed exec wall driven by an allowlist of approved
/// sha256 digests (lowercase hex). See the [module docs](self).
pub struct ExecSupervisor {
    allow: HashSet<String>,
}

impl ExecSupervisor {
    /// Build a supervisor from a set of approved lowercase-hex sha256 digests.
    pub fn new(allow: HashSet<String>) -> Self {
        ExecSupervisor { allow }
    }

    /// Build the allowlist from a profile's [`ExecPolicy`].
    ///
    /// Only **sha256** digests are honored: this wall hashes binaries with
    /// sha256, so a digest in another algorithm cannot be matched here and its
    /// binary is denied (fail-closed). In practice profiles use sha256 (the
    /// default and recommended algorithm). When the profile is signed and
    /// verified before arming, this allowlist is therefore *attested* — it cannot
    /// be widened without breaking the signature.
    pub fn from_exec_policy(policy: &ExecPolicy) -> Self {
        let allow = policy
            .allow_digests
            .iter()
            .filter(|d| d.algo() == HashAlgo::Sha256)
            .map(|d| d.hex().to_string())
            .collect();
        ExecSupervisor::new(allow)
    }

    /// Convenience: build from a whole [`Profile`] (uses `profile.exec`).
    pub fn from_profile(profile: &Profile) -> Self {
        Self::from_exec_policy(&profile.exec)
    }

    /// The pure allow/deny decision. `None` (could not hash) is fail-closed.
    pub fn decide(&self, digest: Option<&str>) -> Decision {
        match digest {
            Some(d) if self.allow.contains(d) => Decision::Allow,
            _ => Decision::Deny,
        }
    }

    /// Install the notify filter on the current process and return the listener.
    ///
    /// Call this in the **parent, before fork**: the child inherits the filter
    /// (across fork, namespace setup, and exec), and its `execve` is delivered to
    /// the returned listener. The fd is set `FD_CLOEXEC` so the agent cannot
    /// inherit it across its own exec and service its own notifications.
    pub fn install(&self) -> io::Result<Listener> {
        // SAFETY: no_new_privs lets an unprivileged process load a filter.
        let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if nnp != 0 {
            return Err(io::Error::last_os_error());
        }
        let filter = build_filter();
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr().cast_mut(),
        };
        // SAFETY: prog points to a live, correctly-sized filter for the call;
        // NEW_LISTENER makes seccomp() return the notification fd.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
                std::ptr::addr_of!(prog),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = fd as RawFd;
        // SAFETY: set close-on-exec so the contained agent never inherits the
        // listener. Failure here would leave the fd agent-reachable, so it is an
        // error, not a warning.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            // SAFETY: own fd, close before returning the error.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok(Listener { fd })
    }

    /// Service exactly one notification: hash the target, decide, report via
    /// `on_event`, and respond. The caller should `poll_ready` first so this does
    /// not block. Returns `Ok(())` when handled (including a benign "expired
    /// before response" race); returns `Err` on a RECV/SEND ioctl failure.
    pub fn serve_one<F: FnMut(&ExecEvent)>(
        &self,
        listener: &Listener,
        on_event: &mut F,
    ) -> io::Result<()> {
        // SAFETY: zeroed is the required initial state before NOTIF_RECV.
        let mut req: SeccompNotif = unsafe { std::mem::zeroed() };
        let req_ptr = std::ptr::addr_of_mut!(req);
        // SAFETY: req_ptr is a live, correctly-sized buffer for the RECV ioctl.
        let r = unsafe { libc::ioctl(listener.fd, SECCOMP_IOCTL_NOTIF_RECV, req_ptr) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }

        // execve(path,...) -> path is args[0]; execveat(dirfd,path,...) -> args[1]
        let is_execveat = i64::from(req.data.nr) == libc::SYS_execveat;
        let addr = if is_execveat {
            req.data.args[1]
        } else {
            req.data.args[0]
        };
        let path = read_path(req.pid, addr).unwrap_or_else(|e| format!("<unreadable: {e}>"));
        let digest = hash_target(req.pid, &path).ok();
        let decision = self.decide(digest.as_deref());

        // If the syscall is no longer pending, do not respond (or report).
        if !notif_id_valid(listener.fd, req.id) {
            return Ok(());
        }

        on_event(&ExecEvent {
            pid: req.pid,
            path: &path,
            digest: digest.as_deref(),
            decision,
        });

        // SAFETY: zeroed response, then filled per the decision.
        let mut resp: SeccompNotifResp = unsafe { std::mem::zeroed() };
        resp.id = req.id;
        match decision {
            Decision::Allow => resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE,
            Decision::Deny => resp.error = -libc::EACCES,
        }
        // SAFETY: resp is a live, correctly-sized buffer for the SEND ioctl.
        let resp_ptr = std::ptr::addr_of_mut!(resp);
        let s = unsafe { libc::ioctl(listener.fd, SECCOMP_IOCTL_NOTIF_SEND, resp_ptr) };
        if s != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

// ---- filter ----------------------------------------------------------------

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

/// Notify on execve/execveat, allow everything else, kill on arch mismatch.
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

// ---- hashing + helpers -----------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hash_reader(mut r: impl Read) -> io::Result<String> {
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

/// Hash a binary by path in the caller's own view (used to seed an allowlist).
pub fn hash_file(path: &str) -> io::Result<String> {
    hash_reader(File::open(path)?)
}

/// Read the NUL-terminated path argument out of the stopped child's memory.
fn read_path(pid: u32, addr: u64) -> io::Result<String> {
    let mem = File::open(format!("/proc/{pid}/mem"))?;
    let mut buf = [0u8; libc::PATH_MAX as usize];
    let n = mem.read_at(&mut buf, addr)?;
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// Hash the file the child will exec, through the child's own mount root so a
/// container path resolves correctly. The child is frozen in execve here.
fn hash_target(pid: u32, path: &str) -> io::Result<String> {
    let candidate = if path.starts_with('/') {
        format!("/proc/{pid}/root{path}")
    } else {
        format!("/proc/{pid}/cwd/{path}")
    };
    let file = File::open(&candidate).or_else(|_| File::open(path))?;
    hash_reader(file)
}

fn notif_id_valid(fd: RawFd, id: u64) -> bool {
    // SAFETY: read-only ioctl over a u64 we own.
    let r = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, std::ptr::addr_of!(id)) };
    r == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowset(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn decide_allows_listed_denies_rest_failclosed() {
        let s = ExecSupervisor::new(allowset(&["aaaa", "bbbb"]));
        assert_eq!(s.decide(Some("aaaa")), Decision::Allow);
        assert_eq!(s.decide(Some("bbbb")), Decision::Allow);
        assert_eq!(s.decide(Some("cccc")), Decision::Deny);
        assert_eq!(s.decide(None), Decision::Deny); // unhashable -> fail-closed
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let s = ExecSupervisor::new(HashSet::new());
        assert_eq!(s.decide(Some("aaaa")), Decision::Deny);
        assert_eq!(s.decide(None), Decision::Deny);
    }

    #[test]
    fn filter_has_expected_shape() {
        assert_eq!(build_filter().len(), 8);
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    #[test]
    fn from_exec_policy_honors_sha256_digests() {
        use ql_profile::ExecDigest;
        let d = ExecDigest::new(HashAlgo::Sha256, "a".repeat(64)).unwrap();
        let policy = ExecPolicy {
            enforce: true,
            allow_digests: vec![d.clone()],
        };
        let s = ExecSupervisor::from_exec_policy(&policy);
        assert_eq!(s.decide(Some(d.hex())), Decision::Allow);
        assert_eq!(s.decide(Some("b".repeat(64).as_str())), Decision::Deny);
        assert_eq!(s.decide(None), Decision::Deny);
    }

    #[test]
    fn from_exec_policy_skips_non_sha256() {
        use ql_profile::ExecDigest;
        // A sha512 digest cannot be matched by this sha256 wall -> fail-closed.
        let d = ExecDigest::new(HashAlgo::Sha512, "a".repeat(128)).unwrap();
        let policy = ExecPolicy {
            enforce: true,
            allow_digests: vec![d.clone()],
        };
        let s = ExecSupervisor::from_exec_policy(&policy);
        assert_eq!(s.decide(Some(d.hex())), Decision::Deny);
    }
}

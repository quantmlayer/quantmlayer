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
//! **supervisor**. To keep the cell's (unfiltered) parent free to run its veth
//! hook — which execs `ip` and would deadlock under a notify filter — the
//! **child** installs the filter and hands the listener fd up to the parent via
//! `SCM_RIGHTS` ([`send_fd`]/[`recv_fd`]). The parent, never filtered, screens
//! every `execve` the child makes: it hashes the resolved binary and allows
//! (`CONTINUE`) or denies (`EACCES`) by digest.
//!
//! For audit it also captures the child's `argv` from the frozen process's
//! memory (bounded, best-effort). This is **observation only**: argv is recorded
//! in the exec ledger but never feeds the verdict, because a multi-threaded
//! tracee could rewrite it between our read and the kernel's copy (the
//! seccomp-notify TOCTOU caveat). The decision rides on the stable content
//! digest; see [`read_argv`]. After allowing an exec it can optionally read the
//! *committed* argv (post-CONTINUE, from `/proc/<pid>/cmdline`) — the sound copy
//! the new process actually sees — to support detect-and-act; see
//! [`read_committed_argv`] and [`ExecSupervisor::with_committed_argv`].
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
use std::time::Duration;

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
    /// The argv the child passed to `execve`, captured (bounded) from its
    /// memory. **Observation only** — best-effort and never used for the
    /// allow/deny decision (a multi-threaded tracee could rewrite it between
    /// this read and the kernel's; see [`read_argv`]). The verdict is on the
    /// content digest, which is stable.
    pub argv: &'a [String],
    /// The **committed** argv — what the kernel installed in the new mm, read
    /// from `/proc/<pid>/cmdline` *after* this exec was allowed to proceed (see
    /// [`read_committed_argv`]). Unlike [`argv`](Self::argv) this is the immutable
    /// copy the new process actually sees, so it is *sound* input for a decision
    /// — but it is post-commit, so it supports detect-and-act (e.g. a later kill),
    /// not a pre-commit gate. Empty unless committed capture is enabled and the
    /// exec was allowed and confirmed within the poll budget.
    pub committed_argv: &'a [String],
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

impl std::os::unix::io::FromRawFd for Listener {
    /// Wrap an externally-obtained notification fd — e.g. one a parent received
    /// from its child via `pidfd_getfd` or `SCM_RIGHTS` in the child-installs
    /// model. The `Listener` takes ownership and closes it on drop.
    ///
    /// # Safety
    /// `fd` must be a valid, owned seccomp notification fd.
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Listener { fd }
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
    capture_committed: bool,
}

impl ExecSupervisor {
    /// Build a supervisor from a set of approved lowercase-hex sha256 digests.
    pub fn new(allow: HashSet<String>) -> Self {
        ExecSupervisor {
            allow,
            capture_committed: false,
        }
    }

    /// Enable reading the **committed** argv (sound, post-CONTINUE) on allowed
    /// execs, for audit/diagnostics. Off by default because it costs a bounded
    /// `/proc/<pid>/cmdline` poll per allowed exec (see [`read_committed_argv`]).
    /// Builder-style: consumes and returns `self`.
    pub fn with_committed_argv(mut self, on: bool) -> Self {
        self.capture_committed = on;
        self
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

    /// Service exactly one notification: hash the target, decide, respond, then
    /// report via `on_event`. The caller should `poll_ready` first so this does
    /// not block. When committed-argv capture is enabled (see
    /// [`with_committed_argv`](Self::with_committed_argv)) an allowed exec also
    /// reads the committed argv after responding, so the reported event carries
    /// both the pre-commit and committed views; this adds a bounded poll on the
    /// allow path. Returns `Ok(())` when handled (including a benign "expired
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

        // execve(path, argv, ...) -> path=args[0], argv=args[1];
        // execveat(dirfd, path, argv, ...) -> path=args[1], argv=args[2].
        let is_execveat = i64::from(req.data.nr) == libc::SYS_execveat;
        let (path_addr, argv_addr) = if is_execveat {
            (req.data.args[1], req.data.args[2])
        } else {
            (req.data.args[0], req.data.args[1])
        };
        let path = read_path(req.pid, path_addr).unwrap_or_else(|e| format!("<unreadable: {e}>"));
        // Observation only: never feeds the decision (see read_argv).
        let argv = read_argv(req.pid, argv_addr);
        let digest = hash_target(req.pid, &path).ok();
        let decision = self.decide(digest.as_deref());

        // If the syscall is no longer pending, do not respond (or report).
        if !notif_id_valid(listener.fd, req.id) {
            return Ok(());
        }

        // The child is frozen in execve until we SEND, so /proc/<pid>/cmdline
        // still shows its pre-exec cmdline; snapshot it now (only when we will
        // read the committed argv) to detect the post-exec change below.
        let want_committed = self.capture_committed && matches!(decision, Decision::Allow);
        let pre_cmdline = if want_committed {
            read_cmdline(req.pid)
        } else {
            Vec::new()
        };

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

        // Post-CONTINUE: the exec was let through, so the kernel switches the mm
        // and populates the committed argv. Read it (sound, unlike `argv`) for
        // audit; gated because it costs a bounded poll. Reported via on_event
        // below so a record carries both the pre-commit and committed views.
        let committed = if want_committed {
            read_committed_argv(req.pid, &pre_cmdline)
        } else {
            Vec::new()
        };

        on_event(&ExecEvent {
            pid: req.pid,
            path: &path,
            argv: &argv,
            committed_argv: &committed,
            digest: digest.as_deref(),
            decision,
        });

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

/// Max argv entries captured for audit. Real coding-agent commands sit well
/// under this; anything longer is truncated in the record (observation only).
const MAX_ARGV: usize = 16;
/// Max bytes captured per argv entry.
const ARG_MAX_LEN: usize = 4096;
/// Size of a userspace pointer in the (same-arch, 64-bit) tracee's argv array.
const PTR_SIZE: usize = std::mem::size_of::<u64>();

/// Read up to [`MAX_ARGV`] NUL-terminated argv strings out of the stopped
/// child's memory. `argv_addr` points to a NUL-terminated array of string
/// pointers (the second arg to `execve`).
///
/// **Observation/audit only, by design.** This is best-effort: a multi-threaded
/// tracee can rewrite these strings between this read and the kernel's own copy
/// during the real `execve` (the documented seccomp-notify TOCTOU caveat —
/// blocking the calling thread does not freeze its siblings). So the captured
/// argv is recorded for the audit ledger but is *never* used for the allow/deny
/// decision, which rides on the content digest of the resolved binary (stable,
/// because the file is hashed through the frozen child's own mount root). Bounds
/// and read errors degrade gracefully to a shorter (possibly empty) vector.
fn read_argv(pid: u32, argv_addr: u64) -> Vec<String> {
    if argv_addr == 0 {
        return Vec::new();
    }
    let mem = match File::open(format!("/proc/{pid}/mem")) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    let mut strbuf = [0u8; ARG_MAX_LEN];
    for i in 0..MAX_ARGV {
        let slot = argv_addr.wrapping_add(i as u64 * PTR_SIZE as u64);
        let mut ptr_bytes = [0u8; PTR_SIZE];
        if !matches!(mem.read_at(&mut ptr_bytes, slot), Ok(n) if n == PTR_SIZE) {
            break;
        }
        let ptr = u64::from_ne_bytes(ptr_bytes);
        if ptr == 0 {
            break; // NULL terminator: end of argv.
        }
        let n = match mem.read_at(&mut strbuf, ptr) {
            Ok(n) => n,
            Err(_) => break,
        };
        let end = strbuf[..n].iter().position(|&b| b == 0).unwrap_or(n);
        out.push(String::from_utf8_lossy(&strbuf[..end]).into_owned());
    }
    out
}

/// Poll attempts for the committed argv to appear after CONTINUE.
const COMMITTED_POLL_TRIES: u32 = 64;
/// Sleep between committed-argv polls (64 * 250us ~= 16ms total budget).
const COMMITTED_POLL_INTERVAL: Duration = Duration::from_micros(250);

/// Read a process's current cmdline (NUL-separated argv) from
/// `/proc/<pid>/cmdline`. Empty vec if unavailable (e.g. the process is gone).
/// Interior empty args are preserved; only the trailing terminator NUL is
/// dropped.
fn read_cmdline(pid: u32) -> Vec<String> {
    let raw = match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut parts: Vec<String> = raw
        .split(|&b| b == 0)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if parts.last().is_some_and(|s| s.is_empty()) {
        parts.pop();
    }
    parts
}

/// Read the **committed** argv after the supervisor has CONTINUEd the exec.
///
/// Unlike [`read_argv`] (which reads the pre-`execve` userspace copy and is thus
/// racy), this reads `/proc/<pid>/cmdline` — the argv the kernel installed in the
/// new mm, the immutable copy the new process will see. It is therefore *sound*
/// input for a decision, but only *after* the exec has been allowed to proceed,
/// so it supports detect-and-act (e.g. a later kill), never a pre-commit gate.
///
/// Handles the populate race: while the child is frozen in `execve`,
/// `/proc/<pid>/cmdline` still shows the *old* cmdline (`pre`). After CONTINUE the
/// kernel switches the mm; we poll until cmdline changes to a non-empty value
/// (the committed argv) or the budget expires. Returns an empty vec if it could
/// not be confirmed in budget — the process exited too fast, or it was a re-exec
/// with byte-identical argv (in which case the committed argv equals `pre`, so no
/// information is lost for a later policy check).
fn read_committed_argv(pid: u32, pre: &[String]) -> Vec<String> {
    for _ in 0..COMMITTED_POLL_TRIES {
        let cur = read_cmdline(pid);
        if !cur.is_empty() && cur.as_slice() != pre {
            return cur;
        }
        std::thread::sleep(COMMITTED_POLL_INTERVAL);
    }
    Vec::new()
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

const FD_SIZE: u32 = std::mem::size_of::<RawFd>() as u32;

/// Send one fd over a connected Unix socket via `SCM_RIGHTS` (with one carrier
/// data byte). This is how the **child** — which installs the notify filter so
/// the parent is never filtered — hands the listener fd up to the supervising
/// parent. `SCM_RIGHTS` needs no `CAP_SYS_PTRACE` and works in unprivileged
/// containers (unlike `pidfd_getfd`, which the default Docker seccomp blocks).
/// Proven on host and in unprivileged Docker in `examples/fd_transfer_probe.rs`.
pub fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
    let mut byte: u8 = b'F';
    let mut iov = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(byte).cast::<libc::c_void>(),
        iov_len: 1,
    };
    let mut cbuf = [0u64; 4]; // 32 bytes, 8-aligned, >= CMSG_SPACE(4)
                              // SAFETY: zeroed msghdr; we set the fields we use below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast::<libc::c_void>();
    // SAFETY: CMSG_SPACE is a pure size computation.
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(FD_SIZE) } as _;
    // SAFETY: fill the single SCM_RIGHTS control message, then send.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(std::ptr::addr_of!(msg));
        if cmsg.is_null() {
            return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(FD_SIZE) as _;
        std::ptr::copy_nonoverlapping(
            std::ptr::addr_of!(fd).cast::<u8>(),
            libc::CMSG_DATA(cmsg),
            FD_SIZE as usize,
        );
        if libc::sendmsg(sock, std::ptr::addr_of!(msg), 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receive one fd sent over a connected Unix socket via `SCM_RIGHTS`. The
/// supervising parent calls this to obtain the child's listener fd, then wraps
/// it with `Listener::from_raw_fd`.
pub fn recv_fd(sock: RawFd) -> io::Result<RawFd> {
    let mut byte: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(byte).cast::<libc::c_void>(),
        iov_len: 1,
    };
    let mut cbuf = [0u64; 4];
    // SAFETY: zeroed msghdr; we set the fields we use below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
    // SAFETY: receive one message, then read the single fd from its cmsg.
    unsafe {
        if libc::recvmsg(sock, std::ptr::addr_of_mut!(msg), 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        let cmsg = libc::CMSG_FIRSTHDR(std::ptr::addr_of!(msg));
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(io::Error::other("no SCM_RIGHTS control message received"));
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg).cast_const(),
            std::ptr::addr_of_mut!(fd).cast::<u8>(),
            FD_SIZE as usize,
        );
        Ok(fd)
    }
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
            ..Default::default()
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
            ..Default::default()
        };
        let s = ExecSupervisor::from_exec_policy(&policy);
        assert_eq!(s.decide(Some(d.hex())), Decision::Deny);
    }

    #[test]
    fn scm_rights_round_trips_an_fd() {
        // Fork-free: send a pipe's read end across a socketpair and prove the
        // received fd is a working dup by reading bytes written to the original
        // write end. Exercises the exact send_fd/recv_fd the cell will use.
        let mut sv: [RawFd; 2] = [0; 2];
        // SAFETY: socketpair into a length-2 array we own.
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair");
        let mut p: [RawFd; 2] = [0; 2];
        // SAFETY: pipe into a length-2 array we own.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0, "pipe");
        let (pr, pw) = (p[0], p[1]);

        send_fd(sv[1], pr).expect("send_fd");
        let got = recv_fd(sv[0]).expect("recv_fd");
        assert!(got >= 0);
        assert_ne!(got, pr, "received fd should be a fresh descriptor");

        let out = [0xABu8; 1];
        // SAFETY: write one byte to the pipe's write end.
        let wn = unsafe { libc::write(pw, out.as_ptr().cast::<libc::c_void>(), 1) };
        assert_eq!(wn, 1);
        let mut inb = [0u8; 1];
        // SAFETY: read one byte through the *received* fd.
        let rn = unsafe { libc::read(got, inb.as_mut_ptr().cast::<libc::c_void>(), 1) };
        assert_eq!(rn, 1);
        assert_eq!(inb[0], 0xAB, "received fd is a working dup of the pipe");

        // SAFETY: close every fd we own.
        unsafe {
            libc::close(sv[0]);
            libc::close(sv[1]);
            libc::close(pr);
            libc::close(pw);
            libc::close(got);
        }
    }
}

// crates/ql-enforce/src/cell.rs
//
//! The [`Cell`]: a constructed containment boundary that runs one command.
//!
//! A cell is assembled from a [`Profile`] and a set of [`Enforcer`]s via
//! [`Cell::builder`]. Running it forks a child, places that child in the
//! namespaces the enforcers requested, applies every enforcer's in-child
//! phase, and finally `exec`s the requested command inside the cage.
//!
//! ## Execution model
//!
//! ```text
//!  parent                          child (contained)
//!  ------                          -----------------
//!  fork ----------------------->   in fresh namespaces
//!  waitpid(child)                  apply each Enforcer::apply_in_child
//!     |                            (fail-closed: any Err => exit, no exec)
//!     |                            execvp(command)
//!  <- exit status
//! ```
//!
//! The parent only waits and reports status; all enforcement happens in the
//! child so that it takes effect before the agent's code runs and cannot
//! leak back to the host.

use crate::context::ChildContext;
use crate::enforcer::Enforcer;
use crate::error::{EnforceError, Result};
use crate::exec_supervisor::{recv_fd, send_fd, Decision, ExecEvent, ExecSupervisor, Listener};
use nix::sched::CloneFlags;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Gid, Pid, Uid};
use ql_profile::Profile;
use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

/// A privileged, parent-side setup step run against the contained child's
/// namespaces after they are created but before the child execs.
///
/// Some containment cannot be done from inside the child: connecting a `veth`
/// pair into the child's network namespace, for example, must be performed by
/// a privileged process in the host namespaces acting on the child by pid.
/// This is the same parent/child synchronization pattern container runtimes
/// use. The hook receives the child's [`Pid`]; returning `Err` aborts the run
/// (the child is signaled to refuse to exec — fail-closed).
pub type ParentHook = Box<dyn Fn(Pid) -> Result<()> + Send + Sync>;

/// A fully-specified containment cell, ready to run a command.
pub struct Cell {
    profile: Profile,
    enforcers: Vec<Box<dyn Enforcer>>,
    /// Optional privileged parent-side setup (see [`ParentHook`]). When `None`
    /// (the common case) the fork path uses no synchronization at all.
    parent_hook: Option<ParentHook>,
    /// When set, the Tier-2 seccomp user-notification exec wall is active: the
    /// child installs a notify filter and hands the listener up to the parent,
    /// which screens every `execve` by content digest. Off by default; the
    /// fork path is byte-for-byte unchanged when it is off.
    exec_supervision: bool,
}

impl Cell {
    /// Begin building a cell for the given profile. The profile is validated
    /// when [`CellBuilder::build`] is called.
    pub fn builder(profile: Profile) -> CellBuilder {
        CellBuilder {
            profile,
            enforcers: Vec::new(),
            parent_hook: None,
            exec_supervision: false,
        }
    }

    /// The union of namespaces required by all enforcers (phase 1).
    fn required_namespaces(&self) -> CloneFlags {
        self.enforcers.iter().fold(CloneFlags::empty(), |acc, e| {
            acc | e.required_namespaces(&self.profile)
        })
    }

    /// The cell's single shared cgroup leaf name, computed once **before**
    /// `fork` so the parent and the contained child agree on one identity. The
    /// child creates and joins it (see [`crate::enforcers::CgroupEnforcer`]);
    /// host-side walls that must act on the cell's cgroup reference the same
    /// name. Unique per launch (pid + nanosecond suffix).
    fn cell_cgroup_leaf_name() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("quantmlayer-cell-{}-{}", std::process::id(), nanos)
    }

    /// Run `command` (argv form; `command[0]` is the program) inside the cell.
    ///
    /// Returns the child's exit code on normal exit. The agent command is only
    /// ever executed if EVERY enforcer applied successfully (fail-closed).
    pub fn run(&self, command: &[String]) -> Result<i32> {
        if command.is_empty() {
            return Err(EnforceError::enforcer("cell", "empty command"));
        }

        // Capture host identity BEFORE we enter the user namespace, so the
        // namespace enforcer can map it correctly inside the child.
        let host_uid = Uid::current().as_raw();
        let host_gid = Gid::current().as_raw();

        let ns_flags = self.required_namespaces();

        // Decide the cell's cgroup identity BEFORE fork, so the parent and the
        // child agree on one name. A cgroup is needed when the profile sets a
        // resource limit OR when exec enforcement is on (the exec wall attaches
        // an lsm_cgroup program to this leaf). When neither holds, no cgroup is
        // created and the leaf is `None` — behavior is unchanged from before.
        let needs_cgroup = self.profile.resources.pids_max.is_some()
            || self.profile.resources.memory_max_bytes.is_some()
            || self.profile.exec.enforce;
        let cgroup_leaf: Option<String> = needs_cgroup.then(Self::cell_cgroup_leaf_name);

        // A sync channel is created ONLY when a parent hook is registered.
        // Without a hook this is `None` and the fork path below is identical to
        // the simple model — no pipes, no synchronization.
        let sync = match self.parent_hook {
            Some(_) => Some(SyncPipes::new()?),
            None => None,
        };

        // The exec wall's fd-passing channel, created only when supervision is
        // on. Independent of the veth `sync` pipes above.
        let exec_chan = if self.exec_supervision {
            Some(ExecChannel::new()?)
        } else {
            None
        };

        // SAFETY: fork in a program that does minimal work in the child before
        // exec. We perform only async-signal-safe-enough operations (namespace
        // setup via /proc writes and mount syscalls) and then execvp. We do not
        // run arbitrary Rust destructors of shared state across the boundary.
        match unsafe { fork() }.map_err(|e| EnforceError::Process {
            op: "fork",
            source: e,
        })? {
            ForkResult::Parent { child } => {
                // If there is a parent hook, run the synchronized handshake:
                // wait for the child to create its namespaces, perform the
                // privileged setup against the child by pid, then release it.
                if let (Some(hook), Some(sync)) = (self.parent_hook.as_ref(), sync.as_ref()) {
                    sync.parent_close_child_ends();
                    sync.parent_wait_ready()?;
                    match hook(child) {
                        Ok(()) => sync.parent_signal_go(),
                        Err(e) => {
                            // Abort: closing the "go" pipe without writing makes
                            // the child see EOF and refuse to exec. Reap it.
                            sync.parent_signal_abort();
                            let _ = waitpid(child, None);
                            return Err(e);
                        }
                    }
                }

                // Tier-2 exec wall: receive the child's notify listener (sent
                // via SCM_RIGHTS), then supervise its execs in place of the
                // plain blocking wait below. The parent is never filtered.
                if let Some(chan) = exec_chan.as_ref() {
                    chan.parent_close_child_end();
                    let lfd = match chan.parent_recv_listener() {
                        Ok(fd) => fd,
                        Err(e) => {
                            chan.parent_signal_abort();
                            let _ = waitpid(child, None);
                            return Err(e);
                        }
                    };
                    // SAFETY: `lfd` is the child's seccomp notify listener,
                    // transferred to us via SCM_RIGHTS; we now own it.
                    let listener = unsafe { Listener::from_raw_fd(lfd) };
                    let supervisor = ExecSupervisor::from_profile(&self.profile);
                    chan.parent_signal_go();
                    chan.parent_close();
                    return self.supervise(child, &listener, &supervisor);
                }

                // Parent: wait for the contained child and translate its status.
                match waitpid(child, None).map_err(|e| EnforceError::Process {
                    op: "wait",
                    source: e,
                })? {
                    WaitStatus::Exited(_, code) => Ok(code),
                    WaitStatus::Signaled(_, sig, _) => {
                        // Convention: 128 + signal number, matching shells.
                        Ok(128 + sig as i32)
                    }
                    other => Err(EnforceError::enforcer(
                        "cell",
                        format!("unexpected child wait status: {other:?}"),
                    )),
                }
            }
            ForkResult::Child => {
                // Child: build the cage, then exec. Any failure here must NOT
                // result in running the command, so we exit non-zero instead.
                let exit_code = match self.run_child(
                    ns_flags,
                    host_uid,
                    host_gid,
                    command,
                    sync.as_ref(),
                    exec_chan.as_ref(),
                    cgroup_leaf.as_deref(),
                ) {
                    Ok(()) => unreachable!("run_child only returns on error; success execs"),
                    Err(e) => {
                        // The cage could not be built. Fail closed: do not
                        // exec. Always say which wall failed and why — a
                        // silent refusal is impossible to operate. Exit 126
                        // = "command found but not executed", here meaning
                        // "refused to run uncontained".
                        eprintln!("ql-enforce: refusing to run agent uncontained: {e}");
                        126
                    }
                };
                // We must not return into the parent's call stack from the child.
                std::process::exit(exit_code);
            }
        }
    }

    /// Child-side routine: enter namespaces, apply enforcers, exec command.
    /// On success this never returns (it execs). On failure it returns Err and
    /// the caller fails closed.
    // A fork-helper coordinating namespaces, host ids, both handshake channels,
    // and the cgroup leaf — the params belong together; bundling buys nothing.
    #[allow(clippy::too_many_arguments)]
    fn run_child(
        &self,
        ns_flags: CloneFlags,
        host_uid: u32,
        host_gid: u32,
        command: &[String],
        sync: Option<&SyncPipes>,
        exec_chan: Option<&ExecChannel>,
        cgroup_leaf: Option<&str>,
    ) -> Result<()> {
        // Close the parent's ends of the sync pipes in this process up front.
        if let Some(sync) = sync {
            sync.child_close_parent_ends();
        }

        let mut ctx = ChildContext::new(host_uid, host_gid);
        if let Some(leaf) = cgroup_leaf {
            ctx = ctx.with_cgroup_leaf(leaf.to_string());
        }

        // --- Phase 2a: pre-userns, while still REAL ROOT ---
        // Operations on host-owned resources (cgroups) must happen here,
        // before we drop into a child user namespace. An `Unsupported` result
        // means the host can't provide that wall; we record and continue
        // rather than refuse to run. Any other error fails closed.
        for enforcer in &self.enforcers {
            match enforcer.apply_pre_userns(&self.profile, &ctx) {
                Ok(()) => {}
                Err(EnforceError::Unsupported { feature, reason }) => {
                    // The host lacks this wall (e.g. a cgroup controller).
                    // Surface it on stderr for the operator; do not abort.
                    eprintln!("ql-enforce: wall `{feature}` unavailable on this host: {reason}");
                }
                Err(e) => {
                    return Err(EnforceError::enforcer(
                        "cell",
                        format!("pre-userns wall `{}` failed: {e}", enforcer.name()),
                    ));
                }
            }
        }

        // --- Enter the requested namespaces (cell core) ---
        // `unshare` here (rather than clone flags) keeps the fork path simple
        // and is equivalent for our single-child model. Skip the call entirely
        // when no namespace is required: an unconditional `unshare(0)` is a
        // harmless no-op on a bare host, but container seccomp profiles (e.g.
        // Docker's default) deny the `unshare` syscall outright with EPERM
        // regardless of flags, which would needlessly fail a no-namespace cell.
        if !ns_flags.is_empty() {
            nix::sched::unshare(ns_flags).map_err(|e| EnforceError::syscall("unshare", e))?;
        }

        // --- Synchronize with the parent hook, if any ---
        // The namespaces now exist. Tell the parent it may perform privileged
        // setup against them (e.g. wire a veth into our netns), and block until
        // it confirms. If the parent aborts, we refuse to exec (fail-closed).
        if let Some(sync) = sync {
            sync.child_signal_ready();
            sync.child_wait_go()?;
        }

        // --- Tier-2 exec wall: install the notify filter, hand it to parent ---
        // Installed HERE — before the in-namespace enforcers (and thus before
        // the static seccomp filter) — so that filter's own `seccomp()`/`prctl`
        // calls are permitted: the notify filter traps only `execve`, allowing
        // everything else. The CHILD installs it so the parent stays unfiltered.
        // The listener fd goes to the parent via SCM_RIGHTS; we then wait for
        // the parent to confirm it is supervising before proceeding to exec.
        if let Some(chan) = exec_chan {
            chan.child_close_parent_end();
            let listener = ExecSupervisor::new(HashSet::new()).install().map_err(|e| {
                EnforceError::enforcer("cell", format!("exec wall: notify filter install: {e}"))
            })?;
            chan.child_send_listener(listener.as_raw_fd())?;
            chan.child_wait_go()?;
            // `listener` drops here, closing the child's copy of the fd. The
            // parent holds the surviving reference and the in-kernel filter
            // persists regardless; the agent's `execve` is delivered to it.
        }

        // --- Phase 2b: in-namespace, as root-in-userns ---
        // namespace enforcer writes the uid/gid maps; mount enforcer hides
        // denied paths. Order is preserved from the builder. These walls fail
        // closed: any error aborts before exec.
        for enforcer in &self.enforcers {
            enforcer
                .apply_in_namespace(&self.profile, &ctx)
                .map_err(|e| {
                    EnforceError::enforcer(
                        "cell",
                        format!("wall `{}` failed: {e}", enforcer.name()),
                    )
                })?;
        }

        // All walls up: exec the agent command, replacing this process.
        let prog = CString::new(command[0].as_str())
            .map_err(|_| EnforceError::enforcer("cell", "command contained NUL byte"))?;
        let argv: Vec<CString> = command
            .iter()
            .map(|a| CString::new(a.as_str()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| EnforceError::enforcer("cell", "argument contained NUL byte"))?;

        execvp(&prog, &argv).map_err(|e| EnforceError::Process {
            op: "exec",
            source: e,
        })?;
        unreachable!("execvp returns only on error, which is handled above");
    }

    /// Tier-2 supervise loop: drive the seccomp notify `listener` while waiting
    /// for the contained `child`, allowing/denying each `execve` by content
    /// digest. Replaces the plain blocking `waitpid` when exec supervision is
    /// on. Single-threaded (no extra threads): poll the listener with a short
    /// timeout, service any pending notification, reap the child when it exits.
    /// This is the loop proven in `examples/fd_transfer_probe.rs`.
    fn supervise(
        &self,
        child: Pid,
        listener: &Listener,
        supervisor: &ExecSupervisor,
    ) -> Result<i32> {
        let mut exit: Option<i32> = None;
        loop {
            if exit.is_none() {
                match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) => {}
                    Ok(WaitStatus::Exited(_, code)) => exit = Some(code),
                    Ok(WaitStatus::Signaled(_, sig, _)) => exit = Some(128 + sig as i32),
                    Ok(_) => {}
                    Err(e) => {
                        return Err(EnforceError::Process {
                            op: "wait",
                            source: e,
                        });
                    }
                }
            }
            let ready = listener.poll_ready(200).unwrap_or(false);
            if ready {
                // A serve error after the child is gone is benign (the listener
                // drains); audit records are layered on in a later slice.
                let _ = supervisor.serve_one(listener, &mut |e: &ExecEvent| {
                    record_tier2_exec(e);
                    if matches!(e.decision, Decision::Deny) {
                        eprintln!("ql-enforce[exec]: denied exec of {}", e.path);
                    }
                });
            } else if let Some(code) = exit {
                return Ok(code);
            }
        }
    }
}

/// The exec wall's fd-passing channel: a `SOCK_CLOEXEC` Unix socketpair over
/// which the contained child sends its notify listener fd up to the parent
/// (via `SCM_RIGHTS`) and the parent sends a one-byte "go" back. Created only
/// when [`CellBuilder::with_exec_supervision`] is set. `SOCK_CLOEXEC` ensures
/// the agent never inherits the socket across its own `exec`.
struct ExecChannel {
    parent_sock: RawFd,
    child_sock: RawFd,
}

impl ExecChannel {
    fn new() -> Result<Self> {
        let mut sv: [RawFd; 2] = [0; 2];
        let kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
        // SAFETY: socketpair writes exactly two fds into a length-2 array.
        if unsafe { libc::socketpair(libc::AF_UNIX, kind, 0, sv.as_mut_ptr()) } != 0 {
            return Err(EnforceError::syscall(
                "socketpair",
                nix::errno::Errno::last(),
            ));
        }
        Ok(ExecChannel {
            parent_sock: sv[0],
            child_sock: sv[1],
        })
    }

    // --- parent side ---
    fn parent_close_child_end(&self) {
        // SAFETY: closing our copy of the fd the child owns.
        unsafe { libc::close(self.child_sock) };
    }
    fn parent_recv_listener(&self) -> Result<RawFd> {
        recv_fd(self.parent_sock).map_err(|e| {
            EnforceError::enforcer("cell", format!("exec wall: receiving listener fd: {e}"))
        })
    }
    fn parent_signal_go(&self) {
        let b = [1u8];
        // SAFETY: write one byte from a length-1 buffer.
        unsafe { libc::write(self.parent_sock, b.as_ptr() as *const libc::c_void, 1) };
    }
    fn parent_signal_abort(&self) {
        // SAFETY: closing without writing makes the child's read return EOF.
        unsafe { libc::close(self.parent_sock) };
    }
    fn parent_close(&self) {
        // SAFETY: the parent is done with the socket; supervision uses the
        // listener fd, not this socket.
        unsafe { libc::close(self.parent_sock) };
    }

    // --- child side ---
    fn child_close_parent_end(&self) {
        // SAFETY: closing our copy of the fd the parent owns.
        unsafe { libc::close(self.parent_sock) };
    }
    fn child_send_listener(&self, fd: RawFd) -> Result<()> {
        send_fd(self.child_sock, fd).map_err(|e| {
            EnforceError::enforcer("cell", format!("exec wall: sending listener fd: {e}"))
        })
    }
    fn child_wait_go(&self) -> Result<()> {
        let mut b = [0u8; 1];
        // SAFETY: read one byte into a length-1 buffer.
        let n = unsafe { libc::read(self.child_sock, b.as_mut_ptr() as *mut libc::c_void, 1) };
        if n == 1 {
            Ok(())
        } else {
            Err(EnforceError::enforcer(
                "cell",
                "exec wall: parent did not confirm supervision; refusing to exec",
            ))
        }
    }
}

/// Builder for a [`Cell`]. Enforcers are applied in the order they are added,
/// which is significant (see [`Cell::run_child`]).
pub struct CellBuilder {
    profile: Profile,
    enforcers: Vec<Box<dyn Enforcer>>,
    parent_hook: Option<ParentHook>,
    exec_supervision: bool,
}

impl CellBuilder {
    /// Add an enforcer (a containment wall). Order matters: add foundational
    /// enforcers (namespaces) before those that depend on them (mounts).
    pub fn with_enforcer(mut self, enforcer: Box<dyn Enforcer>) -> Self {
        self.enforcers.push(enforcer);
        self
    }

    /// Register a privileged parent-side setup step (see [`ParentHook`]). Used
    /// for containment that must be performed from the host namespaces against
    /// the child by pid — e.g. wiring a `veth` into the child's network
    /// namespace. Registering a hook enables the parent/child sync handshake.
    pub fn with_parent_hook(mut self, hook: ParentHook) -> Self {
        self.parent_hook = Some(hook);
        self
    }

    /// Enable the **Tier-2 seccomp user-notification exec wall**. The child
    /// installs the notify filter (keeping the parent unfiltered, so a veth
    /// hook's `ip` execs are unaffected) and transfers the listener fd to the
    /// parent over `SCM_RIGHTS`; the parent screens every `execve` by content
    /// digest, allowing approved binaries (`CONTINUE`) and denying others
    /// (`EACCES`). The allowlist is sourced from the profile's signed
    /// `exec.allow_digests`.
    ///
    /// Invariant: the static seccomp wall (if any) must permit `execve`, or the
    /// notify never fires and the agent simply cannot exec (a loud, fail-closed
    /// failure). Default-allow coding profiles satisfy this.
    pub fn with_exec_supervision(mut self) -> Self {
        self.exec_supervision = true;
        self
    }

    /// Validate the profile and finalize the cell.
    pub fn build(self) -> Result<Cell> {
        // Fail-closed at the boundary: an invalid profile never becomes a cell.
        self.profile.validate()?;
        Ok(Cell {
            profile: self.profile,
            enforcers: self.enforcers,
            parent_hook: self.parent_hook,
            exec_supervision: self.exec_supervision,
        })
    }
}

/// A pair of pipes used to synchronize the parent and the contained child
/// around the [`ParentHook`]. `ready` carries child→parent ("namespaces are
/// up"); `go` carries parent→child ("setup done, you may proceed"). Closing
/// `go` without writing signals an abort, which the child observes as EOF.
struct SyncPipes {
    ready_r: RawFd,
    ready_w: RawFd,
    go_r: RawFd,
    go_w: RawFd,
}

impl SyncPipes {
    fn new() -> Result<Self> {
        let mut ready = [0 as RawFd; 2];
        let mut go = [0 as RawFd; 2];
        // SAFETY: each call writes exactly two fds into a length-2 array.
        if unsafe { libc::pipe(ready.as_mut_ptr()) } != 0 {
            return Err(EnforceError::syscall("pipe", nix::errno::Errno::last()));
        }
        if unsafe { libc::pipe(go.as_mut_ptr()) } != 0 {
            return Err(EnforceError::syscall("pipe", nix::errno::Errno::last()));
        }
        Ok(SyncPipes {
            ready_r: ready[0],
            ready_w: ready[1],
            go_r: go[0],
            go_w: go[1],
        })
    }

    // --- parent side ---
    fn parent_close_child_ends(&self) {
        // SAFETY: closing our copies of the fds the child owns.
        unsafe {
            libc::close(self.ready_w);
            libc::close(self.go_r);
        }
    }
    fn parent_wait_ready(&self) -> Result<()> {
        let mut b = [0u8; 1];
        // SAFETY: read one byte into a length-1 buffer.
        let n = unsafe { libc::read(self.ready_r, b.as_mut_ptr() as *mut libc::c_void, 1) };
        unsafe { libc::close(self.ready_r) };
        if n == 1 {
            Ok(())
        } else {
            Err(EnforceError::enforcer(
                "cell",
                "child exited before its namespaces were ready",
            ))
        }
    }
    fn parent_signal_go(&self) {
        let b = [1u8];
        // SAFETY: write one byte from a length-1 buffer, then close.
        unsafe {
            libc::write(self.go_w, b.as_ptr() as *const libc::c_void, 1);
            libc::close(self.go_w);
        }
    }
    fn parent_signal_abort(&self) {
        // SAFETY: closing without writing makes the child's read return EOF.
        unsafe { libc::close(self.go_w) };
    }

    // --- child side ---
    fn child_close_parent_ends(&self) {
        // SAFETY: closing our copies of the fds the parent owns. Closing our
        // copy of `go_w` is essential so an abort is observable as EOF.
        unsafe {
            libc::close(self.ready_r);
            libc::close(self.go_w);
        }
    }
    fn child_signal_ready(&self) {
        let b = [1u8];
        // SAFETY: write one byte, then close our write end.
        unsafe {
            libc::write(self.ready_w, b.as_ptr() as *const libc::c_void, 1);
            libc::close(self.ready_w);
        }
    }
    fn child_wait_go(&self) -> Result<()> {
        let mut b = [0u8; 1];
        // SAFETY: read one byte into a length-1 buffer.
        let n = unsafe { libc::read(self.go_r, b.as_mut_ptr() as *mut libc::c_void, 1) };
        unsafe { libc::close(self.go_r) };
        if n == 1 {
            Ok(())
        } else {
            Err(EnforceError::enforcer(
                "cell",
                "parent setup failed; refusing to exec",
            ))
        }
    }
}

// --- Tier-2 exec-wall audit capture ------------------------------------------
//
// The supervise loop records one owned decision per screened `execve` into a
// thread-local buffer; the caller (`ql run`) drains it after the run and
// converts each into an attributed audit record (`exec.run`/`exec.deny`),
// tagging the tier. This mirrors the Tier-1 BPF path (`drain_exec_events`),
// keeping ql-enforce decoupled from ql-audit. Single cell per `ql run` process,
// and the supervise loop runs in the caller's thread, so a thread-local needs
// no `Send`/locking.

/// An owned record of one exec decision made by the Tier-2 (seccomp user-
/// notification) exec wall, captured for the audit layer. Mirrors the Tier-1
/// kernel `ExecRecord` shape closely enough for a parallel audit conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier2ExecRecord {
    /// Milliseconds since the Unix epoch (UTC) when the decision was made.
    pub ts_millis: u64,
    /// Whether the exec was allowed (`true`) or denied (`false`).
    pub allowed: bool,
    /// sha256 hex of the resolved binary, or `None` if it could not be hashed.
    pub digest_hex: Option<String>,
    /// Pid of the execing process, in the supervisor's pid namespace.
    pub pid: u32,
    /// The path the child passed to `execve`.
    pub path: String,
    /// The argv the child passed to `execve` (bounded, observation only — never
    /// used for the verdict; see [`crate::exec_supervisor::ExecEvent::argv`]).
    pub argv: Vec<String>,
}

thread_local! {
    /// Decisions recorded by the Tier-2 exec wall for the current run, oldest
    /// first. Filled by the supervise loop; emptied by [`drain_tier2_exec_events`].
    static TIER2_EXEC_EVENTS: RefCell<Vec<Tier2ExecRecord>> = const { RefCell::new(Vec::new()) };
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Record one supervised exec decision into the thread-local buffer. Converts
/// the borrowed [`ExecEvent`] into an owned [`Tier2ExecRecord`].
fn record_tier2_exec(e: &ExecEvent) {
    let rec = Tier2ExecRecord {
        ts_millis: now_millis(),
        allowed: matches!(e.decision, Decision::Allow),
        digest_hex: e.digest.map(|d| d.to_string()),
        pid: e.pid,
        path: e.path.to_string(),
        argv: e.argv.to_vec(),
    };
    TIER2_EXEC_EVENTS.with(|b| b.borrow_mut().push(rec));
}

/// Drain the Tier-2 exec wall's recorded decisions for the run that just
/// finished (oldest first), emptying the buffer. One record per `execve` the
/// wall screened. The caller converts these to audit records, tagging tier=2.
/// Empty when no Tier-2 wall was active.
pub fn drain_tier2_exec_events() -> Vec<Tier2ExecRecord> {
    TIER2_EXEC_EVENTS.with(|b| std::mem::take(&mut *b.borrow_mut()))
}

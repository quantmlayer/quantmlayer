// crates/ql-enforce/src/lib.rs
//
//! # ql-enforce
//!
//! The enforcement engine for QuantmLayer. It turns a portable
//! [`ql_profile::Profile`] into a real, kernel-enforced containment **cell**
//! and runs a command inside it.
//!
//! This crate is Linux-specific by nature (it uses namespaces, mounts, and —
//! in later steps — seccomp, capabilities, and cgroups). The portable policy
//! model lives in `ql-profile`; the platform-specific *how* lives here. That
//! split is deliberate: it keeps the policy layer portable and signable while
//! letting enforcement evolve per platform.
//!
//! ## Quick start
//!
//! ```no_run
//! use ql_profile::Profile;
//! use ql_enforce::standard_coding_cell;
//!
//! let profile = Profile::from_yaml(include_str!("../../../profiles/coding.yaml"))?;
//! let cell = standard_coding_cell(profile)?;
//! let code = cell.run(&["/bin/sh".into(), "-c".into(), "echo hello".into()])?;
//! assert_eq!(code, 0);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Extending
//!
//! Each containment wall is an [`Enforcer`]. Add a new wall by implementing
//! the trait in [`enforcers`] and adding it to the cell builder. Existing
//! walls are never modified.

#![deny(missing_docs)]

// This crate genuinely cannot function off Linux. Fail the build loudly rather
// than silently producing a binary that does not contain anything.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "ql-enforce requires Linux (namespaces, mounts, seccomp). \
                The portable policy model is in `ql-profile`, which is cross-platform."
);

mod cell;
pub mod cgroups;
mod context;
mod enforcer;
pub mod enforcers;
mod error;
pub mod exec_supervisor;
pub mod veth;

pub use cell::{drain_tier2_exec_events, Cell, CellBuilder, Tier2ExecRecord};
pub use context::ChildContext;
pub use enforcer::Enforcer;
pub use error::{EnforceError, Result};
pub use exec_supervisor::{Decision, ExecEvent, ExecSupervisor, Listener};

use enforcers::{
    CgroupEnforcer, MountEnforcer, NamespaceEnforcer, NetworkEnforcer, SeccompEnforcer,
};
use ql_profile::Profile;

/// Build the standard containment cell for a coding agent with the walls
/// implemented so far (cgroup limits + namespaces + filesystem hiding +
/// network isolation + syscall filtering).
///
/// This is a convenience over [`Cell::builder`] that wires the current default
/// set of enforcers in the correct order. As new walls land (capabilities,
/// the allow-list broker), they are added here so callers automatically get
/// the strongest available containment.
///
/// Enforcer order is significant:
/// * [`CgroupEnforcer`] runs in the pre-userns phase (real root), so it must
///   be present to set limits before the process enters the user namespace.
/// * [`NamespaceEnforcer`] must precede [`MountEnforcer`] because the mount
///   step requires the user-namespace uid mapping the namespace step installs.
/// * [`NetworkEnforcer`] brings up loopback inside the new netns; it runs
///   before seccomp so its `ioctl` is not filtered.
/// * [`SeccompEnforcer`] must come **last**: it installs a syscall filter that
///   denies `mount`/`unshare`/etc., so it must run after those setup steps or
///   it would block the cell's own construction.
pub fn standard_coding_cell(profile: Profile) -> Result<Cell> {
    // Fail closed: a profile that requests exec enforcement requires this crate
    // to be built with the `lsm` feature (see `ensure_exec_supported`).
    ensure_exec_supported(&profile)?;
    let builder = Cell::builder(profile.clone())
        .with_enforcer(Box::new(CgroupEnforcer::new()))
        .with_enforcer(Box::new(NamespaceEnforcer::new()))
        .with_enforcer(Box::new(MountEnforcer::new()))
        .with_enforcer(Box::new(NetworkEnforcer::new()))
        .with_enforcer(Box::new(SeccompEnforcer::new()));
    // When exec enforcement is enabled (and `lsm` is built in), this adds a
    // host-side hook that attaches the content-addressed exec wall to the
    // cell's cgroup in the same sync window the veth hook uses; otherwise it is
    // a no-op and the cell keeps its no-hook fast path.
    with_exec_wall(builder, &profile).build()
}

/// Build a coding-agent cell with **brokered** network egress.
///
/// Identical to [`standard_coding_cell`] except the network is wired to an
/// egress broker: the cell's parent hook connects a `veth` pair into the new
/// network namespace (per `plan`), the agent's only route is to the broker,
/// and its `HTTPS_PROXY` is pointed at `proxy_url`. The caller is responsible
/// for running the broker at `proxy_url` and for tearing the veth down (see
/// [`veth::teardown`]) after the cell exits.
pub fn brokered_coding_cell(
    profile: Profile,
    plan: veth::VethPlan,
    proxy_url: String,
) -> Result<Cell> {
    ensure_exec_supported(&profile)?;
    Cell::builder(profile.clone())
        .with_enforcer(Box::new(CgroupEnforcer::new()))
        .with_enforcer(Box::new(NamespaceEnforcer::new()))
        .with_enforcer(Box::new(MountEnforcer::new()))
        .with_enforcer(Box::new(NetworkEnforcer::with_proxy(proxy_url)))
        .with_enforcer(Box::new(SeccompEnforcer::new()))
        .with_parent_hook(brokered_parent_hook(plan, &profile))
        .build()
}

/// Build a coding-agent cell with the **Tier-2** seccomp user-notification exec
/// wall instead of the Tier-1 BPF-LSM wall. Same containment walls as
/// [`standard_coding_cell`], but exec enforcement runs in userspace in the
/// supervising parent — no `lsm` build feature and no kernel BPF-LSM/IMA
/// required. `ql run` selects this when Tier 1 is unavailable.
pub fn coding_cell_with_exec_supervision(profile: Profile) -> Result<Cell> {
    Cell::builder(profile)
        .with_enforcer(Box::new(CgroupEnforcer::new()))
        .with_enforcer(Box::new(NamespaceEnforcer::new()))
        .with_enforcer(Box::new(MountEnforcer::new()))
        .with_enforcer(Box::new(NetworkEnforcer::new()))
        .with_enforcer(Box::new(SeccompEnforcer::new()))
        .with_exec_supervision()
        .build()
}

/// Brokered counterpart of [`coding_cell_with_exec_supervision`]: containment
/// plus allow-listed egress through the broker, with the Tier-2 exec wall. The
/// parent hook only wires the veth — the exec wall is the userspace supervisor
/// in the (unfiltered) parent, so the hook's own `ip` execs are unaffected.
pub fn brokered_coding_cell_with_exec_supervision(
    profile: Profile,
    plan: veth::VethPlan,
    proxy_url: String,
) -> Result<Cell> {
    Cell::builder(profile)
        .with_enforcer(Box::new(CgroupEnforcer::new()))
        .with_enforcer(Box::new(NamespaceEnforcer::new()))
        .with_enforcer(Box::new(MountEnforcer::new()))
        .with_enforcer(Box::new(NetworkEnforcer::with_proxy(proxy_url)))
        .with_enforcer(Box::new(SeccompEnforcer::new()))
        .with_parent_hook(Box::new(move |pid| veth::wire(pid, &plan)))
        .with_exec_supervision()
        .build()
}

// --- exec-enforcement integration (feature `lsm`) -------------------------
//
// The content-addressed exec wall is attached host-side, in the parent hook,
// after the child has joined its cgroup (the pre-userns phase) and signaled
// ready but before it execs the agent — so the agent's first exec is already
// gated. Because the hook's `Err` path is fail-closed (the child sees EOF on
// the go-pipe and refuses to exec), a failed attach refuses the run rather
// than letting the agent escape the wall.

/// Fail-closed guard tying the runtime policy (`exec.enforce`) to the build.
/// With `lsm` on, exec enforcement is available, so this is a no-op. With it
/// off, a profile that asks for the wall is refused rather than silently run
/// without it.
#[cfg(feature = "lsm")]
fn ensure_exec_supported(_profile: &Profile) -> Result<()> {
    Ok(())
}

#[cfg(not(feature = "lsm"))]
fn ensure_exec_supported(profile: &Profile) -> Result<()> {
    if profile.exec.enforce {
        return Err(EnforceError::Unsupported {
            feature: "exec",
            reason: "exec enforcement requested but the `lsm` feature is not built in".into(),
        });
    }
    Ok(())
}

/// Add the standalone exec-enforcement hook to a builder when the profile
/// enables it. No-op when `lsm` is off (a requested wall is already rejected by
/// `ensure_exec_supported`, so reaching here with `enforce` set is impossible).
#[cfg(feature = "lsm")]
fn with_exec_wall(builder: CellBuilder, profile: &Profile) -> CellBuilder {
    if !profile.exec.enforce {
        return builder;
    }
    let prof = profile.clone();
    builder.with_parent_hook(Box::new(move |pid| attach_exec_wall(pid, &prof)))
}

#[cfg(not(feature = "lsm"))]
fn with_exec_wall(builder: CellBuilder, _profile: &Profile) -> CellBuilder {
    builder
}

/// Build the brokered cell's single parent hook. It always wires the veth pair;
/// when exec enforcement is enabled (and `lsm` is built in) it also attaches the
/// exec wall in the same host-side step. The fail-closed wrapper in `Cell::run`
/// covers both — if either returns `Err`, the child refuses to exec.
#[cfg(feature = "lsm")]
fn brokered_parent_hook(plan: veth::VethPlan, profile: &Profile) -> cell::ParentHook {
    if profile.exec.enforce {
        let prof = profile.clone();
        Box::new(move |pid| {
            veth::wire(pid, &plan)?;
            attach_exec_wall(pid, &prof)
        })
    } else {
        Box::new(move |pid| veth::wire(pid, &plan))
    }
}

#[cfg(not(feature = "lsm"))]
fn brokered_parent_hook(plan: veth::VethPlan, _profile: &Profile) -> cell::ParentHook {
    Box::new(move |pid| veth::wire(pid, &plan))
}

/// Attach the content-addressed exec wall to the cell's cgroup, then keep the
/// BPF link alive for the cell's lifetime by leaking it (unpinned).
#[cfg(feature = "lsm")]
fn attach_exec_wall(pid: nix::unistd::Pid, profile: &Profile) -> Result<()> {
    use std::os::fd::AsRawFd;

    let dir = cell_cgroup_dir_for_pid(pid.as_raw())?;
    let cgroup = std::fs::File::open(&dir).map_err(|e| {
        EnforceError::enforcer(
            "exec",
            format!("opening cell cgroup {}: {e}", dir.display()),
        )
    })?;
    let enforcer = ql_lsm::ExecEnforcer::attach(profile, cgroup.as_raw_fd())
        .map_err(|e| EnforceError::enforcer("exec", format!("attaching exec wall: {e}")))?;

    // Stash the live enforcer in this (parent) thread so `drain_exec_events`
    // can read the kernel's exec audit stream after the run, while the BPF link
    // stays alive for the cell's lifetime. The unpinned link auto-detaches when
    // the enforcer is dropped (at drain time, or at process exit). The parent
    // hook runs in the same thread as the caller of `Cell::run`, so a
    // thread-local needs no `Send` handling.
    EXEC_ENFORCER.with(|slot| {
        *slot.borrow_mut() = Some(enforcer);
    });
    Ok(())
}

#[cfg(feature = "lsm")]
thread_local! {
    /// The live exec enforcer for the current run (one cell per `ql run`
    /// process). Set by [`attach_exec_wall`]; the wall stays attached while this
    /// is `Some`. Drained and dropped by [`drain_exec_events`] after the run.
    static EXEC_ENFORCER: std::cell::RefCell<Option<ql_lsm::ExecEnforcer>> =
        std::cell::RefCell::new(None);
}

/// Drain the kernel's per-execve audit stream for the run that just finished,
/// returning one record per exec decision (oldest first). Takes and drops the
/// enforcer, detaching the wall — the run is over. Empty if no wall was active.
#[cfg(feature = "lsm")]
pub fn drain_exec_events() -> Vec<ql_lsm::ExecRecord> {
    EXEC_ENFORCER.with(|slot| {
        let enforcer = slot.borrow_mut().take();
        match enforcer {
            Some(e) => e.drain_events().unwrap_or_default(),
            None => Vec::new(),
        }
    })
}

/// Resolve the cell's cgroup-v2 directory from a pid via the unified (`0::`)
/// entry of `/proc/<pid>/cgroup`. Read by the parent in the host cgroup
/// namespace, so the path is absolute from the v2 root. Exec enforcement is a
/// cgroup-v2 mechanism (`lsm_cgroup`); a v1-only host is reported Unsupported.
#[cfg(feature = "lsm")]
fn cell_cgroup_dir_for_pid(pid: i32) -> Result<std::path::PathBuf> {
    let root = match cgroups::CgroupBackend::detect()? {
        cgroups::CgroupBackend::V2 { root } => root,
        cgroups::CgroupBackend::V1 { .. } => {
            return Err(EnforceError::Unsupported {
                feature: "exec",
                reason: "exec enforcement requires cgroup v2 (lsm_cgroup)".into(),
            })
        }
    };
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|e| EnforceError::enforcer("exec", format!("reading /proc/{pid}/cgroup: {e}")))?;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            return Ok(root.join(rest.trim_start_matches('/')));
        }
    }
    Err(EnforceError::enforcer(
        "exec",
        "no cgroup v2 entry in /proc/<pid>/cgroup for the cell",
    ))
}

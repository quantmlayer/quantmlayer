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
pub mod veth;

pub use cell::{Cell, CellBuilder};
pub use context::ChildContext;
pub use enforcer::Enforcer;
pub use error::{EnforceError, Result};

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
    Cell::builder(profile)
        .with_enforcer(Box::new(CgroupEnforcer::new()))
        .with_enforcer(Box::new(NamespaceEnforcer::new()))
        .with_enforcer(Box::new(MountEnforcer::new()))
        .with_enforcer(Box::new(NetworkEnforcer::new()))
        .with_enforcer(Box::new(SeccompEnforcer::new()))
        .build()
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
    Cell::builder(profile)
        .with_enforcer(Box::new(CgroupEnforcer::new()))
        .with_enforcer(Box::new(NamespaceEnforcer::new()))
        .with_enforcer(Box::new(MountEnforcer::new()))
        .with_enforcer(Box::new(NetworkEnforcer::with_proxy(proxy_url)))
        .with_enforcer(Box::new(SeccompEnforcer::new()))
        .with_parent_hook(Box::new(move |pid| veth::wire(pid, &plan)))
        .build()
}

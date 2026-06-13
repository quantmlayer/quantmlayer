// crates/ql-enforce/src/enforcer.rs
//
//! The [`Enforcer`] trait: the extension point for every containment wall.
//!
//! # Why a trait
//!
//! Each kernel mechanism we use to contain an agent (mount namespaces,
//! seccomp, capability dropping, cgroups, Landlock, network filtering) is an
//! independent "wall". Modeling each as an [`Enforcer`] gives us three
//! properties we care about for an enterprise product:
//!
//! 1. **Additive extension.** A new wall is a new type implementing this
//!    trait. Existing enforcers are never touched, so adding capability
//!    dropping or seccomp later cannot regress mount isolation.
//! 2. **Independent testing.** Each wall is tested in isolation.
//! 3. **Future backends.** A future `CloudAttestationEnforcer` (for when an
//!    agent runs in a vendor cloud we don't own) implements the same trait.
//!
//! # The three-phase model
//!
//! Containment is built in phases because the operations have different
//! privilege and ordering requirements relative to the user namespace:
//!
//! * [`Enforcer::required_namespaces`] — phase 1, consulted in the parent to
//!   decide which namespaces to create.
//! * [`Enforcer::apply_pre_userns`] — phase 2a, run in the child while it is
//!   still **real root**, before entering the user namespace. For operations
//!   on host-owned resources, e.g. joining a cgroup.
//! * [`Enforcer::apply_in_namespace`] — phase 2b, run in the child **after**
//!   it has entered the user + mount namespaces and been mapped to
//!   root-in-namespace. For operations like mounting.
//!
//! An enforcer implements only the phase(s) it needs; the rest default to
//! no-ops.

use crate::context::ChildContext;
use crate::error::Result;
use nix::sched::CloneFlags;
use ql_profile::Profile;

/// One containment wall. See the [module docs](self) for the design rationale.
///
/// Implementors must be `Send + Sync` so a cell can hold a heterogeneous list
/// of them behind `Box<dyn Enforcer>`.
pub trait Enforcer: Send + Sync {
    /// A stable, human-readable name used in logs and error messages.
    /// Keep it short and lowercase, e.g. `"mount"`, `"seccomp"`.
    fn name(&self) -> &'static str;

    /// Phase 1 (parent, before clone): declare which namespaces this enforcer
    /// needs the contained child to be placed in.
    ///
    /// The cell unions the flags requested by every enforcer. An enforcer that
    /// needs no new namespace returns [`CloneFlags::empty`] (the default).
    fn required_namespaces(&self, _profile: &Profile) -> CloneFlags {
        CloneFlags::empty()
    }

    /// Phase 2a (child, real root, before entering the user namespace).
    ///
    /// Use this for operations that require host root on host-owned resources
    /// — most importantly joining a cgroup, whose control files cannot be
    /// written from inside a child user namespace.
    ///
    /// # Failure semantics
    ///
    /// Returning a hard error aborts the cell (fail-closed). Returning
    /// [`crate::EnforceError::Unsupported`] signals the host cannot provide
    /// this wall; the cell may continue without it while recording the gap.
    fn apply_pre_userns(&self, _profile: &Profile, _ctx: &ChildContext) -> Result<()> {
        Ok(())
    }

    /// Phase 2b (child, after entering namespaces, before exec): apply rules
    /// that require root-in-namespace, such as mounts.
    ///
    /// # Failure semantics
    ///
    /// Returning `Err` aborts the whole cell: the child will NOT exec the
    /// agent command. A half-applied cage is worse than none, so enforcers
    /// must fail closed and the cell honors that by refusing to proceed.
    fn apply_in_namespace(&self, _profile: &Profile, _ctx: &ChildContext) -> Result<()> {
        Ok(())
    }
}

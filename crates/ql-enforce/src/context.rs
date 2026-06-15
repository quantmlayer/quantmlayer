// crates/ql-enforce/src/context.rs
//
//! Context objects passed to enforcers.
//!
//! Keeping enforcer inputs in dedicated context structs (rather than a long
//! argument list) means we can add new information for future enforcers
//! without changing the [`crate::Enforcer`] trait signature — another small
//! but real maintainability win.

/// Information available to an enforcer during the in-child phase.
///
/// Currently minimal; this is intentionally a struct (not a bare `&Profile`)
/// so future enforcers can receive additional context (e.g. a resolved
/// workspace root, a session id, a logging handle) without a trait change.
#[non_exhaustive]
pub struct ChildContext {
    /// The real uid of the user who launched the cell, captured before the
    /// user namespace remapped us to root-inside-namespace. Some enforcers
    /// need the original uid (e.g. to set ownership correctly).
    pub host_uid: u32,
    /// The real gid, captured for the same reason.
    pub host_gid: u32,
    /// The cell's single shared cgroup leaf name, decided once by the cell
    /// **before** `fork` so the parent and child agree on one identity. `None`
    /// means the cell needs no cgroup (no resource limits and no exec
    /// enforcement); `Some(name)` means the cgroup enforcer creates/joins a
    /// leaf with this name under whichever hierarchy the host provides.
    pub cgroup_leaf: Option<String>,
}

impl ChildContext {
    /// Construct a child context from the host identity. The cell cgroup leaf
    /// (if any) is attached separately via [`ChildContext::with_cgroup_leaf`].
    pub fn new(host_uid: u32, host_gid: u32) -> Self {
        ChildContext {
            host_uid,
            host_gid,
            cgroup_leaf: None,
        }
    }

    /// Set the shared cell cgroup leaf name (see the field docs). Called by the
    /// cell with a name it computed before `fork`.
    pub(crate) fn with_cgroup_leaf(mut self, leaf: String) -> Self {
        self.cgroup_leaf = Some(leaf);
        self
    }
}

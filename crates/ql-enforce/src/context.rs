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
}

impl ChildContext {
    /// Construct a child context from the host identity.
    pub fn new(host_uid: u32, host_gid: u32) -> Self {
        ChildContext { host_uid, host_gid }
    }
}

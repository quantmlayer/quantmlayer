// crates/ql-enforce/src/enforcers/namespace.rs
//
//! [`NamespaceEnforcer`]: places the agent in fresh Linux namespaces.
//!
//! This enforcer is the foundation the other walls stand on. It requests a
//! new **user** namespace and **mount** namespace (and, in later phases, will
//! add network/PID/IPC/UTS). The user namespace is what lets an unprivileged
//! launcher perform privileged-looking operations (like mounting) *inside the
//! cell* without granting any real privilege on the host.
//!
//! ## The uid/gid mapping dance
//!
//! After a process enters a new user namespace it has no valid uid until a
//! mapping is written. We map the host uid to root *inside* the namespace so
//! that subsequent steps (mounts performed by [`super::mount::MountEnforcer`])
//! are permitted. Writing `gid_map` first requires disabling `setgroups`.
//! This is the standard, well-documented unprivileged-userns sequence.

use crate::context::ChildContext;
use crate::enforcer::Enforcer;
use crate::error::{EnforceError, Result};
use nix::sched::CloneFlags;
use ql_profile::Profile;
use std::fs;

/// Places the contained process into fresh user and mount namespaces.
///
/// In later phases this enforcer will also request network, PID, IPC, and UTS
/// namespaces; the structure here is built to accommodate that by simply
/// OR-ing additional flags in [`Enforcer::required_namespaces`].
#[derive(Debug, Default)]
pub struct NamespaceEnforcer;

impl NamespaceEnforcer {
    /// Create a new namespace enforcer.
    pub fn new() -> Self {
        NamespaceEnforcer
    }

    /// Write the user-namespace uid/gid maps so the in-namespace identity is
    /// root, enabling in-cell mounts. Must run *after* the user namespace is
    /// created and *before* any operation requiring the mapped identity.
    ///
    /// `host_uid`/`host_gid` are the identities to map to root-in-namespace.
    fn write_id_maps(host_uid: u32, host_gid: u32) -> Result<()> {
        // setgroups must be denied before writing gid_map in an unprivileged
        // user namespace, otherwise the gid_map write is rejected.
        fs::write("/proc/self/setgroups", "deny")
            .map_err(|e| EnforceError::enforcer("namespace", format!("setgroups deny: {e}")))?;

        // Map a single id: in-namespace 0 (root) <- host uid/gid.
        fs::write("/proc/self/gid_map", format!("0 {host_gid} 1"))
            .map_err(|e| EnforceError::enforcer("namespace", format!("gid_map: {e}")))?;
        fs::write("/proc/self/uid_map", format!("0 {host_uid} 1"))
            .map_err(|e| EnforceError::enforcer("namespace", format!("uid_map: {e}")))?;

        Ok(())
    }
}

impl Enforcer for NamespaceEnforcer {
    fn name(&self) -> &'static str {
        "namespace"
    }

    /// Request the namespaces this build isolates. Phase 1 (parent side):
    /// the cell creates these when it clones the child.
    ///
    /// NOTE: `CLONE_NEWUSER` must be present for the unprivileged mount setup
    /// to work. Additional namespaces (NET, PID, IPC, UTS) will be added in a
    /// later step by simply extending this set.
    fn required_namespaces(&self, _profile: &Profile) -> CloneFlags {
        CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS
    }

    /// Phase 2b (in-namespace): establish the uid/gid mapping inside the new
    /// user namespace. This makes us root-in-namespace so the mount enforcer
    /// can operate. No host privilege is conferred.
    ///
    /// Sudo case: the PARENT already wrote our maps by pid during the fork
    /// handshake (maps are write-once), so there is nothing to do here — we
    /// are root-in-namespace the moment the handshake completes.
    fn apply_in_namespace(&self, _profile: &Profile, ctx: &ChildContext) -> Result<()> {
        if ctx.maps_preset {
            return Ok(());
        }
        Self::write_id_maps(ctx.host_uid, ctx.host_gid)
    }
}

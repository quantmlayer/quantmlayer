// crates/ql-enforce/src/enforcers/cgroup.rs
//
//! [`CgroupEnforcer`]: caps the cell's resource usage to stop runaway agents.
//!
//! This is the wall that blocks fork bombs and memory exhaustion. It creates a
//! dedicated leaf cgroup, writes the profile's limits (`pids.max`,
//! `memory.max`), and moves the contained process into it. Every process the
//! agent later spawns inherits the cgroup, so the limits bound the entire
//! agent subtree.
//!
//! ## Why this runs in the pre-userns phase
//!
//! cgroup control files in `/sys/fs/cgroup` are owned by the host's real root
//! and live in the initial user namespace. A process that has already entered
//! a *child* user namespace can no longer write them. Therefore the cgroup
//! join must happen while the contained child is still real root — i.e. in
//! [`Enforcer::apply_pre_userns`], before the namespace wall enters the user
//! namespace. The two-phase enforcer model exists precisely to express this
//! ordering constraint cleanly.
//!
//! ## v1 and v2
//!
//! The control-file names differ between hierarchies (`memory.max` on v2 vs
//! `memory.limit_in_bytes` on v1; `cgroup.procs` vs `tasks`). The
//! [`crate::cgroups::CgroupBackend`] tells us which we are on; this enforcer
//! writes the right files for each.

use crate::cgroups::{write_control, CgroupBackend};
use crate::context::ChildContext;
use crate::enforcer::Enforcer;
use crate::error::{EnforceError, Result};
use ql_profile::Profile;
use std::fs;
use std::path::{Path, PathBuf};

/// Caps process count and memory for the contained agent via cgroups.
#[derive(Debug, Default)]
pub struct CgroupEnforcer;

impl CgroupEnforcer {
    /// Create a new cgroup enforcer.
    pub fn new() -> Self {
        CgroupEnforcer
    }

    /// Apply limits on a unified cgroup **v2** hierarchy.
    ///
    /// Returns `Ok(true)` if at least one limit was enforced, `Ok(false)` if
    /// the hierarchy advertised none of our controllers (nothing to do). Only
    /// genuine, unexpected I/O errors propagate as `Err`.
    fn apply_v2(root: &Path, profile: &Profile, leaf_name: &str, my_pid: u32) -> Result<bool> {
        let available = fs::read_to_string(root.join("cgroup.controllers")).unwrap_or_default();
        let has = |c: &str| available.split_whitespace().any(|a| a == c);

        // Nothing we can enforce on this hierarchy.
        if !has("pids") && !has("memory") {
            return Ok(false);
        }

        // Delegate the controllers we need to children. The root cgroup is
        // exempt from the "no internal processes" rule, so this is permitted.
        let want: Vec<&str> = ["pids", "memory"].into_iter().filter(|c| has(c)).collect();
        let directive = want
            .iter()
            .map(|c| format!("+{c}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = write_control(&root.join("cgroup.subtree_control"), &directive);

        // Create the leaf. If we can't (e.g. running unprivileged with no
        // cgroup delegation), report "not applied" so the cell degrades to a
        // loud Unsupported warning and the other walls still protect the agent,
        // rather than failing the whole cell closed.
        let leaf = root.join(leaf_name);
        if fs::create_dir_all(&leaf).is_err() {
            return Ok(false);
        }

        // Set limits best-effort; a missing/unwritable knob shouldn't abort.
        if has("pids") {
            if let Some(pids) = profile.resources.pids_max {
                let _ = write_control(&leaf.join("pids.max"), &pids.to_string());
            }
        }
        if has("memory") {
            if let Some(mem) = profile.resources.memory_max_bytes {
                let _ = write_control(&leaf.join("memory.max"), &mem.to_string());
            }
        }

        // Join: move ourselves into the leaf (v2 uses cgroup.procs). If this
        // fails we are not actually contained by the cgroup, so report it as
        // not-applied (Unsupported) rather than pretending otherwise.
        if write_control(&leaf.join("cgroup.procs"), &my_pid.to_string()).is_err() {
            return Ok(false);
        }
        Ok(true)
    }

    /// Apply limits on the legacy cgroup **v1** hierarchy.
    ///
    /// Returns `Ok(true)` if at least one controller's limit was enforced.
    fn apply_v1(
        pids_mount: &Option<PathBuf>,
        memory_mount: &Option<PathBuf>,
        profile: &Profile,
        leaf_name: &str,
        my_pid: u32,
    ) -> Result<bool> {
        let mut applied = false;

        // pids controller: create a leaf, set pids.max, join. Each step is
        // best-effort: if we lack permission (unprivileged, no delegation) we
        // simply leave this controller unapplied rather than failing the cell.
        if let (Some(mount), Some(limit)) = (pids_mount, profile.resources.pids_max) {
            let leaf = mount.join(leaf_name);
            if fs::create_dir_all(&leaf).is_ok() {
                let _ = write_control(&leaf.join("pids.max"), &limit.to_string());
                if write_control(&leaf.join("cgroup.procs"), &my_pid.to_string()).is_ok() {
                    applied = true;
                }
            }
        }

        // memory controller: create a leaf, set the limit, join (best-effort).
        if let (Some(mount), Some(limit)) = (memory_mount, profile.resources.memory_max_bytes) {
            let leaf = mount.join(leaf_name);
            if fs::create_dir_all(&leaf).is_ok() {
                let _ = write_control(&leaf.join("memory.limit_in_bytes"), &limit.to_string());
                if write_control(&leaf.join("cgroup.procs"), &my_pid.to_string()).is_ok() {
                    applied = true;
                }
            }
        }

        Ok(applied)
    }
}

impl Enforcer for CgroupEnforcer {
    fn name(&self) -> &'static str {
        "cgroups"
    }

    /// Phase 2a (pre-userns, real root): set up and join the cgroup before the
    /// process enters a child user namespace and loses the ability to write
    /// host-owned cgroup files.
    fn apply_pre_userns(&self, profile: &Profile, ctx: &ChildContext) -> Result<()> {
        // The cell decides — before fork — whether a cgroup is needed and, if
        // so, its single shared leaf name. `None` means no cell cgroup is
        // wanted (no resource limits and no exec enforcement): nothing to do.
        // `Some(name)` means create and join that leaf even if the profile sets
        // no resource limits, because a wall that needs the cgroup to exist
        // (exec enforcement attaches an lsm_cgroup program to it) asked for it.
        let Some(leaf_name) = ctx.cgroup_leaf.as_deref() else {
            return Ok(());
        };

        let my_pid = std::process::id();
        let applied = match CgroupBackend::detect()? {
            CgroupBackend::V2 { root } => Self::apply_v2(&root, profile, leaf_name, my_pid)?,
            CgroupBackend::V1 { pids, memory } => {
                Self::apply_v1(&pids, &memory, profile, leaf_name, my_pid)?
            }
        };

        // If the host advertised a backend but none of our controllers were
        // actually usable, signal Unsupported so the cell continues (loudly)
        // rather than silently pretending the limits are in force.
        if !applied {
            return Err(EnforceError::Unsupported {
                feature: "cgroups",
                reason: "no usable pids/memory controller on this host".into(),
            });
        }
        Ok(())
    }
}

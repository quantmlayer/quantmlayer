// crates/ql-enforce/src/cgroups.rs
//
//! cgroup hierarchy detection and a small backend abstraction.
//!
//! Production hosts are not uniform: modern distributions use the unified
//! cgroup **v2** hierarchy, while older systems and some container runtimes
//! still expose the legacy **v1** controllers. A production-grade resource
//! wall must work on both, so this module detects what is available and
//! presents one interface to the [`crate::enforcers::cgroup::CgroupEnforcer`].
//!
//! This module performs NO mounting. It uses whatever the host has already
//! mounted (the normal case). Discovering hierarchies is done by parsing
//! `/proc/self/mounts`, the authoritative view of this process's mount table.

use crate::error::{EnforceError, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Which cgroup hierarchy a leaf will be created under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CgroupBackend {
    /// Unified cgroup v2. `root` is the v2 mount (typically `/sys/fs/cgroup`).
    V2 {
        /// The mount point of the unified v2 hierarchy.
        root: PathBuf,
    },
    /// Legacy cgroup v1. We track the per-controller mount points we need.
    V1 {
        /// Mount point of the `pids` controller, if present.
        pids: Option<PathBuf>,
        /// Mount point of the `memory` controller, if present.
        memory: Option<PathBuf>,
    },
}

impl CgroupBackend {
    /// Detect the cgroup backend available on this host.
    ///
    /// Prefers v2 (the modern standard) **only if the unified hierarchy
    /// actually advertises the controllers we need** — on "hybrid" systems a
    /// v2 mount exists but all controllers live on v1, so a naive v2 choice
    /// would create leaves with no `pids.max`/`memory.max` files. Falls back
    /// to v1 in that case. Returns [`EnforceError::Unsupported`] if neither is
    /// usable, so callers can degrade gracefully rather than crash.
    pub fn detect() -> Result<Self> {
        let mounts = fs::read_to_string("/proc/self/mounts")
            .map_err(|e| EnforceError::enforcer("cgroups", format!("reading mounts: {e}")))?;

        // First pass: a unified v2 mount that actually carries our controllers.
        if let Some(root) = Self::find_v2(&mounts) {
            let controllers =
                fs::read_to_string(root.join("cgroup.controllers")).unwrap_or_default();
            let has_useful = ["pids", "memory"]
                .iter()
                .any(|c| controllers.split_whitespace().any(|a| a == *c));
            if has_useful {
                return Ok(CgroupBackend::V2 { root });
            }
            // else: hybrid mode — controllers are on v1; fall through.
        }

        // Second pass: collect the v1 controller mounts we care about.
        let pids = Self::find_v1_controller(&mounts, "pids");
        let memory = Self::find_v1_controller(&mounts, "memory");
        if pids.is_some() || memory.is_some() {
            return Ok(CgroupBackend::V1 { pids, memory });
        }

        Err(EnforceError::Unsupported {
            feature: "cgroups",
            reason: "no cgroup v2 unified mount with controllers and no usable v1 controllers"
                .into(),
        })
    }

    /// Does this backend provide a usable `pids` controller? Used by callers
    /// (e.g. the benchmark) to decide whether a fork-bomb limit can be tested.
    pub fn supports_pids(&self) -> bool {
        match self {
            CgroupBackend::V2 { root } => Self::v2_has_controller(root, "pids"),
            CgroupBackend::V1 { pids, .. } => pids.is_some(),
        }
    }

    /// Does this backend provide a usable `memory` controller?
    pub fn supports_memory(&self) -> bool {
        match self {
            CgroupBackend::V2 { root } => Self::v2_has_controller(root, "memory"),
            CgroupBackend::V1 { memory, .. } => memory.is_some(),
        }
    }

    /// Read a v2 hierarchy's advertised controllers and test for one.
    fn v2_has_controller(root: &Path, controller: &str) -> bool {
        fs::read_to_string(root.join("cgroup.controllers"))
            .map(|s| s.split_whitespace().any(|c| c == controller))
            .unwrap_or(false)
    }

    /// Find the v2 unified mount point, if any.
    fn find_v2(mounts: &str) -> Option<PathBuf> {
        for line in mounts.lines() {
            // Format: "<src> <mountpoint> <fstype> <opts> ...".
            let mut f = line.split_whitespace();
            let _src = f.next();
            let mountpoint = f.next();
            let fstype = f.next();
            if fstype == Some("cgroup2") {
                if let Some(mp) = mountpoint {
                    return Some(PathBuf::from(mp));
                }
            }
        }
        None
    }

    /// Find the v1 mount point that carries the given controller option
    /// (e.g. "pids" in the comma-separated mount options).
    fn find_v1_controller(mounts: &str, controller: &str) -> Option<PathBuf> {
        for line in mounts.lines() {
            let mut f = line.split_whitespace();
            let _src = f.next();
            let mountpoint = f.next();
            let fstype = f.next();
            let opts = f.next().unwrap_or("");
            if fstype == Some("cgroup") && opts.split(',').any(|o| o == controller) {
                if let Some(mp) = mountpoint {
                    return Some(PathBuf::from(mp));
                }
            }
        }
        None
    }
}

/// Write a value to a cgroup control file, mapping failures to a clear error.
pub(crate) fn write_control(path: &Path, value: &str) -> Result<()> {
    fs::write(path, value).map_err(|e| {
        EnforceError::enforcer(
            "cgroups",
            format!("writing `{value}` to {}: {e}", path.display()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v2_mount() {
        let mounts = "cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev 0 0\n";
        let b = CgroupBackend::find_v2(mounts);
        assert_eq!(b, Some(PathBuf::from("/sys/fs/cgroup")));
    }

    #[test]
    fn parses_v1_pids_controller() {
        let mounts = "\
cgroup /sys/fs/cgroup/cpu cgroup rw,cpu 0 0
none /tmp/p cgroup rw,relatime,pids 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,memory 0 0
";
        assert_eq!(
            CgroupBackend::find_v1_controller(mounts, "pids"),
            Some(PathBuf::from("/tmp/p"))
        );
        assert_eq!(
            CgroupBackend::find_v1_controller(mounts, "memory"),
            Some(PathBuf::from("/sys/fs/cgroup/memory"))
        );
        assert_eq!(CgroupBackend::find_v1_controller(mounts, "blkio"), None);
    }

    #[test]
    fn v2_preferred_over_v1() {
        let mounts = "\
none /tmp/p cgroup rw,pids 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw 0 0
";
        assert!(CgroupBackend::find_v2(mounts).is_some());
    }
}

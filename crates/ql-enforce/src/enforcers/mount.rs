// crates/ql-enforce/src/enforcers/mount.rs
//
//! [`MountEnforcer`]: makes denied filesystem paths invisible to the agent.
//!
//! This is the wall that blocks SSH-key theft. For each entry in the
//! profile's `filesystem.denied` list, we overmount the target with an empty,
//! read-only `tmpfs`. Inside the cell the original contents are gone — a read
//! of `~/.ssh/id_rsa` fails with "No such file or directory" — while the host
//! filesystem is completely untouched (the mount lives only in the cell's
//! mount namespace).
//!
//! ## Why overmounting (rather than permission changes)
//!
//! Hiding-by-overmount is stronger than `chmod`: even a process that is root
//! *inside the namespace* sees an empty directory, because the real inode is
//! no longer reachable through that path. There is nothing to read, so there
//! is nothing to leak.
//!
//! ## Scope of this step
//!
//! This step implements directory hiding (the `/home/**` case that matters
//! for the demo) and exact-path hiding. Richer glob handling and the
//! readonly/readwrite allow-lists are deliberately deferred to a later step,
//! per the build plan's "one wall at a time" discipline.

use crate::context::ChildContext;
use crate::enforcer::Enforcer;
use crate::error::{EnforceError, Result};
use nix::mount::{mount, MsFlags};
use ql_profile::Profile;

/// Hides every path in `filesystem.denied` by overmounting empty tmpfs.
#[derive(Debug, Default)]
pub struct MountEnforcer;

impl MountEnforcer {
    /// Create a new mount enforcer.
    pub fn new() -> Self {
        MountEnforcer
    }

    /// Expand a denied pattern into the concrete, existing paths to hide.
    ///
    /// Supported shapes (those the profiles and the learner actually emit):
    /// * `"/some/dir/**"`        → the directory `"/some/dir"`.
    /// * `"/home/*/.ssh/**"`     → each existing `"/home/<user>/.ssh"`.
    /// * `"/some/exact/path"`    → that exact path (file or directory).
    ///
    /// A single `*` matches one path component and is expanded against the
    /// live filesystem; a trailing `/**` is stripped (we hide the directory it
    /// names). Patterns that match nothing yield an empty list (nothing to do).
    fn expand(pattern: &str) -> Vec<std::path::PathBuf> {
        use std::path::PathBuf;
        let base = pattern.strip_suffix("/**").unwrap_or(pattern);
        let mut frontier = vec![PathBuf::from("/")];
        for comp in base
            .trim_start_matches('/')
            .split('/')
            .filter(|c| !c.is_empty())
        {
            let mut next = Vec::new();
            for dir in &frontier {
                if comp == "*" || comp == "**" {
                    // Wildcard: branch into every entry of this directory.
                    if let Ok(entries) = std::fs::read_dir(dir) {
                        for e in entries.flatten() {
                            next.push(e.path());
                        }
                    }
                } else {
                    // Literal component: descend only if it exists.
                    let p = dir.join(comp);
                    if p.symlink_metadata().is_ok() {
                        next.push(p);
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }
        frontier
    }

    /// Make `/` recursively private within this mount namespace so that the
    /// overmounts we perform cannot propagate back to the host and so we are
    /// not affected by host mount events. This is mandatory before mounting.
    fn make_root_private() -> Result<()> {
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .map_err(|e| EnforceError::syscall("mount(MS_PRIVATE /)", e))
    }

    /// Overmount a single directory target with an empty read-only tmpfs.
    fn hide_dir(target: &std::path::Path) -> Result<()> {
        // Mounting tmpfs over an existing directory replaces the view of its
        // contents with an empty directory for the lifetime of this namespace.
        mount(
            Some("tmpfs"),
            target,
            Some("tmpfs"),
            MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|e| EnforceError::syscall("mount(tmpfs over denied dir)", e))
    }

    /// Hide a single denied *file* (e.g. `/etc/shadow`) by bind-mounting
    /// `/dev/null` over it, so any read returns empty rather than its secret
    /// contents. (tmpfs can only cover directories, hence the bind.)
    fn hide_file(target: &std::path::Path) -> Result<()> {
        mount(
            Some("/dev/null"),
            target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| EnforceError::syscall("mount(bind /dev/null over denied file)", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn expand_resolves_single_wildcard() {
        // Build /tmp/<uniq>/{alice,bob}/.ssh and confirm a `*` pattern finds both.
        let root = std::env::temp_dir().join(format!("ql-expand-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for user in ["alice", "bob"] {
            fs::create_dir_all(root.join(user).join(".ssh")).unwrap();
        }
        let pattern = format!("{}/*/.ssh/**", root.display());
        let mut found = MountEnforcer::expand(&pattern);
        found.sort();
        assert_eq!(found.len(), 2, "expected both users' .ssh dirs: {found:?}");
        assert!(found.iter().all(|p| p.ends_with(".ssh")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn expand_exact_path() {
        let f = std::env::temp_dir().join(format!("ql-exact-{}", std::process::id()));
        fs::write(&f, b"x").unwrap();
        let found = MountEnforcer::expand(f.to_str().unwrap());
        assert_eq!(found, vec![f.clone()]);
        let _ = fs::remove_file(&f);
    }

    #[test]
    fn expand_nonexistent_is_empty() {
        assert!(MountEnforcer::expand("/no/such/path/*/x/**").is_empty());
    }
}

impl Enforcer for MountEnforcer {
    fn name(&self) -> &'static str {
        "mount"
    }

    /// Phase 2b (in-namespace): with the mount namespace already created and
    /// the user namespace mapped to root, hide each denied path.
    fn apply_in_namespace(&self, profile: &Profile, _ctx: &ChildContext) -> Result<()> {
        // Step 1: detach our mount view from the host's propagation.
        Self::make_root_private()?;

        // Step 2: hide each denied path. A failure to hide ANY existing denied
        // path is fail-closed: we return Err, the cell aborts, and the agent
        // never runs. Better to refuse to start than to start with a leaky cage.
        // A pattern that matches nothing on this host is fine (nothing to leak).
        for pattern in &profile.filesystem.denied {
            for target in Self::expand(pattern) {
                match target.symlink_metadata() {
                    Ok(meta) if meta.is_dir() => Self::hide_dir(&target)?,
                    Ok(_) => Self::hide_file(&target)?,
                    Err(_) => {} // vanished between expand and now; nothing to hide
                }
            }
        }

        Ok(())
    }
}

// crates/ql-token/src/capability.rs
//! A capability is a grant set: which paths an agent may read/write, which
//! domains it may reach, which binaries it may exec. Delegation may only
//! *attenuate* a capability — produce a subset — so authority decreases
//! monotonically down the agent tree. [`Capability::is_subset_of`] is the rule
//! that makes that guarantee checkable.

use serde::{Deserialize, Serialize};

/// A set of grants. Empty vectors mean "no authority in that dimension".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    #[serde(default)]
    pub read_paths: Vec<String>,
    #[serde(default)]
    pub write_paths: Vec<String>,
    #[serde(default)]
    pub net_domains: Vec<String>,
    #[serde(default)]
    pub allow_exec: Vec<String>,
}

/// A concrete action an agent attempts, checked against a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    FsRead { path: String },
    FsWrite { path: String },
    NetConnect { domain: String },
    Exec { program: String },
}

impl Capability {
    /// Sort grants for stable serialization/signing.
    pub fn normalized(mut self) -> Self {
        for v in [
            &mut self.read_paths,
            &mut self.write_paths,
            &mut self.net_domains,
            &mut self.allow_exec,
        ] {
            v.sort();
            v.dedup();
        }
        self
    }

    /// Is `self` a subset of (i.e. no broader than) `parent`? Every grant in
    /// `self` must be covered by some grant in `parent`. Paths support `/**`
    /// suffix containment so `/ws/**` can be attenuated to `/ws/src`.
    pub fn is_subset_of(&self, parent: &Capability) -> bool {
        paths_within(&self.read_paths, &parent.read_paths)
            && paths_within(&self.write_paths, &parent.write_paths)
            && set_within(&self.net_domains, &parent.net_domains)
            && set_within(&self.allow_exec, &parent.allow_exec)
    }

    /// Does this capability permit `action`?
    pub fn permits(&self, action: &Action) -> bool {
        match action {
            Action::FsRead { path } => {
                // a read is also permitted if the path is writable
                path_in(path, &self.read_paths) || path_in(path, &self.write_paths)
            }
            Action::FsWrite { path } => path_in(path, &self.write_paths),
            Action::NetConnect { domain } => self.net_domains.contains(domain),
            Action::Exec { program } => self.allow_exec.contains(program),
        }
    }
}

/// Every child path must be within some parent path.
fn paths_within(child: &[String], parent: &[String]) -> bool {
    child.iter().all(|c| path_in(c, parent))
}

/// Is `path` covered by any grant in `grants` (exact or `/**` prefix)?
fn path_in(path: &str, grants: &[String]) -> bool {
    grants.iter().any(|g| path_within_one(path, g))
}

fn path_within_one(child: &str, parent: &str) -> bool {
    if child == parent {
        return true;
    }
    if let Some(prefix) = parent.strip_suffix("/**") {
        return child == prefix || child.starts_with(&format!("{prefix}/"));
    }
    false
}

/// Public containment predicate over the `/**`-suffix path grammar: does the
/// single grant `parent` fully cover `child`? This is the *one* authority on
/// path containment in QuantmLayer. The profile->capability binding in `ql-cli`
/// calls this rather than reimplementing a second, drift-prone semantics — a
/// divergent copy could silently widen or narrow a derived cell, which is the
/// top correctness risk in token-to-cell binding.
pub fn path_contains(parent: &str, child: &str) -> bool {
    path_within_one(child, parent)
}

/// Exact-membership subset for non-path sets (domains, exec).
fn set_within(child: &[String], parent: &[String]) -> bool {
    child.iter().all(|c| parent.contains(c))
}

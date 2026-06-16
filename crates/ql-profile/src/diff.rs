// crates/ql-profile/src/diff.rs
//
//! Diff two profiles into the grants that were added or removed.
//!
//! The motivating use is review provenance: `ql learn` *proposes* a profile, a
//! human *approves* a possibly-edited one, and the difference between them — the
//! grant lines the approval added or removed — is recorded in the audit chain.
//! The diff is set-based and category-labeled, so each change is a readable
//! line like `fs.deny /root/.ssh/**`.

use crate::Profile;
use std::collections::BTreeSet;

/// One added or removed grant: a category label plus the grant's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRef {
    /// The grant category: `fs.read`, `fs.write`, `fs.deny`, `exec`,
    /// `syscall.deny`, `net.allow`, or `exec.digest`.
    pub category: &'static str,
    /// The grant value: a path glob, syscall name, domain, or content digest.
    pub value: String,
}

impl GrantRef {
    fn new(category: &'static str, value: impl Into<String>) -> Self {
        GrantRef {
            category,
            value: value.into(),
        }
    }
}

/// The difference between a proposed profile and an approved/enforced one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyDiff {
    /// Grant lines present in the approved profile but not the proposed one.
    pub added: Vec<GrantRef>,
    /// Grant lines present in the proposed profile but not the approved one.
    pub removed: Vec<GrantRef>,
}

impl PolicyDiff {
    /// Whether the two profiles' grant sets are identical.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Diff `proposed` against `approved`, returning the grant lines the approval
/// added or removed. Each category is compared as a set; ordering is ignored.
pub fn diff(proposed: &Profile, approved: &Profile) -> PolicyDiff {
    let mut d = PolicyDiff::default();

    let p = proposed;
    let a = approved;
    diff_into(
        "fs.read",
        &p.filesystem.readonly,
        &a.filesystem.readonly,
        &mut d,
    );
    diff_into(
        "fs.write",
        &p.filesystem.readwrite,
        &a.filesystem.readwrite,
        &mut d,
    );
    diff_into(
        "fs.deny",
        &p.filesystem.denied,
        &a.filesystem.denied,
        &mut d,
    );
    diff_into(
        "exec",
        &p.processes.allow_exec,
        &a.processes.allow_exec,
        &mut d,
    );
    diff_into("syscall.deny", &p.syscalls.deny, &a.syscalls.deny, &mut d);
    diff_into(
        "net.allow",
        &p.network.allow_domains,
        &a.network.allow_domains,
        &mut d,
    );

    let p_digests: Vec<String> = p.exec.allow_digests.iter().map(|x| x.to_string()).collect();
    let a_digests: Vec<String> = a.exec.allow_digests.iter().map(|x| x.to_string()).collect();
    diff_into("exec.digest", &p_digests, &a_digests, &mut d);

    d
}

/// Add the set difference of one category into `d`.
fn diff_into(category: &'static str, proposed: &[String], approved: &[String], d: &mut PolicyDiff) {
    let p: BTreeSet<&str> = proposed.iter().map(String::as_str).collect();
    let a: BTreeSet<&str> = approved.iter().map(String::as_str).collect();
    for v in a.difference(&p) {
        d.added.push(GrantRef::new(category, *v));
    }
    for v in p.difference(&a) {
        d.removed.push(GrantRef::new(category, *v));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_profiles_have_empty_diff() {
        let p = Profile::default();
        assert!(diff(&p, &p).is_empty());
    }

    #[test]
    fn added_and_removed_grants_are_detected() {
        let mut proposed = Profile::default();
        proposed.filesystem.readonly = vec!["/src/**".into(), "/tests/**".into()];
        proposed.syscalls.deny = vec!["ptrace".into(), "mount".into()];

        let mut approved = proposed.clone();
        // Reviewer tightened: dropped read access to /tests, kept /src.
        approved.filesystem.readonly = vec!["/src/**".into()];
        // Reviewer loosened: removed the mount denial.
        approved.syscalls.deny = vec!["ptrace".into()];
        // Reviewer added a new allowed binary.
        approved.processes.allow_exec = vec!["/usr/bin/git".into()];

        let d = diff(&proposed, &approved);

        // /usr/bin/git is present in approved only.
        assert!(d
            .added
            .iter()
            .any(|g| g.category == "exec" && g.value == "/usr/bin/git"));
        // /tests/** and the mount denial were present in proposed only.
        assert!(d
            .removed
            .iter()
            .any(|g| g.category == "fs.read" && g.value == "/tests/**"));
        assert!(d
            .removed
            .iter()
            .any(|g| g.category == "syscall.deny" && g.value == "mount"));
        assert!(!d.is_empty());
    }
}

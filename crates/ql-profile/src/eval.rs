// crates/ql-profile/src/eval.rs
//
//! The **pure decision layer**: given a [`Profile`] and one observed action,
//! decide whether the profile admits it. These functions are the *single
//! source of truth* for "would this be allowed" — the enforcement paths
//! (`exec_supervisor`, the broker, the mount enforcer) and the non-enforcing
//! `--observe` mode both consult them, so an observe-mode `would-deny` is
//! provably identical to an enforce-mode `deny` **by construction**. If these
//! and the walls ever disagreed, observe would lie about what enforce does —
//! the one failure this layer exists to prevent.
//!
//! Everything here is pure (no syscalls, no filesystem, no I/O) and total, so
//! it is exhaustively unit-testable and cannot behave differently at run time
//! than in a test.
//!
//! ## Faithfulness scope (read before trusting a decision)
//! Each function mirrors exactly what the corresponding wall enforces *today*,
//! no more:
//! * [`Profile::admits_exec`] — mirrors the exec wall: a sha256 digest present
//!   in `exec.allow_digests` is allowed; anything else (including an un-hashable
//!   binary, `None`) is denied. Fail-closed.
//! * [`Profile::admits_domain`] — mirrors the broker: under `default_deny`, a
//!   host is allowed iff it equals, or is a dot-boundary subdomain of, a
//!   `network.allow_domains` entry. With `default_deny = false`, all hosts are
//!   allowed (the broker still runs, but the allow-list is not a gate).
//! * [`Profile::admits_path`] — mirrors the mount wall, which today enforces
//!   only `filesystem.denied` (overmount-to-hide); `readwrite`/`readonly` are
//!   not yet enforced. So this reports [`PathDecision::Denied`] for a path under
//!   a `denied` glob and [`PathDecision::NotEnforced`] otherwise — it does *not*
//!   fabricate an allow/deny from the read/write lists the wall ignores.

use crate::policy::HashAlgo;
use crate::Profile;

/// Outcome of an exec or domain check: does the profile admit this action?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The profile admits this action; the wall would let it through.
    Allow,
    /// The profile does not admit it; the wall would block it.
    Deny,
}

/// Outcome of a filesystem-path check. Distinct from [`Decision`] because the
/// mount wall only enforces `denied` today — everything else is genuinely not
/// evaluated, and saying so is more honest than forcing an Allow/Deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathDecision {
    /// Path is under a `filesystem.denied` glob — the wall hides it.
    Denied,
    /// Path is not denied. The wall does not (yet) enforce read/write scoping,
    /// so no allow/deny is asserted for it.
    NotEnforced,
}

impl Profile {
    /// Would the exec wall admit a binary with this content digest?
    ///
    /// Mirrors the exec wall precisely, including its **on/off switch**: when
    /// `exec.enforce` is false the wall is not applied at all, so every exec is
    /// allowed. When it is true, only sha256 digests in `exec.allow_digests`
    /// match; `None` (un-hashable) is fail-closed to [`Decision::Deny`].
    pub fn admits_exec(&self, digest: Option<&str>) -> Decision {
        if !self.exec.enforce {
            return Decision::Allow;
        }
        match digest {
            Some(d)
                if self
                    .exec
                    .allow_digests
                    .iter()
                    .filter(|a| a.algo() == HashAlgo::Sha256)
                    .any(|a| a.hex() == d) =>
            {
                Decision::Allow
            }
            _ => Decision::Deny,
        }
    }

    /// Would the broker admit an egress connection to `host`?
    ///
    /// Mirrors the broker allow-list: with `default_deny`, allowed iff `host`
    /// equals or is a dot-boundary subdomain of an `allow_domains` entry.
    /// Without `default_deny`, the allow-list is not a gate and all hosts pass.
    pub fn admits_domain(&self, host: &str) -> Decision {
        if !self.network.default_deny {
            return Decision::Allow;
        }
        if self
            .network
            .allow_domains
            .iter()
            .any(|d| host_matches(host, d))
        {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }

    /// Would the mount wall hide this path (i.e. is it `denied`)?
    ///
    /// Returns [`PathDecision::Denied`] when `path` is matched by a
    /// `filesystem.denied` glob, else [`PathDecision::NotEnforced`] — the wall
    /// does not enforce `readwrite`/`readonly`, so this deliberately does not
    /// assert an allow/deny for non-denied paths.
    pub fn admits_path(&self, path: &str) -> PathDecision {
        if self
            .filesystem
            .denied
            .iter()
            .any(|glob| path_matches(path, glob))
        {
            PathDecision::Denied
        } else {
            PathDecision::NotEnforced
        }
    }
}

/// Host matches a granted domain: exact, or a subdomain on a label boundary.
/// Byte-for-byte the broker's `host_matches` (case-insensitive, trailing-dot
/// tolerant) so the two never diverge.
pub fn host_matches(host: &str, domain: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    h == d || h.ends_with(&format!(".{d}"))
}

/// Pure path-glob match mirroring the mount enforcer's `denied` expansion:
/// a trailing `/**` matches the base directory and everything beneath it; a
/// `*` component matches exactly one path component; literal components must
/// match exactly. This is the filesystem-free form of the same rule the wall
/// applies by walking the tree.
pub fn path_matches(path: &str, glob: &str) -> bool {
    let p: Vec<&str> = split_components(path);
    if let Some(base) = glob.strip_suffix("/**") {
        // `/base/**` matches the base dir itself AND anything under it: the
        // base's components must match the path's leading components, and the
        // path must be at least as deep as the base.
        let g = split_components(base);
        p.len() >= g.len() && components_eq(&g, &p[..g.len()])
    } else {
        // No `/**`: exact match — same depth, component-wise.
        let g = split_components(glob);
        g.len() == p.len() && components_eq(&g, &p)
    }
}

/// Split a path/glob into non-empty components.
fn split_components(s: &str) -> Vec<&str> {
    s.trim_matches('/')
        .split('/')
        .filter(|c| !c.is_empty())
        .collect()
}

/// Component-wise equality where a `*` glob component matches any single path
/// component. Slices must be the same length.
fn components_eq(glob: &[&str], path: &[&str]) -> bool {
    glob.len() == path.len() && glob.iter().zip(path).all(|(g, p)| *g == "*" || g == p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ExecDigest, ExecPolicy, FsPolicy, HashAlgo, NetPolicy};

    fn profile() -> Profile {
        Profile {
            network: NetPolicy {
                default_deny: true,
                allow_domains: vec!["api.anthropic.com".into(), "github.com".into()],
                ..Default::default()
            },
            filesystem: FsPolicy {
                denied: vec!["/home/*/.ssh/**".into(), "/etc/shadow".into()],
                ..Default::default()
            },
            exec: ExecPolicy {
                enforce: true,
                allow_digests: vec![ExecDigest::new(HashAlgo::Sha256, "a".repeat(64)).unwrap()],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    // ---- exec ----
    #[test]
    fn exec_allows_listed_digest_denies_rest_and_none() {
        let p = profile();
        assert_eq!(p.admits_exec(Some(&"a".repeat(64))), Decision::Allow);
        assert_eq!(p.admits_exec(Some(&"b".repeat(64))), Decision::Deny);
        assert_eq!(p.admits_exec(None), Decision::Deny); // fail-closed
    }

    #[test]
    fn exec_wall_off_allows_everything() {
        let mut p = profile();
        p.exec.enforce = false; // wall not applied → mirror: allow all
        assert_eq!(p.admits_exec(Some(&"b".repeat(64))), Decision::Allow);
        assert_eq!(p.admits_exec(None), Decision::Allow);
    }

    // ---- domain ----
    #[test]
    fn domain_exact_and_subdomain_on_boundary() {
        let p = profile();
        assert_eq!(p.admits_domain("api.anthropic.com"), Decision::Allow);
        assert_eq!(p.admits_domain("x.github.com"), Decision::Allow); // subdomain
        assert_eq!(p.admits_domain("API.ANTHROPIC.COM"), Decision::Allow); // case
        assert_eq!(p.admits_domain("evil.com"), Decision::Deny);
        // NOT a subdomain match — boundary must be a real dot label.
        assert_eq!(p.admits_domain("notgithub.com"), Decision::Deny);
        assert_eq!(p.admits_domain("evilgithub.com"), Decision::Deny);
    }

    #[test]
    fn domain_without_default_deny_allows_all() {
        let mut p = profile();
        p.network.default_deny = false;
        assert_eq!(p.admits_domain("anything.example"), Decision::Allow);
    }

    // ---- path ----
    #[test]
    fn path_denied_globs_match_tree_and_exact() {
        let p = profile();
        // /** matches the base dir and anything under it, with the `*` component.
        assert_eq!(p.admits_path("/home/alice/.ssh"), PathDecision::Denied);
        assert_eq!(
            p.admits_path("/home/alice/.ssh/id_rsa"),
            PathDecision::Denied
        );
        assert_eq!(
            p.admits_path("/home/bob/.ssh/known_hosts"),
            PathDecision::Denied
        );
        // exact-file denial.
        assert_eq!(p.admits_path("/etc/shadow"), PathDecision::Denied);
        // outside every denied glob → not enforced (NOT a fabricated allow).
        assert_eq!(
            p.admits_path("/home/alice/project/main.rs"),
            PathDecision::NotEnforced
        );
        assert_eq!(p.admits_path("/etc/hosts"), PathDecision::NotEnforced);
        // `*` is single-component: a different second component must not match.
        assert_eq!(
            p.admits_path("/home/alice/other/file"),
            PathDecision::NotEnforced
        );
    }
}

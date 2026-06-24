// crates/ql-cli/src/token_bind.rs
//
//! Token -> cell binding: derive a containment profile from a verified
//! delegation capability.
//!
//! `ql run --token-chain` verifies an Ed25519 delegation chain in userspace
//! ([`ql_token::verify_chain`]: signatures valid, each link only narrows, rooted
//! in a trusted key, not expired) and yields the leaf [`Capability`]. This module
//! intersects the run's base profile with that capability, so the *kernel* then
//! enforces walls that are provably a subset of the parent agent's authority.
//! The chain is verified once, here, at cell-construction time; the kernel does
//! not validate tokens per syscall. The honest claim is "the child's cell is
//! derived from a cryptographically-proven attenuation of the parent's
//! authority" — not "the kernel is an IAM."
//!
//! Tokens model four axes (read/write paths, net domains, exec paths); profiles
//! model more (syscalls, resources, capabilities, content-digests, deny-lists).
//! Binding narrows the four and preserves everything else as the base profile
//! set it. Because intersection only ever *removes* grants, the result is a
//! subset of both inputs — deny-by-default is never widened. This is the inverse
//! of [`crate::token_issue::subtask_capability`]'s forward profile->capability
//! map, and like it the bridge lives in `ql-cli` so `ql-token` stays
//! profile-agnostic.

use ql_profile::Profile;
use ql_token::{path_contains, Capability};

/// Narrow `profile` to the authority in `cap`. The four token-modeled axes
/// become the intersection of the profile's grants and the capability's;
/// `filesystem.denied`, `network.default_deny`/`block_private_ranges`,
/// `syscalls`, `resources`, `capabilities`, `agent_type`, and the content-digest
/// `exec` wall are preserved unchanged.
///
/// Read and write are intersected per-axis (`readonly` against `read_paths`,
/// `readwrite` against `write_paths`), matching
/// [`crate::token_issue::subtask_capability`]'s forward map. This is correct for
/// capabilities minted from profiles; for a hand-authored capability that grants
/// read on a path the base profile only listed under `readwrite`, the result
/// over-narrows (drops the read) rather than widens — the safe direction. See
/// the module-level note and the residual-risks section of the plan.
pub fn bind_profile_to_capability(profile: &Profile, cap: &Capability) -> Profile {
    let mut p = profile.clone();
    p.filesystem.readonly = intersect_paths(&profile.filesystem.readonly, &cap.read_paths);
    p.filesystem.readwrite = intersect_paths(&profile.filesystem.readwrite, &cap.write_paths);
    p.network.allow_domains = intersect_exact(&profile.network.allow_domains, &cap.net_domains);
    p.processes.allow_exec = intersect_exact(&profile.processes.allow_exec, &cap.allow_exec);
    p
}

/// Intersection over the `/**`-suffix path grammar: for each pair of grants
/// where one contains the other, keep the narrower; disjoint grants contribute
/// nothing. Reuses [`ql_token::path_contains`] — the single containment
/// authority — so the binding can never diverge from token verification.
///
/// Every grant returned is a verbatim grant from one input that is contained in
/// a grant of the other, so the result is provably a subset of both inputs.
fn intersect_paths(profile_paths: &[String], cap_paths: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for a in profile_paths {
        for b in cap_paths {
            if path_contains(b, a) {
                out.push(a.clone()); // a is within b: a is the narrower grant
            } else if path_contains(a, b) {
                out.push(b.clone()); // b is within a: b is the narrower grant
            }
            // disjoint: contributes nothing to the intersection
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Exact-membership intersection for non-path sets (domains, exec paths),
/// matching the exact-match semantics [`Capability::permits`] uses for those
/// axes (`net_domains.contains`, `allow_exec.contains`).
fn intersect_exact(profile_set: &[String], cap_set: &[String]) -> Vec<String> {
    let mut out: Vec<String> = profile_set
        .iter()
        .filter(|x| cap_set.contains(*x))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// One-line summary of a capability's grant counts, for the audit binding record.
pub fn capability_summary(cap: &Capability) -> String {
    format!(
        "read={} write={} net={} exec={}",
        cap.read_paths.len(),
        cap.write_paths.len(),
        cap.net_domains.len(),
        cap.allow_exec.len()
    )
}

/// `ql token bind-demo [out.json]` — show that a child's containment cell,
/// derived from an attenuated delegation token, is strictly narrower than the
/// operator's base profile. When `emit` is given, the real (signed) chain is
/// written there and the trust-root hex is printed, so the same invocation
/// doubles as a live fixture for `ql run --token-chain <out.json> --trust-root`.
pub fn bind_demo(emit: Option<&str>) -> String {
    use ql_token::{default_expiry, delegate, issue_root, verify_chain, Identity};

    let mut out = String::new();
    let mut line = |s: &str| {
        out.push_str(s);
        out.push('\n');
    };

    let now = now_ms();
    let exp = default_expiry(now);

    let root = match Identity::generate() {
        Ok(i) => i,
        Err(e) => return format!("bind-demo: rng failed: {e}\n"),
    };
    let agent_a = Identity::generate().expect("rng");
    let agent_b = Identity::generate().expect("rng");

    line("QuantmLayer token-to-cell binding — a child's cell is provably narrower");
    line("");

    // Root grants A a broad capability.
    let a_cap = Capability {
        read_paths: vec!["/ws/**".into()],
        write_paths: vec!["/ws/**".into()],
        net_domains: vec!["github.com".into(), "pypi.org".into()],
        allow_exec: vec!["/usr/bin/git".into()],
    };
    // A attenuates to B: read-only /ws/src, no write, no network, no exec.
    let b_cap = Capability {
        read_paths: vec!["/ws/src".into()],
        write_paths: vec![],
        net_domains: vec![],
        allow_exec: vec![],
    };

    let root_tok = match issue_root(&root, &agent_a.public(), a_cap, exp) {
        Ok(t) => t,
        Err(e) => return format!("bind-demo: issue_root failed: {e}\n"),
    };
    let b_tok = match delegate(&root_tok, &agent_a, &agent_b.public(), b_cap, exp) {
        Ok(t) => t,
        Err(e) => return format!("bind-demo: delegate failed: {e}\n"),
    };
    let chain = vec![root_tok, b_tok];

    // Verify the chain the way `ql run` will, and recover B's leaf capability.
    let trust = root.public();
    let leaf = match verify_chain(&chain, std::slice::from_ref(&trust), now) {
        Ok(c) => c,
        Err(e) => return format!("bind-demo: verify_chain failed: {e}\n"),
    };

    // The operator's base profile: read /ws/src, read-write /ws/**, two domains,
    // git. The token can only narrow this.
    let mut base = Profile::default();
    base.filesystem.readonly = vec!["/ws/src".into()];
    base.filesystem.readwrite = vec!["/ws/**".into()];
    base.network.allow_domains = vec!["github.com".into(), "pypi.org".into()];
    base.processes.allow_exec = vec!["/usr/bin/git".into()];

    let bound = bind_profile_to_capability(&base, &leaf);

    line("operator base profile:");
    for r in profile_rows(&base) {
        line(&r);
    }
    line("");
    line("child cell, derived from B's attenuated token (base INTERSECT token):");
    for r in profile_rows(&bound) {
        line(&r);
    }
    line("");
    line("=> the child may only read /ws/src; it cannot write, reach any domain,");
    line("   or exec git. Containment is derived from the token, not asserted.");

    if let Some(path) = emit {
        match serde_json::to_string_pretty(&chain) {
            Ok(json) => match std::fs::write(path, json) {
                Ok(()) => {
                    line("");
                    line(&format!("wrote signed chain to {path}"));
                    line(&format!(
                        "trust root (pass to --trust-root): {}",
                        trust.to_hex()
                    ));
                    line(&format!(
                        "try: ql run --profile base.yaml --token-chain {path} --trust-root {} -- <cmd>",
                        trust.to_hex()
                    ));
                }
                Err(e) => line(&format!("(could not write chain to {path}: {e})")),
            },
            Err(e) => line(&format!("(could not serialize chain: {e})")),
        }
    }

    out
}

/// Render a profile's four token-modeled axes as aligned display rows for the
/// demo. Each row is a single-argument `format!`, which keeps the call sites
/// short and rustfmt-stable.
fn profile_rows(p: &Profile) -> Vec<String> {
    let show = |v: &[String]| -> String {
        if v.is_empty() {
            "(none)".to_string()
        } else {
            v.join(", ")
        }
    };
    let ro = show(&p.filesystem.readonly);
    let rw = show(&p.filesystem.readwrite);
    let net = show(&p.network.allow_domains);
    let ex = show(&p.processes.allow_exec);
    vec![
        format!("  read-only   : {ro}"),
        format!("  read-write  : {rw}"),
        format!("  net domains : {net}"),
        format!("  exec allow  : {ex}"),
    ]
}

/// Current Unix time in milliseconds (local copy; `run.rs` has its own).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ql_token::{delegate, issue_root, verify_chain, Identity};

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // --- the §4a / §5 path-intersection corner cases ---------------------------

    #[test]
    fn intersect_paths_glob_over_specific_keeps_specific() {
        // /ws/** ∩ /ws/src = /ws/src
        assert_eq!(
            intersect_paths(&v(&["/ws/**"]), &v(&["/ws/src"])),
            v(&["/ws/src"])
        );
        // /ws/src ∩ /ws/** = /ws/src (order-independent)
        assert_eq!(
            intersect_paths(&v(&["/ws/src"]), &v(&["/ws/**"])),
            v(&["/ws/src"])
        );
    }

    #[test]
    fn intersect_paths_equal_globs_keep_glob() {
        // /ws/** ∩ /ws/** = /ws/**
        assert_eq!(
            intersect_paths(&v(&["/ws/**"]), &v(&["/ws/**"])),
            v(&["/ws/**"])
        );
    }

    #[test]
    fn intersect_paths_disjoint_is_empty() {
        // /a/** ∩ /b/** = ∅
        assert!(intersect_paths(&v(&["/a/**"]), &v(&["/b/**"])).is_empty());
    }

    #[test]
    fn intersect_paths_fans_out_to_each_narrower_grant() {
        // /ws/** ∩ {/ws/src, /ws/lib} = {/ws/lib, /ws/src}
        assert_eq!(
            intersect_paths(&v(&["/ws/**"]), &v(&["/ws/src", "/ws/lib"])),
            v(&["/ws/lib", "/ws/src"])
        );
    }

    #[test]
    fn intersect_exact_is_set_intersection() {
        assert_eq!(
            intersect_exact(&v(&["github.com", "pypi.org"]), &v(&["pypi.org"])),
            v(&["pypi.org"])
        );
        assert!(intersect_exact(&v(&["github.com"]), &v(&["pypi.org"])).is_empty());
    }

    // --- binding never widens; preserves untouched axes ------------------------

    #[test]
    fn bind_never_widens_and_preserves_other_axes() {
        let mut base = Profile::default();
        base.filesystem.readonly = v(&["/ws/src"]);
        base.filesystem.readwrite = v(&["/ws/**"]);
        base.filesystem.denied = v(&["/ws/secrets"]);
        base.network.allow_domains = v(&["github.com", "pypi.org"]);
        base.processes.allow_exec = v(&["/usr/bin/git", "/usr/bin/curl"]);

        let cap = Capability {
            read_paths: v(&["/ws/src"]),
            write_paths: v(&["/ws/src"]),
            net_domains: v(&["github.com"]),
            allow_exec: v(&["/usr/bin/git"]),
        };

        let bound = bind_profile_to_capability(&base, &cap);
        assert_eq!(bound.filesystem.readonly, v(&["/ws/src"]));
        assert_eq!(bound.filesystem.readwrite, v(&["/ws/src"]));
        assert_eq!(bound.network.allow_domains, v(&["github.com"]));
        assert_eq!(bound.processes.allow_exec, v(&["/usr/bin/git"]));
        // Untouched axes are preserved exactly.
        assert_eq!(bound.filesystem.denied, v(&["/ws/secrets"]));
        assert_eq!(bound.network.default_deny, base.network.default_deny);
        assert_eq!(bound.agent_type, base.agent_type);
    }

    #[test]
    fn empty_capability_yields_empty_grants() {
        let mut base = Profile::default();
        base.filesystem.readwrite = v(&["/ws/**"]);
        base.network.allow_domains = v(&["github.com"]);
        let cap = Capability::default();
        let bound = bind_profile_to_capability(&base, &cap);
        assert!(bound.filesystem.readwrite.is_empty());
        assert!(bound.network.allow_domains.is_empty());
    }

    // --- the full path: verify a real chain, then bind, then assert narrower ---

    #[test]
    fn verify_chain_then_bind_produces_strict_subset() {
        let now = 1_000_000u64;
        let exp = now + 60_000;
        let root = Identity::generate().unwrap();
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();

        let a_cap = Capability {
            read_paths: v(&["/ws/**"]),
            write_paths: v(&["/ws/**"]),
            net_domains: v(&["github.com", "pypi.org"]),
            allow_exec: v(&["/usr/bin/git"]),
        };
        let b_cap = Capability {
            read_paths: v(&["/ws/src"]),
            write_paths: v(&[]),
            net_domains: v(&[]),
            allow_exec: v(&[]),
        };
        let root_tok = issue_root(&root, &a.public(), a_cap, exp).unwrap();
        let b_tok = delegate(&root_tok, &a, &b.public(), b_cap, exp).unwrap();
        let chain = vec![root_tok, b_tok];

        let leaf = verify_chain(&chain, std::slice::from_ref(&root.public()), now).unwrap();

        let mut base = Profile::default();
        base.filesystem.readonly = v(&["/ws/src"]);
        base.filesystem.readwrite = v(&["/ws/**"]);
        base.network.allow_domains = v(&["github.com", "pypi.org"]);
        base.processes.allow_exec = v(&["/usr/bin/git"]);

        let bound = bind_profile_to_capability(&base, &leaf);
        assert_eq!(bound.filesystem.readonly, v(&["/ws/src"]));
        assert!(bound.filesystem.readwrite.is_empty());
        assert!(bound.network.allow_domains.is_empty());
        assert!(bound.processes.allow_exec.is_empty());
    }
}

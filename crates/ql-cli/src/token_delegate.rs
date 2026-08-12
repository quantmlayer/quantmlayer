// crates/ql-cli/src/token_delegate.rs
//
//! `ql token delegate` — hand a sub-agent a strictly narrower slice of an
//! existing credential.
//!
//! An orchestrating agent that spawns helpers currently has one lever: give
//! each helper the same authority it holds. That makes the blast radius of any
//! one helper equal to the blast radius of the whole task. Delegation lets the
//! parent hand down *less* — this helper may reach crates.io and nothing else
//! — with the narrowing enforced cryptographically rather than by convention.
//!
//! **This is wiring, not new mechanism.** [`ql_token::delegate`] already
//! refuses to broaden and [`ql_token::verify_chain`] already validates every
//! link; `ql-token`'s tests cover both. What was missing was a way to *use*
//! them: issuance minted a single-link chain and there was no path to extend
//! it. This module is that path.
//!
//! ## What the cascade guarantees, and what it does not
//!
//! Each link can only narrow, and the broker verifies the whole chain to a
//! trusted root, so a compromised sub-agent cannot mint itself more authority
//! than its parent held — the attenuation is checked at the point of use, not
//! trusted at the point of issue.
//!
//! It does **not** contain the sub-agent's process. A token governs what the
//! broker will *admit* from a client that presents it; the cell's walls are
//! what stop a process from acting. A sub-agent handed a narrow token but run
//! in a wide cell is still as dangerous as its cell. Narrow the cell too —
//! `--phase` and `ql compile` exist for that — and treat the token as the
//! identity layer over the top, never as a substitute.

use ql_token::{delegate, verify_chain, Capability, Identity, PublicId, Token};
use serde::{Deserialize, Serialize};
use std::io;
use std::os::unix::fs::PermissionsExt;

/// A delegated credential: the chain proving the sub-agent's authority derives
/// from a trusted root, plus the seed it signs with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedBundle {
    /// Hex public key of the session root the chain leads back to. Unchanged
    /// by delegation — the sub-agent answers to the same root.
    pub trust_root: String,
    /// Hex Ed25519 seed of the sub-agent identity. SECRET: it signs actions.
    pub subtask_seed: String,
    /// The full chain, root first. A verifier walks all of it; no link is
    /// taken on trust because an earlier one checked out.
    pub chain: Vec<Token>,
    /// Expiry in Unix milliseconds of the newly issued leaf.
    pub not_after_ms: u64,
}

/// How the caller wants the child's capability restricted.
#[derive(Debug, Clone, Default)]
pub struct Narrowing {
    /// Restrict egress to these domains.
    pub only_domains: Option<Vec<String>>,
    /// Restrict readable paths to these globs.
    pub only_read: Option<Vec<String>>,
    /// Restrict writable paths to these globs.
    pub only_write: Option<Vec<String>>,
    /// Restrict executables to these paths.
    pub only_exec: Option<Vec<String>>,
}

impl Narrowing {
    /// Apply this narrowing to `parent`, by **intersection**.
    ///
    /// Intersecting rather than replacing means a caller naming something the
    /// parent never held gets nothing, instead of producing a capability that
    /// [`ql_token::delegate`] would then reject outright. The result is the
    /// largest capability that is both what was asked for and within the
    /// parent's grant — so a typo narrows rather than failing the whole call.
    pub fn apply(&self, parent: &Capability) -> Capability {
        let keep = |have: &[String], want: &Option<Vec<String>>| -> Vec<String> {
            match want {
                None => have.to_vec(),
                Some(w) => have.iter().filter(|h| w.contains(h)).cloned().collect(),
            }
        };
        Capability {
            read_paths: keep(&parent.read_paths, &self.only_read),
            write_paths: keep(&parent.write_paths, &self.only_write),
            net_domains: keep(&parent.net_domains, &self.only_domains),
            allow_exec: keep(&parent.allow_exec, &self.only_exec),
        }
        .normalized()
    }

    /// True when no restriction was requested at all.
    pub fn is_empty(&self) -> bool {
        self.only_domains.is_none()
            && self.only_read.is_none()
            && self.only_write.is_none()
            && self.only_exec.is_none()
    }
}

/// Errors delegating a credential.
#[derive(Debug)]
pub enum DelegateError {
    /// The parent bundle could not be read or parsed.
    Bundle(String),
    /// The parent chain does not verify (expired, broken, or untrusted root).
    Chain(String),
    /// The token layer refused the delegation.
    Token(ql_token::TokenError),
}

impl std::fmt::Display for DelegateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegateError::Bundle(m) => write!(f, "parent credential: {m}"),
            DelegateError::Chain(m) => write!(f, "parent chain does not verify: {m}"),
            DelegateError::Token(e) => write!(f, "{e}"),
        }
    }
}

/// Extend `parent` with a new leaf for a freshly generated sub-agent.
///
/// The parent chain is verified **before** anything is issued: delegating from
/// a chain that does not itself verify would mint a credential that can never
/// be used, and would hide the real problem behind a later, more confusing
/// failure at the broker.
pub fn delegate_bundle(
    parent_chain: &[Token],
    trust_root: &str,
    parent_seed_hex: &str,
    narrowing: &Narrowing,
    not_after_ms: u64,
    now_ms: u64,
) -> Result<DelegatedBundle, DelegateError> {
    let root = PublicId::from_hex(trust_root)
        .map_err(|e| DelegateError::Bundle(format!("bad trust_root: {e}")))?;
    let parent_cap = verify_chain(parent_chain, std::slice::from_ref(&root), now_ms)
        .map_err(|e| DelegateError::Chain(e.to_string()))?;

    let parent_id = Identity::from_seed_hex(parent_seed_hex)
        .map_err(|e| DelegateError::Bundle(format!("bad subtask_seed: {e}")))?;
    let child = Identity::generate().map_err(DelegateError::Token)?;

    let leaf_tok = parent_chain.last().ok_or_else(|| {
        DelegateError::Bundle("chain is empty; nothing to delegate from".to_string())
    })?;

    // A child must not outlive its parent: a leaf expiring later than the link
    // above it would be unusable anyway (verify_chain checks every link), but
    // clamping here fails loudly at issue time instead of silently at use.
    let not_after_ms = not_after_ms.min(leaf_tok.body.not_after_ms);

    let cap = narrowing.apply(&parent_cap);
    let leaf = delegate(leaf_tok, &parent_id, &child.public(), cap, not_after_ms)
        .map_err(DelegateError::Token)?;

    let mut chain = parent_chain.to_vec();
    chain.push(leaf);
    Ok(DelegatedBundle {
        trust_root: trust_root.to_string(),
        subtask_seed: child.seed_hex(),
        chain,
        not_after_ms,
    })
}

/// Write `bundle` as pretty JSON, `0600` — it carries a signing seed.
pub fn write_bundle(path: &str, bundle: &DelegatedBundle) -> io::Result<()> {
    let json = serde_json::to_string_pretty(bundle).map_err(io::Error::other)?;
    std::fs::write(path, json)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Human-readable one-line summary of a capability, for the operator notice.
pub fn describe(cap: &Capability) -> String {
    format!(
        "{} domain(s), {} read, {} write, {} exec",
        cap.net_domains.len(),
        cap.read_paths.len(),
        cap.write_paths.len(),
        cap.allow_exec.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ql_token::{default_expiry, issue_root};

    fn root_bundle(now: u64) -> (Identity, Identity, Token) {
        let root = Identity::generate().unwrap();
        let agent = Identity::generate().unwrap();
        let cap = Capability {
            read_paths: vec!["/src/**".into()],
            write_paths: vec!["/work/**".into()],
            net_domains: vec!["crates.io".into(), "pypi.org".into()],
            allow_exec: vec!["/usr/bin/git".into(), "/usr/bin/cargo".into()],
        }
        .normalized();
        let tok = issue_root(&root, &agent.public(), cap, default_expiry(now)).unwrap();
        (root, agent, tok)
    }

    /// The cascade: a child holds a strict subset, and the whole chain still
    /// verifies to the original root.
    #[test]
    fn a_delegated_child_holds_a_strict_subset() {
        let now = 1_000_000;
        let (root, agent, tok) = root_bundle(now);
        let n = Narrowing {
            only_domains: Some(vec!["crates.io".into()]),
            ..Default::default()
        };
        let b = delegate_bundle(
            &[tok],
            &root.public().to_hex(),
            &agent.seed_hex(),
            &n,
            default_expiry(now),
            now,
        )
        .expect("delegates");

        assert_eq!(b.chain.len(), 2);
        let eff = verify_chain(&b.chain, &[root.public()], now).expect("chain verifies");
        assert_eq!(eff.net_domains, vec!["crates.io".to_string()]);
        // Untouched dimensions are inherited whole, not dropped.
        assert_eq!(eff.allow_exec.len(), 2);
    }

    /// **The invariant that makes cascading safe.** Asking for authority the
    /// parent never held yields nothing extra — narrowing intersects, so a
    /// child can never climb.
    #[test]
    fn asking_for_more_than_the_parent_held_grants_nothing() {
        let now = 1_000_000;
        let (root, agent, tok) = root_bundle(now);
        let n = Narrowing {
            only_domains: Some(vec!["crates.io".into(), "evil.example".into()]),
            only_exec: Some(vec!["/bin/sh".into()]),
            ..Default::default()
        };
        let b = delegate_bundle(
            &[tok],
            &root.public().to_hex(),
            &agent.seed_hex(),
            &n,
            default_expiry(now),
            now,
        )
        .expect("delegates");

        let eff = verify_chain(&b.chain, &[root.public()], now).unwrap();
        assert_eq!(eff.net_domains, vec!["crates.io".to_string()]);
        assert!(!eff.net_domains.iter().any(|d| d == "evil.example"));
        // /bin/sh was never in the parent's grant, so the child gets no exec.
        assert!(eff.allow_exec.is_empty());
    }

    /// Three levels deep still verifies, and each level is a subset of the one
    /// above it.
    #[test]
    fn attenuation_cascades_through_multiple_levels() {
        let now = 1_000_000;
        let (root, agent, tok) = root_bundle(now);

        let l1 = delegate_bundle(
            &[tok],
            &root.public().to_hex(),
            &agent.seed_hex(),
            &Narrowing {
                only_domains: Some(vec!["crates.io".into(), "pypi.org".into()]),
                ..Default::default()
            },
            default_expiry(now),
            now,
        )
        .unwrap();

        let l2 = delegate_bundle(
            &l1.chain,
            &l1.trust_root,
            &l1.subtask_seed,
            &Narrowing {
                only_domains: Some(vec!["crates.io".into()]),
                only_exec: Some(vec!["/usr/bin/cargo".into()]),
                ..Default::default()
            },
            l1.not_after_ms,
            now,
        )
        .unwrap();

        assert_eq!(l2.chain.len(), 3);
        let eff = verify_chain(&l2.chain, &[root.public()], now).expect("3-link chain verifies");
        assert_eq!(eff.net_domains, vec!["crates.io".to_string()]);
        assert_eq!(eff.allow_exec, vec!["/usr/bin/cargo".to_string()]);
    }

    /// A child cannot outlive its parent: an over-long expiry is clamped at
    /// issue time rather than producing a credential that fails later at use.
    #[test]
    fn a_child_cannot_outlive_its_parent() {
        let now = 1_000_000;
        let (root, agent, tok) = root_bundle(now);
        let parent_expiry = tok.body.not_after_ms;

        let b = delegate_bundle(
            &[tok],
            &root.public().to_hex(),
            &agent.seed_hex(),
            &Narrowing::default(),
            parent_expiry + 86_400_000, // ask for a day beyond the parent
            now,
        )
        .unwrap();
        assert_eq!(b.not_after_ms, parent_expiry);
    }

    /// Delegating from a chain that does not verify fails immediately, rather
    /// than minting a credential that could never be used.
    #[test]
    fn an_unverifiable_parent_chain_is_refused_up_front() {
        let now = 1_000_000;
        let (root, agent, tok) = root_bundle(now);
        let stranger = Identity::generate().unwrap();

        // Right chain, wrong root.
        let err = delegate_bundle(
            std::slice::from_ref(&tok),
            &stranger.public().to_hex(),
            &agent.seed_hex(),
            &Narrowing::default(),
            default_expiry(now),
            now,
        )
        .unwrap_err();
        assert!(matches!(err, DelegateError::Chain(_)), "{err}");

        // Expired parent.
        let err = delegate_bundle(
            &[tok],
            &root.public().to_hex(),
            &agent.seed_hex(),
            &Narrowing::default(),
            default_expiry(now),
            now + 10 * 86_400_000,
        )
        .unwrap_err();
        assert!(matches!(err, DelegateError::Chain(_)), "{err}");
    }

    /// Only the holder of the parent's seed can delegate from it — a stolen
    /// chain without its key is inert.
    #[test]
    fn delegating_requires_the_parents_signing_key() {
        let now = 1_000_000;
        let (root, _agent, tok) = root_bundle(now);
        let impostor = Identity::generate().unwrap();

        let err = delegate_bundle(
            &[tok],
            &root.public().to_hex(),
            &impostor.seed_hex(),
            &Narrowing::default(),
            default_expiry(now),
            now,
        )
        .unwrap_err();
        assert!(matches!(err, DelegateError::Token(_)), "{err}");
    }
}

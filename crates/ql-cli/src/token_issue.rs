// crates/ql-cli/src/token_issue.rs
//
//! Per-subtask credential issuance for `ql run`.
//!
//! Each contained subtask can be given its own short-lived, capability-
//! attenuated identity: a fresh keypair plus a token, signed by an ephemeral
//! session root, granting exactly the authority the enforced profile already
//! describes — the domains it may reach, the paths it may touch, the binaries
//! it may exec — and expiring on its own after a bounded default lifetime.
//!
//! This is the *issuance* half of token-gated enforcement. The *checking* half
//! already exists in the broker: point `ql broker --trust <root>` at the
//! session root emitted here, and a token-aware client that signs its egress
//! with this identity is admitted, while replays and expired tokens are
//! refused. A generic agent that never presents the token is unaffected —
//! issuing a credential does not change how the cell itself is contained.

use ql_profile::Profile;
use ql_token::{default_expiry, issue_root, Capability, Identity, Token};
use serde::{Deserialize, Serialize};
use std::io;
use std::os::unix::fs::PermissionsExt;

/// The capability a subtask should hold: exactly what the enforced profile
/// permits, expressed in the token layer's vocabulary.
pub fn subtask_capability(profile: &Profile) -> Capability {
    Capability {
        read_paths: profile.filesystem.readonly.clone(),
        write_paths: profile.filesystem.readwrite.clone(),
        net_domains: profile.network.allow_domains.clone(),
        allow_exec: profile.processes.allow_exec.clone(),
    }
    .normalized()
}

/// A credential bundle issued for one subtask. Written as JSON; the seed is a
/// secret (it is the subtask's signing key), so the file is created `0600`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialBundle {
    /// Hex public key of the ephemeral session root — pass to `ql broker --trust`.
    pub trust_root: String,
    /// Hex Ed25519 seed of the subtask identity. SECRET: it signs actions.
    pub subtask_seed: String,
    /// The token granting the subtask its capability (a single-link chain).
    pub token: Token,
    /// Expiry in Unix milliseconds, for human reference.
    pub not_after_ms: u64,
}

/// Mint an ephemeral session root and a fresh subtask identity, then issue the
/// subtask a token scoped to `profile`'s authority, expiring at
/// `default_expiry(now_ms)`.
pub fn issue_subtask(profile: &Profile, now_ms: u64) -> ql_token::Result<CredentialBundle> {
    let root = Identity::generate()?;
    let agent = Identity::generate()?;
    let not_after_ms = default_expiry(now_ms);
    let token = issue_root(
        &root,
        &agent.public(),
        subtask_capability(profile),
        not_after_ms,
    )?;
    Ok(CredentialBundle {
        trust_root: root.public().to_hex(),
        subtask_seed: agent.seed_hex(),
        token,
        not_after_ms,
    })
}

/// Serialize `bundle` to `path` as pretty JSON with `0600` permissions, because
/// it carries the subtask's signing seed.
pub fn write_bundle(path: &str, bundle: &CredentialBundle) -> io::Result<()> {
    let json = serde_json::to_string_pretty(bundle).map_err(io::Error::other)?;
    std::fs::write(path, json)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ql_token::{verify_chain, PublicId, TokenError};

    fn profile_with(domains: &[&str]) -> Profile {
        let mut p = Profile::default();
        p.network.allow_domains = domains.iter().map(|s| s.to_string()).collect();
        p.processes.allow_exec = vec!["/usr/bin/git".into()];
        p
    }

    #[test]
    fn capability_mirrors_profile_grants() {
        let cap = subtask_capability(&profile_with(&["pypi.org", "github.com"]));
        assert!(cap.net_domains.contains(&"pypi.org".to_string()));
        assert!(cap.allow_exec.contains(&"/usr/bin/git".to_string()));
    }

    #[test]
    fn issued_token_verifies_then_expires() {
        let now = 1_000_000;
        let b = issue_subtask(&profile_with(&["pypi.org"]), now).unwrap();

        // Valid before expiry...
        let root = PublicId::from_hex(&b.trust_root).unwrap();
        assert!(verify_chain(std::slice::from_ref(&b.token), &[root], now).is_ok());

        // ...and refused once the bounded lifetime has elapsed.
        let root = PublicId::from_hex(&b.trust_root).unwrap();
        assert!(matches!(
            verify_chain(&[b.token], &[root], b.not_after_ms + 1),
            Err(TokenError::Expired)
        ));
    }
}

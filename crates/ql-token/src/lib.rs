// crates/ql-token/src/lib.rs
//! Agent identity and capability-attenuating delegation tokens.
//!
//! Authority flows from a trusted root down a tree of agents and may only ever
//! *narrow*: each delegated token is signed by the parent agent, commits to its
//! parent by hash, and must carry a capability that is a subset of the parent's.
//! [`verify_chain`] proves the whole path; [`verify_action`] proves a concrete
//! signed tool call is within the granted authority.
//!
//! This is the cryptographic mechanism. Wiring it into live enforcement — the
//! cell requiring a valid token before it runs, the broker checking a signed
//! action before egress — is a separate integration step.

mod capability;
mod error;
mod identity;
mod token;

pub use capability::{Action, Capability};
pub use error::{Result, TokenError};
pub use identity::{Identity, PublicId};
pub use token::{
    authorize, default_expiry, delegate, issue_root, sign_action, verify_action, verify_chain,
    ActionBody, AuthzRequest, SignedAction, Token, TokenBody, DEFAULT_TTL_MS,
};

/// A self-contained narrated walkthrough of the whole flow, for `ql token demo`.
/// Generates ephemeral identities, issues and attenuates a token, shows a
/// broadening attempt rejected, and verifies a signed action.
pub fn demo() -> String {
    let mut out = String::new();
    let mut line = |s: &str| {
        out.push_str(s);
        out.push('\n');
    };

    let root = Identity::generate().expect("rng");
    let agent_a = Identity::generate().expect("rng");
    let agent_b = Identity::generate().expect("rng");

    line("QuantmLayer delegation tokens — authority that only narrows");
    line("");
    line(&format!(
        "root authority : {}…",
        &root.public().to_hex()[..16]
    ));
    line(&format!(
        "agent A        : {}…",
        &agent_a.public().to_hex()[..16]
    ));
    line(&format!(
        "agent B        : {}…",
        &agent_b.public().to_hex()[..16]
    ));
    line("");

    // Root grants A a broad capability.
    let a_cap = Capability {
        read_paths: vec!["/ws/**".into()],
        write_paths: vec!["/ws/**".into()],
        net_domains: vec!["pypi.org".into()],
        allow_exec: vec!["/usr/bin/python3".into()],
    };
    let root_token = issue_root(&root, &agent_a.public(), a_cap, 0).expect("issue");
    line("root → A: { rw /ws/**, net pypi.org, exec python3 }");

    // A delegates to B, attenuated to read-only and no network.
    let b_cap = Capability {
        read_paths: vec!["/ws/**".into()],
        write_paths: vec![],
        net_domains: vec![],
        allow_exec: vec![],
    };
    let b_token = delegate(&root_token, &agent_a, &agent_b.public(), b_cap, 0).expect("delegate");
    line("A → B: attenuated to { ro /ws/** }  (no write, no network)");
    line("");

    let chain = vec![root_token, b_token.clone()];
    let trusted = vec![root.public()];
    let now = now_ms();
    match verify_chain(&chain, &trusted, now) {
        Ok(_) => line("verify chain    : OK — every link narrows authority ✓"),
        Err(e) => line(&format!("verify chain    : FAILED — {e}")),
    }

    // B signs a permitted read.
    let read = Action::FsRead {
        path: "/ws/src/main.py".into(),
    };
    let sa = sign_action(&agent_b, read, &b_token.hash(), 1).expect("sign");
    match verify_action(&sa, &b_token, &b_token.body.capability) {
        Ok(()) => line("B reads /ws/src : ALLOWED ✓  (within B's grant)"),
        Err(e) => line(&format!("B reads /ws/src : denied — {e}")),
    }

    // B attempts a write it was not granted.
    let write = Action::FsWrite {
        path: "/ws/src/main.py".into(),
    };
    let sa2 = sign_action(&agent_b, write, &b_token.hash(), 2).expect("sign");
    match verify_action(&sa2, &b_token, &b_token.body.capability) {
        Ok(()) => line("B writes /ws/src: ALLOWED (unexpected!)"),
        Err(_) => line("B writes /ws/src: DENIED ✓  (attenuated to read-only)"),
    }

    // A tries to delegate something it never held (broadening).
    let over = Capability {
        net_domains: vec!["evil.example.com".into()],
        ..Default::default()
    };
    match delegate(&chain[0], &agent_a, &agent_b.public(), over, 0) {
        Ok(_) => line("A → B broaden   : ACCEPTED (unexpected!)"),
        Err(_) => line("A → B broaden   : REJECTED ✓  (cannot grant net it never had)"),
    }

    out
}

/// Current Unix time in milliseconds.
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broad_cap() -> Capability {
        Capability {
            read_paths: vec!["/ws/**".into()],
            write_paths: vec!["/ws/**".into()],
            net_domains: vec!["pypi.org".into()],
            allow_exec: vec!["/usr/bin/python3".into()],
        }
    }

    #[test]
    fn default_ttl_bounds_expiry_and_token_expires() {
        let now = 1_000_000;
        assert_eq!(default_expiry(now), now + DEFAULT_TTL_MS);

        let root = Identity::generate().unwrap();
        let a = Identity::generate().unwrap();
        let rt = issue_root(&root, &a.public(), broad_cap(), default_expiry(now)).unwrap();

        // Valid before expiry; rejected once the bounded lifetime has passed.
        assert!(verify_chain(std::slice::from_ref(&rt), &[root.public()], now).is_ok());
        let after = default_expiry(now) + 1;
        assert!(matches!(
            verify_chain(&[rt], &[root.public()], after),
            Err(TokenError::Expired)
        ));
    }

    #[test]
    fn valid_chain_verifies_and_returns_leaf_cap() {
        let root = Identity::generate().unwrap();
        let a = Identity::generate().unwrap();
        let rt = issue_root(&root, &a.public(), broad_cap(), 0).unwrap();
        let cap = verify_chain(&[rt], &[root.public()], 0).unwrap();
        assert!(cap.net_domains.contains(&"pypi.org".to_string()));
    }

    #[test]
    fn attenuation_narrows_and_broadening_is_rejected() {
        let root = Identity::generate().unwrap();
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let rt = issue_root(&root, &a.public(), broad_cap(), 0).unwrap();

        // narrowing to read-only /ws is fine
        let narrow = Capability {
            read_paths: vec!["/ws/src".into()],
            ..Default::default()
        };
        assert!(delegate(&rt, &a, &b.public(), narrow, 0).is_ok());

        // granting a domain the parent never had is rejected
        let broaden = Capability {
            net_domains: vec!["evil.com".into()],
            ..Default::default()
        };
        assert!(matches!(
            delegate(&rt, &a, &b.public(), broaden, 0),
            Err(TokenError::Broadened(_))
        ));
    }

    #[test]
    fn wrong_delegator_is_rejected() {
        let root = Identity::generate().unwrap();
        let a = Identity::generate().unwrap();
        let imposter = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let rt = issue_root(&root, &a.public(), broad_cap(), 0).unwrap();
        // imposter (not A) tries to delegate A's token
        assert!(delegate(&rt, &imposter, &b.public(), Capability::default(), 0).is_err());
    }

    #[test]
    fn tampered_capability_breaks_verification() {
        let root = Identity::generate().unwrap();
        let a = Identity::generate().unwrap();
        let mut rt = issue_root(&root, &a.public(), broad_cap(), 0).unwrap();
        // tamper: widen the capability after signing
        rt.body.capability.net_domains.push("evil.com".into());
        assert!(matches!(
            verify_chain(&[rt], &[root.public()], 0),
            Err(TokenError::Signature)
        ));
    }

    #[test]
    fn untrusted_root_is_rejected() {
        let root = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        let a = Identity::generate().unwrap();
        let rt = issue_root(&root, &a.public(), broad_cap(), 0).unwrap();
        assert!(matches!(
            verify_chain(&[rt], &[other.public()], 0),
            Err(TokenError::UntrustedRoot)
        ));
    }

    #[test]
    fn expired_token_is_rejected() {
        let root = Identity::generate().unwrap();
        let a = Identity::generate().unwrap();
        let rt = issue_root(&root, &a.public(), broad_cap(), 1_000).unwrap();
        assert!(matches!(
            verify_chain(&[rt], &[root.public()], 2_000),
            Err(TokenError::Expired)
        ));
    }

    #[test]
    fn signed_action_within_capability_is_allowed_else_denied() {
        let root = Identity::generate().unwrap();
        let a = Identity::generate().unwrap();
        let ro = Capability {
            read_paths: vec!["/ws/**".into()],
            ..Default::default()
        };
        let rt = issue_root(&root, &a.public(), ro, 0).unwrap();

        let ok = sign_action(
            &a,
            Action::FsRead {
                path: "/ws/a.py".into(),
            },
            &rt.hash(),
            1,
        )
        .unwrap();
        assert!(verify_action(&ok, &rt, &rt.body.capability).is_ok());

        let bad = sign_action(
            &a,
            Action::FsWrite {
                path: "/ws/a.py".into(),
            },
            &rt.hash(),
            2,
        )
        .unwrap();
        assert!(matches!(
            verify_action(&bad, &rt, &rt.body.capability),
            Err(TokenError::ActionDenied(_))
        ));
    }

    #[test]
    fn full_two_hop_chain_with_action() {
        let root = Identity::generate().unwrap();
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let rt = issue_root(&root, &a.public(), broad_cap(), 0).unwrap();
        let ro = Capability {
            read_paths: vec!["/ws/**".into()],
            ..Default::default()
        };
        let bt = delegate(&rt, &a, &b.public(), ro, 0).unwrap();
        let cap = verify_chain(&[rt, bt.clone()], &[root.public()], 0).unwrap();
        assert!(cap.write_paths.is_empty());

        let act = sign_action(
            &b,
            Action::FsRead {
                path: "/ws/x".into(),
            },
            &bt.hash(),
            1,
        )
        .unwrap();
        assert!(verify_action(&act, &bt, &cap).is_ok());
    }
}

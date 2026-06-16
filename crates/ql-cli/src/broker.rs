// crates/ql-cli/src/broker.rs
//
//! `ql broker` — run the egress broker (HTTP CONNECT proxy) from a profile.
//!
//! By default it enforces the profile's static domain allow-list. With
//! `--trust <root-pubkey-hex>` it switches to *token-gated* egress: a request
//! must carry a valid signed delegation token (in `X-QL-Authorization`) whose
//! capability permits the destination. `--audit <log>` records every decision
//! to a tamper-evident log.

use ql_audit::SystemIdentity;
use ql_broker::{serve, AuditSink, BrokerPolicy};
use ql_profile::Profile;
use ql_token::PublicId;
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

/// Entry point for `ql broker`.
pub fn cmd(args: &[String]) -> ExitCode {
    let mut profile_path: Option<String> = None;
    let mut listen = "127.0.0.1:8080".to_string();
    let mut trust: Vec<String> = Vec::new();
    let mut audit: Option<String> = None;
    let mut system_id: Option<String> = None;
    let mut model_version: Option<String> = None;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--profile" => profile_path = it.next().cloned(),
            "--listen" => {
                if let Some(v) = it.next() {
                    listen = v.clone();
                }
            }
            "--trust" => {
                if let Some(v) = it.next() {
                    trust.push(v.clone());
                }
            }
            "--audit" => audit = it.next().cloned(),
            "--system-id" => system_id = it.next().cloned(),
            "--model-version" => model_version = it.next().cloned(),
            other => {
                eprintln!("ql broker: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    let Some(path) = profile_path else {
        eprintln!("ql broker: --profile <p.yaml> is required");
        return ExitCode::from(2);
    };

    let yaml = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql broker: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let profile = match Profile::from_yaml(&yaml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ql broker: invalid profile: {e}");
            return ExitCode::from(2);
        }
    };

    // Parse trusted roots, if token-gating was requested.
    let mut roots = Vec::new();
    for hex in &trust {
        match PublicId::from_hex(hex) {
            Ok(pk) => roots.push(pk),
            Err(e) => {
                eprintln!("ql broker: bad --trust key `{hex}`: {e}");
                return ExitCode::from(2);
            }
        }
    }

    let mut policy = BrokerPolicy::from_net_policy(&profile.network);
    let gated = !roots.is_empty();
    if gated {
        policy = policy.with_token_gating(roots);
    }
    if let Some(ref a) = audit {
        policy = policy.with_audit(AuditSink::new(a));
    }
    if let Some(id) = system_id {
        policy = policy.with_system(SystemIdentity::ai_system(id, model_version));
    }
    let policy = Arc::new(policy);

    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ql broker: cannot bind {listen}: {e}");
            return ExitCode::from(1);
        }
    };
    if gated {
        eprintln!(
            "ql broker: listening on {listen}; token-gated egress ({} trusted root(s)){}",
            trust.len(),
            audit
                .as_ref()
                .map(|a| format!(", auditing to {a}"))
                .unwrap_or_default()
        );
    } else {
        eprintln!(
            "ql broker: listening on {listen}; {} allow-listed domain(s)",
            profile.network.allow_domains.len()
        );
    }

    if let Err(e) = serve(listener, policy) {
        eprintln!("ql broker: server error: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

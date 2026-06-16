// crates/ql-cli/src/policy.rs
//
//! Write a tamper-evident **policy record** for an enforced profile.
//!
//! At `ql run`, before the agent executes, we append to the hash-chained audit
//! log a commitment to the policy that is about to govern the session: a header
//! summarizing it, then one record per grant carrying its risk level and the
//! reason it exists. Because the records are chained ([`ql_audit`]), the result
//! is a compliance artifact — "proof of what policy ran and why each permission
//! exists" — that anyone can re-verify with `ql audit verify`, without trusting
//! the producer.

use ql_audit::{AuditEvent, AuditLog, Decision};
use ql_learn::risk_report_for_profile;
use ql_profile::Profile;
use ql_risk::RiskLevel;
use std::path::Path;

/// Append a policy record for `profile` to the audit log at `log_path`,
/// classifying each grant from `project_root`'s perspective. Returns the number
/// of records written (header + one per grant).
pub fn record_enforced(
    log_path: &str,
    profile: &Profile,
    project_root: Option<&Path>,
) -> std::io::Result<usize> {
    let report = risk_report_for_profile(profile, project_root);
    let mut log = load_or_new(log_path)?;

    // Header: commit to the policy as a whole and its risk summary.
    let s = &report.summary;
    let header = AuditEvent {
        ts_millis: AuditLog::now_millis(),
        actor: "run".to_string(),
        action: "policy.enforce".to_string(),
        target: format!("agent:{}", report.agent),
        decision: Decision::Info,
        detail: format!(
            "{} grant(s): {} allow-candidate, {} review, {} deny-by-default; {}",
            report.grants.len(),
            s.allow_candidate,
            s.review,
            s.deny_by_default,
            report.basis
        ),
    };
    log.append(header).map_err(to_io)?;

    // One record per grant — the "why each permission exists" trail.
    for g in &report.grants {
        let decision = match g.level {
            RiskLevel::AllowCandidate => Decision::Allow,
            RiskLevel::Review => Decision::Info,
            RiskLevel::DenyByDefault => Decision::Deny,
        };
        let event = AuditEvent {
            ts_millis: AuditLog::now_millis(),
            actor: "run".to_string(),
            action: "policy.grant".to_string(),
            target: g.resource.clone(),
            decision,
            detail: format!("{:?}/{:?}: {}", g.level, g.confidence, g.reason),
        };
        log.append(event).map_err(to_io)?;
    }

    let text = log.to_jsonl().map_err(to_io)?;
    std::fs::write(log_path, text)?;
    Ok(report.grants.len() + 1)
}

/// Load an existing chain to append to, or start a fresh one if the file does
/// not exist yet. A corrupt existing log is an error: we never silently start a
/// new chain over a damaged one.
fn load_or_new(path: &str) -> std::io::Result<AuditLog> {
    match std::fs::read_to_string(path) {
        Ok(s) => AuditLog::from_jsonl(&s).map_err(to_io),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AuditLog::new()),
        Err(e) => Err(e),
    }
}

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

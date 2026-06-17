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

use ql_audit::{AuditEvent, AuditLog, Decision, SystemIdentity};
use ql_learn::risk_report_for_profile;
use ql_profile::{diff, Profile};
use ql_risk::RiskLevel;
use std::path::Path;

/// Append a policy record for `enforced` to the audit log at `log_path`,
/// classifying each grant from `project_root`'s perspective. If `proposed` is
/// given (the originally learned profile), the grant lines the approval added
/// or removed are appended too — the reviewer-changes trail. When `system` is
/// given, every record is attributed to that AI system (EU AI Act Art. 12).
/// Returns the number of records written.
pub fn record_enforced(
    log_path: &str,
    enforced: &Profile,
    proposed: Option<&Profile>,
    project_root: Option<&Path>,
    system: Option<&SystemIdentity>,
) -> std::io::Result<usize> {
    let report = risk_report_for_profile(enforced, project_root);
    let mut log = load_or_new(log_path)?;
    let mut written = 0usize;

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
        system: system.cloned(),
    };
    log.append(header).map_err(to_io)?;
    written += 1;

    // If the profile carries an authorizing signature, record who signed it and
    // the signature that committed this policy — so the trail names the
    // change-control authority for the session, not just the policy itself.
    if let Some(sig) = &enforced.signature {
        let mut detail = format!("{}; sig {}", sig.algorithm, sig.value);
        if let Some(ap) = &enforced.approved_for {
            if let Some(c) = &ap.commit {
                detail = format!("{detail}; commit {c}");
            }
            if let Some(i) = &ap.image_digest {
                detail = format!("{detail}; image {i}");
            }
        }
        let event = AuditEvent {
            ts_millis: AuditLog::now_millis(),
            actor: "run".to_string(),
            action: "policy.signed".to_string(),
            target: sig.public_key.clone(),
            decision: Decision::Info,
            detail,
            system: system.cloned(),
        };
        log.append(event).map_err(to_io)?;
        written += 1;
    }

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
            system: system.cloned(),
        };
        log.append(event).map_err(to_io)?;
        written += 1;
    }

    // Commit to the content-addressed exec allow-list the kernel wall actually
    // enforces (the SHA-256 digests, not just the exec paths classified above).
    // These are the exact digests `bpf_ima_file_hash` checks at every execve, so
    // pinning them in the chain is the tamper-evident record of what content was
    // permitted to run — defeating copy-rename, where the path changes but the
    // content (hence the digest) does not.
    if enforced.exec.enforce && !enforced.exec.allow_digests.is_empty() {
        let header = AuditEvent {
            ts_millis: AuditLog::now_millis(),
            actor: "run".to_string(),
            action: "exec.enforce".to_string(),
            target: "content-addressed exec".to_string(),
            decision: Decision::Info,
            detail: format!(
                "{} digest(s) approved; deny-by-default",
                enforced.exec.allow_digests.len()
            ),
            system: system.cloned(),
        };
        log.append(header).map_err(to_io)?;
        written += 1;

        for d in &enforced.exec.allow_digests {
            let event = AuditEvent {
                ts_millis: AuditLog::now_millis(),
                actor: "run".to_string(),
                action: "exec.digest".to_string(),
                target: d.to_string(),
                decision: Decision::Allow,
                detail: "enforced content digest".to_string(),
                system: system.cloned(),
            };
            log.append(event).map_err(to_io)?;
            written += 1;
        }
    }

    // Reviewer-changes trail: what the approved policy added or removed relative
    // to the originally proposed (learned) one.
    if let Some(prop) = proposed {
        let changes = diff(prop, enforced);
        for g in &changes.added {
            let event = change_event(
                "policy.add",
                g.category,
                &g.value,
                "in enforced, not proposed",
                system,
            );
            log.append(event).map_err(to_io)?;
            written += 1;
        }
        for g in &changes.removed {
            let event = change_event(
                "policy.remove",
                g.category,
                &g.value,
                "in proposed, not enforced",
                system,
            );
            log.append(event).map_err(to_io)?;
            written += 1;
        }
    }

    let text = log.to_jsonl().map_err(to_io)?;
    std::fs::write(log_path, text)?;
    Ok(written)
}

/// Build a `policy.add` / `policy.remove` change record.
fn change_event(
    action: &str,
    category: &str,
    value: &str,
    detail: &str,
    system: Option<&SystemIdentity>,
) -> AuditEvent {
    AuditEvent {
        ts_millis: AuditLog::now_millis(),
        actor: "run".to_string(),
        action: action.to_string(),
        target: format!("{category} {value}"),
        decision: Decision::Info,
        detail: detail.to_string(),
        system: system.cloned(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ql_profile::{ExecDigest, HashAlgo};

    #[test]
    fn commits_enforced_exec_digests_attributed() {
        let digest = ExecDigest::new(HashAlgo::Sha256, "bf".repeat(32)).unwrap();
        let mut profile = Profile::default();
        profile.exec.enforce = true;
        profile.exec.allow_digests.push(digest);
        let sys = SystemIdentity::ai_system("coding-agent-prod", None);

        let name = format!("ql-policy-test-{}.jsonl", std::process::id());
        let path = std::env::temp_dir().join(name);
        let p = path.to_str().expect("temp path is utf-8");
        let _ = std::fs::remove_file(p);

        let n = record_enforced(p, &profile, None, None, Some(&sys)).unwrap();
        assert!(n >= 2, "expected an exec.enforce header + a digest record");

        let log = AuditLog::from_jsonl(&std::fs::read_to_string(p).unwrap()).unwrap();
        assert!(log.verify().is_ok(), "chain must stay intact");

        let recs = log.records();
        let actions: Vec<&str> = recs.iter().map(|r| r.event.action.as_str()).collect();
        assert!(actions.contains(&"exec.enforce"));
        assert!(actions.contains(&"exec.digest"));

        let digest_rec = recs
            .iter()
            .find(|r| r.event.action == "exec.digest")
            .unwrap();
        let attributed = digest_rec.event.system.as_ref().expect("attributed");
        assert_eq!(attributed.system_id, "coding-agent-prod");

        let _ = std::fs::remove_file(p);
    }
}

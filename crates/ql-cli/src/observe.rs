// crates/ql-cli/src/observe.rs
//
//! `ql run --observe` — a non-enforcing dry run.
//!
//! Launch the real agent, let **every** action through unblocked, but evaluate
//! each observed action against the loaded profile and report what enforce mode
//! *would* have done. It answers the question a design partner actually has —
//! "if I turn this on, what breaks, and what does it catch?" — without the risk
//! of turning it on. This is the observe→enforce on-ramp.
//!
//! Every verdict routes through `ql-profile`'s shared evaluator, so an observe
//! `would-deny` is provably the same decision enforce would reach.
//!
//! ## SAFETY
//! During observe the agent is genuinely **NOT contained** — it can read
//! `~/.ssh`, reach any network, run any binary. Observe is a monitoring run,
//! not protection. The `OBSERVE MODE — NOT ENFORCING` banner is printed at
//! start and end, and every audit record is tagged non-enforcing, so a log
//! reader can never mistake an observe run for an enforce run.

use ql_learn::{evaluate, observe_trace, Verdict};
use std::process::ExitCode;

/// Options parsed for an observe run (shared plumbing with `ql run`).
pub struct ObserveOpts {
    /// On-disk profile path, or `None` when a bundled agent was named.
    pub profile_path: Option<String>,
    /// Bundled agent name (`--agent`), or `None`.
    pub agent_name: Option<String>,
    /// Optional audit-log path for the full tagged event stream.
    pub audit_path: Option<String>,
    /// `--strict`: exit non-zero if any would-deny occurred (CI-gate mode).
    pub strict: bool,
    /// `--system-id` for audit attribution.
    pub system_id: Option<String>,
    /// `--model-version` (only with `--system-id`).
    pub model_version: Option<String>,
    /// `--result-json <path>`: write the machine-readable outcome here.
    pub result_json: Option<String>,
    /// The command to observe (everything after `--`).
    pub command: Vec<String>,
}

const BANNER: &str = "\
==================================================================
  OBSERVE MODE - NOT ENFORCING
  The agent is NOT contained. It can read secrets, reach the
  network, and run any binary. This run only REPORTS what enforce
  mode would have done. Do not mistake it for protection.
==================================================================";

/// Entry point for `ql run --observe`.
pub fn cmd(opts: ObserveOpts) -> ExitCode {
    if opts.command.is_empty() {
        eprintln!("ql run --observe: no command given (everything after `--` is the command)");
        return ExitCode::from(2);
    }

    // Resolve the profile to diff against — same source rules as `ql run`.
    let (profile, origin) = match crate::run::resolve_profile_for_observe(
        opts.profile_path.as_deref(),
        opts.agent_name.as_deref(),
    ) {
        Ok(p) => p,
        Err(code) => return code,
    };

    eprintln!("{BANNER}");
    eprintln!(
        "ql observe: diffing `{}` against {origin}",
        opts.command.join(" ")
    );

    // Trace the agent to completion (uncontained), digest-filled.
    let obs = match observe_trace(&opts.command) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ql observe: trace failed: {e}");
            return ExitCode::from(1);
        }
    };

    // Evaluate every observed action against the profile.
    let report = evaluate(&obs, &profile);

    // Emit the full tagged stream to the audit chain, if requested.
    if let Some(audit) = opts.audit_path.as_deref() {
        write_observe_audit(audit, &report, &opts);
    }

    // Human summary.
    print_summary(&report);
    eprintln!("{BANNER}");

    // --strict: any would-deny fails the run (CI gate). Exit code 3 is the
    // documented "policy finding" code (docs/MACHINE-INTERFACE.md): distinct
    // from 1 (ql could not run) and from the agent's own failure, so a CI
    // step can gate on findings without ambiguity.
    let wd = report.would_deny_count();
    let strict_failed = opts.strict && wd > 0;
    if let Some(path) = opts.result_json.as_deref() {
        let findings: Vec<(String, String)> = report
            .would_deny()
            .map(|f| (f.kind.to_string(), f.target.clone()))
            .collect();
        crate::result::write_observe(path, &origin, opts.strict, &findings, strict_failed);
    }
    if strict_failed {
        eprintln!("ql observe: --strict: {wd} would-deny finding(s) — failing run");
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}

/// Print the end-of-run summary: per-dimension counts and the would-deny list.
fn print_summary(report: &ql_learn::ObserveReport) {
    let wd = report.would_deny_count();
    eprintln!(
        "\nql observe summary: {} exec, {} file-open, {} external endpoint(s); {wd} would-deny",
        report.exec_total,
        report.file_total,
        report.external_endpoints.len(),
    );
    if wd > 0 {
        eprintln!("  what enforce mode WOULD HAVE BLOCKED:");
        for f in report.would_deny() {
            eprintln!("    would-deny: {:<6} {}", f.kind, f.target);
        }
    }
    if !report.external_endpoints.is_empty() {
        eprintln!(
            "  network: {} external endpoint(s) observed — domain allow/deny is the broker's\n\
             \x20           job (run with --broker to see per-domain decisions), not evaluated here.",
            report.external_endpoints.len()
        );
    }
}

/// Write every finding into the hash-chained audit log, each tagged
/// `observe`/non-enforcing so it can never be read as an enforce decision.
fn write_observe_audit(audit_path: &str, report: &ql_learn::ObserveReport, opts: &ObserveOpts) {
    use ql_audit::{AuditEvent, AuditLog, Decision, SystemIdentity};

    let system = opts
        .system_id
        .clone()
        .map(|id| SystemIdentity::ai_system(id, opts.model_version.clone()));

    let mut log = AuditLog::new();
    for f in &report.findings {
        // Observe never enforces: an allow is Info, a would-deny is Deny but
        // the action string marks it observe-only so it is unmistakable.
        let (decision, action) = match f.verdict {
            Verdict::Allow => (Decision::Info, format!("observe.{}.allow", f.kind)),
            Verdict::WouldDeny => (Decision::Deny, format!("observe.{}.would_deny", f.kind)),
        };
        let event = AuditEvent {
            ts_millis: AuditLog::now_millis(),
            actor: "observe".to_string(),
            action,
            target: f.target.clone(),
            decision,
            detail: "NOT ENFORCING (observe mode)".to_string(),
            system: system.clone(),
        };
        if log.append(event).is_err() {
            eprintln!("ql observe: audit append failed");
            return;
        }
    }
    match log.to_jsonl() {
        Ok(text) => {
            if let Err(e) = std::fs::write(audit_path, text) {
                eprintln!("ql observe: could not write audit log {audit_path}: {e}");
            } else {
                eprintln!(
                    "ql observe: wrote {} observe record(s) to {audit_path}",
                    report.findings.len()
                );
            }
        }
        Err(e) => eprintln!("ql observe: audit serialize failed: {e}"),
    }
}

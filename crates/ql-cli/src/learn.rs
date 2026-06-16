// crates/ql-cli/src/learn.rs
//
//! `ql learn` — observe an agent and synthesize a least-privilege profile.
//!
//! Run the agent through the tracer permissively (it is *not* contained during
//! learning), watch what it actually does, and emit a profile tightened to
//! exactly that. The generated profile can then be enforced with `ql run`.

use ql_learn::{build_risk_report, learn};
use std::process::ExitCode;

/// Entry point for `ql learn`.
pub fn cmd(args: &[String]) -> ExitCode {
    let sep = args.iter().position(|a| a == "--");
    let (opts, command): (&[String], &[String]) = match sep {
        Some(i) => (&args[..i], &args[i + 1..]),
        None => (args, &[]),
    };

    let mut out: Option<String> = None;
    let mut verbose = false;
    let mut it = opts.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = it.next().cloned(),
            "--verbose" => verbose = true,
            other => {
                eprintln!("ql learn: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    if command.is_empty() {
        eprintln!("ql learn: no command given (everything after `--` is the command to observe)");
        return ExitCode::from(2);
    }

    eprintln!("ql learn: observing `{}`...", command.join(" "));
    let outcome = match learn(command) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ql learn: {e}");
            return ExitCode::from(1);
        }
    };

    if verbose {
        let o = &outcome.observation;
        eprintln!(
            "ql learn: observed {} process(es), {} reads, {} writes, {} exec(s), \
             {} connect(s), {} distinct syscall(s)",
            o.process_count,
            o.reads.len(),
            o.writes.len(),
            o.execs.len(),
            o.connects.len(),
            o.syscalls.len(),
        );
    }

    let yaml = match outcome.profile.to_yaml() {
        Ok(y) => y,
        Err(e) => {
            eprintln!("ql learn: could not serialize profile: {e}");
            return ExitCode::from(1);
        }
    };

    // Notes go to stderr so stdout stays a clean profile when piped.
    for note in &outcome.notes {
        eprintln!("ql learn: note — {note}");
    }

    match out {
        Some(path) => match std::fs::write(&path, &yaml) {
            Ok(()) => {
                eprintln!("ql learn: wrote least-privilege profile to {path}");
                write_risk_report(&outcome, &path)
            }
            Err(e) => {
                eprintln!("ql learn: cannot write {path}: {e}");
                ExitCode::from(1)
            }
        },
        None => {
            print!("{yaml}");
            ExitCode::SUCCESS
        }
    }
}

/// Write the per-grant risk report next to the profile at `out`. Returns the
/// command's exit code: success only if both files were written.
fn write_risk_report(outcome: &ql_learn::LearnOutcome, out: &str) -> ExitCode {
    // The directory the agent was launched in is the project root, so files
    // under it classify as project-local rather than generic home paths.
    let project_root = std::env::current_dir().ok();
    let report = build_risk_report(
        &outcome.profile,
        &outcome.observation,
        project_root.as_deref(),
    );

    let report_path = risk_report_path(out);
    match std::fs::write(&report_path, report.to_json_pretty()) {
        Ok(()) => {
            let s = &report.summary;
            eprintln!(
                "ql learn: wrote risk report to {report_path} \
                 ({} allow-candidate, {} review, {} deny-by-default)",
                s.allow_candidate, s.review, s.deny_by_default
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ql learn: wrote profile but could not write {report_path}: {e}");
            ExitCode::from(1)
        }
    }
}

/// Derive the risk-report path from the profile path: `agent.yaml` becomes
/// `agent.risk-report.json`; an extensionless path just gets the suffix.
fn risk_report_path(out: &str) -> String {
    let stem = out
        .strip_suffix(".yaml")
        .or_else(|| out.strip_suffix(".yml"))
        .unwrap_or(out);
    format!("{stem}.risk-report.json")
}

// crates/ql-cli/src/ci.rs
//
//! `ql run --ci` — make a contained run legible to a CI system.
//!
//! CI needs three things `ql run` does not give it by default: machine-readable
//! artifacts at predictable paths, denials surfaced where a reviewer will see
//! them, and a summary in the job output. `--ci` is an opinionated alias that
//! arranges all three. It adds **no enforcement** and changes no policy.
//!
//! ## `--ci` deliberately does not fail a build on denials
//!
//! A denial is not a failure. In field traces the common case is an agent
//! probing something it turns out not to need: a real goose run denied
//! `nodejs.org` three times, found a legitimate path within its envelope, and
//! passed all 22 tests. A gate that failed on any denial would cry wolf on
//! every honest run, and people would disable it.
//!
//! CI already has the right failure conditions, and `--ci` leaves all of them
//! alone:
//!
//! - **containment failure** — `ql run` already exits 1/2 and the step fails.
//! - **the workload failed** — `ql run` passes the child's exit code through.
//! - **a policy change would break the workload** — that is `ql replay`'s job;
//!   it exits 3 on a regression and belongs in its own step.
//!
//! So `--ci` reports; it does not judge.
//!
//! ## Injection defense
//!
//! Annotations are *commands* to the CI runner, not text. Denied targets are
//! agent-chosen strings (hostnames, digests), so writing them into an
//! annotation unescaped would let a contained agent emit arbitrary workflow
//! commands — setting outputs, masking values, or writing environment files.
//! [`scrub`] strips every character that could terminate or forge a command,
//! and the run summary has already sanitized these strings once on the way in.

use crate::summary::RunSummary;
use std::io::Write;

/// Default artifact paths under `--ci`, so a workflow can reference them
/// without the caller having to pass matching flags in two places.
pub const DEFAULT_VERDICTS: &str = "ql-verdicts.jsonl";
/// Default result-document path under `--ci`.
pub const DEFAULT_RESULT_JSON: &str = "ql-result.json";

/// Make an agent-chosen string safe to place inside a workflow command.
///
/// Newlines terminate a command; `::` opens one; `%` introduces the escape
/// sequences runners decode. Everything outside a conservative allow-list
/// becomes `?`, and the result is length-capped.
fn scrub(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '/' | ' ') {
                c
            } else {
                '?'
            }
        })
        .collect();
    // `::` would open a nested command even though `:` alone is needed for
    // host:port, so collapse any run of colons to one.
    while out.contains("::") {
        out = out.replace("::", ":");
    }
    if out.len() > 120 {
        out.truncate(120);
        out.push('…');
    }
    out
}

/// Emit CI annotations and a step summary for a finished run.
///
/// Denials are emitted as **notices**, not errors: they are facts about what
/// the agent attempted, and the run may well have succeeded anyway.
pub fn report(summary: &RunSummary, verdicts_path: &str, result_path: &str) {
    let ((eg_allow, eg_deny, eg_live), (ex_allow, ex_deny, ex_live)) = summary.counts();
    if !eg_live && !ex_live {
        // No wall with a reporting channel was live; saying anything here
        // would imply coverage that did not exist.
        return;
    }

    let (targets, overflow) = summary.denied_targets();
    for (target, n) in targets.iter().take(20) {
        let t = scrub(target);
        let times = if *n > 1 {
            format!(" ({n} times)")
        } else {
            String::new()
        };
        println!("::notice title=QuantmLayer denial::{t} was denied{times}");
    }
    if overflow > 0 {
        println!("::notice title=QuantmLayer denial::and {overflow} further distinct target(s)");
    }

    write_step_summary(
        (eg_allow, eg_deny, eg_live),
        (ex_allow, ex_deny, ex_live),
        &targets,
        overflow,
        verdicts_path,
        result_path,
    );
}

/// Append a markdown table to `$GITHUB_STEP_SUMMARY` when the runner provides
/// one. Absence is normal (local runs, other CI systems) and not an error.
fn write_step_summary(
    egress: (u64, u64, bool),
    exec: (u64, u64, bool),
    targets: &[(String, u64)],
    overflow: u64,
    verdicts_path: &str,
    result_path: &str,
) {
    let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") else {
        return;
    };
    let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
    else {
        return;
    };

    let mut md =
        String::from("### QuantmLayer containment\n\n| Wall | Allowed | Denied |\n|---|---|---|\n");
    if egress.2 {
        md.push_str(&format!("| egress | {} | {} |\n", egress.0, egress.1));
    }
    if exec.2 {
        md.push_str(&format!("| exec | {} | {} |\n", exec.0, exec.1));
    }
    if !targets.is_empty() {
        md.push_str("\n**Denied targets**\n\n");
        for (t, n) in targets.iter().take(20) {
            let times = if *n > 1 {
                format!(" ×{n}")
            } else {
                String::new()
            };
            md.push_str(&format!("- `{}`{}\n", scrub(t), times));
        }
        if overflow > 0 {
            md.push_str(&format!("- …and {overflow} further distinct target(s)\n"));
        }
    }
    md.push_str(&format!(
        "\nA denial is what the agent *attempted*, not a failure — this run's own exit code is \
         the workload's. Artifacts: `{}`, `{}`. To gate a policy change, replay the stream in \
         its own step: `ql replay {} --profile <proposed.yaml>` (exits 3 on a regression).\n",
        scrub(verdicts_path),
        scrub(result_path),
        scrub(verdicts_path)
    ));
    md.push_str(
        "\nFilesystem and seccomp denials are absent by construction: those walls deny \
         in-kernel with no userspace event.\n",
    );
    let _ = f.write_all(md.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The security property.** An agent-chosen target cannot forge or
    /// terminate a workflow command.
    #[test]
    fn scrub_defuses_workflow_command_injection() {
        let hostile = "evil.test\n::set-output name=x::pwned\n::add-mask::secret";
        let out = scrub(hostile);
        assert!(!out.contains('\n'), "{out}");
        assert!(!out.contains("::"), "{out}");
        assert!(!out.contains('%'), "{out}");
        // The benign part survives, so the annotation is still informative.
        assert!(out.starts_with("evil.test"), "{out}");
    }

    /// Ordinary targets pass through unchanged — a defense that mangles normal
    /// output would get turned off.
    #[test]
    fn scrub_leaves_ordinary_targets_intact() {
        assert_eq!(scrub("pastebin.com:443"), "pastebin.com:443");
        assert_eq!(scrub("registry.npmjs.org:443"), "registry.npmjs.org:443");
        assert_eq!(scrub(&"a".repeat(64)), "a".repeat(64));
    }

    /// Overlong targets are capped so one hostile string cannot flood the log.
    #[test]
    fn scrub_caps_length() {
        let out = scrub(&"x".repeat(500));
        assert!(out.chars().count() <= 121, "{}", out.len());
    }

    /// With no reporting wall live, nothing is emitted: annotations implying
    /// coverage that did not exist would be worse than silence.
    #[test]
    fn silent_when_no_wall_was_live() {
        let s = RunSummary::default();
        let ((_, _, eg), (_, _, ex)) = s.counts();
        assert!(!eg && !ex);
        // report() early-returns; exercised here for the invariant it rests on.
    }
}

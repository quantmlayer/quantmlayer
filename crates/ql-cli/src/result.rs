// crates/ql-cli/src/result.rs
//
//! `--result-json <path>` — the machine-readable outcome of a `ql run`.
//!
//! `ql run`'s stdout/stderr belong to the contained command, and its exit code
//! is (deliberately) the child's exit code, so neither is a usable channel for
//! telling a CI system what *ql itself* concluded. This module writes a single
//! JSON document to an operator-chosen path instead: which mode ran, whether
//! the cell was built, how the child exited, and — in observe mode — every
//! would-deny finding, so a pipeline can gate on findings without scraping
//! human-oriented stderr.
//!
//! The document layout is a stable contract (`ql.run.result/v1`), documented in
//! docs/MACHINE-INTERFACE.md. Fields are only ever added, never renamed or
//! removed, within a schema version.
//!
//! Reporting never alters the run: a result file that cannot be written is
//! reported loudly on stderr, but the run's exit code stays the child's. A
//! consumer that requested a result file should treat its absence as a
//! pipeline error in its own right.

use std::io::Write;

/// Outcome of an enforce-mode run, written where the child's code is known.
pub fn write_enforce(
    path: &str,
    brokered: bool,
    tier_label: &str,
    child_exit: Option<i32>,
    error: Option<&str>,
) {
    let obj = serde_json::json!({
        "schema": "ql.run.result/v1",
        "mode": "enforce",
        "brokered": brokered,
        "exec_tier": tier_label,
        "cell_built": error.map_or(true, |_| child_exit.is_some()),
        "child": {
            "ran": child_exit.is_some(),
            "exit_code": child_exit,
        },
        "error": error,
    });
    write(path, &obj);
}

/// Outcome of an observe-mode run, including the machine-usable would-deny
/// findings that `--strict` gates on.
pub fn write_observe(
    path: &str,
    origin: &str,
    strict: bool,
    would_deny: &[(String, String)],
    strict_failed: bool,
) {
    let findings: Vec<serde_json::Value> = would_deny
        .iter()
        .map(|(kind, target)| serde_json::json!({ "kind": kind, "target": target }))
        .collect();
    let obj = serde_json::json!({
        "schema": "ql.run.result/v1",
        "mode": "observe",
        "profile_origin": origin,
        "strict": strict,
        "strict_failed": strict_failed,
        "would_deny_count": findings.len(),
        "would_deny": findings,
    });
    write(path, &obj);
}

/// Serialize and write, loudly but non-fatally on failure (see module docs).
fn write(path: &str, obj: &serde_json::Value) {
    let rendered = match serde_json::to_string_pretty(obj) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql run: could not render --result-json document: {e}");
            return;
        }
    };
    let attempt = std::fs::File::create(path).and_then(|mut f| {
        f.write_all(rendered.as_bytes())?;
        f.write_all(b"\n")
    });
    if let Err(e) = attempt {
        eprintln!("ql run: could not write --result-json {path}: {e}");
    }
}

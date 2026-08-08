// crates/ql-cli/src/verdicts.rs
//
//! The `--verdicts <path.jsonl>` stream: one JSON line per containment
//! decision, written as the decision happens (egress) or when the kernel's
//! per-run event queue is drained at the end of the run (exec).
//!
//! This is the machine-readable surface for feeding denials back to agent
//! frameworks as observations (OpenHands #4195) and for tailing a run live.
//! It is a plain append-only JSONL file — deliberately NOT the hash-chained
//! audit log, which remains the tamper-evident record. The verdicts stream
//! trades tamper-evidence for real-time availability; anything that needs
//! integrity goes to `--audit`.
//!
//! ## Schema (v1)
//!
//! ```json
//! {"v":1,"ts_millis":0,"source":"egress","decision":"deny",
//!  "target":"pastebin.com:443","rule":"host not in allow-list",
//!  "hint":"add the domain to network.allow_domains if this is legitimate"}
//! ```
//!
//! Within schema version 1, fields are only ever **added**, never renamed or
//! removed — the same contract as `--result-json` (see MACHINE-INTERFACE.md).
//!
//! ## Invariant: hints are compile-time constants
//!
//! `rule` and `hint` are always `&'static str` chosen from the tables in this
//! file. Nothing derived from agent input (paths, argv, hostnames the agent
//! chose) is ever used to *select or construct* a hint — an agent that can
//! steer a hint string can steer whatever consumes the stream. Targets are
//! recorded verbatim as data; guidance text is never synthesized from them.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

/// Current verdicts schema version.
const SCHEMA_V: u32 = 1;

/// A serialized real-time verdict stream. Line-buffered: every event is
/// written and flushed as one complete JSON line, so a `tail -f` reader never
/// sees a torn record.
#[derive(Debug)]
pub struct VerdictWriter {
    file: Mutex<File>,
}

impl VerdictWriter {
    /// Create (truncate) the verdicts file at `path`.
    pub fn create(path: &str) -> std::io::Result<VerdictWriter> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(VerdictWriter {
            file: Mutex::new(file),
        })
    }

    /// Record one egress decision (fires in real time from the broker's
    /// decision hook). `rule` is the broker's static deny reason, or
    /// "allowed" for allows.
    pub fn egress(&self, host: &str, port: u16, allowed: bool, rule: &'static str) {
        self.write_line(
            now_millis(),
            "egress",
            allowed,
            &format!("{host}:{port}"),
            rule,
            egress_hint(rule),
        );
    }

    /// Record one exec-wall decision (drained from the kernel/supervisor
    /// event queue at end of run — near-real-time, not live; see the module
    /// docs for why).
    pub fn exec(&self, ts_millis: u64, target: &str, allowed: bool) {
        let (rule, hint) = if allowed {
            (RULE_ALLOWED, "")
        } else {
            (RULE_EXEC_DENY, EXEC_DENY_HINT)
        };
        self.write_line(ts_millis, "exec", allowed, target, rule, hint);
    }

    fn write_line(
        &self,
        ts_millis: u64,
        source: &str,
        allowed: bool,
        target: &str,
        rule: &'static str,
        hint: &'static str,
    ) {
        let line = serde_json::json!({
            "v": SCHEMA_V,
            "ts_millis": ts_millis,
            "source": source,
            "decision": if allowed { "allow" } else { "deny" },
            "target": target,
            "rule": rule,
            "hint": hint,
        });
        let mut f = self.file.lock().unwrap_or_else(|e| e.into_inner());
        // A verdict line must never abort the contained run; on write failure
        // the stream degrades silently and the audit log remains the record.
        let _ = writeln!(f, "{line}");
        let _ = f.flush();
    }
}

/// Rule string for allowed operations.
const RULE_ALLOWED: &str = "allowed";
/// Rule string for a content-verified exec denial.
const RULE_EXEC_DENY: &str = "binary not on the approved digest list";
/// Hint for a content-verified exec denial.
const EXEC_DENY_HINT: &str = "run `ql learn` on this host to measure the binary and add its digest";

/// Map a broker deny reason (a compile-time constant, see
/// `ql_broker::Decision::Deny`) to a static remediation hint. Unknown reasons
/// map to an empty hint — never to synthesized text.
fn egress_hint(rule: &'static str) -> &'static str {
    match rule {
        "allowed" => "",
        "host not in allow-list" => {
            "add the domain to network.allow_domains in the profile if this is legitimate"
        }
        "resolves to a private/link-local address" => {
            "private-range block (SSRF/rebinding defense); no profile change grants this"
        }
        "host did not resolve" => "destination did not resolve; likely transient or a typo",
        "canary destination (exfiltration attempt blocked)" => {
            "honeytoken tripwire; treat this run as compromised and review the audit log"
        }
        "missing authorization token"
        | "malformed authorization token"
        | "invalid authorization token"
        | "token does not authorize this host"
        | "replayed authorization token" => {
            "token-gated egress refused; verify the delegation chain issued to this cell"
        }
        _ => "",
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_lines(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// Every written verdict is one complete, parseable JSON line carrying
    /// the v1 schema fields, and deny lines carry the static hint for their
    /// rule.
    #[test]
    fn writes_complete_v1_lines_with_static_hints() {
        let dir = std::env::temp_dir().join(format!("ql-verdicts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.jsonl");
        let w = VerdictWriter::create(path.to_str().unwrap()).unwrap();

        w.egress("pypi.org", 443, true, RULE_ALLOWED);
        w.egress("pastebin.com", 443, false, "host not in allow-list");
        w.exec(42, "abc123", false);

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 3);
        for l in &lines {
            assert_eq!(l["v"], 1);
            for k in ["ts_millis", "source", "decision", "target", "rule", "hint"] {
                assert!(l.get(k).is_some(), "missing field {k}");
            }
        }
        assert_eq!(lines[0]["decision"], "allow");
        assert_eq!(lines[0]["target"], "pypi.org:443");
        assert_eq!(lines[1]["decision"], "deny");
        assert_eq!(lines[1]["rule"], "host not in allow-list");
        assert_eq!(
            lines[1]["hint"],
            "add the domain to network.allow_domains in the profile if this is legitimate"
        );
        assert_eq!(lines[2]["source"], "exec");
        assert_eq!(lines[2]["ts_millis"], 42);
        assert_eq!(lines[2]["rule"], RULE_EXEC_DENY);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every broker deny reason that can reach the hook has a hint entry (or
    /// deliberately maps to empty) — and hints never echo the input.
    #[test]
    fn hint_table_covers_broker_reasons_and_never_echoes_input() {
        let reasons = [
            "host not in allow-list",
            "resolves to a private/link-local address",
            "host did not resolve",
            "canary destination (exfiltration attempt blocked)",
            "missing authorization token",
            "malformed authorization token",
            "invalid authorization token",
            "token does not authorize this host",
            "replayed authorization token",
        ];
        for r in reasons {
            // The hint is a static; the strongest property we can assert here
            // is that lookups are total and stable.
            let h1 = egress_hint(r);
            let h2 = egress_hint(r);
            assert!(std::ptr::eq(h1, h2), "hint for {r} must be a single static");
        }
        assert_eq!(egress_hint("some future reason"), "");
    }
}

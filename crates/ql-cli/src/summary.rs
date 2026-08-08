// crates/ql-cli/src/summary.rs
//
//! End-of-run summary for enforced runs: what the walls allowed and denied,
//! as counts and named targets. Printed to stderr after the cell exits.
//!
//! Containment is invisible when it works — a successful run otherwise gives
//! the user nothing to distinguish "the walls held" from "the walls weren't
//! doing anything." The summary fixes that, and it reports rather than
//! congratulates: a denial is a fact about what the agent attempted, not a
//! neutralized threat — most denials in field traces are the agent
//! legitimately probing. Named targets let the user draw their own
//! conclusion.
//!
//! Only walls with a userspace reporting channel appear:
//! - **egress** — the broker's per-CONNECT decisions (brokered runs only).
//! - **exec** — the content-verified exec wall's drained events (tier 1/2).
//!
//! Filesystem (mount-wall) and seccomp denials never appear here: those
//! walls deny in-kernel with no userspace event. Absence of a section means
//! "no reporting channel," never "nothing happened."

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// How many distinct denied targets are kept by name; further distinct
/// targets are counted but folded into a "+N more" tail. Bounds memory
/// against an agent generating unbounded distinct denied destinations.
const MAX_NAMED_TARGETS: usize = 24;

/// Longest a printed target may be; longer ones are truncated with `…`.
const MAX_TARGET_LEN: usize = 64;

/// Thread-safe collector of wall decisions for one run.
#[derive(Debug, Default)]
pub struct RunSummary {
    egress_allowed: AtomicU64,
    egress_denied: AtomicU64,
    exec_allowed: AtomicU64,
    exec_denied: AtomicU64,
    /// `(sanitized target, deny count)`, first-seen order, capped at
    /// [`MAX_NAMED_TARGETS`] named entries.
    denied_targets: Mutex<Vec<(String, u64)>>,
    /// Distinct denied targets beyond the named cap.
    denied_overflow: AtomicU64,
    /// Whether any egress decision was observed (distinguishes "0 allowed,
    /// 0 denied through a live broker" from "no broker at all").
    egress_seen: AtomicU64,
    /// Whether any exec decision was observed.
    exec_seen: AtomicU64,
}

impl RunSummary {
    /// Record one broker egress decision.
    pub fn note_egress(&self, host: &str, port: u16, allowed: bool) {
        self.egress_seen.store(1, Ordering::Relaxed);
        if allowed {
            self.egress_allowed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.egress_denied.fetch_add(1, Ordering::Relaxed);
            self.note_denied_target(&format!("{host}:{port}"));
        }
    }

    /// Record one exec-wall decision. `target` is the binary's content
    /// digest (or `<unhashed>`).
    pub fn note_exec(&self, target: &str, allowed: bool) {
        self.exec_seen.store(1, Ordering::Relaxed);
        if allowed {
            self.exec_allowed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.exec_denied.fetch_add(1, Ordering::Relaxed);
            self.note_denied_target(target);
        }
    }

    fn note_denied_target(&self, target: &str) {
        let clean = sanitize(target);
        let mut named = self
            .denied_targets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = named.iter_mut().find(|(t, _)| *t == clean) {
            entry.1 += 1;
            return;
        }
        if named.len() < MAX_NAMED_TARGETS {
            named.push((clean, 1));
        } else {
            self.denied_overflow.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Render the summary, or `None` when no reporting wall was live (in
    /// which case printing anything would imply coverage that didn't exist).
    pub fn render(&self, audit_path: Option<&str>) -> Option<String> {
        let egress_live = self.egress_seen.load(Ordering::Relaxed) == 1;
        let exec_live = self.exec_seen.load(Ordering::Relaxed) == 1;
        if !egress_live && !exec_live {
            return None;
        }

        let mut sections: Vec<String> = Vec::new();
        if egress_live {
            sections.push(format!(
                "egress {} allowed, {} denied",
                self.egress_allowed.load(Ordering::Relaxed),
                self.egress_denied.load(Ordering::Relaxed),
            ));
        }
        if exec_live {
            sections.push(format!(
                "exec {} allowed, {} denied",
                self.exec_allowed.load(Ordering::Relaxed),
                self.exec_denied.load(Ordering::Relaxed),
            ));
        }

        let mut out = format!("ql: run summary — {}", sections.join("; "));

        let named = self
            .denied_targets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !named.is_empty() {
            let mut parts: Vec<String> = named
                .iter()
                .map(|(t, n)| {
                    if *n > 1 {
                        format!("{t} ×{n}")
                    } else {
                        t.clone()
                    }
                })
                .collect();
            let overflow = self.denied_overflow.load(Ordering::Relaxed);
            if overflow > 0 {
                parts.push(format!("+{overflow} more"));
            }
            out.push_str(&format!("\nql: denied: {}", parts.join(", ")));
        }

        if let Some(path) = audit_path {
            out.push_str(&format!(
                "\nql: audit: {path} (verify: ql audit verify {path})"
            ));
        }
        Some(out)
    }
}

/// Make a target safe to print: agent-chosen bytes (hostnames, paths) must
/// not be able to smuggle terminal escapes into the operator's console.
/// Non-printable and non-ASCII bytes become `?`; overlong targets truncate.
fn sanitize(target: &str) -> String {
    let mut s: String = target
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect();
    if s.len() > MAX_TARGET_LEN {
        s.truncate(MAX_TARGET_LEN);
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Denials are counted per distinct target with ×N folding; the audit
    /// line appears when a log path is set.
    #[test]
    fn renders_counts_named_targets_and_audit_line() {
        let s = RunSummary::default();
        s.note_egress("pypi.org", 443, true);
        s.note_egress("pypi.org", 443, true);
        s.note_egress("pastebin.com", 443, false);
        s.note_egress("pastebin.com", 443, false);
        s.note_egress("evil.example", 443, false);
        s.note_exec("abc123", true);
        s.note_exec("deadbeef", false);

        let out = s.render(Some("/tmp/run.jsonl")).unwrap();
        assert!(out.contains("egress 2 allowed, 3 denied"), "{out}");
        assert!(out.contains("exec 1 allowed, 1 denied"), "{out}");
        assert!(out.contains("pastebin.com:443 ×2"), "{out}");
        assert!(out.contains("evil.example:443"), "{out}");
        assert!(out.contains("deadbeef"), "{out}");
        assert!(
            out.contains("verify: ql audit verify /tmp/run.jsonl"),
            "{out}"
        );
        // Report, don't congratulate: no protection claims in the output.
        assert!(!out.to_lowercase().contains("protect"), "{out}");
        assert!(!out.to_lowercase().contains("threat"), "{out}");
    }

    /// A zero-denial run through a live broker still prints the allowed
    /// counts — that is the case where invisibility is worst.
    #[test]
    fn zero_denial_run_still_reports_allowed_counts() {
        let s = RunSummary::default();
        s.note_egress("pypi.org", 443, true);
        let out = s.render(None).unwrap();
        assert!(out.contains("egress 1 allowed, 0 denied"), "{out}");
        assert!(!out.contains("denied:"), "{out}");
    }

    /// No reporting wall live → no summary at all: printing zeros would
    /// imply coverage that did not exist.
    #[test]
    fn silent_when_no_reporting_wall_was_live() {
        let s = RunSummary::default();
        assert!(s.render(Some("/tmp/run.jsonl")).is_none());
    }

    /// Distinct denied targets beyond the cap fold into "+N more", and
    /// agent-chosen bytes cannot smuggle terminal escapes.
    #[test]
    fn caps_named_targets_and_sanitizes_escapes() {
        let s = RunSummary::default();
        for i in 0..30 {
            s.note_egress(&format!("host{i}.example"), 443, false);
        }
        s.note_egress("evil\x1b[2Jhost.example", 443, false);
        let out = s.render(None).unwrap();
        assert!(out.contains("+7 more"), "{out}");
        assert!(!out.contains('\x1b'), "{out}");

        let long = "x".repeat(200);
        assert!(sanitize(&long).len() <= MAX_TARGET_LEN + '…'.len_utf8());
    }
}

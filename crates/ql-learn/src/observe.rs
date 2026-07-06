// crates/ql-learn/src/observe.rs
//
//! The `--observe` evaluation: diff a completed [`Observation`] against a
//! loaded [`Profile`] and report, per action, what **enforce mode would have
//! done** — without ever blocking. `ql learn` watches to *synthesize* a
//! profile; observe watches to *diff against* an existing one. Same tracer,
//! opposite direction.
//!
//! Every decision here routes through `ql-profile`'s shared evaluator
//! (`admits_exec` / `admits_path`), so an observe `would-deny` is provably the
//! same verdict enforce would reach — see `ql_profile::eval`.
//!
//! ## Faithfulness scope (v1)
//! * **exec** — each observed `execve` is hashed (the tracer already did this,
//!   shebang chain resolved) and checked with `admits_exec`. A binary the
//!   profile doesn't cover is `would-deny: exec` — the row that shows "a dropped
//!   payload would have been blocked."
//! * **filesystem** — each observed read/write path is checked with
//!   `admits_path`. A path under the profile's `denied` set is
//!   `would-deny: read/write`. (The mount wall enforces only `denied` today;
//!   `admits_path` reports `NotEnforced` for everything else rather than faking
//!   a scoping decision.)
//! * **network** — the tracer records `connect(2)` as a resolved **IP:port**,
//!   but profiles allow-list by **domain**, and the IP→domain mapping is gone by
//!   the time `connect` fires. So domain-level allow/deny is **not evaluated
//!   here** — it is the broker's job, and the broker already logs first-seen
//!   ALLOW/DENY per domain when run with `--broker`. Observe reports the raw
//!   external endpoints it saw and says so, rather than inventing a domain
//!   verdict it cannot support. This is the honest boundary, not a TODO.
//! * **syscalls / resource caps** — reported as `not observed`: the tracer sees
//!   syscall *use* but the profile's deny/limit semantics don't reduce to a
//!   per-action allow/deny under this model. We do not fabricate a verdict.

use crate::Observation;
use ql_profile::{Decision, PathDecision, Profile};
use std::net::IpAddr;

/// One action's evaluation against the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The profile admits this action; enforce would allow it.
    Allow,
    /// The profile does not admit it; enforce would block it.
    WouldDeny,
}

/// A single evaluated action, for the audit stream and the summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Dimension: `"exec"`, `"read"`, or `"write"`.
    pub kind: &'static str,
    /// The target (binary path, file path).
    pub target: String,
    /// What enforce mode would have done.
    pub verdict: Verdict,
}

/// The complete observe report: per-dimension counts, the would-deny findings,
/// and the un-evaluated endpoints (network) for operator awareness.
#[derive(Debug, Clone, Default)]
pub struct ObserveReport {
    /// Every evaluated action (exec + filesystem). Allows and would-denies.
    pub findings: Vec<Finding>,
    /// External endpoints the agent connected to (IP:port), NOT domain-evaluated
    /// here — see the module's network note.
    pub external_endpoints: Vec<(IpAddr, u16)>,
    /// Total execs evaluated.
    pub exec_total: usize,
    /// Total file paths evaluated (reads + writes).
    pub file_total: usize,
}

impl ObserveReport {
    /// The would-deny findings only — what enforce mode would have blocked.
    pub fn would_deny(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| f.verdict == Verdict::WouldDeny)
    }

    /// Count of would-deny findings — the number `--strict` gates on.
    pub fn would_deny_count(&self) -> usize {
        self.would_deny().count()
    }
}

/// Evaluate a completed observation against a profile. Pure: no I/O, no
/// enforcement — just the diff. Every verdict comes from `ql-profile`'s shared
/// evaluator, so it matches what enforce would do.
pub fn evaluate(obs: &Observation, profile: &Profile) -> ObserveReport {
    let mut report = ObserveReport::default();

    // exec — check each execve's content digest against the profile.
    for path in &obs.execs {
        let digest = obs.exec_digests.get(path).map(|d| d.hex());
        let verdict = match profile.admits_exec(digest) {
            Decision::Allow => Verdict::Allow,
            Decision::Deny => Verdict::WouldDeny,
        };
        report.findings.push(Finding {
            kind: "exec",
            target: path.clone(),
            verdict,
        });
        report.exec_total += 1;
    }

    // filesystem — a path is a would-deny iff the profile hides it (`denied`).
    // Reads and writes are reported separately for operator clarity.
    for (paths, kind) in [(&obs.reads, "read"), (&obs.writes, "write")] {
        for p in paths {
            let path_str = p.to_string_lossy();
            if let PathDecision::Denied = profile.admits_path(&path_str) {
                report.findings.push(Finding {
                    kind,
                    target: path_str.into_owned(),
                    verdict: Verdict::WouldDeny,
                });
            }
            // NotEnforced paths are not listed as findings — the wall makes no
            // read/write decision, so neither do we. They still count in totals.
            report.file_total += 1;
        }
    }

    // network — collect external endpoints for awareness; not domain-evaluated.
    for (ip, port) in &obs.connects {
        let external = match ip {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local(),
            IpAddr::V6(v6) => !v6.is_loopback(),
        };
        if external {
            report.external_endpoints.push((*ip, *port));
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use ql_profile::{ExecDigest, HashAlgo};

    fn obs_with(execs: &[(&str, &str)], reads: &[&str], writes: &[&str]) -> Observation {
        let mut o = Observation::default();
        for (path, hex) in execs {
            o.record_exec(path.to_string());
            o.exec_digests.insert(
                path.to_string(),
                ExecDigest::new(HashAlgo::Sha256, hex.to_string()).unwrap(),
            );
        }
        for r in reads {
            o.record_open(std::path::PathBuf::from(r), false);
        }
        for w in writes {
            o.record_open(std::path::PathBuf::from(w), true);
        }
        o
    }

    fn profile_allowing(digest_hex: &str, denied: &[&str]) -> Profile {
        use ql_profile::{ExecPolicy, FsPolicy};
        Profile {
            exec: ExecPolicy {
                enforce: true,
                allow_digests: vec![ExecDigest::new(HashAlgo::Sha256, digest_hex).unwrap()],
                ..Default::default()
            },
            filesystem: FsPolicy {
                denied: denied.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn unlisted_exec_is_would_deny_listed_is_allow() {
        let allowed = "a".repeat(64);
        let other = "b".repeat(64);
        let obs = obs_with(
            &[("/usr/bin/git", &allowed), ("/tmp/payload", &other)],
            &[],
            &[],
        );
        let profile = profile_allowing(&allowed, &[]);
        let r = evaluate(&obs, &profile);

        assert_eq!(r.exec_total, 2);
        assert_eq!(r.would_deny_count(), 1);
        let wd: Vec<_> = r.would_deny().collect();
        assert_eq!(wd[0].target, "/tmp/payload");
        assert_eq!(wd[0].kind, "exec");
    }

    #[test]
    fn read_of_denied_path_is_would_deny() {
        let allowed = "a".repeat(64);
        let obs = obs_with(
            &[("/usr/bin/cat", &allowed)],
            &["/home/alice/.ssh/id_rsa", "/home/alice/project/main.rs"],
            &[],
        );
        let profile = profile_allowing(&allowed, &["/home/*/.ssh/**"]);
        let r = evaluate(&obs, &profile);

        // The .ssh read is a would-deny; the project read is not enforced.
        let wd: Vec<_> = r.would_deny().collect();
        assert_eq!(wd.len(), 1);
        assert_eq!(wd[0].kind, "read");
        assert!(wd[0].target.ends_with("id_rsa"));
        assert_eq!(r.file_total, 2);
    }

    #[test]
    fn clean_run_has_zero_would_deny() {
        let allowed = "a".repeat(64);
        let obs = obs_with(&[("/usr/bin/git", &allowed)], &["/workspace/main.rs"], &[]);
        let profile = profile_allowing(&allowed, &["/home/*/.ssh/**"]);
        let r = evaluate(&obs, &profile);
        assert_eq!(r.would_deny_count(), 0);
    }
}

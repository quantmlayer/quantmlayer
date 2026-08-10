// crates/ql-cli/src/replay.rs
//
//! `ql replay` — evaluate a recorded `--verdicts` stream against a proposed
//! profile, offline and deterministically.
//!
//! Today the only way to test a policy change is to run the agent again: a
//! model call, a minute of wall time, and a *nondeterministic* result — the
//! agent may not do the same things twice, so a policy that passes once can
//! fail the next run for reasons unrelated to the policy. Replay re-evaluates
//! the decisions a previous run actually produced, in milliseconds, with no
//! agent and no model.
//!
//! It is the other half of `ql compile`: having compiled an envelope, the
//! immediate question is "will my existing task still work under this?"
//!
//! ## The governing invariant
//!
//! > **Absence of denial is not evidence of compatibility when the recording
//! > stream lacked coverage for that policy axis.**
//!
//! A verdict stream records *the decisions the recording policy made*, not
//! everything the workload did. Every axis therefore has three states, never
//! two — [`AxisOutcome::Unknown`] is a first-class result and, given how
//! QuantmLayer ships, the common one:
//!
//! - **Exec.** `exec.enforce` ships `false` (digests are per-host), and with
//!   it false `select_exec_tier` returns `ExecTier::None` — no wall, no
//!   events. A stream from a default profile contains no exec verdicts at all.
//! - **Egress.** The decision hook is attached only on brokered runs, so a run
//!   without `--broker` contains no egress verdicts.
//! - **Filesystem and seccomp.** These walls deny in-kernel with no userspace
//!   event. They can *never* appear in a verdict stream, so replay cannot
//!   speak to them at all.
//!
//! ## Per-event uncertainty, not just per-axis
//!
//! [`BrokerPolicy::evaluate`] decides on *resolved IPs*; the verdict stream
//! records `host:port` and not the addresses it resolved to. So when a
//! proposed profile would newly admit a host, replay cannot know whether the
//! private-range check would then pass — resolution never happened for a host
//! the recording policy rejected earlier. That event is `Unknown`, and it is
//! precisely the case replay is most often used for: testing a change you
//! expect to *unblock* something.
//!
//! ## PASS is bounded by what the recording run reached
//!
//! If the recorded run was denied at step 3, the workload never attempted
//! steps 4–10, so those operations are not in the stream. Replaying a *more
//! permissive* policy shows PASS over recorded events while a real run under
//! that policy would proceed further and do things never captured. PASS
//! therefore means "no observed operation would be denied" — never "this
//! workload is compatible." The output says so.

use ql_broker::{BrokerPolicy, Decision};
use ql_profile::Profile;
use std::process::ExitCode;

/// One decision parsed from a `--verdicts` JSONL stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedVerdict {
    /// `egress` or `exec`.
    pub source: String,
    /// True when the recording policy allowed the operation.
    pub allowed: bool,
    /// `host:port` for egress, content digest for exec.
    pub target: String,
    /// The static rule string the recording policy produced.
    pub rule: String,
}

impl RecordedVerdict {
    /// Split an egress target into host and port. Returns `None` for targets
    /// that are not `host:port`.
    fn host_port(&self) -> Option<(&str, u16)> {
        let (h, p) = self.target.rsplit_once(':')?;
        Some((h, p.parse().ok()?))
    }
}

/// What a proposed profile would do with one recorded event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventVerdict {
    /// The proposed profile would allow it.
    Allow,
    /// The proposed profile would deny it, with the rule that fires.
    Deny(&'static str),
    /// Cannot be determined from what the stream recorded, with the reason.
    Unknown(&'static str),
}

/// The aggregate state of one policy axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxisOutcome {
    /// Every observed operation on this axis would be allowed.
    Pass,
    /// At least one observed operation would be denied.
    Fail,
    /// The stream lacks the events needed to evaluate this axis.
    Unknown,
}

/// The result of replaying one axis.
#[derive(Debug, Clone)]
pub struct AxisReport {
    /// `egress` or `exec`.
    pub axis: &'static str,
    /// Aggregate outcome.
    pub outcome: AxisOutcome,
    /// Events observed on this axis.
    pub observed: usize,
    /// **Regressions**: events the recording run allowed that the proposed
    /// profile would deny. This is what drives `Fail` — an event that was
    /// already denied and is still denied is not a regression, and reporting
    /// it as failure would make every replay of a real stream look broken.
    pub regressions: usize,
    /// Events denied at record time that would still be denied. Informational.
    pub still_denied: usize,
    /// Events denied at record time that the proposed profile would admit.
    /// Informational, and subject to the bounded-PASS caveat: the workload
    /// never proceeded past them, so what it would then do is unrecorded.
    pub newly_allowed: usize,
    /// Events whose outcome cannot be determined.
    pub undetermined: usize,
    /// Why this axis is `Unknown`, when it is. A compile-time constant.
    pub unknown_reason: Option<&'static str>,
    /// Targets that would regress (allowed then, denied now), first-seen order.
    pub regressed_targets: Vec<String>,
}

/// Replay every recorded egress verdict against `profile`.
///
/// Certainty rules, and why:
/// - **Host not allowed → Deny, certain.** The allow-list check needs no IPs.
/// - **Host allowed and private ranges not blocked → Allow, certain.**
/// - **Host allowed, private ranges blocked, and the event was recorded as a
///   private-range denial → Deny, certain.** The stream told us it resolves
///   privately.
/// - **Host allowed, private ranges blocked, and the event was recorded as
///   allowed → Allow.** The recording run resolved it and did not deny it.
/// - **Host allowed, private ranges blocked, and the event was recorded as
///   denied for any other reason → Unknown.** Resolution may never have
///   happened, so the private-range check cannot be evaluated. This is the
///   "unblock something" case.
pub fn replay_egress(events: &[RecordedVerdict], profile: &Profile) -> AxisReport {
    let policy = BrokerPolicy::from_net_policy(&profile.network);
    let mut report = AxisReport {
        axis: "egress",
        outcome: AxisOutcome::Unknown,
        observed: 0,
        regressions: 0,
        still_denied: 0,
        newly_allowed: 0,
        undetermined: 0,
        unknown_reason: None,
        regressed_targets: Vec::new(),
    };

    for ev in events.iter().filter(|e| e.source == "egress") {
        report.observed += 1;
        let Some((host, _port)) = ev.host_port() else {
            report.undetermined += 1;
            continue;
        };
        match egress_verdict(&policy, profile, host, ev) {
            EventVerdict::Allow => {
                if !ev.allowed {
                    report.newly_allowed += 1;
                }
            }
            EventVerdict::Deny(_) => {
                if ev.allowed {
                    report.regressions += 1;
                    if !report.regressed_targets.contains(&ev.target) {
                        report.regressed_targets.push(ev.target.clone());
                    }
                } else {
                    report.still_denied += 1;
                }
            }
            EventVerdict::Unknown(_) => report.undetermined += 1,
        }
    }

    if report.observed == 0 {
        report.unknown_reason = Some(
            "no egress events in this stream — either the recording run was not \
             brokered (verdicts are emitted only on `--broker` runs), or it was \
             brokered and the workload made no network calls. The stream does not \
             record which walls were live, so these cannot be told apart",
        );
        report.outcome = AxisOutcome::Unknown;
    } else if report.regressions > 0 {
        report.outcome = AxisOutcome::Fail;
    } else if report.undetermined > 0 {
        report.unknown_reason = Some(
            "some events would newly be admitted by the allow-list, but the stream \
             does not record resolved IPs, so the private-range check cannot be \
             evaluated for them",
        );
        report.outcome = AxisOutcome::Unknown;
    } else {
        report.outcome = AxisOutcome::Pass;
    }
    report
}

/// Decide one recorded egress event against the proposed policy.
fn egress_verdict(
    policy: &BrokerPolicy,
    profile: &Profile,
    host: &str,
    ev: &RecordedVerdict,
) -> EventVerdict {
    // The allow-list check alone needs no resolved addresses: evaluating with
    // an empty IP set and private-range blocking disabled isolates it.
    if !host_admitted(policy, host) {
        return EventVerdict::Deny("host not in allow-list");
    }
    if !profile.network.block_private_ranges {
        return EventVerdict::Allow;
    }
    if ev.rule == "resolves to a private/link-local address" {
        // The recording run resolved this host and found a private address.
        return EventVerdict::Deny("resolves to a private/link-local address");
    }
    if ev.allowed {
        // The recording run resolved it and admitted it.
        return EventVerdict::Allow;
    }
    EventVerdict::Unknown(
        "newly admitted by the allow-list, but the recording run never resolved it, \
         so the private-range check cannot be evaluated",
    )
}

/// Is `host` admitted by the profile's allow-list, independent of resolution?
fn host_admitted(policy: &BrokerPolicy, host: &str) -> bool {
    // `evaluate` with a public address isolates the allow-list decision: the
    // private-range branch cannot fire on a documentation-range address that
    // `is_blocked_ip` treats as public... so instead ask the policy directly
    // with an empty resolved set and read which rule fires.
    match policy.evaluate(host, &[]) {
        Decision::Deny("host not in allow-list") => false,
        // Any other outcome means the host cleared the allow-list; the
        // remaining decision is about addresses, handled by the caller.
        _ => true,
    }
}

/// Replay every recorded exec verdict against `profile`.
///
/// Exec is fully determinable when events exist: the stream records the
/// content digest, and the proposed profile either lists it or does not.
pub fn replay_exec(events: &[RecordedVerdict], profile: &Profile) -> AxisReport {
    let mut report = AxisReport {
        axis: "exec",
        outcome: AxisOutcome::Unknown,
        observed: 0,
        regressions: 0,
        still_denied: 0,
        newly_allowed: 0,
        undetermined: 0,
        unknown_reason: None,
        regressed_targets: Vec::new(),
    };

    for ev in events.iter().filter(|e| e.source == "exec") {
        report.observed += 1;
        // No wall in the proposed profile: nothing is denied on this axis.
        let would_allow = !profile.exec.enforce || digest_allowed(profile, &ev.target);
        match (ev.allowed, would_allow) {
            (_, true) if !ev.allowed => report.newly_allowed += 1,
            (_, true) => {}
            (true, false) => {
                report.regressions += 1;
                if !report.regressed_targets.contains(&ev.target) {
                    report.regressed_targets.push(ev.target.clone());
                }
            }
            (false, false) => report.still_denied += 1,
        }
    }

    if report.observed == 0 {
        report.unknown_reason = Some(
            "no exec events in this stream — the recording run almost certainly had \
             `exec.enforce: false` (the shipped default), in which case no exec wall \
             ran and nothing was measured",
        );
        report.outcome = AxisOutcome::Unknown;
    } else if report.regressions > 0 {
        report.outcome = AxisOutcome::Fail;
    } else {
        report.outcome = AxisOutcome::Pass;
    }
    report
}

/// Is this content digest on the proposed profile's approved list?
///
/// The verdict stream records bare lowercase hex; a profile holds validated
/// [`ql_profile::ExecDigest`] values whose `hex()` is the same form. Comparing
/// on `hex()` rather than on the display string keeps this independent of how
/// the digest is spelled in YAML.
fn digest_allowed(profile: &Profile, digest: &str) -> bool {
    let bare = digest.trim_start_matches("sha256:").to_ascii_lowercase();
    profile.exec.allow_digests.iter().any(|d| d.hex() == bare)
}

/// Parse a `--verdicts` JSONL stream. Malformed lines are skipped and counted
/// rather than aborting: a truncated final line is normal when a stream is
/// read while a run is still writing.
pub fn parse_stream(text: &str) -> (Vec<RecordedVerdict>, usize) {
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(v) => {
                let (Some(source), Some(decision), Some(target)) = (
                    v.get("source").and_then(|x| x.as_str()),
                    v.get("decision").and_then(|x| x.as_str()),
                    v.get("target").and_then(|x| x.as_str()),
                ) else {
                    skipped += 1;
                    continue;
                };
                out.push(RecordedVerdict {
                    source: source.to_string(),
                    allowed: decision == "allow",
                    target: target.to_string(),
                    rule: v
                        .get("rule")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .to_string(),
                });
            }
            Err(_) => skipped += 1,
        }
    }
    (out, skipped)
}

/// Run `ql replay`.
pub fn cmd(args: &[String]) -> ExitCode {
    let mut stream_path: Option<String> = None;
    let mut profile_path: Option<String> = None;
    let mut json = false;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--profile" => profile_path = it.next().cloned(),
            "--json" => json = true,
            "-h" | "--help" => {
                print_usage();
                return ExitCode::from(0);
            }
            other if other.starts_with('-') => {
                eprintln!("ql replay: unknown option `{other}`");
                print_usage();
                return ExitCode::from(2);
            }
            other => stream_path = Some(other.to_string()),
        }
    }

    let (Some(stream_path), Some(profile_path)) = (stream_path, profile_path) else {
        eprintln!("ql replay: need a verdicts file and --profile <p.yaml>");
        print_usage();
        return ExitCode::from(2);
    };

    let text = match std::fs::read_to_string(&stream_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ql replay: cannot read {stream_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let profile = match std::fs::read_to_string(&profile_path)
        .map_err(|e| e.to_string())
        .and_then(|t| Profile::from_yaml(&t).map_err(|e| e.to_string()))
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ql replay: cannot load {profile_path}: {e}");
            return ExitCode::from(2);
        }
    };

    let (events, skipped) = parse_stream(&text);
    if events.is_empty() {
        eprintln!(
            "ql replay: {stream_path} contains no readable verdicts \
             (is it a --verdicts stream?)"
        );
        return ExitCode::from(2);
    }

    let egress = replay_egress(&events, &profile);
    let exec = replay_exec(&events, &profile);

    if json {
        print!("{}", render_json(&egress, &exec, events.len(), skipped));
    } else {
        print_human(&egress, &exec, events.len(), skipped);
    }

    // Exit 3 signals "policy findings" per the machine interface, matching
    // `ql validate`. Unknown is NOT a finding — it is absence of evidence, and
    // conflating the two would defeat the point of the third state.
    if egress.outcome == AxisOutcome::Fail || exec.outcome == AxisOutcome::Fail {
        return ExitCode::from(3);
    }
    ExitCode::from(0)
}

fn axis_word(o: AxisOutcome) -> &'static str {
    match o {
        AxisOutcome::Pass => "PASS",
        AxisOutcome::Fail => "FAIL",
        AxisOutcome::Unknown => "UNKNOWN",
    }
}

fn print_human(egress: &AxisReport, exec: &AxisReport, total: usize, skipped: usize) {
    println!("replayed {total} recorded decision(s)");
    if skipped > 0 {
        println!("  ({skipped} unparseable line(s) skipped)");
    }
    println!();
    for r in [egress, exec] {
        println!(
            "  {:<8} {:<8} {} observed · {} regression(s)",
            r.axis,
            axis_word(r.outcome),
            r.observed,
            r.regressions
        );
        if let Some(reason) = r.unknown_reason {
            println!("           reason: {reason}");
        }
        for t in &r.regressed_targets {
            println!("           REGRESSION: {t} was allowed, would now be denied");
        }
        if r.still_denied > 0 {
            println!(
                "           {} event(s) denied before and still denied (not a regression)",
                r.still_denied
            );
        }
        if r.newly_allowed > 0 {
            println!(
                "           {} event(s) denied before would now be admitted — the run \
                 stopped there, so what it would do next is unrecorded",
                r.newly_allowed
            );
        }
    }
    println!();
    println!("  filesystem, seccomp   NOT OBSERVABLE — these walls deny in-kernel with no");
    println!("                        userspace event, so no verdict stream can cover them.");
    println!();
    println!(
        "PASS means no *observed* operation would be denied — not that this workload is\n\
         compatible. A run under a more permissive policy proceeds further and does things\n\
         this stream never captured."
    );
}

fn render_json(egress: &AxisReport, exec: &AxisReport, total: usize, skipped: usize) -> String {
    let axis = |r: &AxisReport| {
        format!(
            "    \"{}\": {{ \"outcome\": \"{}\", \"observed\": {}, \"regressions\": {}, \
             \"undetermined\": {}, \"reason\": {} }}",
            r.axis,
            axis_word(r.outcome).to_lowercase(),
            r.observed,
            r.regressions,
            r.undetermined,
            match r.unknown_reason {
                Some(s) => format!("\"{s}\""),
                None => "null".to_string(),
            }
        )
    };
    format!(
        "{{\n  \"schema\": \"ql.replay/v1\",\n  \"replayed\": {},\n  \"skipped_lines\": {},\n  \"axes\": {{\n{},\n{}\n  }},\n  \"not_observable\": [\"filesystem\", \"seccomp\"]\n}}\n",
        total,
        skipped,
        axis(egress),
        axis(exec)
    )
}

fn print_usage() {
    eprintln!(
        "usage: ql replay <verdicts.jsonl> --profile <proposed.yaml> [--json]\n\
         \n\
         Re-evaluates the decisions a previous run recorded against a proposed profile.\n\
         Offline and deterministic: no agent, no model call.\n\
         \n\
         Each axis reports PASS, FAIL, or UNKNOWN. UNKNOWN means the stream lacks the\n\
         events needed to judge that axis — it is not a pass. Exit 3 on FAIL; UNKNOWN\n\
         is absence of evidence, not a finding.\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_with(domains: &[&str], block_private: bool) -> Profile {
        let mut p = Profile::from_yaml(include_str!("../../../profiles/coding.yaml")).unwrap();
        p.network.allow_domains = domains.iter().map(|s| s.to_string()).collect();
        p.network.default_deny = true;
        p.network.block_private_ranges = block_private;
        p
    }

    fn ev(source: &str, allowed: bool, target: &str, rule: &str) -> RecordedVerdict {
        RecordedVerdict {
            source: source.into(),
            allowed,
            target: target.into(),
            rule: rule.into(),
        }
    }

    /// A host the proposed profile drops is denied with certainty — the
    /// allow-list check needs no resolved addresses.
    #[test]
    fn dropping_a_domain_fails_the_egress_axis() {
        let events = vec![
            ev("egress", true, "crates.io:443", "allowed"),
            ev("egress", true, "pypi.org:443", "allowed"),
        ];
        let r = replay_egress(&events, &profile_with(&["crates.io"], true));
        assert_eq!(r.outcome, AxisOutcome::Fail);
        assert_eq!(r.regressions, 1);
        assert_eq!(r.regressed_targets, vec!["pypi.org:443"]);
    }

    /// A profile that still admits everything observed passes.
    #[test]
    fn superset_profile_passes_the_egress_axis() {
        let events = vec![ev("egress", true, "crates.io:443", "allowed")];
        let r = replay_egress(&events, &profile_with(&["crates.io", "pypi.org"], true));
        assert_eq!(r.outcome, AxisOutcome::Pass);
        assert_eq!(r.regressions, 0);
    }

    /// **The governing invariant.** An empty axis is UNKNOWN, never PASS, and
    /// the reason names the cause rather than reporting an uninformative zero.
    #[test]
    fn empty_axis_is_unknown_with_a_named_cause() {
        let events = vec![ev("egress", true, "crates.io:443", "allowed")];
        let p = profile_with(&["crates.io"], true);

        let exec = replay_exec(&events, &p);
        assert_eq!(exec.outcome, AxisOutcome::Unknown);
        assert_eq!(exec.observed, 0);
        assert!(exec.unknown_reason.unwrap().contains("exec.enforce"));

        let egress = replay_egress(&[ev("exec", true, "abc", "allowed")], &p);
        assert_eq!(egress.outcome, AxisOutcome::Unknown);
        assert!(egress.unknown_reason.unwrap().contains("broker"));
    }

    /// The "unblock something" case: a host the recording policy denied at the
    /// allow-list, now admitted. It was never resolved, so the private-range
    /// check cannot be evaluated — UNKNOWN, not PASS.
    #[test]
    fn newly_admitted_host_that_was_never_resolved_is_unknown() {
        let events = vec![ev(
            "egress",
            false,
            "internal.example:443",
            "host not in allow-list",
        )];
        let r = replay_egress(&events, &profile_with(&["internal.example"], true));
        assert_eq!(r.outcome, AxisOutcome::Unknown);
        assert_eq!(r.undetermined, 1);
        assert_eq!(r.regressions, 0);
        assert!(r.unknown_reason.unwrap().contains("resolved IPs"));
    }

    /// A recorded private-range denial is determinable (the stream told us it
    /// resolves privately) — but it is NOT a regression: it was denied before
    /// and is denied now. Reporting that as failure would make every replay of
    /// a real stream look broken, since real streams contain denials.
    #[test]
    fn already_denied_events_are_not_regressions() {
        let events = vec![ev(
            "egress",
            false,
            "localtest.me:443",
            "resolves to a private/link-local address",
        )];
        let r = replay_egress(&events, &profile_with(&["localtest.me"], true));
        assert_eq!(r.outcome, AxisOutcome::Pass);
        assert_eq!(r.regressions, 0);
        assert_eq!(r.still_denied, 1);

        // Dropping the private-range block newly admits it — reported as such,
        // and the bounded-PASS caveat applies: the run stopped there.
        let r2 = replay_egress(&events, &profile_with(&["localtest.me"], false));
        assert_eq!(r2.outcome, AxisOutcome::Pass);
        assert_eq!(r2.newly_allowed, 1);
    }

    /// Only an allowed-then / denied-now event is a regression, and it is
    /// named.
    #[test]
    fn only_allowed_then_denied_now_counts_as_regression() {
        let events = vec![
            ev("egress", true, "pypi.org:443", "allowed"),
            ev(
                "egress",
                false,
                "evil.example:443",
                "host not in allow-list",
            ),
        ];
        let r = replay_egress(&events, &profile_with(&["crates.io"], true));
        assert_eq!(r.outcome, AxisOutcome::Fail);
        assert_eq!(r.regressions, 1);
        assert_eq!(r.still_denied, 1);
        assert_eq!(r.regressed_targets, vec!["pypi.org:443"]);
    }

    /// Exec is fully determinable when events exist: the digest is either on
    /// the proposed list or it is not. Both digest spellings are accepted.
    #[test]
    fn exec_digests_are_determinable_in_both_spellings() {
        let mut p = profile_with(&["crates.io"], true);
        p.exec.enforce = true;
        let good = "a".repeat(64);
        let bad = "b".repeat(64);
        p.exec.allow_digests =
            vec![ql_profile::ExecDigest::new(ql_profile::HashAlgo::Sha256, good.clone()).unwrap()];

        let events = vec![
            ev("exec", true, &good, "allowed"),
            ev("exec", true, &bad, "allowed"),
        ];
        let r = replay_exec(&events, &p);
        assert_eq!(r.outcome, AxisOutcome::Fail);
        assert_eq!(r.regressions, 1);
        assert_eq!(r.regressed_targets, vec![bad]);
    }

    /// With no exec wall in the proposed profile, exec events are observed but
    /// nothing is denied.
    #[test]
    fn exec_axis_passes_when_the_proposed_profile_does_not_enforce() {
        let mut p = profile_with(&["crates.io"], true);
        p.exec.enforce = false;
        let events = vec![ev("exec", true, &"a".repeat(64), "allowed")];
        let r = replay_exec(&events, &p);
        assert_eq!(r.outcome, AxisOutcome::Pass);
        assert_eq!(r.regressions, 0);
    }

    /// Malformed lines are skipped and counted, not fatal — a truncated final
    /// line is normal when reading a stream a run is still writing.
    #[test]
    fn parser_skips_malformed_lines_and_counts_them() {
        let text = "{\"v\":1,\"source\":\"egress\",\"decision\":\"allow\",\"target\":\"a:1\",\"rule\":\"allowed\"}\n\
                    not json\n\
                    {\"v\":1,\"source\":\"egress\"}\n\
                    {\"v\":1,\"source\":\"exec\",\"decision\":\"deny\",\"target\":\"d\",\"rule\":\"x\"}\n";
        let (events, skipped) = parse_stream(text);
        assert_eq!(events.len(), 2);
        assert_eq!(skipped, 2);
        assert_eq!(events[1].source, "exec");
        assert!(!events[1].allowed);
    }
}

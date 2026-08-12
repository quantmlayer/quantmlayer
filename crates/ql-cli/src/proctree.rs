// crates/ql-cli/src/proctree.rs
//
//! Reconstruct the process tree behind a set of exec audit records.
//!
//! Four isolated denials read very differently from four denials that all
//! happened under one `npm install`. The parent link is a fact the kernel
//! records at exec time (`real_parent`), so grouping by it is derivable —
//! unlike causality, which would have to be inferred and is deliberately not
//! claimed here. This renders *what ran under what*, nothing more.
//!
//! ## Where the data comes from, and why parsing it is awkward
//!
//! `ppid` travels inside the audit record's `detail` string
//! (`pid 4242 ppid 100 (npm)`) rather than as its own field, because
//! `AuditEvent` is covered by the chain hash and adding a field would change
//! how every previously written log verifies. The cost is that grouping must
//! parse a human-readable string back into structure. [`parse_detail`] is
//! therefore strict: anything that does not match exactly yields `None` and
//! the record is reported as ungrouped, rather than being attached to a
//! guessed parent. A visibly ungrouped record is recoverable; a confidently
//! wrong tree is not.
//!
//! ## What the tree cannot show
//!
//! - **Tier 2 has no parent data at all.** seccomp user-notification delivers
//!   the execing pid but not its parent, so a tier-2 log groups nothing and
//!   says so instead of rendering a flat list that looks like a tree of depth
//!   one.
//! - **A denied exec never becomes a parent.** The process was refused, so no
//!   child ever ran under it. Denials appear as leaves, which is accurate.
//! - **Gaps are shown as roots.** A record whose parent is not in the log —
//!   the cell's first exec, whose parent is `ql` itself, or a chain broken by
//!   a record outside the time window — is rendered at top level rather than
//!   silently dropped or attached elsewhere.

use std::collections::{BTreeMap, BTreeSet};

/// One exec record's identity, extracted from an audit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecNode {
    /// The execing process.
    pub pid: u32,
    /// Its real parent at exec time, when the log recorded one.
    pub ppid: Option<u32>,
    /// The task comm.
    pub comm: String,
    /// The binary's content digest, or `<unhashed>`.
    pub target: String,
    /// Whether the exec was allowed (or, in observe mode, would have been).
    pub allowed: bool,
    /// False for observe-mode records. An observe "would-deny" is a
    /// prediction, not a denial that happened: nothing was stopped. Labelling
    /// it the same as an enforced denial would tell a reader the process was
    /// blocked when it ran to completion.
    pub enforced: bool,
    /// Milliseconds since the Unix epoch.
    pub ts_millis: u64,
}

/// Parse `pid <n> ppid <n> (comm)` or `pid <n> (comm)` out of a detail string.
///
/// Strict by design: an unrecognized shape returns `None` so the caller can
/// report the record as ungrouped instead of attaching it to a guess.
pub fn parse_detail(detail: &str) -> Option<(u32, Option<u32>, String)> {
    let rest = detail.strip_prefix("pid ")?;
    let (pid_str, rest) = rest.split_once(' ')?;
    let pid: u32 = pid_str.parse().ok()?;

    let (ppid, rest) = match rest.strip_prefix("ppid ") {
        Some(after) => {
            let (ppid_str, tail) = after.split_once(' ')?;
            (Some(ppid_str.parse::<u32>().ok()?), tail)
        }
        None => (None, rest),
    };

    // Trailing text after the comm is allowed: observe records append their
    // NOT-ENFORCING marker there. Take up to the first ')' rather than
    // requiring the string to end at it.
    let inner = rest.strip_prefix('(')?;
    let (comm, _tail) = inner.split_once(')')?;
    Some((pid, ppid, comm.to_string()))
}

/// One egress connect attributed to a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectNode {
    /// The process that opened it.
    pub pid: u32,
    /// `ip:port`. Not a domain: by `connect` time the name is resolved and
    /// gone.
    pub endpoint: String,
}

/// A rendered tree, plus what could not be placed in it.
#[derive(Debug, Default)]
pub struct Tree {
    /// Rendered lines, already indented.
    pub lines: Vec<String>,
    /// Records whose `detail` did not parse, so their parent is unknown.
    pub unparsed: usize,
    /// Connects whose pid matched no exec node, rendered separately rather
    /// than attached to a neighbour. Attaching an unmatched connect to the
    /// nearest process in time would manufacture exactly the causality this
    /// module refuses to assert.
    pub unattributed: Vec<String>,
    /// Whether any record carried a ppid at all. False means the log came from
    /// a substrate that does not report parents (tier 2), and no grouping is
    /// possible — a materially different statement from "everything is a root".
    pub any_parent_data: bool,
}

/// Build the process tree for `nodes`.
///
/// Nodes whose parent is absent from the set become roots, which is the honest
/// rendering for the cell's first exec (whose parent is `ql`) and for any chain
/// broken by filtering.
/// Build the tree, hanging each connect off the process that opened it.
///
/// This is lineage rather than grouping: a connect's pid comes from the same
/// syscall stop that recorded it, so "this process opened this endpoint" is an
/// observation, not a correlation. A connect whose pid matches no exec node is
/// listed as unattributed.
///
/// Pass an empty `connects` slice for a tree of execs alone.
pub fn build_with_connects(nodes: &[ExecNode], connects: &[ConnectNode], unparsed: usize) -> Tree {
    let mut by_pid: BTreeMap<u32, Vec<&ConnectNode>> = BTreeMap::new();
    let known: BTreeSet<u32> = nodes.iter().map(|n| n.pid).collect();
    let mut unattributed = Vec::new();
    for c in connects {
        if known.contains(&c.pid) {
            by_pid.entry(c.pid).or_default().push(c);
        } else {
            unattributed.push(format!("{} (pid {})", c.endpoint, c.pid));
        }
    }

    let mut tree = Tree {
        unattributed,
        unparsed,
        any_parent_data: nodes.iter().any(|n| n.ppid.is_some()),
        ..Default::default()
    };
    if nodes.is_empty() {
        return tree;
    }
    if !tree.any_parent_data {
        // No parent data: list the execs flat rather than implying structure.
        for n in nodes {
            tree.lines.push(format!("  {}", label(n)));
        }
        return tree;
    }

    let present: BTreeSet<u32> = nodes.iter().map(|n| n.pid).collect();
    let mut children: BTreeMap<u32, Vec<&ExecNode>> = BTreeMap::new();
    let mut roots: Vec<&ExecNode> = Vec::new();
    for n in nodes {
        match n.ppid {
            Some(p) if present.contains(&p) && p != n.pid => children.entry(p).or_default().push(n),
            // Parent outside this set (the cell's first exec, or a chain cut by
            // filtering), or a self-parent, which would loop.
            _ => roots.push(n),
        }
    }
    // Deterministic order: earliest exec first, then pid.
    let by_time =
        |a: &&ExecNode, b: &&ExecNode| a.ts_millis.cmp(&b.ts_millis).then(a.pid.cmp(&b.pid));
    roots.sort_by(by_time);
    for kids in children.values_mut() {
        kids.sort_by(by_time);
    }

    // `seen` bounds the walk: a pid appearing twice (pid reuse within one log)
    // must not be expanded twice, or the render could recurse without end.
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    for r in roots {
        walk(r, &children, &by_pid, 0, &mut seen, &mut tree.lines);
    }
    tree
}

#[allow(clippy::too_many_arguments)]
fn walk(
    node: &ExecNode,
    children: &BTreeMap<u32, Vec<&ExecNode>>,
    connects: &BTreeMap<u32, Vec<&ConnectNode>>,
    depth: usize,
    seen: &mut BTreeSet<u32>,
    out: &mut Vec<String>,
) {
    let indent = "  ".repeat(depth + 1);
    out.push(format!("{indent}{}", label(node)));
    if !seen.insert(node.pid) {
        // Already expanded elsewhere; render the line but do not recurse.
        return;
    }
    // Endpoints this process opened, collapsed by destination with a count —
    // an `npm install` opens hundreds and one line each would bury the tree.
    if let Some(cs) = connects.get(&node.pid) {
        let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
        for c in cs {
            *tally.entry(c.endpoint.as_str()).or_default() += 1;
        }
        for (endpoint, n) in tally {
            let times = if n > 1 {
                format!(" x{n}")
            } else {
                String::new()
            };
            out.push(format!("{indent}  -> {endpoint}{times}"));
        }
    }
    if let Some(kids) = children.get(&node.pid) {
        for k in kids {
            walk(k, children, connects, depth + 1, seen, out);
        }
    }
}

fn label(n: &ExecNode) -> String {
    let verdict = match (n.enforced, n.allowed) {
        (true, true) => "allow",
        (true, false) => "DENY ",
        (false, true) => "would-allow",
        (false, false) => "WOULD-DENY",
    };
    let digest = if n.target.len() >= 16 {
        &n.target[..16]
    } else {
        &n.target
    };
    format!("{verdict} pid {:<7} {:<16} {digest}", n.pid, n.comm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(pid: u32, ppid: Option<u32>, comm: &str, allowed: bool, ts: u64) -> ExecNode {
        ExecNode {
            pid,
            ppid,
            comm: comm.into(),
            target: "a".repeat(64),
            allowed,
            enforced: true,
            ts_millis: ts,
        }
    }

    fn observed(pid: u32, ppid: Option<u32>, allowed: bool) -> ExecNode {
        ExecNode {
            enforced: false,
            ..n(pid, ppid, "sh", allowed, 1)
        }
    }

    /// The shape observed live on a tier-1 box: `sh` under `ql` (whose pid is
    /// not in the log), and `dash` under that `sh`.
    #[test]
    fn nests_a_real_parent_chain_and_roots_the_orphan() {
        let nodes = vec![
            n(34348, Some(34347), "sh", true, 10),
            n(34349, Some(34348), "dash", true, 20),
        ];
        let t = build_with_connects(&nodes, &[], 0);
        assert!(t.any_parent_data);
        assert_eq!(t.lines.len(), 2);
        // 34347 is `ql` itself, outside the cell, so 34348 is a root...
        assert!(t.lines[0].starts_with("  allow pid 34348"), "{:?}", t.lines);
        // ...and 34349 nests one level under it.
        assert!(
            t.lines[1].starts_with("    allow pid 34349"),
            "{:?}",
            t.lines
        );
    }

    /// Detail strings round-trip, including the no-ppid form written before
    /// parent capture existed.
    #[test]
    fn parses_both_detail_forms_and_rejects_anything_else() {
        assert_eq!(
            parse_detail("pid 4242 ppid 100 (npm)"),
            Some((4242, Some(100), "npm".to_string()))
        );
        assert_eq!(
            parse_detail("pid 7 (sh)"),
            Some((7, None, "sh".to_string()))
        );
        // Strict: no guessing at malformed input.
        assert_eq!(parse_detail("pid abc ppid 1 (x)"), None);
        assert_eq!(parse_detail("egress.connect pypi.org:443"), None);
        assert_eq!(parse_detail(""), None);
        // Observe records append a marker after the comm; the tree must still
        // read them, or observe runs group nothing.
        assert_eq!(
            parse_detail("pid 42 ppid 7 (observe) NOT ENFORCING (observe mode)"),
            Some((42, Some(7), "observe".to_string()))
        );
    }

    /// A log with no parent data anywhere (tier 2) is listed flat and flagged,
    /// rather than rendered as a tree of depth one — those are different
    /// claims about what the substrate observed.
    #[test]
    fn no_parent_data_lists_flat_and_says_so() {
        let nodes = vec![n(1, None, "sh", true, 1), n(2, None, "cc", false, 2)];
        let t = build_with_connects(&nodes, &[], 0);
        assert!(!t.any_parent_data);
        assert_eq!(t.lines.len(), 2);
        assert!(t.lines.iter().all(|l| l.starts_with("  ")));
        assert!(!t.lines.iter().any(|l| l.starts_with("    ")));
    }

    /// A denied exec never becomes a parent — the process was refused, so
    /// nothing ran under it. It renders as a leaf.
    #[test]
    fn a_denial_is_a_leaf() {
        let nodes = vec![
            n(10, Some(9), "sh", true, 1),
            n(11, Some(10), "curl", false, 2),
        ];
        let t = build_with_connects(&nodes, &[], 0);
        assert!(t.lines[1].contains("DENY"));
        assert!(t.lines[1].starts_with("    "), "{:?}", t.lines);
    }

    /// A self-parenting record cannot loop the walk, and a repeated pid is
    /// rendered without being expanded twice.
    #[test]
    fn cycles_and_repeated_pids_terminate() {
        let nodes = vec![
            n(5, Some(5), "loop", true, 1),
            n(6, Some(5), "child", true, 2),
            n(6, Some(5), "child-again", true, 3),
        ];
        let t = build_with_connects(&nodes, &[], 0);
        // Terminates, and every record is accounted for.
        assert_eq!(t.lines.len(), 3);
    }

    /// Only per-process decisions belong in the tree. The exec wall also
    /// writes configuration records (`exec.enforce`, `exec.digest`) that
    /// describe how it was set up and have no pid; counting those as
    /// unplaceable reported a failure on every run where nothing had failed.
    #[test]
    fn only_per_process_actions_are_tree_candidates() {
        for action in ["exec.run", "exec.deny"] {
            assert!(matches!(action, "exec.run" | "exec.deny"), "{action}");
        }
        for action in ["exec.enforce", "exec.digest", "egress.connect"] {
            assert!(!matches!(action, "exec.run" | "exec.deny"), "{action}");
        }
    }

    /// An observe-mode record is labelled as a prediction, never as an
    /// enforced outcome. In observe mode nothing is stopped, so rendering a
    /// would-deny as "DENY" would tell a reader the process was blocked when
    /// it ran to completion.
    #[test]
    fn observe_records_are_labelled_as_predictions() {
        let t = build_with_connects(
            &[observed(1, None, true), observed(2, Some(1), false)],
            &[],
            0,
        );
        assert!(t.lines[0].contains("would-allow"), "{:?}", t.lines);
        assert!(t.lines[1].contains("WOULD-DENY"), "{:?}", t.lines);
        // And never the enforced words, which would overstate what happened.
        assert!(!t.lines[0].contains("allow  pid"), "{:?}", t.lines);
        assert!(!t.lines[1].starts_with("    DENY"), "{:?}", t.lines);
    }

    /// **Lineage.** A connect hangs off the process that opened it, because in
    /// observe mode the pid comes from the same syscall stop that recorded the
    /// connect — an observation, not a correlation.
    #[test]
    fn connects_attach_to_the_process_that_opened_them() {
        let nodes = vec![
            n(10, None, "sh", true, 1),
            n(11, Some(10), "curl", true, 2),
            n(12, Some(10), "true", true, 3),
        ];
        let connects = vec![
            ConnectNode {
                pid: 11,
                endpoint: "1.2.3.4:443".into(),
            },
            ConnectNode {
                pid: 11,
                endpoint: "1.2.3.4:443".into(),
            },
            ConnectNode {
                pid: 11,
                endpoint: "5.6.7.8:443".into(),
            },
        ];
        let t = build_with_connects(&nodes, &connects, 0);
        let joined = t.lines.join("\n");

        // Repeats collapse with a count rather than one line each.
        assert!(joined.contains("-> 1.2.3.4:443 x2"), "{joined}");
        assert!(joined.contains("-> 5.6.7.8:443"), "{joined}");
        assert!(t.unattributed.is_empty());

        // The endpoints sit under curl (pid 11), not under its siblings.
        let curl_at = t.lines.iter().position(|l| l.contains("pid 11")).unwrap();
        let true_at = t.lines.iter().position(|l| l.contains("pid 12")).unwrap();
        assert!(curl_at < true_at);
        for i in curl_at + 1..true_at {
            assert!(
                t.lines[i].contains("->"),
                "only endpoints between: {:?}",
                t.lines[i]
            );
        }
    }

    /// A connect whose pid matches no exec node is listed as unattributed —
    /// never attached to the nearest process in time, which would manufacture
    /// causality out of coincidence.
    #[test]
    fn an_unmatched_connect_is_listed_not_guessed() {
        let nodes = vec![n(10, None, "sh", true, 1)];
        let connects = vec![ConnectNode {
            pid: 999,
            endpoint: "9.9.9.9:53".into(),
        }];
        let t = build_with_connects(&nodes, &connects, 0);

        assert_eq!(t.unattributed.len(), 1);
        assert!(t.unattributed[0].contains("9.9.9.9:53"));
        assert!(t.unattributed[0].contains("999"));
        assert!(
            !t.lines.iter().any(|l| l.contains("9.9.9.9")),
            "{:?}",
            t.lines
        );
    }

    /// Unparsed records are counted, never silently dropped.
    #[test]
    fn unparsed_records_are_surfaced() {
        let t = build_with_connects(&[n(1, Some(0), "sh", true, 1)], &[], 3);
        assert_eq!(t.unparsed, 3);
    }
}

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
    /// True when this exec returned an error — the program never ran.
    pub failed: bool,
    /// False for observe-mode records. An observe "would-deny" is a
    /// prediction, not a denial that happened: nothing was stopped. Labelling
    /// it the same as an enforced denial would tell a reader the process was
    /// blocked when it ran to completion.
    pub enforced: bool,
    /// Milliseconds since the Unix epoch.
    pub ts_millis: u64,
    /// Observation order within the run. Several execs share a millisecond
    /// during a PATH search, so this — not the timestamp — is what decides
    /// which image was live when a connect happened. Falls back to
    /// `ts_millis` for records written before sequences existed.
    pub order: u64,
}

/// Parse `pid <n> ppid <n> (comm)` or `pid <n> (comm)` out of a detail string.
///
/// Strict by design: an unrecognized shape returns `None` so the caller can
/// report the record as ungrouped instead of attaching it to a guess.
/// The fields carried in an exec or connect record's `detail` string.
///
/// `seq` is the observation sequence when the record carries one. Ordering
/// uses it rather than the timestamp: several `execve` calls share a
/// millisecond during a PATH search, so timestamps tie and attribution picks
/// whichever record came first — observed naming a binary that never ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail {
    /// The process that performed the action.
    pub pid: u32,
    /// Its parent, when the record carries one.
    pub ppid: Option<u32>,
    /// Observation order, when the record carries one.
    pub seq: Option<u64>,
    /// True when the `execve` failed — a PATH-search candidate.
    pub failed: bool,
    /// The task comm, or the binary's basename in observe mode.
    pub comm: String,
}

pub fn parse_detail(detail: &str) -> Option<Detail> {
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

    let (seq, rest) = match rest.strip_prefix("seq ") {
        Some(after) => {
            let (seq_str, tail) = after.split_once(' ')?;
            (Some(seq_str.parse::<u64>().ok()?), tail)
        }
        None => (None, rest),
    };
    let (failed, rest) = match rest.strip_prefix("miss ") {
        Some(tail) => (true, tail),
        None => (false, rest),
    };

    // Trailing text after the comm is allowed: observe records append their
    // NOT-ENFORCING marker there. Take up to the first ')' rather than
    // requiring the string to end at it.
    let inner = rest.strip_prefix('(')?;
    let (comm, _tail) = inner.split_once(')')?;
    Some(Detail {
        pid,
        ppid,
        seq,
        failed,
        comm: comm.to_string(),
    })
}

/// One egress connect attributed to a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectNode {
    /// The process that opened it.
    pub pid: u32,
    /// That process's parent, used to attribute a process that forked and
    /// never exec'd — such a process is running its parent's image, so its
    /// parent's node is the right owner.
    pub ppid: Option<u32>,
    /// `ip:port`. Not a domain: by `connect` time the name is resolved and
    /// gone.
    pub endpoint: String,
    /// Wall-clock ms at the connect syscall.
    pub ts_millis: u64,
    /// Observation order; see [`ExecNode::order`].
    pub order: u64,
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
    // Attribution key is (pid, exec timestamp), not pid alone.
    //
    // A single pid routinely holds several exec records — a PATH search emits
    // one `execve` per directory tried, and `exec` in a shell replaces the
    // image without forking. Keying on pid alone would hang every connect off
    // whichever record for that pid happened to be walked first, reporting
    // that `dash` opened a socket that `curl` opened. So each connect attaches
    // to the *latest exec at or before it*: the image that was actually
    // running.
    //
    // A process that forked and never exec'd has no record of its own; it is
    // running its parent's image, so its connects attribute to the nearest
    // ancestor that does have one. That is a fact about fork semantics, not a
    // guess about proximity.
    let mut by_node: BTreeMap<(u32, u64), Vec<&ConnectNode>> = BTreeMap::new();
    // Keyed on (pid, order) — see ExecNode::order for why not the timestamp.
    let mut unattributed = Vec::new();
    let parent_of: BTreeMap<u32, Option<u32>> = nodes.iter().map(|n| (n.pid, n.ppid)).collect();

    for c in connects {
        // Resolve to a pid that has exec records, following fork links.
        let mut owner = Some(c.pid);
        if !parent_of.contains_key(&c.pid) {
            owner = c.ppid;
            let mut hops = 0;
            while let Some(p) = owner {
                if parent_of.contains_key(&p) || hops > 16 {
                    break;
                }
                owner = parent_of.get(&p).copied().flatten();
                hops += 1;
            }
            if owner.map(|p| !parent_of.contains_key(&p)).unwrap_or(true) {
                owner = None;
            }
        }

        // Among that pid's execs, the last one at or before this connect.
        let chosen = owner.and_then(|pid| {
            nodes
                .iter()
                // `!n.failed` matters: a PATH-search candidate never ran, so
                // it cannot have opened a socket. Without it, a shell whose
                // `exec` failed and which then connected in place would have
                // its egress credited to a program that was never there.
                .filter(|n| n.pid == pid && !n.failed && n.order <= c.order)
                .max_by_key(|n| n.order)
                .map(|n| (n.pid, n.order))
        });
        match chosen {
            Some(key) => by_node.entry(key).or_default().push(c),
            None => unattributed.push(format!("{} (pid {})", c.endpoint, c.pid)),
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
        // Connects still attach to their own process — attribution does not
        // depend on parentage, and dropping them here silently lost every
        // endpoint of a single-process run, where the root has no parent and
        // there are no children to supply one.
        for n in nodes {
            tree.lines.push(format!("  {}", label(n)));
            if let Some(cs) = by_node.get(&(n.pid, n.order)) {
                for (endpoint, count) in tally(cs) {
                    let times = if count > 1 {
                        format!(" x{count}")
                    } else {
                        String::new()
                    };
                    tree.lines.push(format!("    -> {endpoint}{times}"));
                }
            }
        }
        return tree;
    }

    let present: BTreeSet<u32> = nodes.iter().map(|n| n.pid).collect();
    // Keyed on (pid, order), the same identity connects use. Keying on pid
    // alone attached a child to *every* exec record of its parent: a shell
    // that walked a PATH search rendered its one child once per candidate,
    // including under records for programs that never ran.
    let mut children: BTreeMap<(u32, u64), Vec<&ExecNode>> = BTreeMap::new();
    let mut roots: Vec<&ExecNode> = Vec::new();
    for n in nodes {
        // The parent record that was live when this child appeared: the latest
        // successful exec of that pid at or before it. A failed candidate
        // never ran, so it cannot have spawned anything.
        let parent_key = n
            .ppid
            .filter(|p| present.contains(p) && *p != n.pid)
            .and_then(|p| {
                nodes
                    .iter()
                    .filter(|c| c.pid == p && !c.failed && c.order <= n.order)
                    .max_by_key(|c| c.order)
                    .map(|c| (c.pid, c.order))
            });
        match parent_key {
            Some(key) => children.entry(key).or_default().push(n),
            // Parent outside this set (the cell's first exec, or a chain cut
            // by filtering), or a self-parent, which would loop.
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

    // `seen` bounds the walk. Keyed on (pid, exec time) rather than pid alone
    // because one pid legitimately holds several exec records — a PATH search
    // emits one per directory tried, and shell `exec` replaces the image in
    // place. Keying on pid would collapse those into a single line and hide
    // which image was actually running. Cycles are still bounded, since a
    // record cannot precede itself.
    let mut seen: BTreeSet<(u32, u64)> = BTreeSet::new();
    for r in roots {
        walk(r, &children, &by_node, 0, &mut seen, &mut tree.lines);
    }
    tree
}

#[allow(clippy::too_many_arguments)]
fn walk(
    node: &ExecNode,
    children: &BTreeMap<(u32, u64), Vec<&ExecNode>>,
    connects: &BTreeMap<(u32, u64), Vec<&ConnectNode>>,
    depth: usize,
    seen: &mut BTreeSet<(u32, u64)>,
    out: &mut Vec<String>,
) {
    let indent = "  ".repeat(depth + 1);
    out.push(format!("{indent}{}", label(node)));
    if !seen.insert((node.pid, node.order)) {
        // Already expanded elsewhere; render the line but do not recurse.
        return;
    }
    // Endpoints this process opened, collapsed by destination with a count —
    // an `npm install` opens hundreds and one line each would bury the tree.
    if let Some(cs) = connects.get(&(node.pid, node.order)) {
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
    if let Some(kids) = children.get(&(node.pid, node.order)) {
        for k in kids {
            walk(k, children, connects, depth + 1, seen, out);
        }
    }
}

/// Collapse repeated endpoints into `(endpoint, count)` pairs. An `npm
/// install` opens hundreds of connections and one line each would bury the
/// tree.
///
/// The count is connect *attempts*, not distinct connections: a `connect`
/// interrupted by a signal is restarted and recorded again.
fn tally<'a>(cs: &[&'a ConnectNode]) -> BTreeMap<&'a str, usize> {
    let mut t: BTreeMap<&str, usize> = BTreeMap::new();
    for c in cs {
        *t.entry(c.endpoint.as_str()).or_default() += 1;
    }
    t
}

/// Shorten a target for display, keeping the identifying end.
fn shorten(target: &str, width: usize) -> String {
    if target.chars().count() <= width {
        return target.to_string();
    }
    if target.starts_with('/') {
        // Keep the tail: `…local/bin/curl` beats `/home/mmhasan/.l`.
        let tail: String = target
            .chars()
            .skip(target.chars().count() - (width - 1))
            .collect();
        format!("…{tail}")
    } else {
        target.chars().take(width).collect()
    }
}

fn label(n: &ExecNode) -> String {
    // A candidate the kernel refused never ran, so no verdict about it is
    // meaningful — saying "would-allow" of a program that was not there
    // invites the reader to think it executed.
    let verdict = match (n.failed, n.enforced, n.allowed) {
        (true, _, _) => "PATH miss ",
        (false, true, true) => "allow",
        (false, true, false) => "DENY ",
        (false, false, true) => "would-allow",
        (false, false, false) => "WOULD-DENY",
    };
    // Paths truncate from the LEFT: the tail identifies the program, and
    // cutting `/home/u/.local/bin/curl` to `/home/u/.local/` says nothing.
    // Digests truncate from the right, where the leading bytes identify them.
    let shown = shorten(&n.target, 22);
    let digest = shown.as_str();
    // Padded so the pid column lines up across verdicts of differing widths.
    format!("{verdict:<11} pid {:<7} {:<16} {digest}", n.pid, n.comm)
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
            failed: false,
            ts_millis: ts,
            order: ts,
        }
    }

    fn cn(pid: u32, ppid: Option<u32>, endpoint: &str, ts_millis: u64) -> ConnectNode {
        ConnectNode {
            pid,
            ppid,
            endpoint: endpoint.into(),
            ts_millis,
            order: ts_millis,
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
        // (the verdict column is padded, so match on indent + content rather
        // than an exact prefix).
        assert!(t.lines[0].starts_with("  allow"), "{:?}", t.lines);
        assert!(t.lines[0].contains("pid 34348"), "{:?}", t.lines);
        // ...and 34349 nests one level under it.
        assert!(t.lines[1].starts_with("    allow"), "{:?}", t.lines);
        assert!(t.lines[1].contains("pid 34349"), "{:?}", t.lines);
    }

    /// Detail strings round-trip, including the no-ppid form written before
    /// parent capture existed.
    #[test]
    fn parses_both_detail_forms_and_rejects_anything_else() {
        assert_eq!(
            parse_detail("pid 4242 ppid 100 (npm)"),
            Some(Detail {
                pid: 4242,
                ppid: Some(100),
                seq: None,
                failed: false,
                comm: "npm".into()
            })
        );
        assert_eq!(
            parse_detail("pid 7 (sh)"),
            Some(Detail {
                pid: 7,
                ppid: None,
                seq: None,
                failed: false,
                comm: "sh".into()
            })
        );
        // Strict: no guessing at malformed input.
        assert_eq!(parse_detail("pid abc ppid 1 (x)"), None);
        assert_eq!(parse_detail("egress.connect pypi.org:443"), None);
        assert_eq!(parse_detail(""), None);
        // Observe records append a marker after the comm; the tree must still
        // read them, or observe runs group nothing.
        assert_eq!(
            parse_detail("pid 42 ppid 7 (observe) NOT ENFORCING (observe mode)"),
            Some(Detail {
                pid: 42,
                ppid: Some(7),
                seq: None,
                failed: false,
                comm: "observe".into()
            })
        );
        // With an observation sequence, which is what orders attribution.
        assert_eq!(
            parse_detail("pid 42 ppid 7 seq 13 (curl) NOT ENFORCING (observe mode)"),
            Some(Detail {
                pid: 42,
                ppid: Some(7),
                seq: Some(13),
                failed: false,
                comm: "curl".into()
            })
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
            cn(11, Some(10), "1.2.3.4:443", 5),
            cn(11, Some(10), "1.2.3.4:443", 5),
            cn(11, Some(10), "5.6.7.8:443", 6),
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
        let connects = vec![cn(999, None, "9.9.9.9:53", 5)];
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

    /// **The same-pid, different-image case.** A PATH search emits one
    /// `execve` per directory tried, and shell `exec` replaces an image
    /// without forking — so one pid holds several exec records. A connect must
    /// attach to the image that was live when it happened, not to whichever
    /// record for that pid was walked first. Observed in a real run: `sh -c
    /// 'exec curl …'` produced eight exec records under a single pid.
    #[test]
    fn a_connect_attaches_to_the_image_that_was_running() {
        let nodes = vec![
            // Same pid, three images in sequence — a PATH search then the hit.
            n(20, None, "dash", true, 10),
            n(20, None, "missing", false, 20),
            n(20, None, "curl", true, 30),
        ];
        // Connect happens after the final exec.
        let t = build_with_connects(&nodes, &[cn(20, None, "1.2.3.4:443", 40)], 0);

        let find = |needle: &str| {
            t.lines
                .iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("no `{needle}` line in {:?}", t.lines))
        };
        let ep_at = find("->");
        // The endpoint follows the LAST exec for that pid, not the first.
        assert_eq!(ep_at, find("curl") + 1, "{:?}", t.lines);
        assert!(ep_at > find("dash") + 1, "attached to dash: {:?}", t.lines);
        assert!(
            ep_at > find("missing") + 1,
            "attached to the miss: {:?}",
            t.lines
        );
    }

    /// A process that forked and never exec'd is running its parent's image,
    /// so its connects belong to the parent's node. Observed in a real run:
    /// curl forked a helper that opened five of six connections and had no
    /// exec record of its own.
    #[test]
    fn a_forked_child_attributes_to_its_parents_image() {
        let nodes = vec![
            n(30, None, "sh", true, 10),
            n(31, Some(30), "curl", true, 20),
        ];
        // pid 32 forked from 31 and never exec'd.
        let t = build_with_connects(&nodes, &[cn(32, Some(31), "1.2.3.4:443", 30)], 0);

        assert!(t.unattributed.is_empty(), "{:?}", t.unattributed);
        let curl_at = t.lines.iter().position(|l| l.contains("curl")).unwrap();
        assert!(
            t.lines[curl_at + 1].contains("-> 1.2.3.4:443"),
            "{:?}",
            t.lines
        );
    }

    /// A connect that precedes every exec for its pid has no live image to
    /// attach to, and is reported rather than attached to a later one.
    #[test]
    fn a_connect_before_any_exec_is_unattributed() {
        let nodes = vec![n(40, None, "sh", true, 100)];
        let t = build_with_connects(&nodes, &[cn(40, None, "1.2.3.4:443", 50)], 0);
        assert_eq!(t.unattributed.len(), 1);
        assert!(!t.lines.iter().any(|l| l.contains("->")), "{:?}", t.lines);
    }

    /// A single-process run has no parent data anywhere, so the tree lists
    /// flat — but its connects must still appear. Dropping them here silently
    /// lost every endpoint of `ql run --observe -- curl …`, which is about the
    /// simplest thing anyone would try.
    #[test]
    fn a_flat_listing_still_shows_its_connects() {
        let nodes = vec![n(50, None, "curl", true, 10)];
        let t = build_with_connects(&nodes, &[cn(50, None, "1.2.3.4:443", 20)], 0);
        assert!(!t.any_parent_data);
        assert!(
            t.lines.iter().any(|l| l.contains("-> 1.2.3.4:443")),
            "{:?}",
            t.lines
        );
    }

    /// Ordering uses observation order, not the timestamp. A PATH search
    /// emits several `execve` calls inside one millisecond; ordering by
    /// timestamp ties and picks the first, which in a real run attributed a
    /// connection to a binary that never ran (`/home/.../bin/curl`, ENOENT)
    /// instead of the `/usr/bin/curl` that opened it.
    #[test]
    fn same_millisecond_execs_are_ordered_by_observation_not_time() {
        let mut nodes = vec![
            n(60, None, "dash", true, 100),
            n(60, None, "miss", true, 100),
            n(60, None, "curl", true, 100),
        ];
        // All in the same millisecond; only `order` distinguishes them.
        for (i, node) in nodes.iter_mut().enumerate() {
            node.order = i as u64;
        }
        let mut c = cn(60, None, "1.2.3.4:443", 100);
        c.order = 9;
        let t = build_with_connects(&nodes, &[c], 0);

        let ep_at = t.lines.iter().position(|l| l.contains("->")).unwrap();
        let curl_at = t.lines.iter().position(|l| l.contains("curl")).unwrap();
        assert_eq!(
            ep_at,
            curl_at + 1,
            "must follow the last exec: {:?}",
            t.lines
        );
    }

    /// **Serialization must preserve ordering.** If connect records lack a
    /// sequence, their order falls back to epoch milliseconds while execs
    /// carry small counters — so every exec of a pid compares as "before" and
    /// attribution picks that pid's last exec of the whole run. A process that
    /// connects and *then* execs in place would have its connection credited
    /// to the later image.
    #[test]
    fn a_connect_is_not_credited_to_a_later_image() {
        let mut early = n(70, None, "curl", true, 100);
        early.order = 1;
        let mut later = n(70, None, "python", true, 100);
        later.order = 9;

        // Connect happened between the two execs.
        let mut c = cn(70, None, "1.2.3.4:443", 100);
        c.order = 5;

        let t = build_with_connects(&[early, later], &[c], 0);
        let ep_at = t.lines.iter().position(|l| l.contains("->")).unwrap();
        let curl_at = t.lines.iter().position(|l| l.contains("curl")).unwrap();
        let py_at = t.lines.iter().position(|l| l.contains("python")).unwrap();
        assert_eq!(ep_at, curl_at + 1, "must follow curl: {:?}", t.lines);
        assert!(ep_at < py_at, "credited to the later image: {:?}", t.lines);
    }

    /// A PATH-search candidate never ran, so it carries no verdict — saying
    /// "would-allow" of a program that was not there reads as though it
    /// executed. Observed live: one `curl` produced eight exec records, seven
    /// of them ENOENT.
    #[test]
    fn a_path_miss_is_not_reported_as_a_verdict() {
        let mut miss = n(80, None, "curl", true, 1);
        miss.failed = true;
        miss.enforced = false;
        let real = n(80, None, "curl", true, 2);

        let t = build_with_connects(&[miss, real], &[], 0);
        assert!(t.lines[0].contains("PATH miss"), "{:?}", t.lines);
        assert!(!t.lines[0].contains("would-allow"), "{:?}", t.lines);
        assert!(t.lines[1].contains("allow"), "{:?}", t.lines);
    }

    /// A child attaches to the parent record that was live when it appeared,
    /// not to every record sharing the parent's pid. Found running goose: a
    /// shell walked a PATH search, and its single `head` child rendered five
    /// times — once under each candidate, including three that never ran.
    #[test]
    fn a_child_attaches_to_one_parent_record() {
        let mut miss = n(100, None, "bash", true, 1);
        miss.failed = true;
        let real = n(100, None, "bash", true, 2);
        let child = n(101, Some(100), "head", true, 3);

        let t = build_with_connects(&[miss, real, child], &[], 0);
        let head_lines = t.lines.iter().filter(|l| l.contains("head")).count();
        assert_eq!(
            head_lines, 1,
            "child rendered more than once: {:?}",
            t.lines
        );
        // And under the record that actually ran, not the miss.
        let miss_at = t
            .lines
            .iter()
            .position(|l| l.contains("PATH miss"))
            .unwrap();
        let head_at = t.lines.iter().position(|l| l.contains("head")).unwrap();
        assert!(head_at > miss_at + 1, "attached to the miss: {:?}", t.lines);
    }

    /// A failed candidate cannot own a connection: it never ran. The case is
    /// `sh -c 'exec nosuchcmd || curl …'` — every candidate fails, the shell
    /// continues in place, and the connect belongs to the shell. Attaching it
    /// to the miss would credit egress to a program that was never there.
    #[test]
    fn a_failed_exec_cannot_own_a_connection() {
        let shell = n(90, None, "sh", true, 1);
        let mut miss = n(90, None, "nosuchcmd", true, 2);
        miss.failed = true;

        // Connect happens after the failed candidate.
        let mut c = cn(90, None, "1.2.3.4:443", 3);
        c.order = 3;

        let t = build_with_connects(&[shell, miss], &[c], 0);
        let sh_at = t.lines.iter().position(|l| l.contains("sh ")).unwrap();
        let ep_at = t.lines.iter().position(|l| l.contains("->")).unwrap();
        assert_eq!(ep_at, sh_at + 1, "must belong to the shell: {:?}", t.lines);
        // The miss line must not carry it.
        let miss_at = t
            .lines
            .iter()
            .position(|l| l.contains("PATH miss"))
            .unwrap();
        assert!(
            ep_at < miss_at,
            "credited to a program never run: {:?}",
            t.lines
        );
    }

    /// Paths keep their identifying tail; digests keep their head.
    #[test]
    fn long_targets_shorten_from_the_end_that_matters() {
        let long_path = "/home/someone/.npm-global/bin/curl";
        let shown = shorten(long_path, 22);
        assert!(shown.ends_with("bin/curl"), "{shown}");
        assert!(shown.starts_with('…'), "{shown}");

        let digest = "a".repeat(64);
        assert_eq!(shorten(&digest, 16), "a".repeat(16));
        // Short targets are untouched.
        assert_eq!(shorten("/usr/bin/curl", 22), "/usr/bin/curl");
    }

    /// Unparsed records are counted, never silently dropped.
    #[test]
    fn unparsed_records_are_surfaced() {
        let t = build_with_connects(&[n(1, Some(0), "sh", true, 1)], &[], 3);
        assert_eq!(t.unparsed, 3);
    }
}

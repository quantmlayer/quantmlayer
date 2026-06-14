// crates/ql-cli/src/kill.rs
//
//! `ql kill` / `ql ps` — the revocation ("kill switch") commands.
//!
//! `ql kill <id>` revokes a running cell: it terminates the `ql run` process
//! and every process the agent spawned (a `/proc` process-tree walk, SIGTERM
//! then SIGKILL), then records the revocation in an audit log if one is given.
//!
//! Completeness note: the tree walk catches the agent and its descendants. A
//! process that double-forks and `setsid`s to escape re-parents to init and
//! leaves the tree — catching *those* requires the cell's cgroup
//! (`cgroup.kill`), which is the atomic, no-escape upgrade for the root/cgroup
//! posture. This command is the portable, rootless-capable baseline.

use crate::registry::{self, Handle};
use ql_audit::{AuditEvent, AuditLog, Decision};
use std::process::ExitCode;
use std::time::Duration;

pub fn cmd_kill(args: &[String]) -> ExitCode {
    let mut id: Option<String> = None;
    let mut audit_path: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--audit" => audit_path = it.next().cloned(),
            "-h" | "--help" => {
                eprintln!("usage: ql kill <id> [--audit <log.jsonl>]");
                return ExitCode::SUCCESS;
            }
            other if !other.starts_with('-') => id = Some(other.to_string()),
            other => {
                eprintln!("ql kill: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    let Some(id) = id else {
        eprintln!("ql kill: a cell id is required (see `ql ps`)");
        return ExitCode::from(2);
    };
    let Some(handle) = registry::get(&id) else {
        eprintln!("ql kill: no running cell with id `{id}` (see `ql ps`)");
        return ExitCode::from(1);
    };

    if !registry::pid_alive(handle.pid) {
        eprintln!("ql kill: cell `{id}` already exited; clearing its handle");
        registry::deregister(&id);
        return ExitCode::SUCCESS;
    }

    let n = tree_kill(handle.pid);
    record_revocation(&handle, audit_path.as_deref());
    registry::deregister(&id);
    println!("revoked cell `{id}` ({n} process(es) signalled)");
    ExitCode::SUCCESS
}

pub fn cmd_ps(_args: &[String]) -> ExitCode {
    let mut handles = registry::list();
    // Prune dead handles as we go.
    handles.retain(|h| {
        if registry::pid_alive(h.pid) {
            true
        } else {
            registry::deregister(&h.id);
            false
        }
    });

    if handles.is_empty() {
        println!("no running cells");
        return ExitCode::SUCCESS;
    }
    println!("{:<14} {:>8}  {:<7} COMMAND", "ID", "PID", "BROKER");
    for h in handles {
        println!(
            "{:<14} {:>8}  {:<7} {}",
            h.id,
            h.pid,
            if h.brokered { "yes" } else { "no" },
            h.command
        );
    }
    ExitCode::SUCCESS
}

/// Terminate `root` and all of its descendants: SIGTERM, brief grace, SIGKILL
/// to any survivor. Returns how many processes were signalled.
fn tree_kill(root: u32) -> usize {
    let mut targets = descendants(root);
    targets.push(root);
    targets.sort_unstable();
    targets.dedup();

    for &p in &targets {
        unsafe { libc::kill(p as i32, libc::SIGTERM) };
    }
    std::thread::sleep(Duration::from_millis(300));
    for &p in &targets {
        if registry::pid_alive(p) {
            unsafe { libc::kill(p as i32, libc::SIGKILL) };
        }
    }
    targets.len()
}

/// All descendant pids of `root`, discovered from `/proc/<pid>/stat` parent
/// links (breadth-first). Excludes `root` itself.
fn descendants(root: u32) -> Vec<u32> {
    use std::collections::HashMap;
    // Build pid -> ppid for every process.
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let name = e.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            if let Some(ppid) = read_ppid(pid) {
                children.entry(ppid).or_default().push(pid);
            }
        }
    }
    // BFS from root.
    let mut out = Vec::new();
    let mut queue = vec![root];
    while let Some(p) = queue.pop() {
        if let Some(kids) = children.get(&p) {
            for &k in kids {
                if k != root && !out.contains(&k) {
                    out.push(k);
                    queue.push(k);
                }
            }
        }
    }
    out
}

/// Parse the parent pid from `/proc/<pid>/stat`. The `comm` field may contain
/// spaces and parentheses, so we split after the last ')'.
fn read_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 2..)?; // skip ") "
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse::<u32>().ok()
}

/// Append a revocation record to the audit log if a path was given.
fn record_revocation(h: &Handle, audit_path: Option<&str>) {
    let Some(path) = audit_path else {
        return;
    };
    let mut log = match std::fs::read_to_string(path) {
        Ok(s) => AuditLog::from_jsonl(&s).unwrap_or_default(),
        Err(_) => AuditLog::new(),
    };
    let event = AuditEvent {
        ts_millis: AuditLog::now_millis(),
        actor: "operator".into(),
        action: "cell.revoke".into(),
        target: format!("cell:{}", h.id),
        decision: Decision::Deny,
        detail: format!("revoked `{}` (pid {})", h.command, h.pid),
    };
    if log.append(event).is_ok() {
        if let Ok(text) = log.to_jsonl() {
            let _ = std::fs::write(path, text);
        }
    }
}

// crates/ql-learn/src/observation.rs
//
//! The [`Observation`]: a structured record of what an agent actually *did*
//! during a learning run — which files it read and wrote, which programs it
//! executed, where it tried to connect, and which syscalls it used.
//!
//! This is the raw evidence the synthesizer ([`crate::synth`]) turns into a
//! least-privilege [`ql_profile::Profile`]. Keeping it as plain data (no OS
//! types) makes it easy to serialize, diff across runs, and reason about.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;

use ql_profile::ExecDigest;

/// One observed `connect`, with the process that opened it.
///
/// The endpoint is an IP and port, not a domain: by the time `connect` is
/// called the name is already resolved and gone. That is a real limit on how
/// this reads, not a defect in the attribution — the *lineage* (which process
/// opened it, under which parent) is exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectEvent {
    /// The process that called `connect`.
    pub pid: u32,
    /// Its parent as the tracer saw it, when available.
    pub ppid: Option<u32>,
    /// The destination address.
    pub ip: IpAddr,
    /// The destination port.
    pub port: u16,
    /// The mechanism that observed this event: `"ptrace"` in observe mode.
    pub observed_by: &'static str,
}

/// One observed `execve`, with the process that performed it.
///
/// `observed_by` names the mechanism rather than leaving it implied, because
/// ptrace and the kernel's `real_parent` are not the same fact: ptrace reports
/// the tracer's view, which can differ under re-parenting. A consumer that
/// joins these with enforce-mode records should know which it is looking at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecEvent {
    /// The process that called `execve`.
    pub pid: u32,
    /// Its parent as the tracer saw it, when available.
    pub ppid: Option<u32>,
    /// The program path passed to `execve`.
    pub path: String,
    /// The mechanism that observed this event: `"ptrace"` in observe mode.
    pub observed_by: &'static str,
}

/// Everything the tracer learned from one (or more) processes in a run.
#[derive(Debug, Default, Clone)]
pub struct Observation {
    /// Absolute paths opened for reading only.
    pub reads: BTreeSet<PathBuf>,
    /// Absolute paths opened for writing/creation.
    pub writes: BTreeSet<PathBuf>,
    /// Program paths passed to `execve`.
    pub execs: BTreeSet<String>,
    /// Per-exec events with the pid that performed them, in observed order.
    ///
    /// Kept alongside `execs` rather than replacing it: the set drives profile
    /// synthesis, where order and repetition are noise, while this preserves
    /// the attribution a process tree needs. Enforce mode gets the same fact
    /// from the kernel at `sched_process_exec`; here it comes from the ptrace
    /// stop, which is the tracer's view of the process — see
    /// [`ExecEvent::observed_by`].
    pub exec_events: Vec<ExecEvent>,
    /// SHA-256 content digests of the binaries in `execs`, keyed by path.
    /// Filled by the hashing pass after tracing; empty until then.
    pub exec_digests: BTreeMap<String, ExecDigest>,
    /// Network endpoints the agent attempted to `connect` to.
    pub connects: BTreeSet<(IpAddr, u16)>,
    /// Per-connect events with the process that opened them, in observed
    /// order.
    ///
    /// Kept alongside `connects` for the same reason `exec_events` sits beside
    /// `execs`: the set drives profile synthesis, where duplicates and order
    /// are noise, while this preserves the attribution lineage needs.
    ///
    /// Enforce mode cannot produce this from the same place — the broker sits
    /// on the far side of a veth in another network namespace and sees a TCP
    /// connection, not a process. Here the pid is simply in hand at the
    /// syscall stop, so attribution is exact and needs no correlation.
    pub connect_events: Vec<ConnectEvent>,
    /// Raw syscall numbers observed, with a human-readable name when known.
    pub syscalls: BTreeMap<u64, String>,
    /// Count of distinct processes traced (the agent plus any children).
    pub process_count: u32,
}

impl Observation {
    /// Record a file open, routing it to reads or writes by intent.
    pub fn record_open(&mut self, path: PathBuf, write: bool) {
        // A path opened for writing implies the right to read it too; we keep
        // it only in `writes` and let the synthesizer treat writes ⊇ reads.
        if write {
            self.reads.remove(&path);
            self.writes.insert(path);
        } else if !self.writes.contains(&path) {
            self.reads.insert(path);
        }
    }

    /// Record an `execve` of `path` by `pid`.
    pub fn record_exec(&mut self, path: String, pid: u32, ppid: Option<u32>) {
        if !path.is_empty() {
            self.execs.insert(path.clone());
            self.exec_events.push(ExecEvent {
                pid,
                ppid,
                path,
                observed_by: "ptrace",
            });
        }
    }

    /// Record a `connect` to a resolved endpoint by `pid`.
    pub fn record_connect(&mut self, ip: IpAddr, port: u16, pid: u32, ppid: Option<u32>) {
        self.connects.insert((ip, port));
        self.connect_events.push(ConnectEvent {
            pid,
            ppid,
            ip,
            port,
            observed_by: "ptrace",
        });
    }

    /// Record that syscall number `nr` (named `name`) was used.
    pub fn record_syscall(&mut self, nr: u64, name: &str) {
        self.syscalls.entry(nr).or_insert_with(|| name.to_string());
    }

    /// Whether any observed connection left the local host (i.e. was not to a
    /// loopback or link-local address).
    pub fn has_external_egress(&self) -> bool {
        self.connects.iter().any(|(ip, _)| match ip {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local(),
            IpAddr::V6(v6) => !v6.is_loopback(),
        })
    }
}

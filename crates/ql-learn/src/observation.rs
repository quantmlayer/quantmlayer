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

/// Everything the tracer learned from one (or more) processes in a run.
#[derive(Debug, Default, Clone)]
pub struct Observation {
    /// Absolute paths opened for reading only.
    pub reads: BTreeSet<PathBuf>,
    /// Absolute paths opened for writing/creation.
    pub writes: BTreeSet<PathBuf>,
    /// Program paths passed to `execve`.
    pub execs: BTreeSet<String>,
    /// Network endpoints the agent attempted to `connect` to.
    pub connects: BTreeSet<(IpAddr, u16)>,
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

    /// Record an `execve` of `path`.
    pub fn record_exec(&mut self, path: String) {
        if !path.is_empty() {
            self.execs.insert(path);
        }
    }

    /// Record a `connect` to a resolved endpoint.
    pub fn record_connect(&mut self, ip: IpAddr, port: u16) {
        self.connects.insert((ip, port));
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

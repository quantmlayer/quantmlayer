// crates/ql-learn/src/synth.rs
//
//! Synthesis: turn an [`Observation`] into a least-privilege [`Profile`].
//!
//! This is the "intelligence" half of QuantmLayer. Enforcement is mechanical;
//! deciding *what to enforce* — generalizing a noisy trace into a profile that
//! is tight enough to contain an attacker yet loose enough to let the real
//! workload run — is the defensible part. The heuristics here are deliberately
//! conservative and explainable:
//!
//! * **Files:** writes become read-write directory globs; reads become
//!   read-only globs (collapsed to shallow prefixes so the list stays small).
//! * **Secrets:** any well-known secret location the agent *never touched* is
//!   denied. This is the rule that turns a benign trace into SSH-key-theft
//!   protection: the agent didn't read `~/.ssh`, so the profile forbids it.
//! * **Syscalls:** dangerous syscalls the agent never issued are denied, so a
//!   later prompt-injected run can't `ptrace`, `mount`, or `bpf` its way out.
//! * **Network:** default-deny; observed external egress is surfaced as a note
//!   for the operator rather than silently allow-listed.

use crate::observation::Observation;
use ql_profile::{
    AgentType, CapPolicy, ExecDigest, ExecPolicy, FsPolicy, NetPolicy, ProcPolicy, Profile,
    ResourceLimits, SeccompDefault, SyscallPolicy, SCHEMA_VERSION,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A synthesized profile plus human-readable notes about decisions that
/// warrant operator attention (e.g. observed external egress).
pub struct SynthResult {
    /// The least-privilege profile derived from the observation.
    pub profile: Profile,
    /// Notes/warnings for the operator to review before enforcing.
    pub notes: Vec<String>,
}

/// Well-known secret locations. Each has a path *segment* used to detect
/// whether the agent legitimately touched it, and the denied globs to emit
/// when it did not.
const SECRETS: &[(&str, &[&str])] = &[
    ("/.ssh/", &["/root/.ssh/**", "/home/*/.ssh/**"]),
    ("/.aws/", &["/root/.aws/**", "/home/*/.aws/**"]),
    ("/.gnupg/", &["/root/.gnupg/**", "/home/*/.gnupg/**"]),
    ("/.kube/", &["/root/.kube/**", "/home/*/.kube/**"]),
    ("/.config/gcloud", &["/home/*/.config/gcloud/**"]),
    ("/etc/shadow", &["/etc/shadow"]),
];

/// Dangerous syscalls (name, syscall number). Numbers are resolved through
/// `libc::SYS_*` so they match the numbers the tracer records on whatever
/// architecture we are running on. Any that were never observed are added to
/// the seccomp deny-list.
const DANGEROUS: &[(&str, u64)] = &[
    ("ptrace", libc::SYS_ptrace as u64),
    ("mount", libc::SYS_mount as u64),
    ("umount2", libc::SYS_umount2 as u64),
    ("unshare", libc::SYS_unshare as u64),
    ("pivot_root", libc::SYS_pivot_root as u64),
    ("process_vm_readv", libc::SYS_process_vm_readv as u64),
    ("process_vm_writev", libc::SYS_process_vm_writev as u64),
    ("bpf", libc::SYS_bpf as u64),
    ("kexec_load", libc::SYS_kexec_load as u64),
    ("init_module", libc::SYS_init_module as u64),
    ("finit_module", libc::SYS_finit_module as u64),
    ("delete_module", libc::SYS_delete_module as u64),
];

/// Synthesize a least-privilege profile for a coding agent from `obs`.
pub fn synthesize(obs: &Observation) -> SynthResult {
    let mut notes = Vec::new();

    // --- Filesystem ---
    let readwrite = generalize(&obs.writes, usize::MAX);
    // Reads not already covered by a writable dir, collapsed to shallow prefixes.
    let read_only_paths: BTreeSet<PathBuf> = obs
        .reads
        .iter()
        .filter(|p| !under_any(p, &readwrite))
        .cloned()
        .collect();
    let readonly = generalize(&read_only_paths, 2);

    // Deny every secret location the agent never touched.
    let mut denied = Vec::new();
    for (segment, globs) in SECRETS {
        let touched = obs
            .reads
            .iter()
            .chain(obs.writes.iter())
            .any(|p| p.to_string_lossy().contains(segment));
        if !touched {
            denied.extend(globs.iter().map(|g| g.to_string()));
        } else {
            notes.push(format!(
                "agent accessed a `{segment}` path; left it permitted (not denied)"
            ));
        }
    }

    // --- Syscalls: deny dangerous-and-unused ---
    let deny: Vec<String> = DANGEROUS
        .iter()
        .filter(|(_, nr)| !obs.syscalls.contains_key(nr))
        .map(|(name, _)| name.to_string())
        .collect();

    // --- Network: default-deny; surface external egress for review ---
    if obs.has_external_egress() {
        let endpoints: Vec<String> = obs
            .connects
            .iter()
            .filter(|(ip, _)| match ip {
                std::net::IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local(),
                std::net::IpAddr::V6(v6) => !v6.is_loopback(),
            })
            .map(|(ip, port)| format!("{ip}:{port}"))
            .collect();
        notes.push(format!(
            "agent made external connections ({}); network left default-deny — \
             add the corresponding domains to network.allow_domains if required",
            endpoints.join(", ")
        ));
    }

    // --- Processes ---
    let allow_exec: Vec<String> = obs
        .execs
        .iter()
        .filter(|p| p.starts_with('/'))
        .cloned()
        .collect();

    // --- Content-addressed exec ---
    // Pull the digests computed by the hashing pass (run before synthesis) for
    // the binaries we allow by path. Auto-enable enforcement only when *every*
    // executed binary was hashed: a partial allow-list would deny an un-hashed
    // binary and break the agent's rerun, so we leave it off and tell the
    // operator instead of silently shipping a half-cage.
    let allow_digests: Vec<ExecDigest> = allow_exec
        .iter()
        .filter_map(|p| obs.exec_digests.get(p).cloned())
        .collect();
    let exec_fully_covered = !allow_exec.is_empty() && allow_digests.len() == allow_exec.len();
    if !allow_exec.is_empty() && !exec_fully_covered {
        notes.push(format!(
            "content-addressed exec left disabled: {} of {} executed binaries were hashed; \
             resolve the rest (see notes) and set exec.enforce=true to pin them by content",
            allow_digests.len(),
            allow_exec.len()
        ));
    }

    // --- Resources (not precisely observable via ptrace; conservative caps) ---
    let pids_max = (obs.process_count.saturating_mul(8)).max(64);

    let profile = Profile {
        schema_version: SCHEMA_VERSION,
        agent_type: AgentType::Coding,
        filesystem: FsPolicy {
            readwrite,
            readonly,
            denied,
        },
        network: NetPolicy {
            default_deny: true,
            allow_domains: Vec::new(),
            block_private_ranges: true,
        },
        capabilities: CapPolicy::default(),
        syscalls: SyscallPolicy {
            default_action: SeccompDefault::Allow,
            deny,
            notify: Vec::new(),
        },
        resources: ResourceLimits {
            memory_max_bytes: Some(4 * 1024 * 1024 * 1024),
            cpu_max_percent: None,
            pids_max: Some(pids_max),
            wall_clock_secs: None,
        },
        processes: ProcPolicy { allow_exec },
        exec: ExecPolicy {
            enforce: exec_fully_covered,
            allow_digests,
        },
        approved_for: None,
        signature: None,
    };

    SynthResult { profile, notes }
}

/// Collapse a set of file paths to a minimal set of `<dir>/**` globs.
///
/// Each absolute path contributes its parent directory, truncated to at most
/// `max_components` leading components (so reads under deep system trees fold
/// into a shallow prefix). Directories that are descendants of another kept
/// directory are dropped, leaving the minimal covering set.
fn generalize(paths: &BTreeSet<PathBuf>, max_components: usize) -> Vec<String> {
    let mut dirs: BTreeSet<PathBuf> = BTreeSet::new();
    for p in paths {
        if !p.is_absolute() {
            continue;
        }
        let dir = p.parent().unwrap_or(p);
        dirs.insert(truncate(dir, max_components));
    }
    // BTreeSet iterates in sorted order, so ancestors precede descendants.
    let mut kept: Vec<PathBuf> = Vec::new();
    for d in dirs {
        if !kept.iter().any(|k| d.starts_with(k)) {
            kept.push(d);
        }
    }
    kept.iter().map(|d| format!("{}/**", d.display())).collect()
}

/// Keep at most `n` leading components of `dir` (root counts as one).
fn truncate(dir: &Path, n: usize) -> PathBuf {
    if n == usize::MAX {
        return dir.to_path_buf();
    }
    let mut out = PathBuf::from("/");
    for comp in dir
        .components()
        .skip(1) // skip RootDir
        .take(n)
    {
        out.push(comp);
    }
    out
}

/// Whether `path` falls under any of the `<dir>/**` globs in `globs`.
fn under_any(path: &Path, globs: &[String]) -> bool {
    globs.iter().any(|g| {
        let base = g.strip_suffix("/**").unwrap_or(g);
        path.starts_with(base)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs_with(
        reads: &[&str],
        writes: &[&str],
        execs: &[&str],
        syscalls: &[(u64, &str)],
    ) -> Observation {
        let mut o = Observation::default();
        for r in reads {
            o.record_open(PathBuf::from(r), false);
        }
        for w in writes {
            o.record_open(PathBuf::from(w), true);
        }
        for e in execs {
            o.record_exec(e.to_string());
        }
        for (nr, name) in syscalls {
            o.record_syscall(*nr, name);
        }
        o
    }

    #[test]
    fn untouched_secrets_are_denied() {
        let o = obs_with(
            &["/etc/hostname"],
            &["/tmp/work/out"],
            &["/usr/bin/cc"],
            &[(0, "read")],
        );
        let r = synthesize(&o);
        // The agent never touched ~/.ssh, so it must be denied.
        assert!(r
            .profile
            .filesystem
            .denied
            .iter()
            .any(|d| d.contains(".ssh")));
        // ptrace was never used, so it must be on the seccomp deny-list.
        assert!(r.profile.syscalls.deny.iter().any(|s| s == "ptrace"));
        // The write dir became read-write; the exec was captured.
        assert!(r
            .profile
            .filesystem
            .readwrite
            .iter()
            .any(|p| p.starts_with("/tmp/work")));
        assert!(r
            .profile
            .processes
            .allow_exec
            .contains(&"/usr/bin/cc".to_string()));
        assert!(r.profile.network.default_deny);
    }

    #[test]
    fn touched_secret_is_not_denied() {
        // An agent that legitimately reads its own ~/.ssh keeps it permitted.
        let o = obs_with(&["/home/dev/.ssh/known_hosts"], &[], &[], &[]);
        let r = synthesize(&o);
        assert!(!r
            .profile
            .filesystem
            .denied
            .iter()
            .any(|d| d.contains(".ssh")));
    }

    #[test]
    fn used_syscall_is_not_denied() {
        // If the agent used ptrace, it must NOT be denied. Use the arch-correct
        // syscall number so this holds on x86-64 and aarch64 alike.
        let o = obs_with(&[], &[], &[], &[(libc::SYS_ptrace as u64, "ptrace")]);
        let r = synthesize(&o);
        assert!(!r.profile.syscalls.deny.iter().any(|s| s == "ptrace"));
    }

    #[test]
    fn exec_enforced_only_when_all_binaries_hashed() {
        use ql_profile::HashAlgo;

        let mut o = obs_with(&[], &[], &["/usr/bin/cc", "/bin/sh"], &[]);
        // Simulate the hashing pass having hashed only one of the two binaries.
        o.exec_digests.insert(
            "/usr/bin/cc".to_string(),
            ExecDigest::new(HashAlgo::Sha256, "a".repeat(64)).unwrap(),
        );

        let partial = synthesize(&o);
        // Partial coverage → enforcement stays off, with an explanatory note.
        assert!(!partial.profile.exec.enforce);
        assert_eq!(partial.profile.exec.allow_digests.len(), 1);
        assert!(partial
            .notes
            .iter()
            .any(|n| n.contains("content-addressed exec")));

        // Hash the second binary too → full coverage → enforcement enabled.
        o.exec_digests.insert(
            "/bin/sh".to_string(),
            ExecDigest::new(HashAlgo::Sha256, "b".repeat(64)).unwrap(),
        );
        let full = synthesize(&o);
        assert!(full.profile.exec.enforce);
        assert_eq!(full.profile.exec.allow_digests.len(), 2);
    }
}

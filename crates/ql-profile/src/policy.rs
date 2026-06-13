// crates/ql-profile/src/policy.rs
//
//! The individual policy sections that compose a [`crate::Profile`].
//!
//! Every policy here defaults to the most restrictive sensible value
//! ("deny by default"). A profile constructed via [`Default`] grants an
//! agent essentially nothing; permissions are added explicitly. This is a
//! deliberate safety property: forgetting to specify a section must never
//! result in *more* access.

use serde::{Deserialize, Serialize};

/// The category of agent this profile describes.
///
/// The archetype determines which default profile a deriver starts from.
/// Coding agents are the primary, highest-risk target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    /// Executes arbitrary code: compilers, interpreters, shells. Highest blast radius.
    Coding,
    /// Retrieval/knowledge agent. Reads a store, talks to an LLM, no shell.
    Rag,
    /// Orchestration agent. Many outbound API calls, spawns sub-agents.
    Workflow,
}

/// Filesystem access policy, expressed as path globs.
///
/// `denied` wins over everything: a path matched by `denied` is invisible
/// even if it also matches `readonly` or `readwrite`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FsPolicy {
    /// Globs the agent may read and write.
    pub readwrite: Vec<String>,
    /// Globs the agent may read but not modify.
    pub readonly: Vec<String>,
    /// Globs that must be invisible to the agent (takes precedence).
    pub denied: Vec<String>,
}

/// Network egress policy. Default-deny: nothing is reachable unless listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetPolicy {
    /// When true (the default), all egress is denied unless explicitly allowed.
    pub default_deny: bool,
    /// Domains the agent may reach (exact host match; enforced by the proxy layer).
    pub allow_domains: Vec<String>,
    /// When true, RFC1918 / link-local ranges (e.g. cloud metadata at
    /// 169.254.169.254) are blocked even if a domain resolves to them.
    pub block_private_ranges: bool,
}

impl Default for NetPolicy {
    fn default() -> Self {
        // Deny-by-default, and block private ranges by default. An empty,
        // freshly-defaulted NetPolicy grants no network access at all.
        NetPolicy {
            default_deny: true,
            allow_domains: Vec::new(),
            block_private_ranges: true,
        }
    }
}

/// Linux capability policy. Coding agents almost never need any capability,
/// so the default retained set is empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CapPolicy {
    /// Capabilities to retain, by name (e.g. "CAP_NET_BIND_SERVICE").
    /// Empty means: drop everything.
    pub retain: Vec<String>,
}

/// The action seccomp takes for a syscall not otherwise specified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompDefault {
    /// Allow syscalls not in the deny/notify lists. Used for coding agents,
    /// where the compiler/interpreter long-tail can't be enumerated safely.
    Allow,
    /// Deny syscalls not in the allow list. Used for tight archetypes like RAG.
    Deny,
}

/// Syscall policy.
///
/// For coding agents the strategy is a *denylist over an allow-default*:
/// permit the broad set (compilers need it) but block the handful of
/// syscalls that are never legitimate and are the escape hatches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SyscallPolicy {
    /// Action for syscalls not named in `deny` or `notify`.
    pub default_action: SeccompDefault,
    /// Syscalls that are always blocked (e.g. mount, unshare, ptrace, bpf).
    pub deny: Vec<String>,
    /// Syscalls allowed but trapped for inspection (e.g. execve, connect).
    pub notify: Vec<String>,
}

impl Default for SyscallPolicy {
    fn default() -> Self {
        SyscallPolicy {
            default_action: SeccompDefault::Deny, // safest default; coding profiles override to Allow
            deny: Vec::new(),
            notify: Vec::new(),
        }
    }
}

/// Resource limits enforced via cgroups v2. Stops runaway loops and fork bombs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ResourceLimits {
    /// Hard memory ceiling in bytes. `None` means unset (no limit) — discouraged.
    pub memory_max_bytes: Option<u64>,
    /// CPU quota as a percentage (100 = one core). `None` means unset.
    pub cpu_max_percent: Option<u32>,
    /// Maximum number of processes/threads. Caps fork bombs. `None` means unset.
    pub pids_max: Option<u32>,
    /// Wall-clock timeout per tool call, in seconds. `None` means unset.
    pub wall_clock_secs: Option<u32>,
}

/// Child-process policy. The agent's job is spawning these; we bound which.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ProcPolicy {
    /// Absolute paths of binaries the agent may exec. Empty means none.
    pub allow_exec: Vec<String>,
}

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

/// A cryptographic hash algorithm used for content-addressed exec.
///
/// The variants and their [`HashAlgo::ima_id`] values mirror the kernel's
/// `enum hash_algo`, so a digest authored in a profile can be matched against
/// the value returned by `bpf_ima_file_hash` in the enforcement layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgo {
    /// SHA-1 (20-byte digest). Legacy; present for completeness.
    Sha1,
    /// SHA-256 (32-byte digest). The default and recommended algorithm.
    Sha256,
    /// SHA-384 (48-byte digest).
    Sha384,
    /// SHA-512 (64-byte digest).
    Sha512,
}

impl HashAlgo {
    /// Length of this algorithm's digest, in bytes.
    pub fn digest_len(self) -> usize {
        match self {
            HashAlgo::Sha1 => 20,
            HashAlgo::Sha256 => 32,
            HashAlgo::Sha384 => 48,
            HashAlgo::Sha512 => 64,
        }
    }

    /// The identifier the kernel's IMA subsystem reports for this algorithm
    /// (`HASH_ALGO_*`), as returned by `bpf_ima_file_hash`. This is the
    /// contract the kernel enforcement layer relies on to interpret a digest.
    pub fn ima_id(self) -> u32 {
        match self {
            HashAlgo::Sha1 => 2,
            HashAlgo::Sha256 => 4,
            HashAlgo::Sha384 => 5,
            HashAlgo::Sha512 => 6,
        }
    }

    /// The lowercase short name used in the `"<algo>:<hex>"` digest form.
    pub fn as_str(self) -> &'static str {
        match self {
            HashAlgo::Sha1 => "sha1",
            HashAlgo::Sha256 => "sha256",
            HashAlgo::Sha384 => "sha384",
            HashAlgo::Sha512 => "sha512",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "sha1" => Some(HashAlgo::Sha1),
            "sha256" => Some(HashAlgo::Sha256),
            "sha384" => Some(HashAlgo::Sha384),
            "sha512" => Some(HashAlgo::Sha512),
            _ => None,
        }
    }
}

/// Why an [`ExecDigest`] failed to parse or construct.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExecDigestError {
    /// The string was not of the form `"<algo>:<hex>"`.
    #[error("expected `<algo>:<hex>`, got `{0}`")]
    Malformed(String),
    /// The algorithm name was not one of sha1/sha256/sha384/sha512.
    #[error("unknown hash algorithm `{0}`")]
    UnknownAlgo(String),
    /// The hex payload had the wrong length or contained non-hex characters.
    #[error("invalid {algo} digest: expected {expected} lowercase hex chars")]
    BadHex {
        /// The algorithm whose length was expected.
        algo: &'static str,
        /// Expected number of hex characters (`2 * digest_len`).
        expected: usize,
    },
}

/// A content digest of an approved executable, e.g. `sha256:bf7c…`.
///
/// Constructed only through validating paths ([`ExecDigest::new`],
/// [`std::str::FromStr`], or deserialization), so a value of this type is
/// always a well-formed `(algorithm, correct-length lowercase hex)` pair —
/// downstream consumers never have to re-check it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExecDigest {
    algo: HashAlgo,
    hex: String, // invariant: lowercase, exactly 2 * algo.digest_len() chars
}

impl ExecDigest {
    /// Construct from an algorithm and a hex digest, validating the hex
    /// length and character set. Input is lowercased.
    pub fn new(
        algo: HashAlgo,
        hex: impl Into<String>,
    ) -> std::result::Result<Self, ExecDigestError> {
        let hex = hex.into().to_ascii_lowercase();
        let expected = algo.digest_len() * 2;
        if hex.len() != expected || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ExecDigestError::BadHex {
                algo: algo.as_str(),
                expected,
            });
        }
        Ok(ExecDigest { algo, hex })
    }

    /// The hash algorithm.
    pub fn algo(&self) -> HashAlgo {
        self.algo
    }

    /// The lowercase hex digest, without the `"<algo>:"` prefix.
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// The raw digest bytes, decoded from hex. The kernel enforcement layer
    /// loads these into its allow-list map.
    pub fn to_bytes(&self) -> Vec<u8> {
        // `hex` is validated as even-length ASCII hex, so each parse succeeds;
        // the `unwrap_or` keeps this total without a panic regardless.
        (0..self.hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&self.hex[i..i + 2], 16).unwrap_or(0))
            .collect()
    }
}

impl std::str::FromStr for ExecDigest {
    type Err = ExecDigestError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (algo, hex) = s
            .split_once(':')
            .ok_or_else(|| ExecDigestError::Malformed(s.to_string()))?;
        let algo =
            HashAlgo::parse(algo).ok_or_else(|| ExecDigestError::UnknownAlgo(algo.to_string()))?;
        ExecDigest::new(algo, hex)
    }
}

impl std::fmt::Display for ExecDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algo.as_str(), self.hex)
    }
}

impl TryFrom<String> for ExecDigest {
    type Error = ExecDigestError;
    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<ExecDigest> for String {
    fn from(d: ExecDigest) -> String {
        d.to_string()
    }
}

/// Content-addressed execution policy.
///
/// This is the allow-list half of QuantmLayer's exec containment: instead of
/// trusting a binary by its *path* (which a copy-rename trivially defeats),
/// the enforcement layer hashes each binary at `execve` time and permits it
/// only if its content digest appears here. A new or modified binary —
/// downloaded malware, a freshly compiled payload — has an unknown digest and
/// is denied.
///
/// It is an *additional* layer over [`ProcPolicy`]'s path allow-list and is
/// opt-in via [`ExecPolicy::enforce`], because the digest set is normally
/// produced by observing the agent (e.g. `ql learn`). When `enforce` is on,
/// the set is strictly deny-by-default: only listed digests may run.
///
/// Scope, stated honestly: this pins *which* binaries may execute, not what
/// they do. An interpreter on the allow-list (python, bash) can still run
/// arbitrary scripts; that is bounded by the syscall / filesystem / network
/// walls, not by exec hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ExecPolicy {
    /// When true, only binaries whose content digest is in `allow_digests`
    /// may be exec'd inside the cell. When false (the default), this layer is
    /// inactive and path-based [`ProcPolicy`] governs exec.
    pub enforce: bool,
    /// Approved binary content digests (e.g. `sha256:bf7c…`).
    pub allow_digests: Vec<ExecDigest>,
}

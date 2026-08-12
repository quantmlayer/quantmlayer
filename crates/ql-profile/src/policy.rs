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
    /// Per-binary argv deny rules (v1), keyed by attested content digest. Bound
    /// by the signature exactly like `allow_digests`, so a handed profile's argv
    /// rules cannot be widened or removed without invalidating it.
    ///
    /// Evaluated **post-commit and advisory**: the allow/deny verdict gates on
    /// the content digest, never on argv (a Tier-2 tracee can rewrite argv before
    /// the kernel copies it), so an argv-deny match drives detect-and-act (kill),
    /// not a pre-commit gate. Defense-in-depth that pairs with the digest and
    /// network walls; argv matching is evadable by design (wrappers,
    /// `python -m pip`, renames). Skipped from the serialized form when empty, so
    /// profiles that do not use it keep byte-identical signing bytes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub argv_deny: Vec<ArgvRule>,
}

/// One binary's argv deny rules, keyed by its attested content digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgvRule {
    /// The binary this rule applies to, by content digest (e.g. `sha256:…`).
    pub digest: ExecDigest,
    /// Argv shapes to deny for that binary. Any match denies the invocation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<ArgvDeny>,
}

/// One argv-shape matcher. v1 supports `all_of`: the invocation matches when
/// every listed token appears as an argv *element* (element-equality, not
/// substring — so `-m "ready to push"` does not match `["push"]`). Order- and
/// position-independent. Extensible: future matchers (exact, prefix) add fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ArgvDeny {
    /// Deny when every token here is present as an argv element. An empty set
    /// never matches, so it can never accidentally deny every invocation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_of: Vec<String>,
}

/// The outcome of evaluating an exec's committed argv against an [`ExecPolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgvVerdict {
    /// No argv-deny rule applied to this binary, or none matched.
    Allow,
    /// An argv-deny rule matched; the string names which, for the audit record.
    Deny(String),
}

/// Evaluate an exec's **committed** argv against the per-binary argv deny rules,
/// keyed by the binary's sha256 content digest (lowercase hex, no `sha256:`
/// prefix). Returns [`ArgvVerdict::Deny`] on the first matching rule, else
/// [`ArgvVerdict::Allow`].
///
/// Advisory by design: argv is sound input only *after* the exec commits (see
/// the Tier-2 supervisor), so this drives detect-and-kill, not a pre-commit
/// gate, and the match is evadable — it is a defense-in-depth layer over the
/// content-digest and network walls, not a replacement for them.
pub fn evaluate_argv(policy: &ExecPolicy, digest_hex: &str, argv: &[String]) -> ArgvVerdict {
    for rule in &policy.argv_deny {
        if rule.digest.algo() != HashAlgo::Sha256 || rule.digest.hex() != digest_hex {
            continue;
        }
        for deny in &rule.deny {
            if !deny.all_of.is_empty()
                && deny.all_of.iter().all(|tok| argv.iter().any(|a| a == tok))
            {
                return ArgvVerdict::Deny(format!(
                    "sha256:{digest_hex} argv all_of {:?}",
                    deny.all_of
                ));
            }
        }
    }
    ArgvVerdict::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256(hex: &str) -> ExecDigest {
        ExecDigest::new(HashAlgo::Sha256, hex).expect("valid sha256 hex")
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn policy_with(rules: Vec<ArgvRule>) -> ExecPolicy {
        ExecPolicy {
            argv_deny: rules,
            ..Default::default()
        }
    }

    const GIT: &str = "11ae5e306bce2eca707ff5cd25ede118b24a80ca85cd85a6eb7d658d81abd3df";
    const RM: &str = "227a0fe70cb4aff15bf90afc94b5c4a0be602d0890900cdd856becf12b96e973";

    #[test]
    fn no_rules_allows() {
        let p = policy_with(vec![]);
        assert_eq!(
            evaluate_argv(&p, GIT, &argv(&["git", "push"])),
            ArgvVerdict::Allow
        );
    }

    #[test]
    fn rule_for_other_digest_does_not_apply() {
        let p = policy_with(vec![ArgvRule {
            digest: sha256(RM),
            deny: vec![ArgvDeny {
                all_of: argv(&["-rf", "/"]),
            }],
        }]);
        // The exec is GIT, the rule is for RM -> no match.
        assert_eq!(
            evaluate_argv(&p, GIT, &argv(&["rm", "-rf", "/"])),
            ArgvVerdict::Allow
        );
    }

    #[test]
    fn single_token_match_denies() {
        let p = policy_with(vec![ArgvRule {
            digest: sha256(GIT),
            deny: vec![ArgvDeny {
                all_of: argv(&["push"]),
            }],
        }]);
        match evaluate_argv(&p, GIT, &argv(&["git", "push", "origin", "main"])) {
            ArgvVerdict::Deny(why) => assert!(why.contains("push")),
            ArgvVerdict::Allow => panic!("expected deny"),
        }
    }

    #[test]
    fn element_equality_not_substring() {
        // "push" appears only *inside* a commit-message arg, not as an element.
        let p = policy_with(vec![ArgvRule {
            digest: sha256(GIT),
            deny: vec![ArgvDeny {
                all_of: argv(&["push"]),
            }],
        }]);
        let cmd = argv(&["git", "commit", "-m", "ready to push"]);
        assert_eq!(evaluate_argv(&p, GIT, &cmd), ArgvVerdict::Allow);
    }

    #[test]
    fn all_of_requires_every_token() {
        let p = policy_with(vec![ArgvRule {
            digest: sha256(RM),
            deny: vec![ArgvDeny {
                all_of: argv(&["-rf", "/"]),
            }],
        }]);
        // Both tokens present (order-independent) -> deny.
        assert!(matches!(
            evaluate_argv(&p, RM, &argv(&["rm", "/", "-rf"])),
            ArgvVerdict::Deny(_)
        ));
        // Only one token present -> allow.
        assert_eq!(
            evaluate_argv(&p, RM, &argv(&["rm", "-rf", "tmpdir"])),
            ArgvVerdict::Allow
        );
    }

    #[test]
    fn empty_all_of_never_matches() {
        let p = policy_with(vec![ArgvRule {
            digest: sha256(GIT),
            deny: vec![ArgvDeny { all_of: vec![] }],
        }]);
        assert_eq!(
            evaluate_argv(&p, GIT, &argv(&["git", "push"])),
            ArgvVerdict::Allow
        );
    }

    #[test]
    fn argv_deny_parses_from_yaml() {
        let yaml = format!(
            r#"
enforce: true
argv_deny:
  - digest: sha256:{GIT}
    deny:
      - all_of: [push]
"#
        );
        let p: ExecPolicy = serde_yaml::from_str(&yaml).expect("argv_deny yaml parses");
        assert_eq!(p.argv_deny.len(), 1);
        assert_eq!(p.argv_deny[0].digest.hex(), GIT);
        assert!(matches!(
            evaluate_argv(&p, GIT, &argv(&["git", "push"])),
            ArgvVerdict::Deny(_)
        ));
    }
}

// ---------------------------------------------------------------------------
// Guarantee requirements (Cross-platform Cell, cheap half)
// ---------------------------------------------------------------------------

/// The identity property an approved-execution decision rests on.
///
/// Named as a *guarantee* rather than a mechanism so a policy can state what it
/// needs without naming a backend. The distinction is load-bearing: a
/// path-based allow-list and a content digest both "approve executables", but
/// only one survives an attacker replacing the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecIdentity {
    /// The executable's own content is hashed and compared (Linux BPF-LSM
    /// tier 1, or the userspace seccomp-notify tier 2).
    ContentHash,
    /// Approval is by path, signer, or ACL — not by content. An attacker who
    /// replaces the file at an approved path is not caught.
    PathOrSigner,
}

/// How thoroughly a secret outside the grant is kept from the workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretVisibility {
    /// The path does not exist in the cell's view at all: `ENOENT`, not
    /// `EACCES`. A mount namespace constructs the view, so there is nothing to
    /// probe for.
    Absent,
    /// The path exists and is denied on access. Its existence, name, and
    /// metadata still leak.
    AccessDenied,
}

/// What to do when the substrate cannot meet a requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Degradation {
    /// Refuse to run. The policy asked for a guarantee this host cannot give,
    /// and running anyway would silently deliver something weaker than what
    /// was authorized.
    #[default]
    Refuse,
    /// Run with the strongest available substitute, and say so. Appropriate
    /// when the policy author has decided partial containment beats none.
    Allow,
}

/// Guarantees a policy requires of the substrate, and what to do without them.
///
/// This exists so that a profile states *what it needs* rather than *where it
/// runs*: a host that cannot meet a requirement is disqualified rather than
/// silently delivering something weaker. Absent (the default) preserves
/// today's behavior — take the strongest available tier and report it.
///
/// The fields are deliberately additive and default to `None`, so this can
/// land long before any non-Linux backend exists; retrofitting a requirements
/// vocabulary onto a mature schema is far more expensive than reserving it now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Requirements {
    /// Required execution-identity guarantee, if the policy cares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_identity: Option<ExecIdentity>,
    /// Required secret-visibility guarantee, if the policy cares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_visibility: Option<SecretVisibility>,
    /// What to do when a requirement cannot be met. Defaults to refusing:
    /// a policy that bothered to state a requirement should not quietly get
    /// less than it asked for.
    #[serde(default)]
    pub degradation: Degradation,
}

/// What the running substrate can actually guarantee, for comparison against
/// [`Requirements`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guarantees {
    /// The execution-identity property this host provides.
    pub exec_identity: ExecIdentity,
    /// The secret-visibility property this host provides.
    pub secret_visibility: SecretVisibility,
}

/// One unmet requirement, named for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmet {
    /// Which requirement failed, e.g. `exec_identity`.
    pub requirement: &'static str,
    /// What the policy asked for.
    pub required: &'static str,
    /// What this host can actually provide.
    pub available: &'static str,
}

impl std::fmt::Display for Unmet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} requires `{}` but this host provides `{}`",
            self.requirement, self.required, self.available
        )
    }
}

impl Requirements {
    /// Every requirement this substrate cannot meet. Empty means qualified.
    pub fn unmet(&self, have: &Guarantees) -> Vec<Unmet> {
        let mut out = Vec::new();
        if self.exec_identity == Some(ExecIdentity::ContentHash)
            && have.exec_identity != ExecIdentity::ContentHash
        {
            out.push(Unmet {
                requirement: "exec_identity",
                required: "content_hash",
                available: "path_or_signer",
            });
        }
        if self.secret_visibility == Some(SecretVisibility::Absent)
            && have.secret_visibility != SecretVisibility::Absent
        {
            out.push(Unmet {
                requirement: "secret_visibility",
                required: "absent",
                available: "access_denied",
            });
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Phase-scoped authority
// ---------------------------------------------------------------------------

/// Narrower authority for one named phase of a task.
///
/// The same agent needs different authority at different moments: dependency
/// install needs the registries but no credentials; build and test need the
/// workspace and toolchain but frequently **no egress at all**. A single
/// profile has to cover the session at its widest point — the union of every
/// phase — so the agent runs at maximum width the whole time. A phase runs one
/// step at its own narrower width instead.
///
/// This is a profile-structure change, not new enforcement: a phase is applied
/// by [`Phase::narrow`] to produce an ordinary [`crate::Profile`] which the
/// existing walls enforce unchanged.
///
/// # Invariant: a phase can only narrow
///
/// Every field here *removes* authority. There is deliberately no way to add a
/// domain, a path, or a digest — if a phase could widen, the base profile
/// would stop being an upper bound on the session, and a signature over the
/// base profile would no longer bound what the agent can do. [`Phase::narrow`]
/// intersects with the base rather than replacing it, so even a hand-edited
/// phase naming a domain the base lacks grants nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Phase {
    /// Human note about what this phase is for. Not enforced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Drop all egress for this phase. The common case for build/test: the
    /// dependencies are already fetched, so nothing legitimate needs the
    /// network, and this is the phase where untrusted downloaded code first
    /// executes.
    #[serde(default)]
    pub no_egress: bool,

    /// Restrict egress to these domains. Intersected with the base allow-list,
    /// so a domain the base does not grant is not granted here either.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_domains: Vec<String>,

    /// Restrict read-write filesystem access to these globs. Intersected with
    /// the base grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_readwrite: Vec<String>,

    /// The single path this phase's results are expected to land in.
    ///
    /// Everything else in the working area is scratch. Recording it makes
    /// "what this step produced" distinguishable from "what it merely touched"
    /// — useful for auditing, and the natural input to any future isolation
    /// work. Advisory today: it is not enforced as the *only* writable path,
    /// because a build that cannot write its own temporary files is useless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
}

impl Phase {
    /// Apply this phase to `base`, returning a profile that grants no more
    /// than `base` did.
    ///
    /// Narrowing only: each list is *intersected* with the base's, never
    /// unioned. A phase naming something the base lacks contributes nothing.
    pub fn narrow(&self, base: &crate::Profile) -> crate::Profile {
        let mut p = base.clone();

        if self.no_egress {
            p.network.allow_domains.clear();
            p.network.default_deny = true;
        } else if !self.only_domains.is_empty() {
            p.network
                .allow_domains
                .retain(|d| self.only_domains.contains(d));
        }

        if !self.only_readwrite.is_empty() {
            p.filesystem
                .readwrite
                .retain(|g| self.only_readwrite.contains(g));
        }

        // A phase is a runtime narrowing of an already-approved policy, so any
        // signature over the base no longer describes this document. Drop it
        // rather than carry one that would fail verification and look like
        // tampering.
        p.signature = None;
        p
    }
}

#[cfg(test)]
mod phase_and_requirement_tests {
    use super::*;
    use crate::Profile;

    fn base() -> Profile {
        let mut p = Profile::default();
        p.network.default_deny = true;
        p.network.allow_domains = vec![
            "crates.io".into(),
            "registry.npmjs.org".into(),
            "api.anthropic.com".into(),
        ];
        p.filesystem.readwrite = vec!["/work/**".into(), "/tmp/**".into()];
        p
    }

    /// **The B2b invariant.** A phase cannot grant anything the base did not.
    /// Naming a domain or path outside the base contributes nothing, so the
    /// base profile stays an upper bound on the whole session — which is what
    /// makes a signature over it meaningful.
    #[test]
    fn a_phase_can_never_widen_the_base() {
        let b = base();
        let ph = Phase {
            only_domains: vec![
                "crates.io".into(),
                // Not in the base: must NOT appear in the result.
                "evil.example".into(),
            ],
            only_readwrite: vec!["/work/**".into(), "/etc/**".into()],
            ..Default::default()
        };
        let out = ph.narrow(&b);

        assert_eq!(out.network.allow_domains, vec!["crates.io".to_string()]);
        assert!(!out
            .network
            .allow_domains
            .iter()
            .any(|d| d == "evil.example"));
        assert_eq!(out.filesystem.readwrite, vec!["/work/**".to_string()]);
        assert!(!out.filesystem.readwrite.iter().any(|g| g == "/etc/**"));

        // Every grant in the narrowed profile was present in the base.
        for d in &out.network.allow_domains {
            assert!(b.network.allow_domains.contains(d), "widened with {d}");
        }
        for g in &out.filesystem.readwrite {
            assert!(b.filesystem.readwrite.contains(g), "widened with {g}");
        }
    }

    /// The build/test case: no egress at all, which is the phase where
    /// freshly-downloaded code first runs.
    #[test]
    fn no_egress_phase_drops_every_domain() {
        let out = Phase {
            no_egress: true,
            ..Default::default()
        }
        .narrow(&base());
        assert!(out.network.allow_domains.is_empty());
        assert!(out.network.default_deny);
    }

    /// An empty phase changes nothing — absence of a restriction is not a
    /// restriction.
    #[test]
    fn an_empty_phase_is_a_no_op() {
        let b = base();
        let out = Phase::default().narrow(&b);
        assert_eq!(out.network.allow_domains, b.network.allow_domains);
        assert_eq!(out.filesystem.readwrite, b.filesystem.readwrite);
    }

    /// A narrowed profile drops the base's signature: the signature covered a
    /// different document, and carrying one that cannot verify would look like
    /// tampering rather than like the deliberate narrowing it is.
    #[test]
    fn narrowing_drops_a_signature_it_would_invalidate() {
        let mut b = base();
        b.signature = Some(crate::ProfileSignature {
            algorithm: "ed25519".into(),
            public_key: "00".repeat(32),
            value: "00".repeat(64),
        });
        let out = Phase {
            no_egress: true,
            ..Default::default()
        }
        .narrow(&b);
        assert!(out.signature.is_none());
    }

    /// Phases and requirements survive a YAML round-trip, and a profile
    /// without them serializes exactly as before (the additive guarantee).
    #[test]
    fn phases_and_requirements_round_trip_and_stay_additive() {
        let mut b = base();
        let plain = b.to_yaml().unwrap();
        assert!(
            !plain.contains("phases"),
            "absent fields must not serialize"
        );
        assert!(!plain.contains("requirements"));

        b.phases.insert(
            "build".into(),
            Phase {
                description: Some("compile and test; nothing to fetch".into()),
                no_egress: true,
                output_path: Some("/work/target".into()),
                ..Default::default()
            },
        );
        b.requirements = Some(Requirements {
            exec_identity: Some(ExecIdentity::ContentHash),
            secret_visibility: Some(SecretVisibility::Absent),
            degradation: Degradation::Refuse,
        });

        let round = Profile::from_yaml(&b.to_yaml().unwrap()).unwrap();
        assert!(round.phases["build"].no_egress);
        assert_eq!(
            round.phases["build"].output_path.as_deref(),
            Some("/work/target")
        );
        assert_eq!(
            round.requirements.unwrap().exec_identity,
            Some(ExecIdentity::ContentHash)
        );
    }

    /// A host that cannot meet a stated requirement is disqualified, and the
    /// report names what was asked for versus what is available.
    #[test]
    fn unmet_requirements_are_named_not_silently_downgraded() {
        let req = Requirements {
            exec_identity: Some(ExecIdentity::ContentHash),
            secret_visibility: Some(SecretVisibility::Absent),
            degradation: Degradation::Refuse,
        };

        let linux = Guarantees {
            exec_identity: ExecIdentity::ContentHash,
            secret_visibility: SecretVisibility::Absent,
        };
        assert!(req.unmet(&linux).is_empty(), "tier-1 Linux must qualify");

        let weaker = Guarantees {
            exec_identity: ExecIdentity::PathOrSigner,
            secret_visibility: SecretVisibility::AccessDenied,
        };
        let gaps = req.unmet(&weaker);
        assert_eq!(gaps.len(), 2);
        assert!(gaps[0].to_string().contains("exec_identity"));
        assert!(gaps[0].to_string().contains("content_hash"));
        assert!(gaps[1].to_string().contains("secret_visibility"));
    }

    /// Stating no requirement qualifies everywhere: this is what keeps the
    /// field additive for every profile that predates it.
    #[test]
    fn no_requirements_qualifies_on_any_substrate() {
        let weakest = Guarantees {
            exec_identity: ExecIdentity::PathOrSigner,
            secret_visibility: SecretVisibility::AccessDenied,
        };
        assert!(Requirements::default().unmet(&weakest).is_empty());
    }
}

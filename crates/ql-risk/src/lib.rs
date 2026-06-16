// crates/ql-risk/src/lib.rs
//
//! Risk classification for the grants a synthesized profile proposes.
//!
//! The synthesizer ([`ql-learn`]) turns a trace into a least-privilege profile.
//! This crate annotates each grant in that profile with a **risk level** and a
//! **confidence**, so a profile stops being an opaque allow-list and becomes
//! something a human can *review*: "this line is safe to keep, this one you
//! should look at, this one is denied by default and here's why."
//!
//! ## What the signal is — and what it is not
//!
//! The classification is a deterministic function of two things we actually
//! have: the resource (a path, endpoint, or syscall name) and the grant's
//! *kind* (read / write / denied-secret / exec / egress / denied-syscall). From
//! the resource we derive a coarse **sensitivity** (secret, system, home,
//! system-library, project/temp), and the kind decides how that sensitivity
//! maps to a level — reading `/etc` is routine; writing it is not.
//!
//! **Confidence is a property of the rule, not a statistic.** `High` means the
//! resource matched a known pattern unambiguously (a recognized credential
//! path, a system directory, a temporary directory). `Medium` means it is
//! plausible but unrecognized — a home path that may or may not be the project,
//! a binary outside the standard system paths, an unknown external endpoint —
//! the cases a human should confirm. We deliberately do **not** claim a
//! frequency- or sample-size-based confidence here, because the tracer records
//! distinct resources as sets, not counts: there is no "seen 40 times" signal
//! to stand on yet. Folding in true frequency is a separate, later step.

use serde::{Deserialize, Serialize};

/// How a proposed grant should be treated when a human reviews the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Low-sensitivity and project-local — safe to keep without scrutiny.
    AllowCandidate,
    /// Plausible but unverifiable from one trace — a human should confirm it.
    Review,
    /// Sensitive by nature (secrets, cloud metadata, dangerous syscalls) — off
    /// unless explicitly justified.
    DenyByDefault,
}

/// How decisively a classification rule matched. See the crate docs: this is
/// rule-decisiveness, not a statistical confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// The kind of grant being classified — it decides how a resource's sensitivity
/// maps onto a risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    /// Read-only filesystem access.
    FsRead,
    /// Read-write filesystem access.
    FsWrite,
    /// A denied-by-default filesystem location (e.g. a secret the agent never
    /// touched), emitted as evidence of what the profile forbids.
    FsDenied,
    /// A binary the profile permits the agent to execute.
    Exec,
    /// An external network endpoint the agent was observed reaching.
    NetEgress,
    /// A dangerous syscall the profile denies (never used during learning).
    SyscallDenied,
}

/// The result of classifying one grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// How to treat the grant on review.
    pub level: RiskLevel,
    /// How decisively the rule matched.
    pub confidence: Confidence,
    /// A human-readable justification naming the rule that fired.
    pub reason: String,
}

/// Context that sharpens classification. Currently the project root: files
/// under the directory the agent was launched in read as project-local rather
/// than as generic home/unknown paths, which is the difference between a report
/// that is mostly noise and one a human can act on.
#[derive(Debug, Default, Clone)]
pub struct Context {
    /// Absolute path of the project root, if known.
    pub project_root: Option<String>,
}

/// Classify a single grant with no extra context. `resource` is a path,
/// `ip:port` endpoint, or syscall name; `kind` selects the rule set.
pub fn classify(resource: &str, kind: GrantKind) -> RiskAssessment {
    classify_in(resource, kind, &Context::default())
}

/// Classify a single grant within a [`Context`] (e.g. knowing the project root).
pub fn classify_in(resource: &str, kind: GrantKind, ctx: &Context) -> RiskAssessment {
    let (level, confidence, reason) = match kind {
        GrantKind::FsRead => classify_fs_read(resource, ctx),
        GrantKind::FsWrite => classify_fs_write(resource, ctx),
        GrantKind::FsDenied => (
            RiskLevel::DenyByDefault,
            Confidence::High,
            format!("denied by default: sensitive location `{resource}` (never accessed)"),
        ),
        GrantKind::Exec => classify_exec(resource),
        GrantKind::NetEgress => classify_net(resource),
        GrantKind::SyscallDenied => (
            RiskLevel::DenyByDefault,
            Confidence::High,
            format!("dangerous syscall `{resource}` denied — never used during learning"),
        ),
    };
    RiskAssessment {
        level,
        confidence,
        reason,
    }
}

/// Coarse sensitivity of a filesystem path. Ordering matters: secret patterns
/// are checked first, then temp/project (so `/var/tmp` does not read as system),
/// then libraries, then the rest of the system tree, then home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sensitivity {
    Secret,
    SystemLib,
    System,
    Home,
    Project,
    Unknown,
}

fn sensitivity_in(path: &str, ctx: &Context) -> Sensitivity {
    // Secrets win even inside the project root: a key checked into the repo is
    // still a key.
    if is_secret(path) {
        return Sensitivity::Secret;
    }
    if let Some(root) = ctx.project_root.as_deref() {
        if !root.is_empty() && path.starts_with(root) {
            return Sensitivity::Project;
        }
    }
    if is_project(path) {
        Sensitivity::Project
    } else if is_system_lib(path) {
        Sensitivity::SystemLib
    } else if is_system(path) {
        Sensitivity::System
    } else if is_home(path) {
        Sensitivity::Home
    } else {
        Sensitivity::Unknown
    }
}

fn is_secret(path: &str) -> bool {
    const MARKERS: &[&str] = &[
        "/.ssh",
        "/.aws",
        "/.gnupg",
        "/.kube",
        "/.config/gcloud",
        "/.docker/config",
        "/.netrc",
        "/.config/gh/",
    ];
    if MARKERS.iter().any(|m| path.contains(m)) {
        return true;
    }
    matches!(path, "/etc/shadow" | "/etc/gshadow" | "/etc/sudoers")
        || path.starts_with("/etc/sudoers.d")
}

fn is_project(path: &str) -> bool {
    path == "/tmp"
        || path.starts_with("/tmp/")
        || path.starts_with("/var/tmp")
        || path.starts_with("/dev/shm")
        || !path.starts_with('/') // a relative path is project-local scratch
}

fn is_system_lib(path: &str) -> bool {
    const PREFIXES: &[&str] = &["/usr/", "/lib/", "/lib64", "/opt/"];
    PREFIXES.iter().any(|p| path.starts_with(p))
}

fn is_system(path: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "/etc", "/root", "/boot", "/sys", "/proc", "/dev", "/run", "/var",
    ];
    PREFIXES.iter().any(|p| path.starts_with(p))
}

fn is_home(path: &str) -> bool {
    path.starts_with("/home/") || path.starts_with("/Users/")
}

fn is_system_binary(path: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "/usr/bin/",
        "/bin/",
        "/usr/sbin/",
        "/sbin/",
        "/usr/local/bin/",
        "/usr/local/sbin/",
    ];
    PREFIXES.iter().any(|p| path.starts_with(p))
}

fn classify_fs_read(resource: &str, ctx: &Context) -> (RiskLevel, Confidence, String) {
    match sensitivity_in(resource, ctx) {
        Sensitivity::Secret => (
            RiskLevel::Review,
            Confidence::High,
            format!("agent read a credential location `{resource}` — verify this is intended"),
        ),
        Sensitivity::SystemLib => (
            RiskLevel::AllowCandidate,
            Confidence::High,
            format!("read-only access to system libraries or shared data `{resource}`"),
        ),
        Sensitivity::System => (
            RiskLevel::AllowCandidate,
            Confidence::High,
            format!("read-only access to a system path `{resource}`"),
        ),
        Sensitivity::Project => (
            RiskLevel::AllowCandidate,
            Confidence::High,
            format!("read-only access to a project or temporary path `{resource}`"),
        ),
        Sensitivity::Home => (
            RiskLevel::Review,
            Confidence::Medium,
            format!("read access to a user-home path `{resource}` outside the project"),
        ),
        Sensitivity::Unknown => (
            RiskLevel::Review,
            Confidence::Medium,
            format!("read access to an unrecognized path `{resource}`"),
        ),
    }
}

fn classify_fs_write(resource: &str, ctx: &Context) -> (RiskLevel, Confidence, String) {
    match sensitivity_in(resource, ctx) {
        Sensitivity::Project => (
            RiskLevel::AllowCandidate,
            Confidence::High,
            format!("writes confined to a project or temporary path `{resource}`"),
        ),
        Sensitivity::Secret => (
            RiskLevel::Review,
            Confidence::High,
            format!("agent wrote to a credential location `{resource}` — review carefully"),
        ),
        Sensitivity::SystemLib | Sensitivity::System => (
            RiskLevel::Review,
            Confidence::High,
            format!("agent writes into a system path `{resource}` — verify"),
        ),
        Sensitivity::Home => (
            RiskLevel::Review,
            Confidence::Medium,
            format!("agent writes into a user-home path `{resource}` outside the project"),
        ),
        Sensitivity::Unknown => (
            RiskLevel::Review,
            Confidence::Medium,
            format!("agent writes into an unrecognized path `{resource}` — verify"),
        ),
    }
}

fn classify_exec(resource: &str) -> (RiskLevel, Confidence, String) {
    if is_system_binary(resource) {
        (
            RiskLevel::AllowCandidate,
            Confidence::High,
            format!("executes a standard system binary `{resource}`"),
        )
    } else {
        (
            RiskLevel::Review,
            Confidence::Medium,
            format!("executes a binary outside standard system paths `{resource}` — verify"),
        )
    }
}

fn classify_net(resource: &str) -> (RiskLevel, Confidence, String) {
    if resource.contains("169.254.169.254") {
        (
            RiskLevel::DenyByDefault,
            Confidence::High,
            format!("cloud-metadata endpoint `{resource}` — high SSRF risk; kept default-deny"),
        )
    } else {
        (
            RiskLevel::Review,
            Confidence::Medium,
            format!("external egress to `{resource}`; default-deny, allow-list only if required"),
        )
    }
}

/// How a [`RiskReport`] is produced — recorded in every report so a reader
/// knows exactly what the classification does and does not rest on.
const BASIS: &str = "classification from path sensitivity and grant kind over a single observed session; confidence is rule-decisiveness, not observed frequency";

/// One classified grant in a [`RiskReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRisk {
    /// The resource: a path, `ip:port` endpoint, or syscall name.
    pub resource: String,
    /// What sort of grant it is.
    pub kind: GrantKind,
    /// How to treat it on review.
    pub level: RiskLevel,
    /// How decisively the rule matched.
    pub confidence: Confidence,
    /// Why this line exists and why it got this level.
    pub reason: String,
}

impl GrantRisk {
    /// Classify one grant into a report row, honoring `ctx`.
    pub fn classify(resource: impl Into<String>, kind: GrantKind, ctx: &Context) -> Self {
        let resource = resource.into();
        let a = classify_in(&resource, kind, ctx);
        GrantRisk {
            resource,
            kind,
            level: a.level,
            confidence: a.confidence,
            reason: a.reason,
        }
    }
}

/// Counts of each risk level across a report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskSummary {
    /// Grants safe to keep without scrutiny.
    pub allow_candidate: usize,
    /// Grants a human should confirm.
    pub review: usize,
    /// Grants denied by default.
    pub deny_by_default: usize,
}

/// A reviewable risk report for one synthesized profile: every grant, its
/// classification, and why it exists — emitted alongside the profile so an
/// operator can sign off on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskReport {
    /// The agent/profile kind this report describes.
    pub agent: String,
    /// What the classification rests on (and what it does not).
    pub basis: String,
    /// Per-level counts.
    pub summary: RiskSummary,
    /// Every classified grant.
    pub grants: Vec<GrantRisk>,
}

impl RiskReport {
    /// Build a report from classified grants, computing the summary counts.
    pub fn new(agent: impl Into<String>, grants: Vec<GrantRisk>) -> Self {
        let mut summary = RiskSummary::default();
        for g in &grants {
            match g.level {
                RiskLevel::AllowCandidate => summary.allow_candidate += 1,
                RiskLevel::Review => summary.review += 1,
                RiskLevel::DenyByDefault => summary.deny_by_default += 1,
            }
        }
        RiskReport {
            agent: agent.into(),
            basis: BASIS.to_string(),
            summary,
            grants,
        }
    }

    /// Render the report as pretty JSON.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_reads_are_flagged_for_review() {
        let a = classify("/home/dev/.ssh/id_rsa", GrantKind::FsRead);
        assert_eq!(a.level, RiskLevel::Review);
        assert_eq!(a.confidence, Confidence::High);
    }

    #[test]
    fn denied_secret_glob_is_deny_by_default() {
        let a = classify("/root/.ssh/**", GrantKind::FsDenied);
        assert_eq!(a.level, RiskLevel::DenyByDefault);
        assert_eq!(a.confidence, Confidence::High);
    }

    #[test]
    fn system_and_lib_reads_are_allow_candidates() {
        for p in [
            "/etc/resolv.conf",
            "/usr/lib/x.so",
            "/lib64/ld.so",
            "/usr/share/ca",
        ] {
            let a = classify(p, GrantKind::FsRead);
            assert_eq!(a.level, RiskLevel::AllowCandidate, "{p}");
        }
    }

    #[test]
    fn project_writes_allow_but_system_writes_review() {
        let proj = classify("/tmp/build/**", GrantKind::FsWrite);
        assert_eq!(proj.level, RiskLevel::AllowCandidate);
        let sys = classify("/etc/cron.d/**", GrantKind::FsWrite);
        assert_eq!(sys.level, RiskLevel::Review);
        assert_eq!(sys.confidence, Confidence::High);
    }

    #[test]
    fn home_paths_need_review_without_frequency() {
        // Without a frequency/project-root signal we conservatively flag home
        // paths for review rather than guessing they are the project.
        let a = classify("/home/dev/project/main.rs", GrantKind::FsRead);
        assert_eq!(a.level, RiskLevel::Review);
        assert_eq!(a.confidence, Confidence::Medium);
    }

    #[test]
    fn standard_binaries_allow_nonstandard_review() {
        assert_eq!(
            classify("/usr/bin/cc", GrantKind::Exec).level,
            RiskLevel::AllowCandidate
        );
        let dropped = classify("/tmp/payload", GrantKind::Exec);
        assert_eq!(dropped.level, RiskLevel::Review);
        assert_eq!(dropped.confidence, Confidence::Medium);
    }

    #[test]
    fn cloud_metadata_egress_is_deny_others_review() {
        let meta = classify("169.254.169.254:80", GrantKind::NetEgress);
        assert_eq!(meta.level, RiskLevel::DenyByDefault);
        assert_eq!(meta.confidence, Confidence::High);
        let ext = classify("93.184.216.34:443", GrantKind::NetEgress);
        assert_eq!(ext.level, RiskLevel::Review);
    }

    #[test]
    fn denied_syscall_is_deny_by_default() {
        assert_eq!(
            classify("ptrace", GrantKind::SyscallDenied).level,
            RiskLevel::DenyByDefault
        );
    }

    #[test]
    fn levels_serialize_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&RiskLevel::AllowCandidate).unwrap(),
            "\"allow_candidate\""
        );
        assert_eq!(
            serde_json::to_string(&Confidence::High).unwrap(),
            "\"high\""
        );
        assert_eq!(
            serde_json::to_string(&GrantKind::NetEgress).unwrap(),
            "\"net_egress\""
        );
    }

    #[test]
    fn project_root_paths_become_allow_candidates() {
        let ctx = Context {
            project_root: Some("/home/dev/proj".to_string()),
        };
        let in_proj = classify_in("/home/dev/proj/src/main.rs", GrantKind::FsRead, &ctx);
        assert_eq!(in_proj.level, RiskLevel::AllowCandidate);
        // A secret under the project root is still a secret.
        let secret = classify_in("/home/dev/proj/.aws/credentials", GrantKind::FsRead, &ctx);
        assert_eq!(secret.level, RiskLevel::Review);
    }

    #[test]
    fn report_summary_counts_levels() {
        let ctx = Context::default();
        let grants = vec![
            GrantRisk::classify("/tmp/x", GrantKind::FsWrite, &ctx),
            GrantRisk::classify("/root/.ssh/**", GrantKind::FsDenied, &ctx),
            GrantRisk::classify("93.184.216.34:443", GrantKind::NetEgress, &ctx),
        ];
        let report = RiskReport::new("coding", grants);
        assert_eq!(report.summary.allow_candidate, 1);
        assert_eq!(report.summary.deny_by_default, 1);
        assert_eq!(report.summary.review, 1);
        assert!(report.to_json_pretty().contains("allow_candidate"));
    }
}

// crates/ql-enforce/src/error.rs
//
//! Error types for cell construction and enforcement.
//!
//! Enforcement failures are security-relevant: if an enforcer cannot apply
//! its rules, the cell must NOT run the agent (fail-closed). These error
//! types carry enough context to log precisely which wall failed and why.
//!
//! One variant, [`EnforceError::Unsupported`], is treated specially: it means
//! "this host genuinely cannot provide this wall" (e.g. a kernel without the
//! required cgroup controller). That is distinct from a hard failure and the
//! cell may choose to continue without that wall while recording its absence.

use thiserror::Error;

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, EnforceError>;

/// Everything that can go wrong while building or running a containment cell.
#[derive(Debug, Error)]
pub enum EnforceError {
    /// A specific enforcer failed to apply. `enforcer` names which wall failed.
    #[error("enforcer `{enforcer}` failed: {reason}")]
    Enforcer {
        /// The [`crate::Enforcer::name`] of the enforcer that failed.
        enforcer: &'static str,
        /// Human-readable cause.
        reason: String,
    },

    /// A raw OS syscall failed. Wraps the underlying errno for diagnostics.
    #[error("system call `{op}` failed: {source}")]
    Syscall {
        /// The logical operation being attempted (e.g. "unshare", "mount").
        op: &'static str,
        /// The underlying errno.
        #[source]
        source: nix::Error,
    },

    /// Spawning or waiting on the contained child process failed.
    #[error("failed to {op} contained process: {source}")]
    Process {
        /// The operation (e.g. "fork", "wait", "exec").
        op: &'static str,
        /// The underlying errno.
        #[source]
        source: nix::Error,
    },

    /// The profile itself was rejected before enforcement began.
    #[error("invalid profile: {0}")]
    Profile(#[from] ql_profile::ProfileError),

    /// This host cannot provide the requested wall (e.g. a missing cgroup
    /// controller). Distinct from a failure: the cell may continue without
    /// this wall while recording that it was unavailable.
    #[error("unsupported on this host: {feature} ({reason})")]
    Unsupported {
        /// The wall/feature that is unavailable.
        feature: &'static str,
        /// Why it is unavailable.
        reason: String,
    },
}

impl EnforceError {
    /// Build an [`EnforceError::Enforcer`] without boilerplate.
    pub fn enforcer(name: &'static str, reason: impl Into<String>) -> Self {
        EnforceError::Enforcer {
            enforcer: name,
            reason: reason.into(),
        }
    }

    /// Wrap a syscall failure with the logical operation name.
    pub fn syscall(op: &'static str, source: nix::Error) -> Self {
        EnforceError::Syscall { op, source }
    }
}

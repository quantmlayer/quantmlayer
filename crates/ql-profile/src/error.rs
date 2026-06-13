// crates/ql-profile/src/error.rs
//
//! Error types for profile loading and validation.
//!
//! All fallible operations in this crate return [`Result`] with a
//! structured [`ProfileError`]. We never panic on bad input — a malformed
//! profile is an expected, recoverable condition, not a bug.

use thiserror::Error;

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, ProfileError>;

/// Everything that can go wrong while loading or validating a [`crate::Profile`].
#[derive(Debug, Error)]
pub enum ProfileError {
    /// The profile text was not valid YAML, or did not match the schema.
    #[error("failed to parse profile as YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// The profile text was not valid JSON, or did not match the schema.
    #[error("failed to parse profile as JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// The profile's `schema_version` is one this build does not understand.
    #[error("unsupported schema_version {found}; this build supports {supported}")]
    UnsupportedSchemaVersion {
        /// The version found in the profile.
        found: u32,
        /// The version this build supports.
        supported: u32,
    },

    /// The profile parsed but failed a semantic validation rule.
    /// `field` locates the problem; `reason` explains it.
    #[error("invalid profile at `{field}`: {reason}")]
    Validation {
        /// Dotted path to the offending field, e.g. `resources.memory_max_bytes`.
        field: String,
        /// Human-readable explanation.
        reason: String,
    },
}

impl ProfileError {
    /// Helper to build a [`ProfileError::Validation`] without boilerplate.
    pub(crate) fn validation(field: impl Into<String>, reason: impl Into<String>) -> Self {
        ProfileError::Validation {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

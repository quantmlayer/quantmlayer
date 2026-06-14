// crates/ql-audit/src/error.rs
//! Errors for the audit log.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, AuditError>;

#[derive(Debug, Error)]
pub enum AuditError {
    /// The hash chain is broken at this record — the log was tampered with.
    #[error("audit chain broken at record #{seq} (line {index}): {reason}")]
    Tampered {
        seq: u64,
        index: usize,
        reason: &'static str,
    },

    /// A JSONL line could not be parsed into a record.
    #[error("could not parse audit record on line {line}: {source}")]
    Parse {
        line: usize,
        source: serde_json::Error,
    },

    /// Serialization failure (hashing/canonicalization).
    #[error("audit serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

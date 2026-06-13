// crates/ql-learn/src/error.rs
//
//! Error type for the learner.

use std::fmt;

/// Errors that can occur while tracing an agent or synthesizing a profile.
#[derive(Debug)]
pub enum LearnError {
    /// A syscall/ptrace operation failed.
    Trace(String),
    /// The traced command could not be started.
    Spawn(String),
}

impl fmt::Display for LearnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LearnError::Trace(m) => write!(f, "trace error: {m}"),
            LearnError::Spawn(m) => write!(f, "could not start command: {m}"),
        }
    }
}

impl std::error::Error for LearnError {}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, LearnError>;

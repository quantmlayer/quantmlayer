// crates/ql-token/src/error.rs
//! Errors for identity, tokens, and signed actions.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, TokenError>;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("invalid key material: {0}")]
    Key(&'static str),

    #[error("bad signature")]
    Signature,

    #[error("malformed hex: {0}")]
    Hex(&'static str),

    /// A delegated token tried to grant authority its parent did not hold.
    #[error("attenuation violation: a delegated token must not broaden authority ({0})")]
    Broadened(&'static str),

    /// The chain did not link correctly (issuer mismatch or wrong parent hash).
    #[error("broken delegation chain: {0}")]
    Chain(&'static str),

    /// The root issuer is not in the trusted set.
    #[error("untrusted root issuer")]
    UntrustedRoot,

    #[error("token expired (not_after has passed)")]
    Expired,

    /// A signed action is not permitted by the capability it was checked against.
    #[error("action not permitted by capability: {0}")]
    ActionDenied(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

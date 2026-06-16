// crates/ql-token/src/token.rs
//! Delegation tokens and signed tool calls.
//!
//! A token binds a [`Capability`] to a subject identity, signed by an issuer.
//! A *root* token is signed by a trusted root authority. A *delegated* token is
//! signed by the agent the parent token was issued to, may only attenuate the
//! parent's capability, and commits to the parent by hash — so a verifier can
//! walk the chain and prove authority only ever narrowed.
//!
//! A [`SignedAction`] is an agent signing a concrete action bound to the token
//! that authorizes it; verification checks the signature and that the action is
//! within the (already chain-verified) capability.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capability::{Action, Capability};
use crate::error::{Result, TokenError};
use crate::identity::{hex_encode, Identity, PublicId};

/// The signed contents of a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBody {
    /// Who signed this token (hex public key).
    pub issuer: String,
    /// The agent this token grants authority to (hex public key).
    pub subject: String,
    /// The granted capability.
    pub capability: Capability,
    /// Hash of the parent token (`None` for a root token).
    pub parent_hash: Option<String>,
    /// Expiry in Unix ms (`0` = no expiry).
    pub not_after_ms: u64,
}

/// A token: its body plus the issuer's signature over the canonical body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub body: TokenBody,
    pub signature: String,
}

fn canonical<T: Serialize>(t: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(t)?)
}

impl Token {
    /// Stable hash of this token (body + signature), used to chain children.
    pub fn hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(serde_json::to_vec(&self.body).unwrap_or_default());
        h.update(b"\0");
        h.update(self.signature.as_bytes());
        hex_encode(&h.finalize())
    }

    fn expired(&self, now_ms: u64) -> bool {
        self.body.not_after_ms != 0 && now_ms > self.body.not_after_ms
    }

    fn verify_sig(&self) -> Result<()> {
        let issuer = PublicId::from_hex(&self.body.issuer)?;
        issuer.verify(&canonical(&self.body)?, &self.signature)
    }
}

/// A sane bounded default lifetime for issued tokens: one hour. Issuance sites
/// should prefer this over `0` (no expiry) so a leaked or forgotten token stops
/// working on its own.
pub const DEFAULT_TTL_MS: u64 = 60 * 60 * 1000;

/// The expiry timestamp for a token issued at `now_ms` with the default
/// lifetime. Saturating, so a clock near `u64::MAX` cannot wrap to a tiny
/// expiry that would be instantly stale.
pub fn default_expiry(now_ms: u64) -> u64 {
    now_ms.saturating_add(DEFAULT_TTL_MS)
}

/// Issue a root token: a trusted authority grants `capability` to `subject`.
pub fn issue_root(
    authority: &Identity,
    subject: &PublicId,
    capability: Capability,
    not_after_ms: u64,
) -> Result<Token> {
    let body = TokenBody {
        issuer: authority.public().to_hex(),
        subject: subject.to_hex(),
        capability: capability.normalized(),
        parent_hash: None,
        not_after_ms,
    };
    let signature = authority.sign(&canonical(&body)?);
    Ok(Token { body, signature })
}

/// Delegate from `parent` to `subject`, attenuating to `capability`. The
/// `delegator` must be the agent `parent` was issued to, and `capability` must
/// be a subset of the parent's — broadening is rejected.
pub fn delegate(
    parent: &Token,
    delegator: &Identity,
    subject: &PublicId,
    capability: Capability,
    not_after_ms: u64,
) -> Result<Token> {
    if delegator.public().to_hex() != parent.body.subject {
        return Err(TokenError::Chain(
            "delegator is not the subject of the parent token",
        ));
    }
    let capability = capability.normalized();
    if !capability.is_subset_of(&parent.body.capability) {
        return Err(TokenError::Broadened(
            "delegated capability exceeds the parent's grant",
        ));
    }
    let body = TokenBody {
        issuer: delegator.public().to_hex(),
        subject: subject.to_hex(),
        capability,
        parent_hash: Some(parent.hash()),
        not_after_ms,
    };
    let signature = delegator.sign(&canonical(&body)?);
    Ok(Token { body, signature })
}

/// Verify a full chain (root first). Returns the effective (leaf) capability if
/// every link is valid: signatures check out, each issuer is the parent's
/// subject, each step only narrows authority, nothing is expired, and the root
/// is trusted.
pub fn verify_chain(
    chain: &[Token],
    trusted_roots: &[PublicId],
    now_ms: u64,
) -> Result<Capability> {
    let Some(root) = chain.first() else {
        return Err(TokenError::Chain("empty chain"));
    };
    if root.body.parent_hash.is_some() {
        return Err(TokenError::Chain("root token must have no parent"));
    }
    let root_issuer = PublicId::from_hex(&root.body.issuer)?;
    if !trusted_roots.contains(&root_issuer) {
        return Err(TokenError::UntrustedRoot);
    }
    root.verify_sig()?;
    if root.expired(now_ms) {
        return Err(TokenError::Expired);
    }

    for window in chain.windows(2) {
        let (prev, cur) = (&window[0], &window[1]);
        if cur.body.issuer != prev.body.subject {
            return Err(TokenError::Chain("issuer is not the parent's subject"));
        }
        if cur.body.parent_hash.as_deref() != Some(prev.hash().as_str()) {
            return Err(TokenError::Chain("parent hash does not match"));
        }
        if !cur.body.capability.is_subset_of(&prev.body.capability) {
            return Err(TokenError::Broadened("a link broadened authority"));
        }
        cur.verify_sig()?;
        if cur.expired(now_ms) {
            return Err(TokenError::Expired);
        }
    }

    Ok(chain.last().expect("non-empty").body.capability.clone())
}

// --- signed tool calls -----------------------------------------------------

/// The signed contents of an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionBody {
    pub action: Action,
    /// The hash of the leaf token that authorizes this action.
    pub token_hash: String,
    /// A caller-supplied nonce (replay protection is the caller's concern).
    pub nonce: u64,
}

/// An action signed by the agent performing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAction {
    pub body: ActionBody,
    /// The acting agent (hex public key) — must be the leaf token's subject.
    pub signer: String,
    pub signature: String,
}

/// Sign an action, binding it to the leaf token that authorizes it.
pub fn sign_action(
    signer: &Identity,
    action: Action,
    leaf_token_hash: &str,
    nonce: u64,
) -> Result<SignedAction> {
    let body = ActionBody {
        action,
        token_hash: leaf_token_hash.to_string(),
        nonce,
    };
    let signature = signer.sign(&canonical(&body)?);
    Ok(SignedAction {
        body,
        signer: signer.public().to_hex(),
        signature,
    })
}

/// Verify a signed action against a chain-verified leaf capability. Checks that
/// the signer is the leaf's subject, the action is bound to the leaf token, the
/// signature is valid, and the action is permitted by the capability.
pub fn verify_action(
    action: &SignedAction,
    leaf: &Token,
    leaf_capability: &Capability,
) -> Result<()> {
    if action.signer != leaf.body.subject {
        return Err(TokenError::Chain("action signer is not the leaf subject"));
    }
    if action.body.token_hash != leaf.hash() {
        return Err(TokenError::Chain("action is not bound to the leaf token"));
    }
    let signer = PublicId::from_hex(&action.signer)?;
    signer.verify(&canonical(&action.body)?, &action.signature)?;
    if !leaf_capability.permits(&action.body.action) {
        return Err(TokenError::ActionDenied(format!(
            "{:?}",
            action.body.action
        )));
    }
    Ok(())
}

/// A complete authorization an agent presents to a policy enforcement point: the
/// delegation chain that establishes its authority, plus the signed action it
/// wants to take. Serializes to one hex blob (e.g. an HTTP header value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthzRequest {
    pub chain: Vec<Token>,
    pub action: SignedAction,
}

impl AuthzRequest {
    /// Encode as a hex string (compact JSON).
    pub fn to_hex(&self) -> Result<String> {
        Ok(crate::identity::hex_encode(&canonical(self)?))
    }

    /// Decode from a hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = crate::identity::hex_decode(s)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

/// Authorize a request at a policy enforcement point: verify the chain (rooted
/// in a trusted authority, only narrowing), then verify the signed action is
/// bound to the leaf and permitted by the granted capability. Returns the
/// verified action so the caller can check it matches the resource requested.
pub fn authorize(req: &AuthzRequest, trusted_roots: &[PublicId], now_ms: u64) -> Result<Action> {
    let cap = verify_chain(&req.chain, trusted_roots, now_ms)?;
    let leaf = req.chain.last().ok_or(TokenError::Chain("empty chain"))?;
    verify_action(&req.action, leaf, &cap)?;
    Ok(req.action.body.action.clone())
}

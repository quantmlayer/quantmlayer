// crates/ql-token/src/identity.rs
//! Agent identity: an Ed25519 keypair. A public key *is* the agent's identity;
//! tokens bind capabilities to a public key, and signatures prove an action or
//! delegation came from the holder of the matching private key.

use crate::error::{Result, TokenError};
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};

/// A public identity (Ed25519 public key), carried as 32 bytes / hex.
#[derive(Clone)]
pub struct PublicId(pub(crate) PublicKey);

impl PublicId {
    /// Hex (64 chars) of the 32-byte public key.
    pub fn to_hex(&self) -> String {
        hex_encode(self.0.as_ref())
    }

    /// Parse a public id from hex.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex_decode(s)?;
        let pk =
            PublicKey::from_slice(&bytes).map_err(|_| TokenError::Key("invalid public key"))?;
        Ok(PublicId(pk))
    }

    /// Verify a detached signature (hex) over `msg`.
    pub fn verify(&self, msg: &[u8], sig_hex: &str) -> Result<()> {
        let sig_bytes = hex_decode(sig_hex)?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| TokenError::Hex("signature must be 64 bytes"))?;
        self.0.verify(msg, &sig).map_err(|_| TokenError::Signature)
    }
}

impl PartialEq for PublicId {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}
impl Eq for PublicId {}

impl std::fmt::Debug for PublicId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicId({})", self.to_hex())
    }
}

/// A full agent identity (private + public). Keep the private side secret.
pub struct Identity {
    kp: KeyPair,
    seed: [u8; 32],
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| TokenError::Key("OS RNG unavailable"))?;
        Self::from_seed_bytes(seed)
    }

    fn from_seed_bytes(seed: [u8; 32]) -> Result<Self> {
        let kp = KeyPair::from_seed(Seed::new(seed));
        Ok(Identity { kp, seed })
    }

    /// Reconstruct from a 32-byte private seed (hex).
    pub fn from_seed_hex(s: &str) -> Result<Self> {
        let bytes = hex_decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| TokenError::Key("seed must be 32 bytes"))?;
        Self::from_seed_bytes(arr)
    }

    /// The private seed as hex (store securely).
    pub fn seed_hex(&self) -> String {
        hex_encode(&self.seed)
    }

    /// This identity's public id.
    pub fn public(&self) -> PublicId {
        PublicId(self.kp.pk)
    }

    /// Sign a message, returning a hex signature (deterministic).
    pub fn sign(&self, msg: &[u8]) -> String {
        hex_encode(self.kp.sk.sign(msg, None).as_ref())
    }
}

// --- hex (no external dependency) ------------------------------------------

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub(crate) fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(TokenError::Hex("odd length"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| TokenError::Hex("non-hex digit")))
        .collect()
}

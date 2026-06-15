// crates/ql-broker/src/nonce.rs
//
//! Per-leaf-token anti-replay for signed actions.
//!
//! Every signed action commits to the leaf token that authorizes it (by hash)
//! and carries a caller-supplied nonce. The token layer deliberately does NOT
//! track nonces — it says so in its own docs — because replay defense belongs
//! to the policy enforcement point that actually admits an action. For egress,
//! that point is this broker.
//!
//! **Scope is per leaf token.** A nonce is unique within the authority of one
//! leaf token, not globally: two different leaves (two different delegated
//! agents) keep independent nonce sequences, so unrelated agents never collide
//! and one agent cannot exhaust another's nonce space.
//!
//! **Mechanism is a monotonic high-water mark per leaf.** An action is admitted
//! only if its nonce is strictly greater than the highest already admitted for
//! that leaf; the first nonce seen for a leaf is always fresh. This makes replay
//! impossible — a replayed nonce is `<=` the high-water mark — with O(1) state
//! per leaf. The alternative, a set of every nonce ever seen, would grow without
//! bound and hand an attacker a memory-exhaustion vector; a security component
//! must not do that. The cost is a contract on callers: per leaf token, use
//! strictly increasing nonces (a simple counter), and do not depend on
//! out-of-order concurrent delivery being admitted. (A sliding-window variant
//! could tolerate reordering later if a real workload needs it.)
//!
//! Entries for expired leaf tokens are pruned: an expired token fails chain
//! verification before it ever reaches this check, so its entry is dead weight
//! and is dropped opportunistically, bounding the map to live leaves.

use std::collections::HashMap;
use std::sync::Mutex;

/// The result of an anti-replay check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceCheck {
    /// The nonce is fresh; it has been recorded as the leaf's new high-water
    /// mark and the action may proceed.
    Fresh,
    /// The nonce was already used for this leaf (it is `<=` the high-water
    /// mark): a replay, and the action must be refused.
    Replay,
}

/// Per-leaf monotonic nonce high-water marks. Internally synchronized, so a
/// single store can be shared across the broker's connection threads behind an
/// `Arc`.
#[derive(Debug, Default)]
pub struct NonceStore {
    inner: Mutex<HashMap<String, Entry>>,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    /// Highest nonce admitted for this leaf so far.
    high_water: u64,
    /// The leaf token's expiry (Unix ms; `0` = no expiry), used for pruning.
    not_after_ms: u64,
}

impl NonceStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check `nonce` against the high-water mark for `leaf_hash`; if fresh,
    /// record it as the new high-water mark.
    ///
    /// Returns [`NonceCheck::Fresh`] iff `nonce` is strictly greater than every
    /// nonce previously admitted for this leaf (so the first action for a leaf
    /// is always fresh); otherwise [`NonceCheck::Replay`]. `leaf_not_after_ms`
    /// is the leaf token's expiry (`0` = none), kept so expired entries can be
    /// pruned; `now_ms` is the current time.
    pub fn check_and_record(
        &self,
        leaf_hash: &str,
        nonce: u64,
        leaf_not_after_ms: u64,
        now_ms: u64,
    ) -> NonceCheck {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Drop entries whose leaf tokens have expired — they can no longer pass
        // chain verification, so tracking them is pure overhead. This bounds the
        // map to leaves that are still live.
        map.retain(|_, e| e.not_after_ms == 0 || e.not_after_ms >= now_ms);

        match map.get_mut(leaf_hash) {
            Some(e) if nonce > e.high_water => {
                e.high_water = nonce;
                e.not_after_ms = leaf_not_after_ms;
                NonceCheck::Fresh
            }
            Some(_) => NonceCheck::Replay,
            None => {
                map.insert(
                    leaf_hash.to_string(),
                    Entry {
                        high_water: nonce,
                        not_after_ms: leaf_not_after_ms,
                    },
                );
                NonceCheck::Fresh
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEVER: u64 = 0; // no expiry
    const NOW: u64 = 1_000;

    // Record `nonce` for `leaf` with no expiry at the fixed test clock.
    fn rec(s: &NonceStore, leaf: &str, nonce: u64) -> NonceCheck {
        s.check_and_record(leaf, nonce, NEVER, NOW)
    }

    #[test]
    fn first_nonce_for_a_leaf_is_fresh() {
        let s = NonceStore::new();
        assert_eq!(rec(&s, "leaf", 1), NonceCheck::Fresh);
    }

    #[test]
    fn exact_replay_is_rejected() {
        let s = NonceStore::new();
        assert_eq!(rec(&s, "leaf", 5), NonceCheck::Fresh);
        assert_eq!(rec(&s, "leaf", 5), NonceCheck::Replay);
    }

    #[test]
    fn lower_nonce_rejected_higher_admitted() {
        let s = NonceStore::new();
        assert_eq!(rec(&s, "leaf", 10), NonceCheck::Fresh);
        assert_eq!(rec(&s, "leaf", 9), NonceCheck::Replay);
        assert_eq!(rec(&s, "leaf", 11), NonceCheck::Fresh);
    }

    #[test]
    fn leaves_have_independent_sequences() {
        let s = NonceStore::new();
        assert_eq!(rec(&s, "leaf-a", 7), NonceCheck::Fresh);
        // The same nonce on a different leaf is fresh — scope is per leaf.
        assert_eq!(rec(&s, "leaf-b", 7), NonceCheck::Fresh);
        // ...and the replay rule remains per-leaf.
        assert_eq!(rec(&s, "leaf-a", 7), NonceCheck::Replay);
    }

    #[test]
    fn nonce_zero_is_a_valid_first_value() {
        let s = NonceStore::new();
        assert_eq!(rec(&s, "leaf", 0), NonceCheck::Fresh);
        assert_eq!(rec(&s, "leaf", 0), NonceCheck::Replay);
    }

    #[test]
    fn expired_leaf_entry_is_pruned() {
        let s = NonceStore::new();
        // Leaf token expires at t=500; record a high nonce while it is live.
        assert_eq!(s.check_and_record("leaf", 9, 500, 100), NonceCheck::Fresh);
        // Past expiry the entry is pruned, so a lower nonce that would have been
        // a replay is instead treated as a fresh first-sighting.
        assert_eq!(s.check_and_record("leaf", 1, 0, 600), NonceCheck::Fresh);
    }
}

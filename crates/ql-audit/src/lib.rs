// crates/ql-audit/src/lib.rs
//! A tamper-evident, hash-chained audit log for containment-relevant actions.
//!
//! Each record commits to the one before it:
//!
//! ```text
//! hash[i] = SHA-256( seq[i] || prev_hash[i] || canonical(event[i]) )
//! prev_hash[i] = hash[i-1]   (prev_hash[0] = GENESIS)
//! ```
//!
//! Any insertion, deletion, reordering, or edit of a record breaks the chain
//! and is detected by [`AuditLog::verify`]. The log is stored as JSON Lines
//! (one record per line) so it is greppable, appendable, and portable. This is
//! the evidence layer: "prove what the agent attempted and that the record
//! wasn't altered after the fact."
//!
//! The log records *decisions and lifecycle*, not every syscall — the natural
//! producers are the egress broker (allow/deny per destination) and the cell
//! (session start/end, which walls applied).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod error;
pub use error::{AuditError, Result};

/// The genesis previous-hash for the first record (64 hex zeros).
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A single auditable action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Milliseconds since the Unix epoch (UTC).
    pub ts_millis: u64,
    /// Who took the action: e.g. "broker", "cell", "learn".
    pub actor: String,
    /// What was attempted: e.g. "egress.connect", "session.start", "wall.apply".
    pub action: String,
    /// The object of the action: e.g. "pypi.org:443", a profile hash, a path.
    pub target: String,
    /// The outcome: [`Decision::Allow`], [`Decision::Deny`], or [`Decision::Info`].
    pub decision: Decision,
    /// Free-form context (kept stable; it is part of the hash).
    #[serde(default)]
    pub detail: String,
}

/// The outcome recorded for an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
    Info,
}

/// A chained record: an event plus its position and hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub event: AuditEvent,
    /// Hash of the previous record (or [`GENESIS`] for the first).
    pub prev_hash: String,
    /// This record's hash (hex SHA-256 over seq, prev_hash, and the event).
    pub hash: String,
}

/// Compute the chain hash for a record's contents. Deterministic: the event is
/// canonicalized via compact JSON with a fixed field order (serde declaration
/// order), and the seq + prev_hash are folded in.
fn chain_hash(seq: u64, prev_hash: &str, event: &AuditEvent) -> Result<String> {
    let canon = serde_json::to_vec(event)?;
    let mut h = Sha256::new();
    h.update(seq.to_be_bytes());
    h.update(prev_hash.as_bytes());
    h.update(b"\0");
    h.update(&canon);
    Ok(hex(&h.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// An append-only, hash-chained audit log.
#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    records: Vec<AuditRecord>,
}

impl AuditLog {
    /// A new, empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records seen so far.
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// The current chain head (hash of the last record, or [`GENESIS`]).
    pub fn head(&self) -> &str {
        self.records
            .last()
            .map(|r| r.hash.as_str())
            .unwrap_or(GENESIS)
    }

    /// Append an event, extending the chain. Returns the new record.
    pub fn append(&mut self, event: AuditEvent) -> Result<&AuditRecord> {
        let seq = self.records.len() as u64;
        let prev_hash = self.head().to_string();
        let hash = chain_hash(seq, &prev_hash, &event)?;
        self.records.push(AuditRecord {
            seq,
            event,
            prev_hash,
            hash,
        });
        Ok(self.records.last().expect("just pushed"))
    }

    /// Serialize the whole log to JSON Lines (one record per line).
    pub fn to_jsonl(&self) -> Result<String> {
        let mut out = String::new();
        for r in &self.records {
            out.push_str(&serde_json::to_string(r)?);
            out.push('\n');
        }
        Ok(out)
    }

    /// Parse a log from JSON Lines. Does NOT verify the chain — call
    /// [`AuditLog::verify`] for that.
    pub fn from_jsonl(s: &str) -> Result<Self> {
        let mut records = Vec::new();
        for (i, line) in s.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let rec: AuditRecord = serde_json::from_str(line).map_err(|e| AuditError::Parse {
                line: i + 1,
                source: e,
            })?;
            records.push(rec);
        }
        Ok(Self { records })
    }

    /// Verify the chain end to end. On success the log is intact; on failure the
    /// error names the first record where the chain breaks (tamper detected).
    pub fn verify(&self) -> Result<()> {
        let mut expected_prev = GENESIS.to_string();
        for (idx, r) in self.records.iter().enumerate() {
            let seq_ok = r.seq == idx as u64;
            let link_ok = r.prev_hash == expected_prev;
            let recomputed = chain_hash(r.seq, &r.prev_hash, &r.event)?;
            let hash_ok = recomputed == r.hash;
            if !(seq_ok && link_ok && hash_ok) {
                return Err(AuditError::Tampered {
                    seq: r.seq,
                    index: idx,
                    reason: if !seq_ok {
                        "sequence number out of order"
                    } else if !link_ok {
                        "prev_hash does not chain to the previous record"
                    } else {
                        "record hash does not match its contents (record was altered)"
                    },
                });
            }
            expected_prev = r.hash.clone();
        }
        Ok(())
    }

    /// Convenience: current Unix time in milliseconds (for producers).
    pub fn now_millis() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(action: &str, target: &str, decision: Decision) -> AuditEvent {
        AuditEvent {
            ts_millis: 1_700_000_000_000,
            actor: "broker".into(),
            action: action.into(),
            target: target.into(),
            decision,
            detail: String::new(),
        }
    }

    fn sample_log() -> AuditLog {
        let mut log = AuditLog::new();
        log.append(ev("session.start", "profile:abc123", Decision::Info))
            .unwrap();
        log.append(ev("egress.connect", "pypi.org:443", Decision::Allow))
            .unwrap();
        log.append(ev("egress.connect", "169.254.169.254:80", Decision::Deny))
            .unwrap();
        log.append(ev("session.end", "exit:0", Decision::Info))
            .unwrap();
        log
    }

    #[test]
    fn intact_log_verifies() {
        assert!(sample_log().verify().is_ok());
    }

    #[test]
    fn roundtrips_through_jsonl() {
        let log = sample_log();
        let text = log.to_jsonl().unwrap();
        let parsed = AuditLog::from_jsonl(&text).unwrap();
        assert_eq!(parsed.records(), log.records());
        assert!(parsed.verify().is_ok());
    }

    #[test]
    fn editing_a_record_is_detected() {
        let log = sample_log();
        let mut parsed = AuditLog::from_jsonl(&log.to_jsonl().unwrap()).unwrap();
        // Flip a denied egress into an allowed one without recomputing the hash.
        parsed.records[2].event.decision = Decision::Allow;
        let err = parsed.verify().unwrap_err();
        match err {
            AuditError::Tampered { seq, .. } => assert_eq!(seq, 2),
            other => panic!("expected Tampered, got {other:?}"),
        }
    }

    #[test]
    fn deleting_a_record_is_detected() {
        let log = sample_log();
        let mut parsed = AuditLog::from_jsonl(&log.to_jsonl().unwrap()).unwrap();
        parsed.records.remove(1); // drop the pypi allow
        assert!(parsed.verify().is_err());
    }

    #[test]
    fn head_advances_and_chains() {
        let log = sample_log();
        let recs = log.records();
        assert_eq!(recs[0].prev_hash, GENESIS);
        assert_eq!(recs[1].prev_hash, recs[0].hash);
        assert_eq!(log.head(), recs[3].hash);
    }
}

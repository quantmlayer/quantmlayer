// crates/ql-learn/src/digest.rs
//
//! Content hashing of executed binaries — the bridge from *observed paths* to
//! a *content-addressed* exec allow-list.
//!
//! `ql learn` records the path of every binary an agent execs; this module
//! hashes those files with SHA-256, the same algorithm IMA computes in the
//! kernel, so a learned digest matches what `bpf_ima_file_hash` produces at
//! enforcement time. The output is the agent's demonstrated executable set
//! pinned by *content* rather than by name: a renamed or modified binary has a
//! different (unknown) digest and is denied.

use ql_profile::{ExecDigest, HashAlgo};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

/// Hash each absolute path in `execs` with SHA-256.
///
/// Returns a map from path to its [`ExecDigest`], plus notes for any binary
/// that could not be read or hashed. Read failures become notes rather than
/// hard errors, so one unreadable binary never aborts a learning run.
/// Non-absolute program names are skipped: they cannot be content-addressed
/// reliably (they depend on `$PATH` resolution at run time).
pub(crate) fn hash_executables(
    execs: &BTreeSet<String>,
) -> (BTreeMap<String, ExecDigest>, Vec<String>) {
    let mut digests = BTreeMap::new();
    let mut notes = Vec::new();

    for path in execs.iter().filter(|p| p.starts_with('/')) {
        match hash_file(path) {
            Ok(hex) => match ExecDigest::new(HashAlgo::Sha256, hex) {
                Ok(digest) => {
                    digests.insert(path.clone(), digest);
                }
                Err(e) => notes.push(format!(
                    "could not form a digest for `{path}`: {e}; left out of the exec allow-list"
                )),
            },
            Err(e) => notes.push(format!(
                "could not hash `{path}`: {e}; left out of the exec allow-list"
            )),
        }
    }

    (digests, notes)
}

/// SHA-256 a file's contents, streaming in chunks so a large binary is never
/// read whole into memory. Returns the lowercase hex digest.
fn hash_file(path: &str) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Lowercase hex encoding (mirrors `ql-audit`'s helper; avoids a hex-crate dep).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_a_file_to_its_known_sha256() {
        // SHA-256("abc") is a published NIST test vector.
        let path = std::env::temp_dir().join(format!("ql-digest-test-{}", std::process::id()));
        std::fs::write(&path, b"abc").expect("write temp file");
        let p = path.to_string_lossy().to_string();

        let mut execs = BTreeSet::new();
        execs.insert(p.clone());
        execs.insert("relative-name".to_string()); // skipped: not absolute
        execs.insert("/nonexistent/ql-learn/missing".to_string()); // noted: unreadable

        let (digests, notes) = hash_executables(&execs);

        let d = digests.get(&p).expect("temp file was hashed");
        assert_eq!(d.algo(), HashAlgo::Sha256);
        assert_eq!(
            d.hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(!digests.contains_key("relative-name"));
        assert!(notes.iter().any(|n| n.contains("missing")));

        let _ = std::fs::remove_file(&path);
    }
}

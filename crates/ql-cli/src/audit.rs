// crates/ql-cli/src/audit.rs
//
//! `ql audit` — work with the tamper-evident audit log.
//!
//! * `ql audit verify <log.jsonl>`
//!   Re-walk the hash chain and report whether the log is intact or where it
//!   was altered. Anyone can run this on a log they were handed; they do not
//!   need to trust the producer.
//! * `ql audit append <log.jsonl> --actor A --action X --target T \
//!        --decision allow|deny|info [--detail "..."]`
//!   Append a hash-chained record. This is the sink any component (broker,
//!   cell, a wrapper script) writes through.

use ql_audit::{AuditEvent, AuditLog, Decision};
use std::process::ExitCode;

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("verify") => verify(&args[1..]),
        Some("append") => append(&args[1..]),
        Some("export") => export(&args[1..]),
        Some("rotate") => rotate(&args[1..]),
        Some("retention") => retention(&args[1..]),
        Some("keygen") => keygen(&args[1..]),
        Some("-h") | Some("--help") | None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("ql audit: unknown subcommand `{other}`");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn verify(args: &[String]) -> ExitCode {
    let mut path: Option<&String> = None;
    let mut json = false;
    for a in args {
        match a.as_str() {
            "--json" => json = true,
            other if path.is_none() && !other.starts_with('-') => path = Some(a),
            other => {
                eprintln!("ql audit verify: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    let Some(path) = path else {
        eprintln!("ql audit verify: a log file path is required");
        return ExitCode::from(2);
    };
    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql audit verify: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let log = match AuditLog::from_jsonl(&text) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ql audit verify: {e}");
            return ExitCode::from(1);
        }
    };
    // Exit codes are part of the machine contract (docs/MACHINE-INTERFACE.md):
    // 0 = chain verified, 3 = chain verification FAILED (tamper finding),
    // 1 = could not parse, 2 = usage / unreadable file. A CI gate can
    // therefore distinguish "the ledger is bad" from "the check didn't run".
    match log.verify() {
        Ok(()) => {
            if json {
                print_verify_json(path, true, log.records().len(), None);
            } else {
                println!(
                    "{path}: INTACT — {} record(s), chain verified",
                    log.records().len()
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            if json {
                print_verify_json(path, false, log.records().len(), Some(&e.to_string()));
            } else {
                eprintln!("{path}: TAMPERED — {e}");
            }
            ExitCode::from(3)
        }
    }
}

/// Emit the machine-readable verify result on stdout. Stable contract: see
/// docs/MACHINE-INTERFACE.md.
fn print_verify_json(path: &str, ok: bool, records: usize, error: Option<&str>) {
    let obj = serde_json::json!({
        "schema": "ql.audit.verify/v1",
        "file": path,
        "ok": ok,
        "records": records,
        "error": error,
    });
    match serde_json::to_string_pretty(&obj) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("ql audit verify: cannot render json: {e}"),
    }
}

fn append(args: &[String]) -> ExitCode {
    let Some(path) = args.first() else {
        eprintln!("ql audit append: a log file path is required");
        return ExitCode::from(2);
    };
    let mut actor = None;
    let mut action = None;
    let mut target = None;
    let mut decision = None;
    let mut detail = String::new();

    let mut it = args[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--actor" => actor = it.next().cloned(),
            "--action" => action = it.next().cloned(),
            "--target" => target = it.next().cloned(),
            "--decision" => decision = it.next().cloned(),
            "--detail" => detail = it.next().cloned().unwrap_or_default(),
            other => {
                eprintln!("ql audit append: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    let (Some(actor), Some(action), Some(target), Some(decision_str)) =
        (actor, action, target, decision)
    else {
        eprintln!("ql audit append: --actor, --action, --target and --decision are all required");
        return ExitCode::from(2);
    };
    let decision = match decision_str.as_str() {
        "allow" => Decision::Allow,
        "deny" => Decision::Deny,
        "info" => Decision::Info,
        other => {
            eprintln!("ql audit append: --decision must be allow|deny|info (got `{other}`)");
            return ExitCode::from(2);
        }
    };

    // Load existing chain (if any) so the new record links to its head.
    let mut log = match std::fs::read_to_string(path) {
        Ok(s) => match AuditLog::from_jsonl(&s) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("ql audit append: existing log is unreadable: {e}");
                return ExitCode::from(1);
            }
        },
        Err(_) => AuditLog::new(), // new log
    };

    let event = AuditEvent {
        ts_millis: AuditLog::now_millis(),
        actor,
        action,
        target,
        decision,
        detail,
        system: None,
    };
    let (seq, hash) = match log.append(event) {
        Ok(rec) => (rec.seq, rec.hash.clone()),
        Err(e) => {
            eprintln!("ql audit append: {e}");
            return ExitCode::from(1);
        }
    };

    let text = match log.to_jsonl() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ql audit append: {e}");
            return ExitCode::from(1);
        }
    };
    match std::fs::write(path, text) {
        Ok(()) => {
            println!("appended record #{seq} ({}…)", &hash[..16.min(hash.len())]);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ql audit append: cannot write {path}: {e}");
            ExitCode::from(2)
        }
    }
}

/// `ql audit export <log> --out <dir> [--since <ms>] [--until <ms>]` — write a
/// self-contained evidence bundle (records + manifest + a standalone verifier)
/// for a contiguous, time-bounded segment of the chain. The bundle is verifiable
/// by anyone with only the Python standard library — no QuantmLayer needed.
fn export(args: &[String]) -> ExitCode {
    let mut log_path: Option<&str> = None;
    let mut out_dir: Option<&str> = None;
    let mut since: Option<u64> = None;
    let mut until: Option<u64> = None;
    let mut sign_key: Option<&str> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out_dir = it.next().map(String::as_str),
            "--since" => since = it.next().and_then(|s| s.parse().ok()),
            "--until" => until = it.next().and_then(|s| s.parse().ok()),
            "--sign-key" => sign_key = it.next().map(String::as_str),
            s if !s.starts_with('-') && log_path.is_none() => log_path = Some(s),
            other => {
                eprintln!("ql audit export: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    let Some(path) = log_path else {
        eprintln!("ql audit export: a log file path is required");
        return ExitCode::from(2);
    };
    let Some(out) = out_dir else {
        eprintln!("ql audit export: --out <dir> is required");
        return ExitCode::from(2);
    };

    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql audit export: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let log = match AuditLog::from_jsonl(&text) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ql audit export: {e}");
            return ExitCode::from(1);
        }
    };
    // Never package a log that does not verify — an evidence bundle must start
    // from an intact chain.
    if let Err(e) = log.verify() {
        eprintln!("ql audit export: refusing to export a tampered log: {e}");
        return ExitCode::from(1);
    }

    // Select a contiguous segment covering the requested time window.
    let all = log.records();
    let lo = match since {
        Some(s) => all
            .iter()
            .position(|r| r.event.ts_millis >= s)
            .unwrap_or(all.len()),
        None => 0,
    };
    let hi = match until {
        Some(u) => all
            .iter()
            .rposition(|r| r.event.ts_millis <= u)
            .map(|i| i + 1)
            .unwrap_or(0),
        None => all.len(),
    };
    if lo >= hi {
        eprintln!("ql audit export: no records in the requested time range");
        return ExitCode::from(1);
    }
    let window = &all[lo..hi];

    let mut body = String::new();
    for r in window {
        match serde_json::to_string(r) {
            Ok(line) => {
                body.push_str(&line);
                body.push('\n');
            }
            Err(e) => {
                eprintln!("ql audit export: serialize record: {e}");
                return ExitCode::from(1);
            }
        }
    }

    let mut manifest = serde_json::json!({
        "schema": "ql-audit-export/1",
        "source": path,
        "exported_at_ms": AuditLog::now_millis(),
        "since_ms": since,
        "until_ms": until,
        "record_count": window.len(),
        "first_seq": window.first().map(|r| r.seq),
        "last_seq": window.last().map(|r| r.seq),
        "anchor_prev_hash": window.first().map(|r| r.prev_hash.clone()),
        "head_hash": window.last().map(|r| r.hash.clone()),
        "full_log_head": log.head(),
        "full_log_count": all.len(),
        "canonicalization": "sha256( be64(seq) || prev_hash_ascii || 0x00 || compact_json(event) )"
    });

    // Optional deployer signature over the head hash: integrity comes from the
    // chain, authenticity (who attests to this segment) comes from the signature.
    if let Some(key_path) = sign_key {
        let head_hash = window.last().map(|r| r.hash.clone()).unwrap_or_default();
        match sign_head(key_path, &head_hash) {
            Ok((signature, public_key)) => {
                if let Some(obj) = manifest.as_object_mut() {
                    obj.insert("signature_alg".into(), serde_json::json!("ed25519"));
                    obj.insert("signed_field".into(), serde_json::json!("head_hash"));
                    obj.insert("public_key".into(), serde_json::json!(public_key));
                    obj.insert("signature".into(), serde_json::json!(signature));
                }
            }
            Err(e) => {
                eprintln!("ql audit export: {e}");
                return ExitCode::from(1);
            }
        }
    }

    let manifest = match serde_json::to_string_pretty(&manifest) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql audit export: manifest: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = std::fs::create_dir_all(out) {
        eprintln!("ql audit export: cannot create {out}: {e}");
        return ExitCode::from(2);
    }
    for (name, content) in [
        ("records.jsonl", body.as_str()),
        ("manifest.json", manifest.as_str()),
        ("verify.py", VERIFY_PY),
        ("VERIFY.md", VERIFY_MD),
    ] {
        let p = std::path::Path::new(out).join(name);
        if let Err(e) = std::fs::write(&p, content) {
            eprintln!("ql audit export: cannot write {}: {e}", p.display());
            return ExitCode::from(2);
        }
    }

    println!(
        "exported {} record(s) (seq {}-{}) to {out}/  —  verify with: python3 {out}/verify.py",
        window.len(),
        window.first().map(|r| r.seq).unwrap_or(0),
        window.last().map(|r| r.seq).unwrap_or(0),
    );
    ExitCode::SUCCESS
}

/// `ql audit rotate <log> --archive-dir <dir> [--reason <text>]` — seal the
/// active log into an immutable archive and start a fresh chain that commits the
/// sealed head, so the trail stays provably continuous across files. This is how
/// file size is bounded without ever breaking the chain: you cannot prune a
/// hash chain, so you seal-and-continue instead.
fn rotate(args: &[String]) -> ExitCode {
    let mut log_path: Option<&str> = None;
    let mut archive_dir: Option<&str> = None;
    let mut reason = String::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--archive-dir" => archive_dir = it.next().map(String::as_str),
            "--reason" => reason = it.next().cloned().unwrap_or_default(),
            s if !s.starts_with('-') && log_path.is_none() => log_path = Some(s),
            other => {
                eprintln!("ql audit rotate: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    let Some(path) = log_path else {
        eprintln!("ql audit rotate: a log file path is required");
        return ExitCode::from(2);
    };
    let Some(adir) = archive_dir else {
        eprintln!("ql audit rotate: --archive-dir <dir> is required");
        return ExitCode::from(2);
    };

    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql audit rotate: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let mut log = match AuditLog::from_jsonl(&text) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ql audit rotate: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = log.verify() {
        eprintln!("ql audit rotate: refusing to rotate a tampered log: {e}");
        return ExitCode::from(1);
    }
    if log.records().is_empty() {
        eprintln!("ql audit rotate: log is empty, nothing to seal");
        return ExitCode::from(1);
    }

    // Seal: a final record committing the segment's head, appended in-chain.
    let sealed_count = log.records().len();
    let pre_seal_head = log.head().to_string();
    let mut detail = format!("sealed {sealed_count} record(s)");
    if !reason.is_empty() {
        detail.push_str("; ");
        detail.push_str(&reason);
    }
    let seal = AuditEvent {
        ts_millis: AuditLog::now_millis(),
        actor: "audit".to_string(),
        action: "log.seal".to_string(),
        target: pre_seal_head,
        decision: Decision::Info,
        detail,
        system: None,
    };
    if let Err(e) = log.append(seal) {
        eprintln!("ql audit rotate: {e}");
        return ExitCode::from(1);
    }
    let archive_head = log.head().to_string();

    let archived = match log.to_jsonl() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ql audit rotate: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = std::fs::create_dir_all(adir) {
        eprintln!("ql audit rotate: cannot create {adir}: {e}");
        return ExitCode::from(2);
    }
    let head_short = &archive_head[..16.min(archive_head.len())];
    let fname = format!("audit-{}-{head_short}.jsonl", AuditLog::now_millis());
    let apath = std::path::Path::new(adir).join(&fname);
    if let Err(e) = std::fs::write(&apath, archived) {
        eprintln!("ql audit rotate: cannot write {}: {e}", apath.display());
        return ExitCode::from(2);
    }

    // Continue: a fresh chain whose first record commits the archived head.
    let mut next = AuditLog::new();
    let cont = AuditEvent {
        ts_millis: AuditLog::now_millis(),
        actor: "audit".to_string(),
        action: "log.continue".to_string(),
        target: archive_head.clone(),
        decision: Decision::Info,
        detail: format!("continues from {fname}"),
        system: None,
    };
    if let Err(e) = next.append(cont) {
        eprintln!("ql audit rotate: {e}");
        return ExitCode::from(1);
    }
    let next_text = match next.to_jsonl() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ql audit rotate: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = std::fs::write(path, next_text) {
        eprintln!("ql audit rotate: cannot write {path}: {e}");
        return ExitCode::from(2);
    }

    println!(
        "sealed {sealed_count} record(s) to {}  (head {head_short}…)\n\
         active log {path} now continues from that head",
        apath.display()
    );
    ExitCode::SUCCESS
}

/// `ql audit retention <archive-dir> [--min-keep-days <n>]` — report sealed
/// archives against the retention floor (default 180 days, the EU AI Act Art. 12
/// minimum). Reports only; it never deletes, since destroying audit evidence is
/// a deliberate, reviewable act, not a side effect of a status command.
fn retention(args: &[String]) -> ExitCode {
    let mut dir: Option<&str> = None;
    let mut min_keep_days: u64 = 180;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--min-keep-days" => {
                if let Some(v) = it.next().and_then(|s| s.parse().ok()) {
                    min_keep_days = v;
                }
            }
            s if !s.starts_with('-') && dir.is_none() => dir = Some(s),
            other => {
                eprintln!("ql audit retention: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    let Some(dir) = dir else {
        eprintln!("ql audit retention: an archive directory is required");
        return ExitCode::from(2);
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("ql audit retention: cannot read {dir}: {e}");
            return ExitCode::from(2);
        }
    };

    let now = AuditLog::now_millis();
    let day_ms: u64 = 86_400_000;
    let floor_ms = min_keep_days.saturating_mul(day_ms);
    let mut archives: Vec<(String, u64)> = Vec::new();
    for ent in entries.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if let Some(ms) = parse_archive_stamp(&name) {
            archives.push((name, ms));
        }
    }
    archives.sort_by_key(|(_, ms)| *ms);
    if archives.is_empty() {
        println!("{dir}: no sealed audit archives found");
        return ExitCode::SUCCESS;
    }

    println!(
        "retention floor: {min_keep_days} day(s); {} archive(s) in {dir}",
        archives.len()
    );
    for (name, ms) in &archives {
        let age_ms = now.saturating_sub(*ms);
        let age_days = age_ms / day_ms;
        let status = if age_ms < floor_ms {
            "MUST-KEEP"
        } else {
            "eligible-to-delete"
        };
        println!("  {name}  age {age_days}d  {status}");
    }
    ExitCode::SUCCESS
}

/// Parse the millisecond seal-stamp out of an archive name `audit-<ms>-<head>.jsonl`.
fn parse_archive_stamp(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("audit-")?;
    rest.split('-').next()?.parse().ok()
}

/// Load an Ed25519 private seed (hex) from `key_path` and sign `head_hash`'s
/// ASCII bytes. Returns `(signature_hex, public_key_hex)`.
fn sign_head(key_path: &str, head_hash: &str) -> Result<(String, String), String> {
    let seed = std::fs::read_to_string(key_path)
        .map_err(|e| format!("cannot read sign key {key_path}: {e}"))?;
    let id = ql_token::Identity::from_seed_hex(seed.trim())
        .map_err(|e| format!("invalid sign key {key_path}: {e}"))?;
    Ok((id.sign(head_hash.as_bytes()), id.public().to_hex()))
}

/// `ql audit keygen [--out <path>]` — generate an Ed25519 deployer signing key.
/// Writes the private seed (chmod 600) and prints the public key to publish, so
/// auditors can verify signed export bundles.
fn keygen(args: &[String]) -> ExitCode {
    let mut out: Option<&str> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = it.next().map(String::as_str),
            other => {
                eprintln!("ql audit keygen: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    let id = match ql_token::Identity::generate() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("ql audit keygen: {e}");
            return ExitCode::from(1);
        }
    };
    let public_key = id.public().to_hex();
    match out {
        Some(path) => {
            if let Err(e) = std::fs::write(path, format!("{}\n", id.seed_hex())) {
                eprintln!("ql audit keygen: cannot write {path}: {e}");
                return ExitCode::from(2);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            println!("private signing key written to {path} (keep secret)");
            println!("public key (publish so auditors can verify): {public_key}");
        }
        None => {
            println!("private seed (store securely): {}", id.seed_hex());
            println!("public key (publish):          {public_key}");
        }
    }
    ExitCode::SUCCESS
}

/// Standalone, dependency-free (Python stdlib only) chain verifier shipped in
/// every export bundle. Replicates `chain_hash` exactly.
const VERIFY_PY: &str = r#"#!/usr/bin/env python3
# Standalone verifier for a QuantmLayer audit evidence bundle.
# Requires only the Python standard library. Run from the bundle directory:
#     python3 verify.py
import json, hashlib, struct, sys, os

def chain_hash(rec):
    canon = json.dumps(rec["event"], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    h = hashlib.sha256()
    h.update(struct.pack(">Q", rec["seq"]))
    h.update(rec["prev_hash"].encode("utf-8"))
    h.update(b"\x00")
    h.update(canon)
    return h.hexdigest()

here = os.path.dirname(os.path.abspath(__file__))
recs = []
with open(os.path.join(here, "records.jsonl"), encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            recs.append(json.loads(line))
if not recs:
    print("no records in bundle"); sys.exit(1)

prev = recs[0]["prev_hash"]
for r in recs:
    if chain_hash(r) != r["hash"]:
        print("TAMPERED: record seq %d hash mismatch" % r["seq"]); sys.exit(1)
    if r["prev_hash"] != prev:
        print("TAMPERED: record seq %d does not link to the previous record" % r["seq"]); sys.exit(1)
    prev = r["hash"]

man = None
try:
    with open(os.path.join(here, "manifest.json"), encoding="utf-8") as f:
        man = json.load(f)
except FileNotFoundError:
    pass

if man is not None and man.get("head_hash") != recs[-1]["hash"]:
    print("WARNING: manifest head_hash does not match the last record"); sys.exit(1)

print("INTACT: %d record(s), chain verified; head %s..." % (len(recs), recs[-1]["hash"][:16]))

# Optional authenticity: the chain proves integrity; a deployer signature over
# the head proves who produced it. Checked opportunistically (stdlib has no
# ed25519, so the chain check above never depends on this).
if man is not None and man.get("signature") and man.get("public_key"):
    sig = man["signature"]; pub = man["public_key"]
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        print("SIGNATURE: present, not checked (pip install cryptography); deployer key %s..." % pub[:16])
    else:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(sig), recs[-1]["hash"].encode())
            print("SIGNATURE: valid; deployer key %s..." % pub[:16])
        except Exception:
            print("SIGNATURE: INVALID"); sys.exit(1)

sys.exit(0)
"#;

/// Human-facing verification instructions shipped in every export bundle.
const VERIFY_MD: &str = r#"# QuantmLayer audit evidence bundle

A contiguous segment of a tamper-evident, hash-chained audit log. You can verify
its integrity yourself with no QuantmLayer software — only the Python standard
library.

## Files
- records.jsonl  one audit record per line (the exported segment)
- manifest.json  export metadata (source, time range, sequence range, head hash)
- verify.py      standalone verifier (Python standard library only)

## Verify

    python3 verify.py

It recomputes each record's hash as

    SHA256( big-endian-u64(seq) || prev_hash-ascii || 0x00 || compact-json(event) )

and confirms every record links to the one before it. "INTACT" means no record
in the segment was altered, added, or removed.

## Notes
- The first record's prev_hash (the manifest "anchor_prev_hash") refers to the
  record immediately before this segment in the full log, and is by design
  outside the bundle. The manifest records the full log's head hash and total
  count so you can confirm what portion you received.
- Each record names the AI system it is attributed to (event.system) and carries
  a millisecond wall-clock timestamp (event.ts_millis).

## Authenticity (signed bundles)
If manifest.json carries "signature" and "public_key", the deployer signed the
head hash with an Ed25519 key. The chain already proves integrity; this proves
who attests to the segment. verify.py checks it automatically when the Python
"cryptography" package is installed. To check by hand, obtain the deployer's
public key through a trusted channel, confirm it matches "public_key", then:

    python3 -c 'import json,sys; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as K; m=json.load(open("manifest.json")); K.from_public_bytes(bytes.fromhex(m["public_key"])).verify(bytes.fromhex(m["signature"]), m["head_hash"].encode()); print("signature OK")'
"#;

fn print_help() {
    eprintln!(
        "ql audit — tamper-evident, hash-chained audit log\n\
         \n\
         USAGE:\n\
         \x20 ql audit verify <log.jsonl>\n\
         \x20 ql audit append <log.jsonl> --actor <a> --action <x> --target <t> \\\n\
         \x20                  --decision allow|deny|info [--detail <text>]\n\
         \x20 ql audit export <log.jsonl> --out <dir> [--since <ms>] [--until <ms>] [--sign-key <key>]\n\
         \x20 ql audit keygen [--out <key>]\n\
         \x20 ql audit rotate <log.jsonl> --archive-dir <dir> [--reason <text>]\n\
         \x20 ql audit retention <archive-dir> [--min-keep-days <n>]\n\
         \n\
         Any party can verify a log they were handed; they need not trust the producer.\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_writes_a_verifiable_bundle() {
        // A small intact log.
        let mut log = AuditLog::new();
        for i in 0..3u64 {
            let ev = AuditEvent {
                ts_millis: 1000 + i,
                actor: "run".to_string(),
                action: "policy.grant".to_string(),
                target: format!("cap{i}"),
                decision: Decision::Allow,
                detail: String::new(),
                system: None,
            };
            log.append(ev).unwrap();
        }

        let dir = std::env::temp_dir().join(format!("ql-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("log.jsonl");
        std::fs::write(&log_path, log.to_jsonl().unwrap()).unwrap();

        let out = dir.join("bundle");
        let args = vec![
            log_path.to_str().unwrap().to_string(),
            "--out".to_string(),
            out.to_str().unwrap().to_string(),
        ];
        // ExitCode is not comparable; assert on the side-effect files instead.
        let _ = export(&args);

        // The exported records re-parse as a valid, intact chain.
        let recs = std::fs::read_to_string(out.join("records.jsonl")).unwrap();
        let reparsed = AuditLog::from_jsonl(&recs).unwrap();
        assert!(reparsed.verify().is_ok());
        assert_eq!(reparsed.records().len(), 3);

        // Manifest carries the schema and the full-log head; the verifier ships.
        let man = std::fs::read_to_string(out.join("manifest.json")).unwrap();
        assert!(man.contains("ql-audit-export/1"));
        assert!(man.contains(log.head()));
        assert!(out.join("verify.py").exists());
        assert!(out.join("VERIFY.md").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_signs_head_when_key_given() {
        let mut log = AuditLog::new();
        for i in 0..2u64 {
            log.append(AuditEvent {
                ts_millis: 1000 + i,
                actor: "run".to_string(),
                action: "policy.grant".to_string(),
                target: format!("cap{i}"),
                decision: Decision::Allow,
                detail: String::new(),
                system: None,
            })
            .unwrap();
        }

        let dir = std::env::temp_dir().join(format!("ql-sign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("log.jsonl");
        std::fs::write(&log_path, log.to_jsonl().unwrap()).unwrap();

        let id = ql_token::Identity::generate().unwrap();
        let keyfile = dir.join("key.hex");
        std::fs::write(&keyfile, id.seed_hex()).unwrap();

        let out = dir.join("bundle");
        let args = vec![
            log_path.to_str().unwrap().to_string(),
            "--out".to_string(),
            out.to_str().unwrap().to_string(),
            "--sign-key".to_string(),
            keyfile.to_str().unwrap().to_string(),
        ];
        let _ = export(&args);

        let man: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(out.join("manifest.json")).unwrap())
                .unwrap();
        let sig = man["signature"].as_str().unwrap();
        let pubkey = man["public_key"].as_str().unwrap();
        let head = man["head_hash"].as_str().unwrap();

        // The signature verifies over the head, against the bundled public key,
        // and the head matches the real log head.
        let pid = ql_token::PublicId::from_hex(pubkey).unwrap();
        assert!(pid.verify(head.as_bytes(), sig).is_ok());
        assert_eq!(head, log.head());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_seals_and_continues() {
        let mut log = AuditLog::new();
        for i in 0..3u64 {
            log.append(AuditEvent {
                ts_millis: 1000 + i,
                actor: "run".to_string(),
                action: "policy.grant".to_string(),
                target: format!("cap{i}"),
                decision: Decision::Allow,
                detail: String::new(),
                system: None,
            })
            .unwrap();
        }
        let pre_head = log.head().to_string();

        let dir = std::env::temp_dir().join(format!("ql-rotate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.jsonl");
        std::fs::write(&log_path, log.to_jsonl().unwrap()).unwrap();
        let adir = dir.join("archive");

        let args = vec![
            log_path.to_str().unwrap().to_string(),
            "--archive-dir".to_string(),
            adir.to_str().unwrap().to_string(),
        ];
        let _ = rotate(&args);

        // Archive: exactly one sealed file, intact, ending in a log.seal that
        // commits the pre-seal head.
        let mut arch_files: Vec<_> = std::fs::read_dir(&adir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        assert_eq!(arch_files.len(), 1);
        let arch_text = std::fs::read_to_string(arch_files.pop().unwrap()).unwrap();
        let archived = AuditLog::from_jsonl(&arch_text).unwrap();
        assert!(archived.verify().is_ok());
        let last = archived.records().last().unwrap();
        assert_eq!(last.event.action, "log.seal");
        assert_eq!(last.event.target, pre_head);
        let archive_head = archived.head().to_string();

        // Active log: a fresh chain whose only record continues from the archive
        // head, and which still accepts further appends.
        let active_text = std::fs::read_to_string(&log_path).unwrap();
        let mut active = AuditLog::from_jsonl(&active_text).unwrap();
        assert!(active.verify().is_ok());
        assert_eq!(active.records().len(), 1);
        assert_eq!(active.records()[0].event.action, "log.continue");
        assert_eq!(active.records()[0].event.target, archive_head);
        active
            .append(AuditEvent {
                ts_millis: 2000,
                actor: "run".to_string(),
                action: "policy.grant".to_string(),
                target: "cap-new".to_string(),
                decision: Decision::Allow,
                detail: String::new(),
                system: None,
            })
            .unwrap();
        assert!(active.verify().is_ok());
        assert_eq!(active.records().len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_parses_and_reports() {
        assert_eq!(
            parse_archive_stamp("audit-1700000000000-abcd1234.jsonl"),
            Some(1_700_000_000_000)
        );
        assert_eq!(parse_archive_stamp("audit-42-x.jsonl"), Some(42));
        assert_eq!(parse_archive_stamp("not-an-archive.txt"), None);
        assert_eq!(parse_archive_stamp("audit-notanumber-x.jsonl"), None);

        let dir = std::env::temp_dir().join(format!("ql-retn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fname = format!("audit-{}-aaaa.jsonl", AuditLog::now_millis());
        std::fs::write(dir.join(fname), "x").unwrap();
        // Smoke: a real directory must not panic.
        let _ = retention(&[dir.to_str().unwrap().to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

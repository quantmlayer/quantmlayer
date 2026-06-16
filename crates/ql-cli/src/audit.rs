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
    let Some(path) = args.first() else {
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
    match log.verify() {
        Ok(()) => {
            println!(
                "{path}: INTACT — {} record(s), chain verified",
                log.records().len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{path}: TAMPERED — {e}");
            ExitCode::from(1)
        }
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

fn print_help() {
    eprintln!(
        "ql audit — tamper-evident, hash-chained audit log\n\
         \n\
         USAGE:\n\
         \x20 ql audit verify <log.jsonl>\n\
         \x20 ql audit append <log.jsonl> --actor <a> --action <x> --target <t> \\\n\
         \x20                  --decision allow|deny|info [--detail <text>]\n\
         \n\
         Any party can verify a log they were handed; they need not trust the producer.\n"
    );
}

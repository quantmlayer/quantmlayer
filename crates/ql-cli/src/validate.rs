// crates/ql-cli/src/validate.rs
//
//! `ql validate` — load a profile, validate it, and summarize the containment
//! it describes. Useful in CI to catch a malformed or dangerously-permissive
//! profile before it is ever used to run an agent.

use ql_profile::{Profile, SeccompDefault};
use std::process::ExitCode;

/// Entry point for `ql validate`.
pub fn cmd(args: &[String]) -> ExitCode {
    let mut profile_path: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--profile" => profile_path = it.next().cloned(),
            other => {
                eprintln!("ql validate: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    let Some(path) = profile_path else {
        eprintln!("ql validate: --profile <p.yaml> is required");
        return ExitCode::from(2);
    };

    let yaml = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql validate: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let profile = match Profile::from_yaml(&yaml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ql validate: parse error: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = profile.validate() {
        eprintln!("ql validate: INVALID — {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = profile.lint_authoring() {
        eprintln!("ql validate: INVALID — {e}");
        return ExitCode::from(1);
    }

    // Advisory only (never fails validation): warn if a `#!` shim is approved but
    // the interpreter it execs into is not — the multi-call-binary gap that denied
    // `/usr/bin/coreutils` on GKE COS. Filesystem-dependent, so it is best-effort.
    for gap in ql_learn::exec_shim_gaps(&profile) {
        eprintln!("ql validate: note: {gap}");
    }

    print_summary(&path, &profile);
    ExitCode::SUCCESS
}

/// Print a human-readable summary of the walls a profile will apply.
fn print_summary(path: &str, p: &Profile) {
    println!("{path}: VALID (schema v{})", p.schema_version);
    println!("  agent type   : {:?}", p.agent_type);
    println!(
        "  filesystem   : {} read-write, {} read-only, {} denied path(s)",
        p.filesystem.readwrite.len(),
        p.filesystem.readonly.len(),
        p.filesystem.denied.len()
    );
    println!(
        "  network      : default_deny={}, {} allowed domain(s), block_private_ranges={}",
        p.network.default_deny,
        p.network.allow_domains.len(),
        p.network.block_private_ranges
    );
    let syscall_mode = match p.syscalls.default_action {
        SeccompDefault::Allow => "allow-by-default",
        SeccompDefault::Deny => "deny-by-default",
    };
    println!(
        "  syscalls     : {syscall_mode}, {} denied, {} notify",
        p.syscalls.deny.len(),
        p.syscalls.notify.len()
    );
    println!(
        "  resources    : pids_max={}, memory_max={}, cpu_max={}",
        opt(p.resources.pids_max),
        opt(p.resources.memory_max_bytes),
        opt(p.resources.cpu_max_percent),
    );
    println!(
        "  exec allow   : {} entry(ies)",
        p.processes.allow_exec.len()
    );
}

/// Render an optional numeric limit as a string ("unset" when absent).
fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string())
        .unwrap_or_else(|| "unset".to_string())
}

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
    let mut agent_name: Option<String> = None;
    let mut mcp = false;
    let mut json = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--profile" => profile_path = it.next().cloned(),
            "--agent" => agent_name = it.next().cloned(),
            "--mcp" => mcp = true,
            "--json" => json = true,
            other => {
                eprintln!("ql validate: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    // Exactly one profile source: an on-disk path, a bundled agent name, or
    // the embedded MCP-server profile.
    let (path, yaml) = match (profile_path, agent_name, mcp) {
        (Some(p), None, false) => {
            let yaml = match std::fs::read_to_string(&p) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("ql validate: cannot read {p}: {e}");
                    return ExitCode::from(2);
                }
            };
            (p, yaml)
        }
        (None, Some(name), false) => match crate::agent::bundled(&name) {
            Some(a) => (format!("<bundled:{}>", a.name), a.yaml.to_string()),
            None => {
                eprintln!("ql validate: unknown agent `{name}` (see `ql agent list`)");
                return ExitCode::from(2);
            }
        },
        (None, None, true) => (
            "<bundled:mcp>".to_string(),
            crate::mcp::MCP_PROFILE_YAML.to_string(),
        ),
        (None, None, false) => {
            eprintln!("ql validate: --profile <p.yaml>, --agent <name>, or --mcp is required");
            return ExitCode::from(2);
        }
        _ => {
            eprintln!("ql validate: --profile, --agent, and --mcp are mutually exclusive");
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
    let notes: Vec<String> = ql_learn::exec_shim_gaps(&profile);
    for gap in &notes {
        eprintln!("ql validate: note: {gap}");
    }

    if json {
        print_json(&path, &profile, &notes);
    } else {
        print_summary(&path, &profile);
    }
    ExitCode::SUCCESS
}

/// Emit the machine-readable validation summary on stdout. Stable contract:
/// see docs/MACHINE-INTERFACE.md. Only reached when the profile is valid —
/// an invalid profile exits 1 before any summary, so `"valid"` is always
/// `true` here and exists for consumer convenience.
fn print_json(path: &str, p: &Profile, notes: &[String]) {
    let syscall_mode = match p.syscalls.default_action {
        SeccompDefault::Allow => "allow-by-default",
        SeccompDefault::Deny => "deny-by-default",
    };
    let obj = serde_json::json!({
        "schema": "ql.validate.result/v1",
        "profile": path,
        "valid": true,
        "schema_version": p.schema_version,
        "agent_type": format!("{:?}", p.agent_type),
        "filesystem": {
            "readwrite": p.filesystem.readwrite.len(),
            "readonly": p.filesystem.readonly.len(),
            "denied": p.filesystem.denied.len(),
        },
        "network": {
            "default_deny": p.network.default_deny,
            "allow_domains": p.network.allow_domains.len(),
            "block_private_ranges": p.network.block_private_ranges,
        },
        "syscalls": {
            "mode": syscall_mode,
            "deny": p.syscalls.deny.len(),
            "notify": p.syscalls.notify.len(),
        },
        "resources": {
            "pids_max": p.resources.pids_max,
            "memory_max_bytes": p.resources.memory_max_bytes,
            "cpu_max_percent": p.resources.cpu_max_percent,
        },
        "exec_allow": p.processes.allow_exec.len(),
        "notes": notes,
    });
    match serde_json::to_string_pretty(&obj) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("ql validate: cannot render json: {e}"),
    }
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

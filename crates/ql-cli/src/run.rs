// crates/ql-cli/src/run.rs
//
//! `ql run` — execute a command inside a containment cell.
//!
//! Everything after `--` is the command to run; the options before it select
//! and tune the profile. The command's stdout/stderr pass through untouched
//! and `ql` exits with the command's own exit code, so `ql run` is transparent
//! to scripts and CI.

use ql_broker::{serve, BrokerPolicy};
use ql_enforce::veth::VethPlan;
use ql_enforce::{brokered_coding_cell, standard_coding_cell, veth};
use ql_profile::Profile;
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

/// Entry point for `ql run`.
pub fn cmd(args: &[String]) -> ExitCode {
    // Split options from the command at the first `--`.
    let sep = args.iter().position(|a| a == "--");
    let (opts, command): (&[String], &[String]) = match sep {
        Some(i) => (&args[..i], &args[i + 1..]),
        None => (args, &[]),
    };

    let mut profile_path: Option<String> = None;
    let mut workspace: Option<String> = None;
    let mut audit_path: Option<String> = None;
    let mut verbose = false;
    let mut brokered = false;

    let mut it = opts.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--profile" => profile_path = it.next().cloned(),
            "--workspace" => workspace = it.next().cloned(),
            "--audit" => audit_path = it.next().cloned(),
            "--verbose" => verbose = true,
            "--broker" => brokered = true,
            other => {
                eprintln!("ql run: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    let Some(path) = profile_path else {
        eprintln!("ql run: --profile <p.yaml> is required");
        return ExitCode::from(2);
    };
    if command.is_empty() {
        eprintln!("ql run: no command given (everything after `--` is the command)");
        return ExitCode::from(2);
    }

    // Load and validate the profile.
    let mut profile = match load_profile(&path) {
        Ok(p) => p,
        Err(code) => return code,
    };

    // If a workspace is given, grant read-write to it.
    if let Some(ws) = workspace {
        profile.filesystem.readwrite.push(format!("{ws}/**"));
    }

    // Register this run so `ql ps` can list it and `ql kill` can revoke it
    // from another shell. We record THIS process's pid — the parent of the
    // contained agent — so revoking the tree takes the agent down with it.
    let id = std::env::var("QL_CELL_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{:08x}", (std::process::id() as u128 ^ nanos()) as u32));
    let handle = crate::registry::Handle {
        id: id.clone(),
        pid: std::process::id(),
        command: command.join(" "),
        profile: path.clone(),
        started_ms: now_ms(),
        brokered,
    };
    let _ = crate::registry::register(&handle);
    eprintln!("ql: cell `{id}` running (revoke from another shell: ql kill {id})");

    // Tamper-evident policy record: commit to the policy that will govern this
    // session, and the reason for each grant, before the agent runs.
    if let Some(audit) = audit_path.as_deref() {
        let project_root = std::env::current_dir().ok();
        match crate::policy::record_enforced(audit, &profile, project_root.as_deref()) {
            Ok(n) => eprintln!("ql: wrote {n} policy record(s) to {audit}"),
            Err(e) => eprintln!("ql run: could not write policy log {audit}: {e}"),
        }
    }

    let code = if brokered {
        run_brokered(profile, command, verbose)
    } else {
        run_default(profile, command, verbose)
    };
    crate::registry::deregister(&id);
    code
}

/// Current Unix time in milliseconds.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Standard run: full containment with default-deny network.
fn run_default(profile: Profile, command: &[String], verbose: bool) -> ExitCode {
    if verbose {
        eprintln!(
            "ql: containing `{}` (walls: cgroups, namespaces, mount, network[deny], seccomp)",
            command.join(" ")
        );
    }
    let cell = match standard_coding_cell(profile) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ql run: could not build containment cell: {e}");
            return ExitCode::from(1);
        }
    };
    match cell.run(command) {
        Ok(code) => ExitCode::from(clamp_code(code)),
        Err(e) => {
            eprintln!("ql run: containment failure (command not executed): {e}");
            ExitCode::from(1)
        }
    }
}

/// Brokered run: containment plus allow-listed egress through the broker. The
/// agent's only network route is a veth uplink to the broker, which enforces
/// the profile's domain allow-list and refuses private/link-local addresses.
fn run_brokered(profile: Profile, command: &[String], verbose: bool) -> ExitCode {
    // Plan a unique point-to-point subnet/link for this run.
    let seed = std::process::id() ^ (nanos() as u32);
    let plan = VethPlan::for_seed(seed);

    // Start the broker on an ephemeral port (all interfaces, so it is reachable
    // at the veth host IP once that link comes up).
    let listener = match TcpListener::bind("0.0.0.0:0") {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ql run: cannot start broker: {e}");
            return ExitCode::from(1);
        }
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(e) => {
            eprintln!("ql run: broker addr error: {e}");
            return ExitCode::from(1);
        }
    };
    let policy = Arc::new(BrokerPolicy::from_net_policy(&profile.network));
    std::thread::spawn(move || {
        let _ = serve(listener, policy);
    });

    let proxy_url = format!("http://{}:{}", plan.host_ip, port);
    if verbose {
        eprintln!(
            "ql: brokered egress via {proxy_url}; {} allow-listed domain(s)",
            profile.network.allow_domains.len()
        );
    }

    let cell = match brokered_coding_cell(profile, plan.clone(), proxy_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ql run: could not build brokered cell: {e}");
            return ExitCode::from(1);
        }
    };

    let result = cell.run(command);
    // Always tear the veth down, success or failure.
    veth::teardown(&plan);

    match result {
        Ok(code) => ExitCode::from(clamp_code(code)),
        Err(e) => {
            eprintln!("ql run: containment failure (command not executed): {e}");
            ExitCode::from(1)
        }
    }
}

/// Nanosecond counter for unique-ish veth subnet seeds.
fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Read and validate a profile, mapping failures to an exit code.
fn load_profile(path: &str) -> Result<Profile, ExitCode> {
    let yaml = std::fs::read_to_string(path).map_err(|e| {
        eprintln!("ql run: cannot read {path}: {e}");
        ExitCode::from(2)
    })?;
    let profile = Profile::from_yaml(&yaml).map_err(|e| {
        eprintln!("ql run: invalid profile: {e}");
        ExitCode::from(2)
    })?;
    profile.validate().map_err(|e| {
        eprintln!("ql run: profile failed validation: {e}");
        ExitCode::from(2)
    })?;
    Ok(profile)
}

/// Map a process exit code (i32) into the 0–255 range an `ExitCode` carries.
/// Out-of-range or negative codes collapse to 1 (generic failure).
fn clamp_code(code: i32) -> u8 {
    u8::try_from(code).unwrap_or(1)
}

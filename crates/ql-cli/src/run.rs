// crates/ql-cli/src/run.rs
//
//! `ql run` — execute a command inside a containment cell.
//!
//! Everything after `--` is the command to run; the options before it select
//! and tune the profile. The command's stdout/stderr pass through untouched
//! and `ql` exits with the command's own exit code, so `ql run` is transparent
//! to scripts and CI.

use ql_audit::SystemIdentity;
use ql_broker::{serve, AuditSink, BrokerPolicy};
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
    let mut proposed_path: Option<String> = None;
    let mut issue_token_path: Option<String> = None;
    let mut system_id: Option<String> = None;
    let mut model_version: Option<String> = None;
    let mut verbose = false;
    let mut brokered = false;
    let mut require_signed = false;
    let mut trust_signers: Vec<String> = Vec::new();
    let mut expect_commit: Option<String> = None;
    let mut expect_image: Option<String> = None;

    let mut it = opts.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--profile" => profile_path = it.next().cloned(),
            "--workspace" => workspace = it.next().cloned(),
            "--audit" => audit_path = it.next().cloned(),
            "--proposed" => proposed_path = it.next().cloned(),
            "--issue-token" => issue_token_path = it.next().cloned(),
            "--system-id" => system_id = it.next().cloned(),
            "--model-version" => model_version = it.next().cloned(),
            "--verbose" => verbose = true,
            "--broker" => brokered = true,
            "--require-signed" => require_signed = true,
            "--trust-signer" => {
                if let Some(v) = it.next() {
                    trust_signers.push(v.clone());
                }
            }
            "--expect-commit" => expect_commit = it.next().cloned(),
            "--expect-image" => expect_image = it.next().cloned(),
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

    // Signed-profile gate. A profile carrying a signature must verify; with
    // --require-signed or --trust-signer, a valid authorized signature is
    // mandatory. Runs BEFORE any runtime profile mutation (e.g. --workspace) so
    // the signature covers exactly what was authored and signed.
    match check_signature(&profile, require_signed, &trust_signers) {
        Ok(Some(signer)) => {
            let short = &signer[..16.min(signer.len())];
            eprintln!("ql: profile signature OK (signer {short}…)");
            // The signed approval context is only trustworthy once the signature
            // checks out, so enforce it here, inside the valid-signature branch.
            let want_commit = expect_commit.as_deref();
            let want_image = expect_image.as_deref();
            if let Err(code) = check_approved_for(&profile, want_commit, want_image) {
                return code;
            }
        }
        Ok(None) => {}
        Err(code) => return code,
    }

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

    // Identity that the audit records — policy commitments and, in brokered
    // mode, egress decisions — are attributed to (EU AI Act Art. 12).
    let system = system_id
        .as_deref()
        .map(|id| SystemIdentity::ai_system(id, model_version.clone()));

    // Tamper-evident policy record: commit to the policy that will govern this
    // session, and the reason for each grant, before the agent runs.
    if let Some(audit) = audit_path.as_deref() {
        let project_root = std::env::current_dir().ok();
        let proposed = proposed_path.as_deref().and_then(load_profile_lenient);
        // Attribute the records to the agent identity, if the operator named one.
        match crate::policy::record_enforced(
            audit,
            &profile,
            proposed.as_ref(),
            project_root.as_deref(),
            system.as_ref(),
        ) {
            Ok(n) => eprintln!("ql: wrote {n} policy record(s) to {audit}"),
            Err(e) => eprintln!("ql run: could not write policy log {audit}: {e}"),
        }
    }

    // Per-subtask credential: mint a fresh, capability-attenuated, expiring
    // identity for this cell, scoped to exactly what the profile permits.
    if let Some(out) = issue_token_path.as_deref() {
        match crate::token_issue::issue_subtask(&profile, now_ms()) {
            Ok(bundle) => match crate::token_issue::write_bundle(out, &bundle) {
                Ok(()) => eprintln!(
                    "ql: issued subtask token to {out} (trust root {}, expires {})",
                    &bundle.trust_root[..16.min(bundle.trust_root.len())],
                    bundle.not_after_ms
                ),
                Err(e) => eprintln!("ql run: could not write token bundle {out}: {e}"),
            },
            Err(e) => eprintln!("ql run: could not issue subtask token: {e}"),
        }
    }

    let code = if brokered {
        run_brokered(
            profile,
            command,
            verbose,
            audit_path.as_deref(),
            system.as_ref(),
        )
    } else {
        run_default(
            profile,
            command,
            verbose,
            audit_path.as_deref(),
            system.as_ref(),
        )
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

/// Enforce the operator's signed-profile policy before arming.
///
/// Returns the verified signer's public key when a valid signature is present,
/// `Ok(None)` when no signature is required and none is attached, or an error
/// exit code when the policy is violated — a missing signature (under
/// `--require-signed`/`--trust-signer`), an invalid signature (tampered
/// profile), or a signature from an untrusted signer.
fn check_signature(
    profile: &Profile,
    require_signed: bool,
    trust_signers: &[String],
) -> Result<Option<String>, ExitCode> {
    let required = require_signed || !trust_signers.is_empty();
    let Some(sig) = profile.signature.clone() else {
        if required {
            eprintln!("ql run: profile is unsigned but a signature is required");
            return Err(ExitCode::from(1));
        }
        return Ok(None);
    };
    let bytes = match profile.signing_bytes() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ql run: cannot canonicalize profile: {e}");
            return Err(ExitCode::from(1));
        }
    };
    let pid = match ql_token::PublicId::from_hex(&sig.public_key) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ql run: bad public key in profile signature: {e}");
            return Err(ExitCode::from(1));
        }
    };
    if pid.verify(&bytes, &sig.value).is_err() {
        eprintln!("ql run: profile signature INVALID — refusing to arm");
        return Err(ExitCode::from(1));
    }
    if !trust_signers.is_empty() {
        let pk = &sig.public_key;
        let trusted = trust_signers.iter().any(|t| t.eq_ignore_ascii_case(pk));
        if !trusted {
            let short = &pk[..16.min(pk.len())];
            eprintln!("ql run: signer {short}… not trusted — refusing to arm");
            return Err(ExitCode::from(1));
        }
    }
    Ok(Some(sig.public_key))
}

/// Enforce the signed `approved_for` binding against the operator's asserted run
/// context (`--expect-commit` / `--expect-image`). A mismatch means the profile
/// was approved for a different commit or image than the one actually running —
/// refuse to arm. Only meaningful for a validly-signed profile; the caller gates
/// on that.
fn check_approved_for(
    profile: &Profile,
    expect_commit: Option<&str>,
    expect_image: Option<&str>,
) -> Result<(), ExitCode> {
    let Some(approved) = &profile.approved_for else {
        return Ok(());
    };
    if let (Some(want), Some(actual)) = (&approved.commit, expect_commit) {
        if !want.eq_ignore_ascii_case(actual) {
            let a = &want[..12.min(want.len())];
            let b = &actual[..12.min(actual.len())];
            eprintln!("ql run: approved for commit {a}…, running {b}… — refusing");
            return Err(ExitCode::from(1));
        }
    }
    if let (Some(want), Some(actual)) = (&approved.image_digest, expect_image) {
        if !want.eq_ignore_ascii_case(actual) {
            eprintln!("ql run: profile approved for a different image — refusing");
            return Err(ExitCode::from(1));
        }
    }
    Ok(())
}

/// Standard run: full containment with default-deny network.
fn run_default(
    profile: Profile,
    command: &[String],
    verbose: bool,
    audit_path: Option<&str>,
    system: Option<&SystemIdentity>,
) -> ExitCode {
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
    let result = cell.run(command);
    write_exec_events(audit_path, system);
    match result {
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
fn run_brokered(
    profile: Profile,
    command: &[String],
    verbose: bool,
    audit_path: Option<&str>,
    system: Option<&SystemIdentity>,
) -> ExitCode {
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
    let mut policy = BrokerPolicy::from_net_policy(&profile.network);
    // Unify the ledger: send the in-process broker's egress decisions to the
    // same audit log the policy records went to (the AuditSink continues the
    // existing chain), attributed to the same AI system.
    if let Some(path) = audit_path {
        policy = policy.with_audit(AuditSink::new(path));
        if let Some(sys) = system {
            policy = policy.with_system(sys.clone());
        }
        eprintln!("ql: auditing brokered egress to {path}");
    }
    let policy = Arc::new(policy);
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
    write_exec_events(audit_path, system);
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

/// Drain the kernel's per-execve audit stream (content-addressed exec wall) for
/// the run that just finished and append one attributed record per decision —
/// `exec.run` (allowed) / `exec.deny` (denied) — to the unified ledger, chaining
/// onto the policy and egress records. No-op without the `lsm` feature, when no
/// wall was active, or when no audit log is set.
#[cfg(feature = "lsm")]
fn write_exec_events(audit_path: Option<&str>, system: Option<&SystemIdentity>) {
    use ql_audit::{AuditEvent, AuditLog, Decision};

    let events = ql_enforce::drain_exec_events();
    if events.is_empty() {
        return;
    }
    let Some(path) = audit_path else {
        return;
    };

    let mut log = match std::fs::read_to_string(path) {
        Ok(s) => match AuditLog::from_jsonl(&s) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("ql: exec audit: cannot parse {path}: {e}");
                return;
            }
        },
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => AuditLog::new(),
        Err(e) => {
            eprintln!("ql: exec audit: cannot read {path}: {e}");
            return;
        }
    };

    for ev in events {
        let (action, decision) = if ev.allowed {
            ("exec.run", Decision::Allow)
        } else {
            ("exec.deny", Decision::Deny)
        };
        let event = AuditEvent {
            ts_millis: ev.ts_millis,
            actor: "exec".to_string(),
            action: action.to_string(),
            target: ev.digest_hex.unwrap_or_else(|| "<unhashed>".to_string()),
            decision,
            detail: format!("pid {} ({})", ev.pid, ev.comm),
            system: system.cloned(),
        };
        if log.append(event).is_err() {
            eprintln!("ql: exec audit: append failed");
            return;
        }
    }

    match log.to_jsonl() {
        Ok(text) => {
            if let Err(e) = std::fs::write(path, text) {
                eprintln!("ql: exec audit: write {path} failed: {e}");
            }
        }
        Err(e) => eprintln!("ql: exec audit: serialize failed: {e}"),
    }
}

#[cfg(not(feature = "lsm"))]
fn write_exec_events(_audit_path: Option<&str>, _system: Option<&SystemIdentity>) {}

/// Nanosecond counter for unique-ish veth subnet seeds.
fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Read and validate a profile, mapping failures to an exit code.
/// Load a profile for diffing without aborting the run on failure: a missing or
/// invalid proposed baseline just means no diff is recorded, never a refused
/// run. Returns `None` (with a warning) rather than an exit code.
fn load_profile_lenient(path: &str) -> Option<Profile> {
    match std::fs::read_to_string(path) {
        Ok(s) => match Profile::from_yaml(&s) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("ql run: proposed profile {path} is invalid ({e}); skipping diff");
                None
            }
        },
        Err(e) => {
            eprintln!("ql run: cannot read proposed profile {path} ({e}); skipping diff");
            None
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_default() -> (Profile, String) {
        let id = ql_token::Identity::generate().unwrap();
        let mut p = Profile::default();
        let bytes = p.signing_bytes().unwrap();
        p.signature = Some(ql_profile::ProfileSignature {
            algorithm: "ed25519".to_string(),
            public_key: id.public().to_hex(),
            value: id.sign(&bytes),
        });
        (p, id.public().to_hex())
    }

    #[test]
    fn gate_accepts_valid_trusted_signature() {
        let (p, signer) = signed_default();
        let got = check_signature(&p, true, std::slice::from_ref(&signer)).unwrap();
        assert_eq!(got, Some(signer));
    }

    #[test]
    fn gate_rejects_tampered_signature() {
        let (mut p, _) = signed_default();
        // Change the policy after signing — the signature must no longer verify.
        p.network.default_deny = !p.network.default_deny;
        assert!(check_signature(&p, false, &[]).is_err());
    }

    #[test]
    fn gate_requires_signature_only_when_asked() {
        let unsigned = Profile::default();
        assert!(check_signature(&unsigned, true, &[]).is_err());
        assert!(check_signature(&unsigned, false, &[]).unwrap().is_none());
    }

    #[test]
    fn gate_rejects_untrusted_signer() {
        let (p, _) = signed_default();
        let other = ql_token::Identity::generate().unwrap().public().to_hex();
        assert!(check_signature(&p, false, std::slice::from_ref(&other)).is_err());
    }

    fn approved(commit: Option<&str>, image: Option<&str>) -> Profile {
        Profile {
            approved_for: Some(ql_profile::ApprovedFor {
                commit: commit.map(str::to_string),
                image_digest: image.map(str::to_string),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn approved_for_commit_matches_and_mismatches() {
        let p = approved(Some("abc123"), None);
        assert!(check_approved_for(&p, Some("abc123"), None).is_ok());
        assert!(check_approved_for(&p, Some("def456"), None).is_err());
        // Operator asserts no context -> nothing to check.
        assert!(check_approved_for(&p, None, None).is_ok());
        // Unpinned profile -> ok regardless of context.
        let q = Profile::default();
        assert!(check_approved_for(&q, Some("anything"), None).is_ok());
    }

    #[test]
    fn approved_for_image_mismatch_refuses() {
        let p = approved(None, Some("sha256:aaaa"));
        assert!(check_approved_for(&p, None, Some("sha256:aaaa")).is_ok());
        assert!(check_approved_for(&p, None, Some("sha256:bbbb")).is_err());
    }
}

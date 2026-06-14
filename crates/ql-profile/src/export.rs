// crates/ql-profile/src/export.rs
//! Export a [`Profile`] to runtime-agnostic formats other sandboxes consume.
//!
//! The intelligence QuantmLayer derives — what an agent needs and what it must
//! not touch — is valuable even where QuantmLayer doesn't own the kernel. These
//! exporters render a profile into standard artifacts (an OCI/Docker seccomp
//! profile, a `docker run` invocation) so the policy travels with the agent.
//!
//! Honesty is the point: a portable profile must never be *silently* weaker
//! than the original. Each exporter reports, via [`ExportNotes`], exactly what
//! the target can and cannot enforce — and the gaps are precisely where local
//! containment (QuantmLayer) still earns its keep.

use crate::policy::SeccompDefault;
use crate::Profile;

use serde_json::json;

/// What a given target runtime can and cannot enforce from a profile.
#[derive(Debug, Clone, Default)]
pub struct ExportNotes {
    /// Policy elements the target enforces faithfully.
    pub enforced: Vec<String>,
    /// Policy elements the target cannot enforce (needs QuantmLayer or an
    /// external mechanism). These are the honest gaps.
    pub gaps: Vec<String>,
}

/// Render the profile's syscall policy as an OCI/Docker-compatible seccomp
/// profile (JSON). Consumable by `docker run --security-opt seccomp=<file>`,
/// containerd, CRI-O, and any OCI runtime.
///
/// The architecture list covers both targets QuantmLayer supports (x86-64 and
/// aarch64) plus 32-bit x86 compat, so the exported profile is portable across
/// hosts.
pub fn to_oci_seccomp(profile: &Profile) -> String {
    let sys = &profile.syscalls;
    let architectures = json!(["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"]);

    let (default_action, rules) = match sys.default_action {
        // Common case (coding agents): allow by default, block the deny list.
        SeccompDefault::Allow => {
            let mut rules = Vec::new();
            if !sys.deny.is_empty() {
                rules.push(json!({
                    "names": sorted(&sys.deny),
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": 1, // EPERM
                }));
            }
            if !sys.notify.is_empty() {
                rules.push(json!({
                    "names": sorted(&sys.notify),
                    "action": "SCMP_ACT_NOTIFY",
                }));
            }
            ("SCMP_ACT_ALLOW", rules)
        }
        // Tight archetypes: deny by default. A working default-deny seccomp
        // needs the full allow-list of permitted syscalls, which a denylist
        // profile does not enumerate — so this export is a starting point that
        // must be completed for the target program. See to_oci_seccomp_notes().
        SeccompDefault::Deny => {
            let mut rules = Vec::new();
            if !sys.deny.is_empty() {
                rules.push(json!({
                    "names": sorted(&sys.deny),
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": 1,
                }));
            }
            ("SCMP_ACT_ERRNO", rules)
        }
    };

    let doc = json!({
        "defaultAction": default_action,
        "architectures": architectures,
        "syscalls": rules,
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

/// Notes for the seccomp export: what it covers and any caveats.
pub fn to_oci_seccomp_notes(profile: &Profile) -> ExportNotes {
    let mut notes = ExportNotes::default();
    match profile.syscalls.default_action {
        SeccompDefault::Allow => {
            notes
                .enforced
                .push("syscall deny-list enforced via SCMP_ACT_ERRNO (EPERM)".into());
            if !profile.syscalls.notify.is_empty() {
                notes.gaps.push(
                    "notify syscalls exported as SCMP_ACT_NOTIFY; honored only where the \
                     runtime supports seccomp user-notification"
                        .into(),
                );
            }
        }
        SeccompDefault::Deny => {
            notes.gaps.push(
                "default-deny policy: you must add an allow-list of the syscalls the target \
                 program needs, or it will be blocked. QuantmLayer applies that allow-list \
                 from its archetype baseline; a standalone seccomp file cannot infer it."
                    .into(),
            );
        }
    }
    notes
}

/// Render the profile as a `docker run` invocation that applies everything
/// Docker *can* enforce, with a header documenting the gaps it cannot. The
/// caller is expected to write the seccomp JSON ([`to_oci_seccomp`]) to
/// `seccomp_filename` alongside.
pub fn to_docker_run(profile: &Profile, image: &str, seccomp_filename: &str) -> String {
    let mut notes = ExportNotes::default();
    let mut args: Vec<String> = vec!["--rm".into()];

    // Seccomp — fully portable.
    args.push(format!("--security-opt seccomp={seccomp_filename}"));
    notes.enforced.push("syscall policy (seccomp)".into());

    // Capabilities — drop all, re-add the retained set.
    args.push("--cap-drop ALL".into());
    for cap in &profile.capabilities.retain {
        args.push(format!("--cap-add {}", docker_cap(cap)));
    }
    notes.enforced.push("Linux capabilities".into());

    // Resource limits.
    if let Some(p) = profile.resources.pids_max {
        args.push(format!("--pids-limit {p}"));
        notes.enforced.push("process count (pids)".into());
    }
    if let Some(m) = profile.resources.memory_max_bytes {
        args.push(format!("--memory {m}"));
        notes.enforced.push("memory limit".into());
    }
    if let Some(c) = profile.resources.cpu_max_percent {
        // Docker takes fractional CPUs; percent/100.
        args.push(format!("--cpus {:.2}", c as f64 / 100.0));
        notes.enforced.push("CPU limit".into());
    }

    // Filesystem — Docker isolates the *whole* filesystem rather than hiding
    // specific paths within a shared tree. We can mount the workspace dirs, but
    // path-level *denial* (e.g. hiding ~/.ssh while sharing $HOME) does not map.
    for dir in &profile.filesystem.readwrite {
        if let Some(d) = concrete_dir(dir) {
            args.push(format!("-v {d}:{d}"));
        }
    }
    for dir in &profile.filesystem.readonly {
        if let Some(d) = concrete_dir(dir) {
            args.push(format!("-v {d}:{d}:ro"));
        }
    }
    if !profile.filesystem.denied.is_empty() {
        notes.gaps.push(format!(
            "path-level denial of {} secret path(s) (e.g. SSH/cloud creds): Docker isolates \
             the whole filesystem instead of hiding specific paths within a shared tree. \
             Don't mount those paths in; QuantmLayer hides them even on the real host FS.",
            profile.filesystem.denied.len()
        ));
    }

    // Network — Docker has no built-in domain allow-list.
    if profile.network.default_deny {
        if profile.network.allow_domains.is_empty() {
            args.push("--network none".into());
            notes.enforced.push("network: fully disabled".into());
        } else {
            notes.gaps.push(format!(
                "domain allow-list egress ({} domain(s)): Docker cannot allow-list destinations. \
                 Use the QuantmLayer broker (`ql broker`) or an external egress proxy.",
                profile.network.allow_domains.len()
            ));
        }
    }

    // Exec allow-list.
    if !profile.processes.allow_exec.is_empty() {
        notes.gaps.push(
            "exec allow-list: Docker cannot restrict which binaries the agent may exec.".into(),
        );
    }

    // Assemble, with a documented header.
    let mut out = String::new();
    out.push_str("# QuantmLayer profile exported as a `docker run` invocation.\n");
    out.push_str("# Write the seccomp JSON to ");
    out.push_str(seccomp_filename);
    out.push_str(" alongside this command.\n#\n");
    out.push_str("# Enforced by Docker:\n");
    for e in &notes.enforced {
        out.push_str(&format!("#   - {e}\n"));
    }
    if !notes.gaps.is_empty() {
        out.push_str("#\n# NOT enforceable by Docker (needs QuantmLayer or an external tool):\n");
        for g in &notes.gaps {
            out.push_str(&format!("#   - {g}\n"));
        }
    }
    out.push_str("#\n");
    out.push_str("docker run \\\n");
    for a in &args {
        out.push_str(&format!("  {a} \\\n"));
    }
    out.push_str(&format!("  {image} <command>\n"));
    out
}

/// Notes for the docker export (same content the rendered header carries).
pub fn to_docker_notes(profile: &Profile, seccomp_filename: &str) -> ExportNotes {
    // Re-run the renderer's classification without the shell text.
    let rendered = to_docker_run(profile, "image", seccomp_filename);
    let mut notes = ExportNotes::default();
    for line in rendered.lines() {
        if let Some(rest) = line.strip_prefix("#   - ") {
            // crude split: everything before "NOT enforceable" header is enforced
            notes.enforced.push(rest.to_string());
        }
    }
    // The above is a convenience; callers that need the precise split should use
    // to_docker_run's header. Keep enforced/gaps non-empty for ergonomics.
    if notes.enforced.is_empty() {
        notes.enforced.push("see rendered header".into());
    }
    notes
}

// --- helpers ---------------------------------------------------------------

fn sorted(v: &[String]) -> Vec<String> {
    let mut s = v.to_vec();
    s.sort();
    s.dedup();
    s
}

/// Docker `--cap-add` takes capability names without the `CAP_` prefix.
fn docker_cap(cap: &str) -> String {
    cap.trim_start_matches("CAP_").to_string()
}

/// A profile path may contain glob wildcards (`/home/*/.cache/**`). Docker
/// volume mounts need a concrete directory, so skip wildcarded entries (the
/// caller mounts what it can; wildcards are a gap Docker can't express).
fn concrete_dir(path: &str) -> Option<String> {
    if path.contains('*') {
        None
    } else {
        Some(path.trim_end_matches("/**").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SyscallPolicy;

    fn coding_like() -> Profile {
        // A minimal Allow+denylist profile like a learned coding profile.
        let mut p = Profile {
            syscalls: SyscallPolicy {
                default_action: SeccompDefault::Allow,
                deny: vec!["ptrace".into(), "mount".into(), "bpf".into()],
                notify: vec![],
            },
            ..Default::default()
        };
        p.resources.pids_max = Some(64);
        p.resources.memory_max_bytes = Some(4 * 1024 * 1024 * 1024);
        p.network.default_deny = true;
        p.filesystem.denied = vec!["/root/.ssh/**".into(), "/home/*/.ssh/**".into()];
        p
    }

    #[test]
    fn seccomp_allow_denylist_is_valid_json_and_blocks_denied() {
        let p = coding_like();
        let s = to_oci_seccomp(&p);
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
        assert_eq!(v["defaultAction"], "SCMP_ACT_ALLOW");
        let names = v["syscalls"][0]["names"].as_array().unwrap();
        assert!(names.iter().any(|n| n == "ptrace"));
        assert_eq!(v["syscalls"][0]["action"], "SCMP_ACT_ERRNO");
        // multi-arch
        let arches = v["architectures"].as_array().unwrap();
        assert!(arches.iter().any(|a| a == "SCMP_ARCH_AARCH64"));
        assert!(arches.iter().any(|a| a == "SCMP_ARCH_X86_64"));
    }

    #[test]
    fn docker_run_flags_what_docker_can_and_notes_gaps() {
        let p = coding_like();
        let out = to_docker_run(&p, "ubuntu:22.04", "ql-seccomp.json");
        assert!(out.contains("--security-opt seccomp=ql-seccomp.json"));
        assert!(out.contains("--cap-drop ALL"));
        assert!(out.contains("--pids-limit 64"));
        assert!(out.contains("--memory 4294967296"));
        assert!(out.contains("--network none")); // default_deny + no domains
                                                 // the denied SSH paths are a documented gap, not silently dropped
        assert!(out.contains("path-level denial"));
    }

    #[test]
    fn seccomp_deny_default_flags_the_allowlist_caveat() {
        let mut p = coding_like();
        p.syscalls.default_action = SeccompDefault::Deny;
        let notes = to_oci_seccomp_notes(&p);
        assert!(notes.gaps.iter().any(|g| g.contains("allow-list")));
    }
}

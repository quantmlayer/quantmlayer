// crates/ql-enforce/src/enforcers/seccomp.rs
//
//! [`SeccompEnforcer`]: blocks never-legitimate syscalls with seccomp-bpf.
//!
//! This is the wall that stops an agent from using the kernel's escape
//! hatches — `ptrace`/`process_vm_readv` (read another process's memory),
//! `mount`/`pivot_root`/`setns`/`unshare` (manipulate namespaces),
//! `bpf`/`kexec_load`/`init_module` (load code into the kernel), and similar.
//! Filesystem and namespace walls hide *resources*; seccomp removes *verbs*.
//!
//! ## Why classic seccomp-bpf (and not the user-notification API)
//!
//! We compile a classic seccomp-bpf filter whose denied syscalls return
//! `EPERM`. Classic seccomp-bpf is available on every enterprise kernel since
//! 3.5 (2012), so this wall works identically on RHEL 8/9, all current Ubuntu
//! LTS, Amazon Linux, etc. The newer user-notification API (`SECCOMP_RET_-
//! USER_NOTIF`, 5.0+) would let us *inspect* calls (the profile's `notify`
//! list); that is a deliberate future enhancement, gated behind a newer
//! kernel, and is intentionally not required here.
//!
//! ## Filter shape
//!
//! Default action **allow** (a compiler/toolchain makes thousands of distinct
//! syscalls — allow-listing them is brittle), with an explicit **deny list**
//! returning `EPERM`. This matches the profile's `default_action: allow` plus
//! `deny: [...]`. A profile that instead sets `default_action: deny` is also
//! supported: the lists swap roles.
//!
//! ## Ordering
//!
//! Installed in the in-namespace phase, **last**, immediately before `exec`.
//! Installing last ensures the cell's own setup syscalls (mounts, uid maps)
//! are not caught by the filter; only the agent runs under it. Once installed,
//! a seccomp filter cannot be removed or loosened by the filtered process, so
//! the agent inherits it across `exec` and into every child.

use crate::context::ChildContext;
use crate::enforcer::Enforcer;
use crate::error::{EnforceError, Result};
use ql_profile::{Profile, SeccompDefault};
use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter};
use std::collections::BTreeMap;

/// Installs a seccomp-bpf filter derived from the profile's syscall policy.
#[derive(Debug, Default)]
pub struct SeccompEnforcer;

impl SeccompEnforcer {
    /// Create a new seccomp enforcer.
    pub fn new() -> Self {
        SeccompEnforcer
    }

    /// Resolve a syscall name to its number on the build target architecture.
    ///
    /// We map the security-relevant syscalls explicitly rather than depend on
    /// a name table, so an unknown name in a profile is a hard error (we never
    /// silently fail to deny something the operator asked us to deny).
    fn syscall_number(name: &str) -> Result<libc::c_long> {
        let n = match name {
            "mount" => libc::SYS_mount,
            "umount2" => libc::SYS_umount2,
            "pivot_root" => libc::SYS_pivot_root,
            "chroot" => libc::SYS_chroot,
            "setns" => libc::SYS_setns,
            "unshare" => libc::SYS_unshare,
            "kexec_load" => libc::SYS_kexec_load,
            "init_module" => libc::SYS_init_module,
            "finit_module" => libc::SYS_finit_module,
            "delete_module" => libc::SYS_delete_module,
            "bpf" => libc::SYS_bpf,
            "ptrace" => libc::SYS_ptrace,
            "process_vm_readv" => libc::SYS_process_vm_readv,
            "process_vm_writev" => libc::SYS_process_vm_writev,
            "perf_event_open" => libc::SYS_perf_event_open,
            "keyctl" => libc::SYS_keyctl,
            "add_key" => libc::SYS_add_key,
            "reboot" => libc::SYS_reboot,
            "swapon" => libc::SYS_swapon,
            "swapoff" => libc::SYS_swapoff,
            other => {
                return Err(EnforceError::enforcer(
                    "seccomp",
                    format!("unknown syscall name in profile: `{other}`"),
                ))
            }
        };
        Ok(n)
    }

    /// Build the compiled BPF program for the profile's syscall policy.
    ///
    /// Separated from installation so it can be unit-tested without actually
    /// restricting the test process.
    pub(crate) fn build_program(profile: &Profile) -> Result<BpfProgram> {
        // The listed syscalls match unconditionally (empty rule vector). The
        // `match`/`mismatch` actions depend on whether the profile defaults to
        // allow (deny the list) or deny (allow the list).
        let mut rules: BTreeMap<libc::c_long, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
        for name in &profile.syscalls.deny {
            rules.insert(Self::syscall_number(name)?, vec![]);
        }

        let (match_action, mismatch_action) = match profile.syscalls.default_action {
            // default allow → the listed syscalls are the ones we deny.
            SeccompDefault::Allow => (
                SeccompAction::Errno(libc::EPERM as u32),
                SeccompAction::Allow,
            ),
            // default deny → the listed syscalls are the only ones allowed.
            SeccompDefault::Deny => (
                SeccompAction::Allow,
                SeccompAction::Errno(libc::EPERM as u32),
            ),
        };

        let arch = std::env::consts::ARCH
            .try_into()
            .map_err(|_| EnforceError::Unsupported {
                feature: "seccomp",
                reason: format!(
                    "unsupported architecture for seccomp: {}",
                    std::env::consts::ARCH
                ),
            })?;

        let filter = SeccompFilter::new(rules, mismatch_action, match_action, arch)
            .map_err(|e| EnforceError::enforcer("seccomp", format!("building filter: {e}")))?;

        let program: BpfProgram = filter
            .try_into()
            .map_err(|e| EnforceError::enforcer("seccomp", format!("compiling filter: {e}")))?;
        Ok(program)
    }
}

impl Enforcer for SeccompEnforcer {
    fn name(&self) -> &'static str {
        "seccomp"
    }

    /// Phase 2b (in-namespace), run LAST: compile and install the filter just
    /// before the cell execs the agent. After this point the process — and
    /// every child it forks or execs — runs under the filter and cannot
    /// remove it.
    fn apply_in_namespace(&self, profile: &Profile, _ctx: &ChildContext) -> Result<()> {
        // An empty deny list under default-allow would be a no-op filter; skip
        // to avoid the (small) overhead and keep the cell honest.
        if matches!(profile.syscalls.default_action, SeccompDefault::Allow)
            && profile.syscalls.deny.is_empty()
        {
            return Ok(());
        }

        let program = Self::build_program(profile)?;

        // `no_new_privs` is mandatory: without it an unprivileged process may
        // not install a filter. Setting it also prevents regaining privileges
        // via setuid binaries — defense in depth.
        // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is always safe to call.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(EnforceError::syscall(
                "prctl(PR_SET_NO_NEW_PRIVS)",
                nix::errno::Errno::last(),
            ));
        }

        apply_filter(&program).map_err(|e| {
            // If the host forbids installing filters, treat it as Unsupported
            // so the cell can continue (loudly) rather than refuse to run.
            EnforceError::Unsupported {
                feature: "seccomp",
                reason: format!("kernel refused the filter: {e}"),
            }
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_known_syscalls() {
        assert_eq!(
            SeccompEnforcer::syscall_number("ptrace").unwrap(),
            libc::SYS_ptrace
        );
        assert_eq!(
            SeccompEnforcer::syscall_number("mount").unwrap(),
            libc::SYS_mount
        );
    }

    #[test]
    fn unknown_syscall_is_an_error() {
        assert!(SeccompEnforcer::syscall_number("definitely_not_a_syscall").is_err());
    }

    #[test]
    fn builds_a_program_for_the_default_profile() {
        // The bundled coding profile must compile to a valid BPF program.
        let profile = Profile::from_yaml(include_str!("../../../../profiles/coding.yaml")).unwrap();
        let program = SeccompEnforcer::build_program(&profile).unwrap();
        // A compiled filter is a non-empty vector of BPF instructions.
        assert!(!program.is_empty());
    }
}

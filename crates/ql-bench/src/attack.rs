// crates/ql-bench/src/attack.rs
//
//! The attack catalog.
//!
//! Each [`Attack`] is one way a compromised or prompt-injected coding agent
//! could harm a host. For every attack we record *which containment wall*
//! addresses it and whether that wall is implemented yet. This makes the
//! benchmark a truthful roadmap: an attack whose wall is not built reports
//! [`Status::Pending`] rather than a fake green — and flips to a real,
//! measured result the moment its wall lands.
//!
//! ## Honesty principle
//!
//! We never mark an attack "blocked" without actually running it and
//! observing the block. Pending rows name the exact wall that will close
//! them. This is what lets a third party re-run the harness and trust it.

/// Whether an attack can be executed now, or is waiting on an unbuilt wall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The wall is implemented; the attack is executed and measured for real.
    Runnable,
    /// The wall is not implemented yet; the attack is listed but not run.
    Pending,
}

/// One attack scenario in the catalog.
#[derive(Debug, Clone)]
pub struct Attack {
    /// Stable identifier, matching its `benchmark/<id>/` directory.
    pub id: &'static str,
    /// Short human-readable title for the report.
    pub title: &'static str,
    /// The containment wall (enforcer) that addresses this attack.
    pub target_wall: &'static str,
    /// Whether the wall exists yet.
    pub status: Status,
}

/// The full catalog. Order here is the order rows appear in the report.
///
/// As walls are implemented, change a `Pending` attack to `Runnable` and add
/// its execution logic in `backends.rs`. Nothing else needs to change.
pub fn catalog() -> Vec<Attack> {
    vec![
        Attack {
            id: "ssh_theft",
            title: "SSH private-key theft",
            target_wall: "mount",
            status: Status::Runnable,
        },
        Attack {
            id: "workspace_escape",
            title: "Read secrets outside the workspace",
            target_wall: "mount",
            status: Status::Runnable,
        },
        Attack {
            id: "forkbomb",
            title: "Resource exhaustion (fork bomb)",
            target_wall: "cgroups",
            status: Status::Runnable,
        },
        Attack {
            id: "capability_escalation",
            title: "Cross-process memory read / ptrace",
            target_wall: "seccomp",
            status: Status::Runnable,
        },
        Attack {
            id: "ssrf_metadata",
            title: "Cloud-metadata SSRF (169.254.169.254)",
            target_wall: "network",
            status: Status::Runnable,
        },
        Attack {
            id: "unauthorized_exec",
            title: "Run an unauthorized tool (content-addressed exec)",
            target_wall: "exec",
            status: Status::Runnable,
        },
        Attack {
            id: "dns_rebinding",
            title: "DNS rebinding to a private address (allow-listed host)",
            target_wall: "broker",
            status: Status::Runnable,
        },
        Attack {
            id: "interpreter_mutable_code",
            title: "Interpreter loads mutable code (script read at open time)",
            target_wall: "exec (open-time measurement)",
            status: Status::Pending,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The interpreter-loads-mutable-code row is a documented gap: the exec
    /// wall hashes the executable image at execve, not scripts an interpreter
    /// reads at open time. It must stay `Pending` (reported as not-covered)
    /// until an open-time measurement wall is built — never a fake green. This
    /// test fails loudly if someone flips it to Runnable without adding the
    /// wall, protecting the harness's honesty guarantee.
    #[test]
    fn interpreter_mutable_code_stays_pending_until_a_wall_exists() {
        let atk = catalog()
            .into_iter()
            .find(|a| a.id == "interpreter_mutable_code")
            .expect("interpreter row present");
        assert_eq!(
            atk.status,
            Status::Pending,
            "the interpreter row must stay Pending until open-time measurement \
             exists; flipping it to Runnable without the wall would be a fake green"
        );
        assert!(
            atk.target_wall.contains("open-time"),
            "the pending row must name the unbuilt wall so the report explains itself"
        );
    }

    /// The DNS-rebinding row targets the broker's resolved-IP check — a
    /// different wall than the SSRF row (which tests the network namespace).
    /// Keeping them distinct is what lets the report show both defenses.
    #[test]
    fn rebinding_and_ssrf_target_distinct_walls() {
        let cat = catalog();
        let rebind = cat.iter().find(|a| a.id == "dns_rebinding").unwrap();
        let ssrf = cat.iter().find(|a| a.id == "ssrf_metadata").unwrap();
        assert_eq!(rebind.target_wall, "broker");
        assert_ne!(rebind.target_wall, ssrf.target_wall);
        assert_eq!(rebind.status, Status::Runnable);
    }
}

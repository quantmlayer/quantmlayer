//! Exec-enforcement tier selection.
//!
//! Picks the strongest *content-verified* exec wall the host and build can
//! provide for a run, or fails closed. The two content-verified tiers:
//!
//! * **Tier 1 — BPF-LSM** (in-kernel, strongest). Requires the `lsm` build
//!   feature *and* a BPF-LSM + BTF + IMA host.
//! * **Tier 2 — seccomp user-notification** (userspace). Requires only kernel
//!   seccomp user-notify support; works without the `lsm` build, which is the
//!   point — it is the degraded-substrate path (e.g. cloud hosts without IMA).
//!
//! Tier 3 (Landlock) is intentionally *not* selectable here: it is path-
//! restricted, not content-verified, so it cannot satisfy `exec.enforce`. When
//! a Landlock-exec enforcer exists, an operator may opt into path-only
//! degradation explicitly; the default for "enforce demanded, no content tier"
//! is to refuse, never to silently downgrade.

/// The exec-enforcement tier selected for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecTier {
    /// No exec wall — the profile did not request enforcement.
    None,
    /// Tier 1: in-kernel BPF-LSM, content-verified.
    BpfLsm,
    /// Tier 2: userspace seccomp user-notification, content-verified.
    SeccompNotify,
}

impl ExecTier {
    /// Stable label for audit records, matching `ql doctor`'s tier names.
    pub fn label(self) -> &'static str {
        match self {
            ExecTier::None => "none",
            ExecTier::BpfLsm => "tier1_bpf_lsm",
            ExecTier::SeccompNotify => "tier2_seccomp_notify",
        }
    }
}

/// The outcome of tier selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TierChoice {
    /// Run with this tier.
    Use(ExecTier),
    /// Refuse the run: enforcement was demanded but no content-verified tier is
    /// available here. Carries an operator-facing reason.
    Refuse(String),
}

/// Select the exec tier for a run.
///
/// * `enforce`   — the profile's `exec.enforce`.
/// * `t1_usable` — Tier 1 is usable: the `lsm` feature is built in *and* the
///   host substrate supports it (BPF-LSM + BTF + IMA).
/// * `t2_usable` — Tier 2 is usable: the host supports seccomp user-notify.
///
/// Fail-closed: when enforcement is demanded and neither content-verified tier
/// is available, [`TierChoice::Refuse`] rather than a silent downgrade.
pub fn select_exec_tier(enforce: bool, t1_usable: bool, t2_usable: bool) -> TierChoice {
    if !enforce {
        return TierChoice::Use(ExecTier::None);
    }
    if t1_usable {
        TierChoice::Use(ExecTier::BpfLsm)
    } else if t2_usable {
        TierChoice::Use(ExecTier::SeccompNotify)
    } else {
        TierChoice::Refuse(
            "profile sets exec.enforce but no content-verified exec tier is available here \
             (need BPF-LSM with the `lsm` build, or kernel seccomp user-notification); \
             refusing rather than running without content-verified exec control"
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_enforce_means_no_wall_regardless_of_substrate() {
        for t1 in [false, true] {
            for t2 in [false, true] {
                assert_eq!(
                    select_exec_tier(false, t1, t2),
                    TierChoice::Use(ExecTier::None)
                );
            }
        }
    }

    #[test]
    fn tier1_preferred_when_usable() {
        assert_eq!(
            select_exec_tier(true, true, true),
            TierChoice::Use(ExecTier::BpfLsm)
        );
        assert_eq!(
            select_exec_tier(true, true, false),
            TierChoice::Use(ExecTier::BpfLsm)
        );
    }

    #[test]
    fn tier2_when_tier1_unavailable() {
        assert_eq!(
            select_exec_tier(true, false, true),
            TierChoice::Use(ExecTier::SeccompNotify)
        );
    }

    #[test]
    fn refuse_when_enforce_and_no_content_tier() {
        match select_exec_tier(true, false, false) {
            TierChoice::Refuse(msg) => {
                assert!(msg.contains("exec.enforce"));
                assert!(msg.contains("refusing"));
            }
            other => panic!("expected Refuse, got {other:?}"),
        }
    }

    #[test]
    fn labels_match_doctor_names() {
        assert_eq!(ExecTier::None.label(), "none");
        assert_eq!(ExecTier::BpfLsm.label(), "tier1_bpf_lsm");
        assert_eq!(ExecTier::SeccompNotify.label(), "tier2_seccomp_notify");
    }
}

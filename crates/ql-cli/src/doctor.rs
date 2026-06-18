// crates/ql-cli/src/doctor.rs
//
//! `ql doctor` — read-only preflight. Reports which of the six containment walls
//! are available on this host, the best available *exec-enforcement tier*, and an
//! honest "N/6" summary, so an operator knows before arming what protection they
//! will actually get here.
//!
//! It reads `/proc` and `/sys`, and performs exactly one read-only capability
//! query — the Landlock ABI version — which creates no ruleset and changes no
//! kernel state. It never loads a BPF program or mutates anything. `--json` emits
//! a machine-readable capability object for the portability matrix.

use std::process::ExitCode;

/// Per-wall verdict.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    /// Present and usable.
    Ok,
    /// Present but with a runtime caveat or weaker guarantee.
    Degraded,
    /// Definitively absent on this host.
    Off,
    /// Could not be determined read-only (often: needs sudo).
    Unknown,
}

impl Status {
    fn code(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Degraded => "degraded",
            Status::Off => "off",
            Status::Unknown => "unknown",
        }
    }
    fn tag(self) -> &'static str {
        match self {
            Status::Ok => "[ OK ]",
            Status::Degraded => "[ ~~ ]",
            Status::Off => "[ NO ]",
            Status::Unknown => "[ ?? ]",
        }
    }
    /// A wall "contains" (counts toward N/6) when present, even if degraded.
    fn contains(self) -> bool {
        matches!(self, Status::Ok | Status::Degraded)
    }
}

struct Wall {
    name: &'static str,
    status: Status,
    detail: String,
}

/// One layer of the exec-wall degradation ladder (see MASTER_PLAN §5 P0).
struct ExecTier {
    name: &'static str,
    available: bool,
    detail: String,
}

/// The full exec-enforcement picture: which tiers exist + the strongest active.
struct ExecAssessment {
    tiers: Vec<ExecTier>,
    active: &'static str,
}

struct Report {
    kernel: String,
    arch: &'static str,
    distro: String,
    walls: Vec<Wall>,
    exec: ExecAssessment,
}

impl Report {
    fn active(&self) -> usize {
        self.walls.iter().filter(|w| w.status.contains()).count()
    }
}

pub fn cmd(args: &[String]) -> ExitCode {
    let json = matches!(args.first().map(String::as_str), Some("--json"));
    let report = probe();
    if json {
        print_json(&report);
    } else {
        print_human(&report);
    }
    ExitCode::SUCCESS
}

// ---- read-only helpers -----------------------------------------------------

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

/// Find an executable by name in the usual locations (no PATH spawning).
fn have_bin(name: &str) -> bool {
    ["/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/"]
        .iter()
        .any(|d| exists(&format!("{d}{name}")))
}

fn distro_pretty() -> String {
    let Some(text) = read("/etc/os-release") else {
        return "unknown".to_string();
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            return v.trim_matches('"').to_string();
        }
    }
    "unknown".to_string()
}

/// Is `bpf` one of the comma-separated active LSMs?
fn lsm_has_bpf(lsm: &str) -> bool {
    lsm.split(',').any(|x| x.trim() == "bpf")
}

/// Query the Landlock ABI version, unprivileged and read-only.
///
/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` returns
/// the supported ABI version without creating a ruleset or changing any state.
/// Returns `Some(version)` when Landlock is available, `None` otherwise. This
/// works even in unprivileged containers where `/sys/kernel/security/lsm` is not
/// readable, which is exactly the portability-matrix case.
fn landlock_abi() -> Option<libc::c_long> {
    // The VERSION flag, passed register-width: glibc `syscall()` reads each
    // variadic argument as a `long`, so a 32-bit value risks undefined upper bits.
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1;
    // SAFETY: a pure version query — null ruleset attr, zero size, the VERSION
    // flag. It allocates nothing and mutates no process or kernel state.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    (ret >= 1).then_some(ret)
}

// ---- the six walls ---------------------------------------------------------

fn wall_namespaces() -> Wall {
    let parsed =
        read("/proc/sys/user/max_user_namespaces").and_then(|s| s.trim().parse::<u64>().ok());
    let (status, detail) = match parsed {
        Some(0) => (Status::Off, "user namespaces disabled (max=0)".to_string()),
        Some(n) => (Status::Ok, format!("user namespaces available (max={n})")),
        None if exists("/proc/self/ns/user") => (
            Status::Degraded,
            "namespaces present; userns limit unknown".to_string(),
        ),
        None => (Status::Unknown, "cannot read namespace support".to_string()),
    };
    Wall {
        name: "namespaces",
        status,
        detail,
    }
}

fn wall_capabilities() -> Wall {
    let (status, detail) = match read("/proc/self/status") {
        Some(s) if s.lines().any(|l| l.starts_with("CapBnd:")) => {
            (Status::Ok, "capability bounding set present".to_string())
        }
        Some(_) => (Status::Unknown, "CapBnd not found in status".to_string()),
        None => (Status::Unknown, "cannot read /proc/self/status".to_string()),
    };
    Wall {
        name: "capabilities",
        status,
        detail,
    }
}

fn wall_seccomp() -> Wall {
    let (status, detail) = match read("/proc/sys/kernel/seccomp/actions_avail") {
        Some(s) if s.contains("user_notif") => {
            (Status::Ok, "seccomp + user-notify available".to_string())
        }
        Some(_) => (Status::Ok, "seccomp available (no user-notify)".to_string()),
        None => (Status::Off, "seccomp not available".to_string()),
    };
    Wall {
        name: "seccomp",
        status,
        detail,
    }
}

fn wall_cgroups_v2() -> Wall {
    let (status, detail) = match read("/sys/fs/cgroup/cgroup.controllers") {
        Some(c) if c.split_whitespace().any(|x| x == "pids") => {
            (Status::Ok, "cgroup v2; pids controller present".to_string())
        }
        Some(_) => (
            Status::Degraded,
            "cgroup v2; pids not delegated".to_string(),
        ),
        None => (Status::Off, "no cgroup v2 unified hierarchy".to_string()),
    };
    Wall {
        name: "cgroups_v2",
        status,
        detail,
    }
}

fn wall_network() -> Wall {
    let netns = exists("/proc/self/ns/net");
    let ip = have_bin("ip");
    let (status, detail) = match (netns, ip) {
        (true, true) => (
            Status::Ok,
            "netns + ip(8); veth needs NET_ADMIN at run".to_string(),
        ),
        (true, false) => (
            Status::Degraded,
            "netns present; ip(8) not found".to_string(),
        ),
        (false, _) => (Status::Off, "network namespaces unavailable".to_string()),
    };
    Wall {
        name: "network",
        status,
        detail,
    }
}

// ---- exec-wall tier assessment ---------------------------------------------

/// Pick the strongest active exec tier. Tier 1/2 are digest (content-verified);
/// Tier 3 (Landlock) is path-restricted only and never a digest substitute.
fn active_tier(t1: bool, t2: bool, t3: bool) -> &'static str {
    if t1 {
        "tier1_bpf_lsm"
    } else if t2 {
        "tier2_seccomp_notify"
    } else if t3 {
        "tier3_landlock_path"
    } else {
        "none"
    }
}

/// Probe which exec-enforcement substrates the host *kernel* supports, as three
/// booleans: (tier1 BPF-LSM+BTF+IMA, tier2 seccomp user-notify, tier3 Landlock).
/// Used by `ql run` to select a tier. Compile-time `lsm` gating is the caller's
/// concern; this reports only the kernel substrate.
pub(crate) fn exec_substrate() -> (bool, bool, bool) {
    let t1 = read("/sys/kernel/security/lsm")
        .as_deref()
        .is_some_and(lsm_has_bpf)
        && exists("/sys/kernel/btf/vmlinux")
        && (exists("/sys/kernel/security/ima") || exists("/sys/kernel/security/integrity/ima"));
    let t2 =
        read("/proc/sys/kernel/seccomp/actions_avail").is_some_and(|s| s.contains("user_notif"));
    let t3 = landlock_abi().is_some();
    (t1, t2, t3)
}

fn assess_exec() -> ExecAssessment {
    // Tier 1 — BPF-LSM + BTF + IMA (kernel, content-verified, best).
    let bpf = read("/sys/kernel/security/lsm").as_deref().map(lsm_has_bpf);
    let btf = exists("/sys/kernel/btf/vmlinux");
    let ima = exists("/sys/kernel/security/ima") || exists("/sys/kernel/security/integrity/ima");
    let (t1, t1d) = match bpf {
        Some(true) if btf && ima => (true, "BPF-LSM + BTF + IMA".to_string()),
        Some(true) => (false, "BPF-LSM active but missing BTF/IMA".to_string()),
        Some(false) => (false, "bpf not in active LSM stack".to_string()),
        None => (false, "LSM stack unreadable (try sudo)".to_string()),
    };

    // Tier 2 — seccomp user-notification (userspace, content-verified).
    // Kernel support is read from actions_avail; installing a listener may still
    // need CAP_SYS_ADMIN or no_new_privs at run — the matrix confirms that live.
    let seccomp = read("/proc/sys/kernel/seccomp/actions_avail");
    let t2 = seccomp.is_some_and(|s| s.contains("user_notif"));
    let t2d = if t2 {
        "seccomp user-notify supported".to_string()
    } else {
        "seccomp user-notify unavailable".to_string()
    };

    // Tier 3 — Landlock execute allowlist (unprivileged; PATH-based, NOT digest).
    let (t3, t3d) = match landlock_abi() {
        Some(v) => (true, format!("Landlock ABI v{v} (path-restricted)")),
        None => (false, "Landlock unavailable".to_string()),
    };

    ExecAssessment {
        active: active_tier(t1, t2, t3),
        tiers: vec![
            ExecTier {
                name: "tier1_bpf_lsm",
                available: t1,
                detail: t1d,
            },
            ExecTier {
                name: "tier2_seccomp_notify",
                available: t2,
                detail: t2d,
            },
            ExecTier {
                name: "tier3_landlock_path",
                available: t3,
                detail: t3d,
            },
        ],
    }
}

fn wall_exec_from(a: &ExecAssessment) -> Wall {
    let (status, detail) = match a.active {
        "tier1_bpf_lsm" => (Status::Ok, "content-verified (kernel BPF-LSM)".to_string()),
        "tier2_seccomp_notify" => (
            Status::Ok,
            "content-verified (userspace seccomp-notify)".to_string(),
        ),
        "tier3_landlock_path" => (
            Status::Degraded,
            "path-restricted only (Landlock, not digest)".to_string(),
        ),
        _ => {
            // Distinguish "definitely none" from "couldn't read the kernel tier".
            let unreadable = a.tiers.iter().any(|t| t.detail.contains("unreadable"));
            if unreadable {
                (
                    Status::Unknown,
                    "no userspace tier; kernel tier needs sudo".to_string(),
                )
            } else {
                (
                    Status::Off,
                    "no exec enforcement tier available".to_string(),
                )
            }
        }
    };
    Wall {
        name: "exec_wall",
        status,
        detail,
    }
}

fn probe() -> Report {
    let exec = assess_exec();
    let exec_wall = wall_exec_from(&exec);
    Report {
        kernel: read("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        arch: std::env::consts::ARCH,
        distro: distro_pretty(),
        walls: vec![
            wall_namespaces(),
            wall_capabilities(),
            wall_seccomp(),
            wall_cgroups_v2(),
            wall_network(),
            exec_wall,
        ],
        exec,
    }
}

// ---- output ----------------------------------------------------------------

fn print_human(r: &Report) {
    eprintln!(
        "QuantmLayer preflight — {} / kernel {} / {}",
        r.distro, r.kernel, r.arch
    );
    eprintln!();
    for w in &r.walls {
        eprintln!("  {}  {:<13} {}", w.status.tag(), w.name, w.detail);
    }
    eprintln!();
    let active = r.active();
    eprintln!("  {active} / {} walls available.", r.walls.len());
    eprintln!();
    eprintln!("  exec enforcement — best available tier:");
    for t in &r.exec.tiers {
        let mark = if t.available { "x" } else { " " };
        eprintln!("    [{mark}] {:<22} {}", t.name, t.detail);
    }
    eprintln!("    -> active: {}", r.exec.active);
    match r.exec.active {
        "tier3_landlock_path" => eprintln!(
            "  NOTE: only a path-restricted (Landlock) exec wall is available here;\n  \
             this does NOT defeat copy-rename and is not a content-verified guarantee."
        ),
        "none" => eprintln!(
            "  NOTE: no exec-enforcement tier here; the other walls still contain.\n  \
             Expected in managed Kubernetes / unprivileged nested Docker."
        ),
        _ => {}
    }
}

fn print_json(r: &Report) {
    let walls: serde_json::Map<String, serde_json::Value> = r
        .walls
        .iter()
        .map(|w| {
            (
                w.name.to_string(),
                serde_json::json!({ "status": w.status.code(), "detail": w.detail }),
            )
        })
        .collect();
    let tiers: serde_json::Map<String, serde_json::Value> = r
        .exec
        .tiers
        .iter()
        .map(|t| {
            (
                t.name.to_string(),
                serde_json::json!({ "available": t.available, "detail": t.detail }),
            )
        })
        .collect();
    let obj = serde_json::json!({
        "host": { "kernel": r.kernel, "arch": r.arch, "distro": r.distro },
        "walls": walls,
        "exec": { "active": r.exec.active, "tiers": tiers },
        "active": r.active(),
        "total": r.walls.len(),
    });
    match serde_json::to_string_pretty(&obj) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("ql doctor: cannot render json: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_reports_six_walls_without_panicking() {
        let r = probe();
        assert_eq!(r.walls.len(), 6);
        assert!(r.active() <= 6);
        assert!(r.walls.iter().all(|w| !w.detail.is_empty()));
        assert_eq!(r.exec.tiers.len(), 3);
    }

    #[test]
    fn contains_counts_present_walls_only() {
        assert!(Status::Ok.contains());
        assert!(Status::Degraded.contains());
        assert!(!Status::Off.contains());
        assert!(!Status::Unknown.contains());
    }

    #[test]
    fn lsm_has_bpf_parses_the_stack() {
        assert!(lsm_has_bpf("capability,landlock,yama,bpf"));
        assert!(lsm_has_bpf("bpf"));
        assert!(!lsm_has_bpf("capability,landlock,yama"));
        assert!(!lsm_has_bpf(""));
    }

    #[test]
    fn active_tier_prefers_strongest_then_path_then_none() {
        assert_eq!(active_tier(true, true, true), "tier1_bpf_lsm");
        assert_eq!(active_tier(false, true, true), "tier2_seccomp_notify");
        assert_eq!(active_tier(false, false, true), "tier3_landlock_path");
        assert_eq!(active_tier(false, false, false), "none");
    }

    #[test]
    fn landlock_abi_query_never_panics() {
        // Whatever the host, the query must return cleanly (Some(v) or None).
        let _ = landlock_abi();
    }
}

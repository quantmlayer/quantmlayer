// crates/ql-bench/src/backends.rs
//
//! Containment backends and the execution of runnable attacks.
//!
//! A [`Backend`] is a way to run a command under some containment regime. We
//! ship two:
//!
//! * [`Backend::None`] — no containment (the baseline; shows the attack works).
//! * [`Backend::QuantmLayer`] — our cell from `ql-enforce`.
//!
//! Additional backends (Docker, E2B, Daytona) are intentionally left as future
//! work: they implement the same idea (run argv under their sandbox) and slot
//! in as new variants without changing the catalog or the report.
//!
//! ## Observation channels
//!
//! Most attacks use the **filesystem** as the channel: the attack tries to
//! exfiltrate a secret into a loot file inside the workspace (a real host
//! directory the cell does not hide), and the harness inspects the loot after
//! the run. Loot present => VULNERABLE; absent => BLOCKED.
//!
//! The fork-bomb attack instead measures *how many processes it could spawn*
//! via the [`ql-forkprobe`](../bin/ql-forkprobe.rs) helper, comparing the
//! count against a threshold: a `pids.max` cap holds the count far below the
//! attempted target.

use crate::attack::Attack;
use ql_enforce::standard_coding_cell;
use ql_profile::Profile;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// The result of running one attack under one backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The attack failed to achieve its goal — containment held.
    Blocked,
    /// The attack achieved its goal — the host was exposed.
    Vulnerable,
    /// The attack was not executed (its wall is not implemented yet).
    Pending,
    /// The attack's wall exists, but this host cannot provide the kernel
    /// feature it needs (e.g. no pids controller). Honestly distinct from
    /// "blocked": we did not contain it, we just couldn't test it here.
    Unsupported,
}

impl Outcome {
    /// A compact glyph for the report table.
    pub fn glyph(self) -> &'static str {
        match self {
            Outcome::Blocked => "✅ blocked",
            Outcome::Vulnerable => "❌ vulnerable",
            Outcome::Pending => "— pending",
            Outcome::Unsupported => "— unsupported",
        }
    }

    /// A machine-friendly token for JSON/CSV output.
    pub fn token(self) -> &'static str {
        match self {
            Outcome::Blocked => "blocked",
            Outcome::Vulnerable => "vulnerable",
            Outcome::Pending => "pending",
            Outcome::Unsupported => "unsupported",
        }
    }
}

/// A containment regime under which we run attacks.
#[derive(Debug, Clone, Copy)]
pub enum Backend {
    /// No containment. Establishes that the attack genuinely works.
    None,
    /// A default `docker run` agent container (workspace bind-mounted, default
    /// network/seccomp/capabilities — i.e. no extra hardening flags). This is
    /// the common "just run the agent in a container" baseline.
    Docker,
    /// QuantmLayer's containment cell (`ql-enforce`).
    QuantmLayer,
}

impl Backend {
    /// Column header for the report.
    pub fn label(self) -> &'static str {
        match self {
            Backend::None => "No containment",
            Backend::Docker => "Docker",
            Backend::QuantmLayer => "QuantmLayer",
        }
    }

    /// Machine-friendly key for JSON/CSV.
    pub fn key(self) -> &'static str {
        match self {
            Backend::None => "none",
            Backend::Docker => "docker",
            Backend::QuantmLayer => "quantmlayer",
        }
    }
}

// ---------------------------------------------------------------------------
// Docker backend
// ---------------------------------------------------------------------------

/// The image used for the Docker backend. Pinned for reproducibility and
/// matched to a glibc that runs the harness's probe binaries (Ubuntu 22.04).
const DOCKER_IMAGE: &str = "ubuntu:22.04";

/// Did the Docker container actually execute our attack command?
enum DockerRun {
    /// It ran (so the loot/count judgement that follows is meaningful).
    Ran,
    /// Docker is unavailable or the container could not run — report honestly
    /// as Unsupported rather than mistaking a non-run for a "blocked" attack.
    Unavailable,
}

/// Whether the `docker` CLI is usable and can run our image. Cached: the first
/// call may pull the image (~tens of MB) once; subsequent calls are instant.
fn docker_ready() -> bool {
    static READY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *READY.get_or_init(|| {
        let daemon_ok = Command::new("docker")
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !daemon_ok {
            return false;
        }
        // Pull/verify the image once, with output visible so a first-run pull
        // isn't mistaken for a hang.
        eprintln!("ql-bench: preparing Docker backend (first run may pull {DOCKER_IMAGE})...");
        Command::new("docker")
            .args(["run", "--rm", DOCKER_IMAGE, "true"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

/// Run `script` via `/bin/sh -c` inside a default agent container: `workspace`
/// is bind-mounted read-write (so the harness can read loot afterward) and each
/// path in `ro_mounts` read-only (e.g. probe binaries). No hardening flags are
/// added — this models a plain `docker run` with the project mounted.
///
/// A sentinel file under `workspace` proves the command executed, so a
/// docker/image failure is reported as [`DockerRun::Unavailable`] instead of
/// silently looking like a blocked attack.
fn docker_run_script(workspace: &Path, ro_mounts: &[&Path], script: &str) -> DockerRun {
    if !docker_ready() {
        return DockerRun::Unavailable;
    }
    let sentinel = workspace.join(".ql_docker_ran");
    let _ = fs::remove_file(&sentinel);

    let full = format!(
        "{script}; echo ok > {sentinel} 2>/dev/null; true",
        sentinel = shell_quote(sentinel.to_str().unwrap()),
    );

    let ws = workspace.to_str().unwrap();
    let mut cmd = Command::new("docker");
    cmd.arg("run").arg("--rm");
    cmd.arg("-v").arg(format!("{ws}:{ws}"));
    for p in ro_mounts {
        let s = p.to_str().unwrap();
        cmd.arg("-v").arg(format!("{s}:{s}:ro"));
    }
    cmd.arg(DOCKER_IMAGE).arg("/bin/sh").arg("-c").arg(&full);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let _ = cmd.status();

    if sentinel.exists() {
        let _ = fs::remove_file(&sentinel);
        DockerRun::Ran
    } else {
        DockerRun::Unavailable
    }
}

/// A freshly-prepared, isolated sandbox for one attack run.
///
/// Holds the temp directory layout and is cleaned up on drop, so repeated
/// runs never leak state into each other or onto the host.
struct Sandbox {
    base: PathBuf,
    /// Where the agent is allowed to work (a real host dir, not hidden).
    workspace: PathBuf,
    /// The secret the attack tries to steal.
    secret_path: PathBuf,
    /// The directory containing the secret (what we deny/hide).
    secret_dir_root: PathBuf,
    /// The file the attack writes loot into, inside the workspace.
    loot_path: PathBuf,
}

impl Sandbox {
    /// Build a sandbox for the given attack id. The secret lives in a
    /// different place depending on the attack, but the mechanics are shared.
    fn prepare(attack_id: &str) -> std::io::Result<Self> {
        let base = std::env::temp_dir().join(format!(
            "ql-bench-{}-{}-{}",
            attack_id,
            std::process::id(),
            nanos()
        ));
        let workspace = base.join("workspace");
        fs::create_dir_all(&workspace)?;

        // Choose where the secret lives. Both cases are "outside the
        // workspace", which is exactly what the agent must not reach.
        let (secret_dir_root, secret_path) = match attack_id {
            "ssh_theft" => {
                let home = base.join("home/victim");
                let ssh = home.join(".ssh");
                fs::create_dir_all(&ssh)?;
                (base.join("home"), ssh.join("id_rsa"))
            }
            _ => {
                // workspace_escape and any other filesystem attack.
                let vault = base.join("vault");
                fs::create_dir_all(&vault)?;
                (vault.clone(), vault.join("passwords.txt"))
            }
        };
        fs::write(&secret_path, SECRET_MARKER)?;

        Ok(Sandbox {
            loot_path: workspace.join("loot.txt"),
            base,
            workspace,
            secret_path,
            secret_dir_root,
        })
    }

    /// The argv that attempts the theft: copy the secret into the loot file.
    /// `2>/dev/null; true` ensures the shell exits 0 regardless, so we judge
    /// success by the loot file alone, not by exit code.
    fn exfil_argv(&self) -> Vec<String> {
        let script = format!(
            "cat {secret} > {loot} 2>/dev/null; true",
            secret = shell_quote(self.secret_path.to_str().unwrap()),
            loot = shell_quote(self.loot_path.to_str().unwrap()),
        );
        vec!["/bin/sh".into(), "-c".into(), script]
    }

    /// A profile that hides the secret directory and permits the workspace.
    fn profile(&self) -> Profile {
        let mut p = Profile::from_yaml(include_str!("../../../profiles/coding.yaml"))
            .expect("bundled coding.yaml must parse");
        p.filesystem.denied = vec![format!("{}/**", self.secret_dir_root.to_str().unwrap())];
        p.filesystem.readwrite = vec![format!("{}/**", self.workspace.to_str().unwrap())];
        p
    }

    /// Did the attack succeed? True if the loot file holds the secret.
    fn was_exfiltrated(&self) -> bool {
        match fs::read_to_string(&self.loot_path) {
            Ok(contents) => contents.contains(SECRET_MARKER),
            Err(_) => false,
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// Run one attack under one backend and judge the outcome.
///
/// Pending attacks (wall not implemented) are never executed; they return
/// [`Outcome::Pending`] for every backend.
pub fn run(backend: Backend, attack: &Attack) -> std::io::Result<Outcome> {
    use crate::attack::Status;
    if attack.status == Status::Pending {
        return Ok(Outcome::Pending);
    }

    // The fork-bomb attack uses a different observation channel (process
    // count) and is dispatched to its own runner.
    if attack.id == "forkbomb" {
        return run_forkbomb(backend);
    }
    // The capability-escalation attack runs a syscall probe.
    if attack.id == "capability_escalation" {
        return run_syscall_escalation(backend);
    }
    // The SSRF attack tries to reach an internal/metadata service.
    if attack.id == "ssrf_metadata" {
        return run_ssrf(backend);
    }

    let sandbox = Sandbox::prepare(attack.id)?;
    let argv = sandbox.exfil_argv();

    match backend {
        Backend::None => {
            // Baseline: run the shell directly, no containment at all.
            let status = Command::new(&argv[0]).args(&argv[1..]).status()?;
            let _ = status; // exit code is irrelevant; we judge by loot.
        }
        Backend::Docker => {
            // Same exfiltration attempt inside a default agent container, with
            // only the workspace bind-mounted. The secret lives OUTSIDE the
            // workspace, so Docker's filesystem isolation alone decides this.
            match docker_run_script(&sandbox.workspace, &[], &argv[2]) {
                DockerRun::Ran => {}
                DockerRun::Unavailable => return Ok(Outcome::Unsupported),
            }
        }
        Backend::QuantmLayer => {
            // Run inside a cell built from the attack's profile.
            let cell =
                standard_coding_cell(sandbox.profile()).expect("cell builds for a valid profile");
            // The cell's run() may return an error only on infrastructural
            // failure; a blocked attack is a normal (non-zero) exit, not an Err.
            let _ = cell.run(&argv).expect("cell runs the attack command");
        }
    }

    Ok(if sandbox.was_exfiltrated() {
        Outcome::Vulnerable
    } else {
        Outcome::Blocked
    })
}

/// Marker string used as the "secret". Distinctive so loot matching is exact.
const SECRET_MARKER: &str = "QL_TOP_SECRET_a7f3e9c1";

/// Verify a path/string has no shell metacharacters, then wrap in single
/// quotes. Our paths are harness-generated temp paths, so this is belt-and-
/// suspenders, but we never want the harness itself to be injectable.
fn shell_quote(s: &str) -> String {
    debug_assert!(
        !s.contains('\'') && !s.contains('\n'),
        "harness paths must not contain quotes or newlines"
    );
    format!("'{s}'")
}

/// Monotonic-ish nanosecond suffix to keep sandbox dirs unique within a run.
fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Convenience: does a path exist? (Used by tests/diagnostics.)
#[allow(dead_code)]
pub(crate) fn exists(p: &Path) -> bool {
    p.exists()
}

// ---------------------------------------------------------------------------
// Fork-bomb attack
// ---------------------------------------------------------------------------

/// How many processes the probe attempts to spawn.
const FORKBOMB_TARGET: i32 = 200;
/// pids.max applied to the cell for this attack (well below the target).
const FORKBOMB_PIDS_MAX: u32 = 64;
/// If the probe started at least this many children, no cap stopped it.
const FORKBOMB_VULNERABLE_THRESHOLD: i32 = 150;

/// Run the fork-bomb attack: spawn many processes and see whether a `pids.max`
/// cap holds the count down.
///
/// * Baseline (`None`): the probe reaches the target → VULNERABLE.
/// * QuantmLayer: `pids.max` caps the count far below the target → BLOCKED,
///   *provided* the host has a pids controller. If it does not (and we cannot
///   provide one), the honest result is `Unsupported`.
fn run_forkbomb(backend: Backend) -> std::io::Result<Outcome> {
    // QuantmLayer can only block this if a pids controller exists. On modern
    // cgroup-v2 hosts it always does; in constrained sandboxes we best-effort
    // provide one (see ensure_pids_controller). If still absent, report
    // honestly rather than claim a block we didn't perform.
    if matches!(backend, Backend::QuantmLayer) && !ensure_pids_controller() {
        return Ok(Outcome::Unsupported);
    }

    let probe = match forkprobe_path() {
        Some(p) => p,
        None => return Ok(Outcome::Unsupported), // can't locate the probe binary
    };

    // Sandbox with a real workspace for the loot (count) file.
    let base = std::env::temp_dir().join(format!(
        "ql-bench-forkbomb-{}-{}",
        std::process::id(),
        nanos()
    ));
    let workspace = base.join("workspace");
    fs::create_dir_all(&workspace)?;
    let loot = workspace.join("count.txt");

    // argv: run the probe, redirecting its printed count into the loot file.
    let script = format!(
        "{probe} {target} > {loot} 2>/dev/null; true",
        probe = shell_quote(probe.to_str().unwrap()),
        target = FORKBOMB_TARGET,
        loot = shell_quote(loot.to_str().unwrap()),
    );
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script];

    match backend {
        Backend::None => {
            let _ = Command::new(&argv[0]).args(&argv[1..]).status()?;
        }
        Backend::Docker => {
            // Default `docker run` sets no pids limit, so the fork bomb is
            // expected to reach its target unless the operator added
            // `--pids-limit` by hand. We measure rather than assume.
            match docker_run_script(&workspace, &[&probe], &argv[2]) {
                DockerRun::Ran => {}
                DockerRun::Unavailable => return Ok(Outcome::Unsupported),
            }
        }
        Backend::QuantmLayer => {
            let cell = standard_coding_cell(forkbomb_profile(&workspace))
                .expect("cell builds for a valid profile");
            let _ = cell.run(&argv).expect("cell runs the probe");
        }
    }

    // Read the count the probe reported.
    let started: i32 = fs::read_to_string(&loot)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let _ = fs::remove_dir_all(&base);

    Ok(if started >= FORKBOMB_VULNERABLE_THRESHOLD {
        Outcome::Vulnerable
    } else {
        Outcome::Blocked
    })
}

/// Build the profile for the fork-bomb attack: a tight `pids.max`, and crucially
/// NO denied paths, so the probe binary (which lives outside the workspace)
/// stays reachable. We are testing the cgroup wall here, not filesystem hiding.
fn forkbomb_profile(workspace: &Path) -> Profile {
    let mut p = Profile::from_yaml(include_str!("../../../profiles/coding.yaml"))
        .expect("bundled coding.yaml must parse");
    p.resources.pids_max = Some(FORKBOMB_PIDS_MAX);
    p.filesystem.denied = vec![];
    p.filesystem.readwrite = vec![
        format!("{}/**", workspace.to_str().unwrap()),
        "/tmp/**".to_string(),
    ];
    p
}

/// Locate the `ql-forkprobe` helper binary.
fn forkprobe_path() -> Option<PathBuf> {
    probe_path("ql-forkprobe")
}

/// Locate a helper probe binary, which Cargo builds alongside the `ql-bench`
/// binary (same directory).
fn probe_path(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join(name);
    candidate.exists().then_some(candidate)
}

// ---------------------------------------------------------------------------
// Capability-escalation attack (ptrace / cross-process memory)
// ---------------------------------------------------------------------------

/// Run the capability-escalation attack: attempt a `ptrace` call, which is the
/// gateway to reading or hijacking other processes' memory.
///
/// * Baseline (`None`): `ptrace` succeeds → the probe prints the marker →
///   VULNERABLE.
/// * QuantmLayer: the seccomp wall denies `ptrace` (EPERM) → no marker →
///   BLOCKED. If the host cannot install a seccomp filter at all, the cell
///   continues without it and the attack honestly reports VULNERABLE.
fn run_syscall_escalation(backend: Backend) -> std::io::Result<Outcome> {
    let probe = match probe_path("ql-syscallprobe") {
        Some(p) => p,
        None => return Ok(Outcome::Unsupported), // can't locate the probe binary
    };

    let base = std::env::temp_dir().join(format!(
        "ql-bench-capesc-{}-{}",
        std::process::id(),
        nanos()
    ));
    let workspace = base.join("workspace");
    fs::create_dir_all(&workspace)?;
    let loot = workspace.join("loot.txt");

    let script = format!(
        "{probe} > {loot} 2>/dev/null; true",
        probe = shell_quote(probe.to_str().unwrap()),
        loot = shell_quote(loot.to_str().unwrap()),
    );
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script];

    match backend {
        Backend::None => {
            let _ = Command::new(&argv[0]).args(&argv[1..]).status()?;
        }
        Backend::Docker => {
            // Whether ptrace is blocked depends on Docker's default seccomp
            // profile and capabilities — we measure it rather than assume.
            match docker_run_script(&workspace, &[&probe], &argv[2]) {
                DockerRun::Ran => {}
                DockerRun::Unavailable => return Ok(Outcome::Unsupported),
            }
        }
        Backend::QuantmLayer => {
            // The profile keeps coding.yaml's syscall deny list (which includes
            // ptrace) but hides nothing on the filesystem, so the probe binary
            // stays reachable — we are testing the seccomp wall, not mount.
            let cell = standard_coding_cell(syscall_attack_profile(&workspace))
                .expect("cell builds for a valid profile");
            let _ = cell.run(&argv).expect("cell runs the probe");
        }
    }

    let exfiltrated = fs::read_to_string(&loot)
        .map(|s| s.contains(SECRET_MARKER))
        .unwrap_or(false);
    let _ = fs::remove_dir_all(&base);

    Ok(if exfiltrated {
        Outcome::Vulnerable
    } else {
        Outcome::Blocked
    })
}

/// Profile for the syscall-escalation attack: coding.yaml's syscall deny list
/// intact (it denies ptrace), no filesystem hiding so the probe is reachable.
fn syscall_attack_profile(workspace: &Path) -> Profile {
    let mut p = Profile::from_yaml(include_str!("../../../profiles/coding.yaml"))
        .expect("bundled coding.yaml must parse");
    p.filesystem.denied = vec![];
    p.filesystem.readwrite = vec![
        format!("{}/**", workspace.to_str().unwrap()),
        "/tmp/**".to_string(),
    ];
    p
}

// ---------------------------------------------------------------------------
// SSRF / cloud-metadata attack
// ---------------------------------------------------------------------------

/// Run the SSRF attack: try to reach an internal network service standing in
/// for the cloud-metadata endpoint.
///
/// The harness hosts a fake "metadata" service on the host's primary
/// (non-loopback, private) IP. The probe tries to read it.
///
/// * Baseline (`None`): the host route exists → the probe reads the marker →
///   VULNERABLE.
/// * QuantmLayer: the network namespace has no route off-host → the connection
///   fails → BLOCKED.
fn run_ssrf(backend: Backend) -> std::io::Result<Outcome> {
    let probe = match probe_path("ql-netprobe") {
        Some(p) => p,
        None => return Ok(Outcome::Unsupported),
    };

    // Determine the host's primary IP (the address an SSRF would pivot to).
    let host_ip = match primary_ipv4() {
        Some(ip) => ip,
        None => return Ok(Outcome::Unsupported), // no non-loopback route to test
    };

    // Stand up the fake metadata service bound to that IP. It answers exactly
    // one connection with the secret marker, then the listener is dropped.
    let listener = match std::net::TcpListener::bind((host_ip.as_str(), 0)) {
        Ok(l) => l,
        Err(_) => return Ok(Outcome::Unsupported),
    };
    let port = listener.local_addr()?.port();
    let server = std::thread::spawn(move || {
        // Serve exactly one connection with the secret marker, then exit. The
        // runner guarantees a connection arrives (the probe, or an unblock
        // connect below), so this never hangs.
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::Write;
            let _ = stream.write_all(SECRET_MARKER.as_bytes());
        }
    });

    let base =
        std::env::temp_dir().join(format!("ql-bench-ssrf-{}-{}", std::process::id(), nanos()));
    let workspace = base.join("workspace");
    fs::create_dir_all(&workspace)?;
    let loot = workspace.join("loot.txt");

    let script = format!(
        "{probe} {ip} {port} > {loot} 2>/dev/null; true",
        probe = shell_quote(probe.to_str().unwrap()),
        ip = shell_quote(&host_ip),
        port = port,
        loot = shell_quote(loot.to_str().unwrap()),
    );
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script];

    match backend {
        Backend::None => {
            let _ = Command::new(&argv[0]).args(&argv[1..]).status()?;
        }
        Backend::Docker => {
            // A default-bridge container can still reach the host's primary IP
            // (and thus a cloud-metadata endpoint) unless the operator added
            // `--network none` or an egress policy. We measure it.
            match docker_run_script(&workspace, &[&probe], &argv[2]) {
                DockerRun::Ran => {}
                DockerRun::Unavailable => return Ok(Outcome::Unsupported),
            }
        }
        Backend::QuantmLayer => {
            let cell = standard_coding_cell(ssrf_attack_profile(&workspace))
                .expect("cell builds for a valid profile");
            let _ = cell.run(&argv).expect("cell runs the probe");
        }
    }

    let exfiltrated = fs::read_to_string(&loot)
        .map(|s| s.contains(SECRET_MARKER))
        .unwrap_or(false);

    // Guarantee the server thread makes progress: if the probe never connected
    // (blocked case), this connect is the one the server accepts; if the probe
    // already connected (baseline), the server has exited and this is a
    // harmless refused connect. Either way, join() then returns promptly.
    let _ = std::net::TcpStream::connect_timeout(
        &format!("{host_ip}:{port}").parse().unwrap(),
        Duration::from_millis(500),
    );
    let _ = server.join();
    let _ = fs::remove_dir_all(&base);

    Ok(if exfiltrated {
        Outcome::Vulnerable
    } else {
        Outcome::Blocked
    })
}

/// Profile for the SSRF attack: default-deny network (coding.yaml already sets
/// this), nothing hidden so the probe binary is reachable.
fn ssrf_attack_profile(workspace: &Path) -> Profile {
    let mut p = Profile::from_yaml(include_str!("../../../profiles/coding.yaml"))
        .expect("bundled coding.yaml must parse");
    p.filesystem.denied = vec![];
    p.filesystem.readwrite = vec![
        format!("{}/**", workspace.to_str().unwrap()),
        "/tmp/**".to_string(),
    ];
    p
}

/// Discover the host's primary non-loopback IPv4 address using the standard
/// "connect a UDP socket and read the local address" trick (no packets sent).
fn primary_ipv4() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    match ip {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() => Some(v4.to_string()),
        _ => None,
    }
}

/// Ensure a `pids` controller is available so the fork-bomb limit can be
/// exercised. Returns true if one is (now) usable.
///
/// On modern cgroup-v2 hosts the pids controller is already present and this
/// does nothing. In constrained sandboxes (hybrid/v1 layouts where pids is
/// not mounted) we best-effort mount the legacy v1 pids controller at a temp
/// path.
///
/// IMPORTANT: this mounting is a **benchmark/sandbox convenience only**. The
/// product enforcer (`ql-enforce`) never mounts cgroup hierarchies; it only
/// uses what the host already provides.
fn ensure_pids_controller() -> bool {
    use ql_enforce::cgroups::CgroupBackend;

    if CgroupBackend::detect()
        .map(|b| b.supports_pids())
        .unwrap_or(false)
    {
        return true;
    }

    // Best-effort mount of the v1 pids controller (requires CAP_SYS_ADMIN).
    let mp = Path::new("/tmp/ql-bench-pids");
    if fs::create_dir_all(mp).is_err() {
        return false;
    }
    let mounted = nix::mount::mount(
        Some("none"),
        mp,
        Some("cgroup"),
        nix::mount::MsFlags::empty(),
        Some("pids"),
    )
    .is_ok();

    mounted
        && CgroupBackend::detect()
            .map(|b| b.supports_pids())
            .unwrap_or(false)
}

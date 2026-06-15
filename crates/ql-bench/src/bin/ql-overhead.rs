// crates/ql-bench/src/bin/ql-overhead.rs
//! Measures the per-invocation overhead of full containment (cold start, no
//! pooling), next to a default `docker run`.
//!
//! It times a trivial command (`/bin/true`) run directly, inside a freshly
//! built cell, and — when the docker CLI is available — inside a default
//! `docker run` container, then reports the differences. The point is an
//! *honest* per-invocation number for the performance story: this is what one
//! agent invocation pays for all the walls today (before any cell pooling),
//! sitting beside the cost of the common "just containerize it" baseline.
//!
//! Numbers are host- and posture-specific. Under root every wall (including
//! cgroups) is applied; rootless without cgroup delegation skips the cgroup
//! wall, so its overhead is correspondingly lower. The output states which.
//!
//! Usage:
//!     ql-overhead [--iters N] [path/to/profile.yaml]
//! Defaults: 50 iterations, profiles/coding.yaml.

use std::process::{Command, Stdio};
use std::time::Instant;

use ql_enforce::standard_coding_cell;
use ql_profile::Profile;

/// p-th percentile (0..=100) of an already-sorted slice of nanosecond samples.
fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p / 100.0) * (sorted.len() as f64 - 1.0);
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        // linear interpolation between the two nearest ranks
        let frac = rank - lo as f64;
        let a = sorted[lo] as f64;
        let b = sorted[hi] as f64;
        (a + (b - a) * frac) as u128
    }
}

fn ms(nanos: u128) -> f64 {
    nanos as f64 / 1_000_000.0
}

/// The image used to time a default `docker run`. Matches the benchmark
/// harness so the security and cost stories use the same container baseline.
const DOCKER_IMAGE: &str = "ubuntu:22.04";

/// Is the docker CLI usable, and is the image pulled and warm? Returns true
/// only after a `docker run` of the image succeeds, so the timed loop measures
/// warm per-invocation cold start rather than a one-time image pull.
fn docker_warm() -> bool {
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
    eprintln!("ql-overhead: warming Docker image {DOCKER_IMAGE} (one-time pull excluded)...");
    Command::new("docker")
        .args(["run", "--rm", DOCKER_IMAGE, "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Time `f` `iters` times, returning per-iteration nanosecond samples.
fn time_loop(iters: usize, mut f: impl FnMut()) -> Vec<u128> {
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_nanos());
    }
    samples.sort_unstable();
    samples
}

/// Result of timing the +exec-wall cell variant. In a non-`lsm` build the
/// `Measured` variant is never constructed, which is expected, not dead code.
#[cfg_attr(not(feature = "lsm"), allow(dead_code))]
enum ExecMeasure {
    /// Per-iteration nanosecond samples for the +exec cell.
    Measured(Vec<u128>),
    /// The exec wall could not be exercised here (non-`lsm` build, or a kernel
    /// without BPF-LSM); carries a reason printed verbatim in the report.
    Unsupported(String),
}

/// Time the +exec-wall cell: the base profile with content-addressed exec
/// forced on, approving only the workload binary by digest.
#[cfg(feature = "lsm")]
fn measure_exec_variant(base: &Profile, trivial: &[String], iters: usize) -> ExecMeasure {
    let exec_profile = match exec_variant_profile(base) {
        Ok(p) => p,
        Err(e) => return ExecMeasure::Unsupported(e),
    };
    // Probe once: if the exec cell can't run here, report why instead of timing.
    if let Err(e) = standard_coding_cell(exec_profile.clone()).and_then(|c| c.run(trivial)) {
        return ExecMeasure::Unsupported(format!("exec cell could not run: {e}"));
    }
    for _ in 0..5usize.min(iters) {
        let _ = standard_coding_cell(exec_profile.clone()).and_then(|c| c.run(trivial));
    }
    let samples = time_loop(iters, || {
        let _ = standard_coding_cell(exec_profile.clone()).and_then(|c| c.run(trivial));
    });
    ExecMeasure::Measured(samples)
}

#[cfg(not(feature = "lsm"))]
fn measure_exec_variant(_base: &Profile, _trivial: &[String], _iters: usize) -> ExecMeasure {
    ExecMeasure::Unsupported("not an `lsm` build — rebuild with `--features lsm`".to_string())
}

/// The base profile with content-addressed exec forced on, approving only the
/// workload binary by digest — so the cell attaches the BPF-LSM exec wall.
#[cfg(feature = "lsm")]
fn exec_variant_profile(base: &Profile) -> Result<Profile, String> {
    use ql_profile::ExecPolicy;

    let digest = sha256_exec_digest("/bin/true").map_err(|e| format!("hashing /bin/true: {e}"))?;
    let mut p = base.clone();
    p.exec = ExecPolicy {
        enforce: true,
        allow_digests: vec![digest],
    };
    Ok(p)
}

/// SHA-256 a binary's contents into an `ExecDigest`, streaming in chunks.
#[cfg(feature = "lsm")]
fn sha256_exec_digest(path: &str) -> std::io::Result<ql_profile::ExecDigest> {
    use ql_profile::{ExecDigest, HashAlgo};
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let mut hex = String::with_capacity(64);
    for b in hasher.finalize().iter() {
        hex.push_str(&format!("{b:02x}"));
    }
    ExecDigest::new(HashAlgo::Sha256, hex)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad exec digest"))
}

fn main() {
    // --- args ---------------------------------------------------------------
    let mut iters = 50usize;
    let mut no_docker = false;
    let mut md_path: Option<String> = None;
    let mut profile_path = String::from("profiles/coding.yaml");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--iters" => {
                iters = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| fail("--iters needs a positive integer"));
            }
            "--no-docker" => no_docker = true,
            "--md" => md_path = args.next(),
            "-h" | "--help" => {
                println!(
                    "usage: ql-overhead [--iters N] [--no-docker] [--md FILE] [path/to/profile.yaml]"
                );
                return;
            }
            other => profile_path = other.to_string(),
        }
    }
    if iters == 0 {
        fail("--iters must be > 0");
    }

    // --- load profile -------------------------------------------------------
    let yaml = std::fs::read_to_string(&profile_path).unwrap_or_else(|e| {
        fail(&format!("could not read profile {profile_path}: {e}"));
    });
    let profile = Profile::from_yaml(&yaml)
        .unwrap_or_else(|e| fail(&format!("could not parse {profile_path}: {e:?}")));

    // Two cell configurations that isolate the content-addressed exec wall:
    // `standard_profile` is the base with exec enforcement forced OFF (the five
    // always-on walls), and the +exec variant below is the SAME base with exec
    // forced ON — so the delta between them is purely the exec wall.
    let mut standard_profile = profile.clone();
    standard_profile.exec.enforce = false;

    let trivial: Vec<String> = vec!["/bin/true".to_string()];

    // --- probe: make sure the cell can actually run here --------------------
    // If containment can't be established on this host/posture, bail with
    // guidance rather than printing meaningless numbers.
    match standard_coding_cell(standard_profile.clone()).and_then(|c| c.run(&trivial)) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("ql-overhead: the cell could not run on this host: {e}");
            eprintln!("Run as root (sudo) or install the AppArmor profile");
            eprintln!("(sudo make install-apparmor) so the cell can use a user namespace.");
            std::process::exit(1);
        }
    }

    // --- warmup (discarded) -------------------------------------------------
    for _ in 0..5usize.min(iters) {
        let _ = Command::new("/bin/true").status();
        let _ = standard_coding_cell(standard_profile.clone()).and_then(|c| c.run(&trivial));
    }

    // --- baseline: /bin/true with no containment ----------------------------
    let base = time_loop(iters, || {
        let _ = Command::new("/bin/true").status();
    });

    // --- cell, standard walls: exec OFF, full cold start --------------------
    let cell = time_loop(iters, || {
        let _ = standard_coding_cell(standard_profile.clone()).and_then(|c| c.run(&trivial));
    });

    // --- cell, + exec wall: the SAME base with content-addressed exec ON -----
    // Built only in an `lsm` feature build on a BPF-LSM/IMA kernel; otherwise
    // reported as unsupported, never faked.
    let exec = measure_exec_variant(&profile, &trivial, iters);

    // --- docker: a default `docker run` per invocation (warm image) ---------
    // The common "just containerize the agent" model spins up a fresh
    // container per run. Timed warm (image pre-pulled, daemon already up), so
    // this is cold-start vs cold-start. Skipped, with a printed note, if
    // docker is unavailable — never silently dropped.
    let docker: Option<Vec<u128>> = if no_docker {
        None
    } else if docker_warm() {
        Some(time_loop(iters, || {
            let _ = Command::new("docker")
                .args(["run", "--rm", DOCKER_IMAGE, "true"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }))
    } else {
        eprintln!("ql-overhead: docker unavailable — skipping the container row.");
        None
    };

    // --- report -------------------------------------------------------------
    let posture = if nix::unistd::geteuid().is_root() {
        "root (all walls incl. cgroups applied)"
    } else {
        "rootless (cgroup wall may be skipped without delegation)"
    };

    let base_p50 = percentile(&base, 50.0);
    let base_p95 = percentile(&base, 95.0);
    let cell_p50 = percentile(&cell, 50.0);
    let cell_p95 = percentile(&cell, 95.0);
    let overhead_p50 = cell_p50.saturating_sub(base_p50);

    println!("Containment overhead — per-invocation cold start, no pooling");
    println!("host posture : {posture}");
    println!("profile      : {profile_path}");
    println!("iterations   : {iters}");
    println!();
    println!("                          median       p95");
    println!(
        "baseline /bin/true       {:>7.2} ms  {:>7.2} ms",
        ms(base_p50),
        ms(base_p95)
    );
    if let Some(d) = &docker {
        println!(
            "docker run /bin/true     {:>7.2} ms  {:>7.2} ms  (warm image)",
            ms(percentile(d, 50.0)),
            ms(percentile(d, 95.0))
        );
    }
    println!(
        "cell, standard walls     {:>7.2} ms  {:>7.2} ms",
        ms(cell_p50),
        ms(cell_p95)
    );
    match &exec {
        ExecMeasure::Measured(e) => println!(
            "cell, + exec wall        {:>7.2} ms  {:>7.2} ms",
            ms(percentile(e, 50.0)),
            ms(percentile(e, 95.0))
        ),
        ExecMeasure::Unsupported(reason) => {
            println!("cell, + exec wall            —  unsupported  ({reason})");
        }
    }
    println!("--------------------------------------------------");
    println!(
        "standard walls overhead  {:>7.2} ms  (median, vs baseline)",
        ms(overhead_p50)
    );
    if let ExecMeasure::Measured(e) = &exec {
        let e50 = percentile(e, 50.0);
        println!(
            "exec wall adds           {:>7.2} ms  (median, vs standard walls)",
            ms(e50.saturating_sub(cell_p50))
        );
    }
    if let Some(d) = &docker {
        let d50 = percentile(d, 50.0);
        println!(
            "docker overhead          {:>7.2} ms  (median, vs baseline)",
            ms(d50.saturating_sub(base_p50))
        );
        // Compare the heaviest cell configuration we measured against docker.
        let (cell_kind, heaviest) = match &exec {
            ExecMeasure::Measured(e) => ("+exec cell", percentile(e, 50.0)),
            ExecMeasure::Unsupported(_) => ("cell", cell_p50),
        };
        println!();
        if heaviest <= d50 {
            let factor = d50 as f64 / heaviest.max(1) as f64;
            println!(
                "Cold start: the {cell_kind} is {factor:.1}x faster than docker run (median)."
            );
        } else {
            let factor = heaviest as f64 / d50.max(1) as f64;
            println!(
                "Cold start: docker run is {factor:.1}x faster than the {cell_kind} (median)."
            );
        }
    }
    println!();
    println!("Notes:");
    println!("- Cold start: every call rebuilds the cell / starts a fresh container.");
    println!("  The exec wall loads + attaches a BPF-LSM program per cell; a long-lived");
    println!("  broker attaching one program to each cell's cgroup amortizes it toward ~0.");
    println!("  Docker likewise amortizes via `docker exec` into a long-lived container.");
    println!("- Docker timed warm: image pre-pulled, daemon already running; the one-time");
    println!("  pull is excluded. All numbers are host- and posture-specific.");

    if let Some(path) = &md_path {
        let md = render_md(&profile_path, iters, posture, &base, &cell, &docker, &exec);
        match std::fs::write(path, md) {
            Ok(()) => eprintln!("ql-overhead: wrote {path}"),
            Err(e) => eprintln!("ql-overhead: could not write {path}: {e}"),
        }
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("ql-overhead: {msg}");
    std::process::exit(2);
}

/// Format a nanosecond sample as a `"%.2 ms"` cell for the Markdown table.
fn fmt_ms(n: u128) -> String {
    format!("{:.2} ms", ms(n))
}

/// Render the overhead results as a self-describing Markdown document. The
/// header records posture, profile, iteration count, and whether the exec wall
/// was actually measured, so a committed copy states how it was produced.
fn render_md(
    profile_path: &str,
    iters: usize,
    posture: &str,
    base: &[u128],
    cell: &[u128],
    docker: &Option<Vec<u128>>,
    exec: &ExecMeasure,
) -> String {
    let base_p50 = percentile(base, 50.0);
    let base_p95 = percentile(base, 95.0);
    let cell_p50 = percentile(cell, 50.0);
    let cell_p95 = percentile(cell, 95.0);

    let exec_label = match exec {
        ExecMeasure::Measured(_) => "exec wall measured",
        ExecMeasure::Unsupported(_) => {
            "exec wall NOT measured (non-lsm build or unsupported kernel)"
        }
    };

    let baseline_row = format!(
        "| baseline `/bin/true` | {} | {} | — |\n",
        fmt_ms(base_p50),
        fmt_ms(base_p95)
    );
    let docker_row = match docker {
        Some(d) => format!(
            "| `docker run` `/bin/true` (warm image) | {} | {} | {} vs baseline |\n",
            fmt_ms(percentile(d, 50.0)),
            fmt_ms(percentile(d, 95.0)),
            fmt_ms(percentile(d, 50.0).saturating_sub(base_p50))
        ),
        None => String::new(),
    };
    let standard_row = format!(
        "| cell, standard walls | {} | {} | {} vs baseline |\n",
        fmt_ms(cell_p50),
        fmt_ms(cell_p95),
        fmt_ms(cell_p50.saturating_sub(base_p50))
    );
    let exec_row = match exec {
        ExecMeasure::Measured(e) => format!(
            "| cell, + exec wall | {} | {} | {} vs standard walls |\n",
            fmt_ms(percentile(e, 50.0)),
            fmt_ms(percentile(e, 95.0)),
            fmt_ms(percentile(e, 50.0).saturating_sub(cell_p50))
        ),
        ExecMeasure::Unsupported(reason) => {
            format!("| cell, + exec wall | — | — | unsupported ({reason}) |\n")
        }
    };
    let comparison = match docker {
        Some(d) => {
            let d50 = percentile(d, 50.0);
            let (kind, heaviest) = match exec {
                ExecMeasure::Measured(e) => ("+exec cell", percentile(e, 50.0)),
                ExecMeasure::Unsupported(_) => ("cell", cell_p50),
            };
            if heaviest <= d50 {
                let factor = d50 as f64 / heaviest.max(1) as f64;
                format!(
                    "**Cold start: the {kind} is {factor:.1}× faster than `docker run` (median).**\n"
                )
            } else {
                let factor = heaviest as f64 / d50.max(1) as f64;
                format!(
                    "**Cold start: `docker run` is {factor:.1}× faster than the {kind} (median).**\n"
                )
            }
        }
        None => String::new(),
    };

    format!(
        "# QuantmLayer Containment Overhead

_Generated by `ql-overhead` — regenerate, do not edit by hand (see the Makefile `overhead` target)._

**Generated under:** {posture} · profile `{profile_path}` · {iters} iterations · {exec_label}

Per-invocation **cold start** — every call builds a fresh cell / starts a fresh container (no pooling).

| Configuration | median | p95 | overhead (median) |
|---|---|---|---|
{baseline_row}{docker_row}{standard_row}{exec_row}
{comparison}
Notes:
- Cold start: every call rebuilds the cell or starts a fresh container.
- The exec wall loads + attaches a BPF-LSM program per cell; a long-lived broker attaching one program per cell cgroup amortizes it toward ~0. Docker amortizes the same way via `docker exec` into a long-lived container.
- Docker timed warm: image pre-pulled, daemon already running; the one-time pull is excluded. All numbers are host- and posture-specific.
"
    )
}

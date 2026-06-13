// crates/ql-bench/src/bin/ql-overhead.rs
//! Measures the per-call overhead of full containment (cold start, no pooling).
//!
//! It times a trivial command (`/bin/true`) run directly vs. run inside a
//! freshly-built cell, and reports the difference. The point is an *honest*
//! baseline number for the performance story: this is what one agent
//! invocation pays for all five walls today, before any cell pooling.
//!
//! Numbers are host- and posture-specific. Under root every wall (including
//! cgroups) is applied; rootless without cgroup delegation skips the cgroup
//! wall, so its overhead is correspondingly lower. The output states which.
//!
//! Usage:
//!     ql-overhead [--iters N] [path/to/profile.yaml]
//! Defaults: 50 iterations, profiles/coding.yaml.

use std::process::Command;
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

fn main() {
    // --- args ---------------------------------------------------------------
    let mut iters = 50usize;
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
            "-h" | "--help" => {
                println!("usage: ql-overhead [--iters N] [path/to/profile.yaml]");
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

    let trivial: Vec<String> = vec!["/bin/true".to_string()];

    // --- probe: make sure the cell can actually run here --------------------
    // If containment can't be established on this host/posture, bail with
    // guidance rather than printing meaningless numbers.
    match standard_coding_cell(profile.clone()).and_then(|c| c.run(&trivial)) {
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
        let _ = standard_coding_cell(profile.clone()).and_then(|c| c.run(&trivial));
    }

    // --- baseline: /bin/true with no containment ----------------------------
    let base = time_loop(iters, || {
        let _ = Command::new("/bin/true").status();
    });

    // --- cell: /bin/true inside a freshly built cell (full cold start) ------
    let cell = time_loop(iters, || {
        let _ = standard_coding_cell(profile.clone()).and_then(|c| c.run(&trivial));
    });

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

    println!("QuantmLayer cell overhead — cold start, no pooling");
    println!("host posture : {posture}");
    println!("profile      : {profile_path}");
    println!("iterations   : {iters}");
    println!();
    println!("                        median       p95");
    println!(
        "baseline /bin/true     {:>7.2} ms  {:>7.2} ms",
        ms(base_p50),
        ms(base_p95)
    );
    println!(
        "cell + /bin/true       {:>7.2} ms  {:>7.2} ms",
        ms(cell_p50),
        ms(cell_p95)
    );
    println!("------------------------------------------------");
    println!(
        "containment overhead   {:>7.2} ms  (median, cell - baseline)",
        ms(overhead_p50)
    );
    println!();
    println!("Note: cold start — every call rebuilds the cell. This is the number");
    println!("cell pooling aims to reduce; rerun after pooling lands to compare.");
}

fn fail(msg: &str) -> ! {
    eprintln!("ql-overhead: {msg}");
    std::process::exit(2);
}

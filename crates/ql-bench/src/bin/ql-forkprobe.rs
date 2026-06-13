// crates/ql-bench/src/bin/ql-forkprobe.rs
//
//! `ql-forkprobe` — a SAFE, bounded fork-bomb probe for the benchmark.
//!
//! A real fork bomb is dangerous to run. This probe instead attempts to spawn
//! up to `N` short-lived child processes and prints how many it successfully
//! created. Under a `pids.max` limit the kernel returns `EAGAIN` once the cap
//! is reached, so the printed count is bounded well below `N`; without a limit
//! it reaches `N`. The benchmark compares the count to a threshold to decide
//! blocked vs vulnerable.
//!
//! Safety properties:
//! * The attempt is bounded to `N` (no unbounded growth).
//! * Children sleep briefly then exit on their own, and the parent reaps them,
//!   so no processes leak even if the cap is never hit.
//!
//! Usage: `ql-forkprobe <N>` — prints the number of children started.

use std::env;

fn main() {
    let target: i32 = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let mut children = Vec::new();
    let mut started = 0i32;

    for _ in 0..target {
        // SAFETY: fork in a tiny program; the child does only async-signal-safe
        // work (nanosleep + _exit). We bound the count and reap below.
        match unsafe { libc::fork() } {
            0 => {
                // Child: stay alive briefly so concurrent count is meaningful,
                // then exit without running any destructors.
                let ts = libc::timespec {
                    tv_sec: 1,
                    tv_nsec: 0,
                };
                unsafe {
                    libc::nanosleep(&ts, std::ptr::null_mut());
                    libc::_exit(0);
                }
            }
            pid if pid > 0 => {
                started += 1;
                children.push(pid);
            }
            _ => {
                // fork failed (EAGAIN): the pids.max cap stopped us.
                break;
            }
        }
    }

    // Report how many we managed to start. This is the observable signal.
    println!("{started}");

    // Reap every child we created so nothing leaks.
    for pid in children {
        let mut status = 0i32;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
    }
}

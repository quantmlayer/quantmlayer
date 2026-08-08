// crates/ql-cli/src/rlimit.rs
//
//! Process resource-limit helpers. Lives in ql-cli (not ql-broker) because
//! the broker crate is `#![forbid(unsafe_code)]`; rlimit syscalls belong with
//! the process owner that spawns the broker thread.

/// Raise RLIMIT_NOFILE's soft limit to the hard limit, best-effort. Failure
/// leaves the current limit in place — the broker's accept-loop backoff still
/// bounds the damage; this just makes fd exhaustion far less likely under
/// package-manager connection storms.
pub fn raise_nofile_soft_to_hard() {
    // SAFETY: getrlimit/setrlimit are called with a valid pointer to an
    // initialized rlimit struct and a valid resource constant; nothing is
    // aliased and no memory outlives the call.
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 && lim.rlim_cur < lim.rlim_max {
            lim.rlim_cur = lim.rlim_max;
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// After the raise, the soft limit equals the hard limit (or the call was
    /// a no-op because they already matched). Read back via getrlimit.
    #[test]
    fn soft_limit_reaches_hard_limit() {
        raise_nofile_soft_to_hard();
        // SAFETY: same contract as above — valid struct, valid constant.
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
        assert_eq!(rc, 0);
        assert_eq!(lim.rlim_cur, lim.rlim_max);
    }
}

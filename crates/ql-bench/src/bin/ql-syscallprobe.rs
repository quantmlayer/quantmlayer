// crates/ql-bench/src/bin/ql-syscallprobe.rs
//
//! `ql-syscallprobe` — tests whether a privileged-escape syscall is permitted.
//!
//! The probe attempts `ptrace(PTRACE_TRACEME)`. `ptrace` is the canonical
//! cross-process-memory / code-injection primitive: if an agent can call it,
//! it can read or hijack other processes. The seccomp wall denies it.
//!
//! * If `ptrace` is permitted, the call succeeds and the probe prints the
//!   secret marker — the harness reads this as VULNERABLE.
//! * If seccomp denies it, the call returns `-1`/`EPERM`, nothing is printed,
//!   and the harness reads this as BLOCKED.
//!
//! `PTRACE_TRACEME` is harmless (it only requests that our own parent be
//! allowed to trace us) and the process exits immediately, so the probe is
//! safe to run uncontained for the baseline measurement.

fn main() {
    // SAFETY: ptrace(PTRACE_TRACEME, ...) takes no pointers we must keep valid;
    // it either succeeds (returns 0) or fails (returns -1 and sets errno).
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };

    // rc == -1 means the syscall was refused (seccomp EPERM) — blocked.
    // Any other return means ptrace is available — the escape primitive works.
    if rc != -1 {
        println!("QL_TOP_SECRET_a7f3e9c1");
    }
}

// crates/ql-learn/src/lib.rs
//
//! `ql-learn` — the *learning* half of QuantmLayer.
//!
//! Containment ([`ql_enforce`](../ql_enforce/index.html)) is the attention-
//! getter; learning is the moat. This crate observes an agent's real behavior
//! by tracing its syscalls, then synthesizes a least-privilege
//! [`ql_profile::Profile`] from what it actually needed — so an operator never
//! has to hand-write one, and a later compromised run is bounded to the
//! agent's demonstrated needs.
//!
//! ```no_run
//! let result = ql_learn::learn(&["./my-agent".to_string(), "build".to_string()])?;
//! println!("{}", result.profile.to_yaml().unwrap());
//! for note in &result.notes {
//!     eprintln!("note: {note}");
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![deny(missing_docs)]

mod digest;
mod error;
mod observation;
mod observe;
mod risk;
mod shim;
mod synth;
mod trace;

pub use error::{LearnError, Result};
pub use observation::Observation;
pub use observe::{evaluate, Finding, ObserveReport, Verdict};
pub use risk::{build_risk_report, risk_report_for_profile};
pub use shim::{exec_shim_gaps, resolve_shebang_interpreter, resolve_shim_interpreters};
pub use synth::{synthesize, SynthResult};

/// Trace `command` to completion and synthesize a least-privilege profile from
/// what it did. Returns the profile, the notes, and the raw observation.
pub fn learn(command: &[String]) -> Result<LearnOutcome> {
    let mut observation = trace::trace(command)?;

    // A `#!` shim (e.g. multi-call `/bin/true` -> `/usr/bin/coreutils`) execs its
    // interpreter as a SEPARATE kernel event that content-addressed enforcement
    // gates on its own, and ptrace only ever records one side of the shim (entry
    // resolves via /proc/<pid>/exe to the interpreter; a child execve records the
    // script path). Resolve the shebang chain and add the interpreters before
    // hashing, so an enforced learned profile pins the WHOLE exec chain instead of
    // denying the interpreter (the gap observed live on GKE COS).
    let interpreters = shim::resolve_shim_interpreters(&observation.execs);
    observation.execs.extend(interpreters);

    // Turn the observed exec *paths* into content digests before synthesis, so
    // the learned profile can pin the agent's executable set by content. This
    // is the bridge to kernel-side content-addressed exec enforcement.
    let (digests, mut notes) = digest::hash_executables(&observation.execs);
    observation.exec_digests = digests;

    let SynthResult {
        profile,
        notes: synth_notes,
    } = synthesize(&observation);
    notes.extend(synth_notes);

    Ok(LearnOutcome {
        profile,
        notes,
        observation,
    })
}

/// The full result of a learning run.
pub struct LearnOutcome {
    /// The synthesized least-privilege profile.
    pub profile: ql_profile::Profile,
    /// Operator-facing notes about decisions worth reviewing.
    pub notes: Vec<String>,
    /// The raw observation the profile was derived from.
    pub observation: Observation,
}

/// Trace `command` to completion and return the digest-filled [`Observation`]
/// **without** synthesizing a profile — the input `--observe` needs.
///
/// Identical to the first half of [`learn`]: run the tracer, resolve the
/// shebang/shim exec chain, and hash the executables into content digests, so
/// the observation's `exec_digests` match exactly what the exec wall would
/// hash. The agent is *not* contained during this trace (same as learning).
pub fn observe_trace(command: &[String]) -> Result<Observation> {
    let mut observation = trace::trace(command)?;
    let interpreters = shim::resolve_shim_interpreters(&observation.execs);
    observation.execs.extend(interpreters);
    let (digests, _notes) = digest::hash_executables(&observation.execs);
    observation.exec_digests = digests;
    Ok(observation)
}

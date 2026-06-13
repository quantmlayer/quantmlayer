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

mod error;
mod observation;
mod synth;
mod trace;

pub use error::{LearnError, Result};
pub use observation::Observation;
pub use synth::{synthesize, SynthResult};

/// Trace `command` to completion and synthesize a least-privilege profile from
/// what it did. Returns the profile, the notes, and the raw observation.
pub fn learn(command: &[String]) -> Result<LearnOutcome> {
    let observation = trace::trace(command)?;
    let SynthResult { profile, notes } = synthesize(&observation);
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

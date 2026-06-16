// crates/ql-profile/src/lib.rs
//
//! # ql-profile
//!
//! The pure, OS-independent data model for QuantmLayer agent permission
//! profiles. A [`Profile`] declares *what an agent is allowed to do*:
//! filesystem, network, capabilities, syscalls, resources, and child
//! processes. It says nothing about *how* that is enforced — enforcement
//! lives in `ql-enforce` and is platform-specific.
//!
//! This separation is deliberate and load-bearing: because this crate has
//! no OS dependencies, a [`Profile`] is portable. It can be authored,
//! validated, version-controlled, exported to another runtime, and
//! cryptographically signed without any kernel involved. That is what lets
//! the product remain relevant even if agent execution moves to a cloud we
//! do not control.
//!
//! ## Safety property: deny by default
//!
//! Every policy section defaults to its most restrictive value. A
//! `Profile::default()` grants an agent essentially nothing. Permissions are
//! only ever *added* explicitly, so an omission can never widen access.

#![deny(missing_docs)]
#![forbid(unsafe_code)] // this crate is pure data; it must never need unsafe

mod diff;
mod error;
mod export;
mod policy;

pub use diff::{diff, GrantRef, PolicyDiff};
pub use error::{ProfileError, Result};
pub use export::{
    to_docker_notes, to_docker_run, to_oci_seccomp, to_oci_seccomp_notes, ExportNotes,
};
pub use policy::{
    AgentType, CapPolicy, ExecDigest, ExecDigestError, ExecPolicy, FsPolicy, HashAlgo, NetPolicy,
    ProcPolicy, ResourceLimits, SeccompDefault, SyscallPolicy,
};

use serde::{Deserialize, Serialize};

/// The schema version this build understands. Bump on breaking changes to
/// the [`Profile`] shape; never reuse an old number for new semantics.
pub const SCHEMA_VERSION: u32 = 1;

/// A complete, declarative description of one agent's permitted behavior.
///
/// Construct via [`Profile::from_yaml`] / [`Profile::from_json`] (then call
/// [`Profile::validate`]), or build programmatically from [`Default`] and
/// add permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// Schema version of this profile document. Must equal [`SCHEMA_VERSION`].
    pub schema_version: u32,

    /// The archetype this profile targets.
    pub agent_type: AgentType,

    /// Filesystem access policy.
    #[serde(default)]
    pub filesystem: FsPolicy,

    /// Network egress policy.
    #[serde(default)]
    pub network: NetPolicy,

    /// Linux capability policy.
    #[serde(default)]
    pub capabilities: CapPolicy,

    /// Syscall policy.
    #[serde(default)]
    pub syscalls: SyscallPolicy,

    /// Resource limits.
    #[serde(default)]
    pub resources: ResourceLimits,

    /// Child-process policy.
    #[serde(default)]
    pub processes: ProcPolicy,

    /// Content-addressed execution policy (approved binary content digests).
    /// Additive over `processes`; off unless `exec.enforce` is set.
    #[serde(default)]
    pub exec: ExecPolicy,
}

impl Profile {
    /// Parse a profile from a YAML string. Does **not** validate semantics;
    /// call [`Profile::validate`] afterwards.
    pub fn from_yaml(s: &str) -> Result<Self> {
        let p: Profile = serde_yaml::from_str(s)?;
        Ok(p)
    }

    /// Parse a profile from a JSON string. Does **not** validate semantics;
    /// call [`Profile::validate`] afterwards.
    pub fn from_json(s: &str) -> Result<Self> {
        let p: Profile = serde_json::from_str(s)?;
        Ok(p)
    }

    /// Serialize this profile to YAML (the canonical authoring format).
    pub fn to_yaml(&self) -> Result<String> {
        Ok(serde_yaml::to_string(self)?)
    }

    /// Serialize this profile to JSON (for export / API transport).
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Check semantic validity. Parsing succeeds for many documents that are
    /// nonetheless unsafe or incoherent; this is where we reject them.
    ///
    /// Validation is intentionally strict and fail-closed: when in doubt,
    /// reject, so a questionable profile never silently becomes a loose cage.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ProfileError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: SCHEMA_VERSION,
            });
        }

        // A coding agent with no executable allowed cannot function; this is
        // almost certainly a mistake, and a silent empty allowlist is a trap.
        if self.agent_type == AgentType::Coding && self.processes.allow_exec.is_empty() {
            return Err(ProfileError::validation(
                "processes.allow_exec",
                "a coding agent profile must allow at least one executable",
            ));
        }

        // Content-addressed exec, when enabled, is strictly allow-listed. An
        // enabled-but-empty digest set would deny every exec — almost always a
        // mistake, since the digests are normally produced by `ql learn`.
        if self.exec.enforce && self.exec.allow_digests.is_empty() {
            return Err(ProfileError::validation(
                "exec.allow_digests",
                "exec.enforce=true with no allow_digests would deny every exec; \
                 add approved digests (e.g. via `ql learn`) or set enforce=false",
            ));
        }

        // If network is not default-deny, we require an explicit acknowledgement
        // via a non-empty allow list; an "allow everything" profile must be
        // deliberate, not the result of an empty section.
        if !self.network.default_deny && self.network.allow_domains.is_empty() {
            return Err(ProfileError::validation(
                "network.default_deny",
                "default_deny=false with no allow_domains would permit all egress; \
                 set default_deny=true or list allowed domains explicitly",
            ));
        }

        // Resource limits should be set for any real deployment; a missing
        // pids_max is the difference between a contained fork bomb and a dead host.
        if let Some(0) = self.resources.pids_max {
            return Err(ProfileError::validation(
                "resources.pids_max",
                "pids_max must be greater than zero",
            ));
        }
        if let Some(0) = self.resources.memory_max_bytes {
            return Err(ProfileError::validation(
                "resources.memory_max_bytes",
                "memory_max_bytes must be greater than zero",
            ));
        }

        Ok(())
    }
}

impl Default for Profile {
    /// A maximally-restrictive profile: deny-by-default everywhere, no
    /// executables, no network, no capabilities. Useful as a base to build on.
    fn default() -> Self {
        Profile {
            schema_version: SCHEMA_VERSION,
            agent_type: AgentType::Coding,
            filesystem: FsPolicy::default(),
            network: NetPolicy::default(),
            capabilities: CapPolicy::default(),
            syscalls: SyscallPolicy::default(),
            resources: ResourceLimits::default(),
            processes: ProcPolicy::default(),
            exec: ExecPolicy::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundled coding-agent profile must load, validate, and round-trip.
    #[test]
    fn coding_profile_loads_validates_and_roundtrips() {
        let yaml = include_str!("../../../profiles/coding.yaml");

        let profile = Profile::from_yaml(yaml).expect("coding.yaml should parse");
        profile.validate().expect("coding.yaml should be valid");

        assert_eq!(profile.agent_type, AgentType::Coding);
        assert_eq!(profile.schema_version, SCHEMA_VERSION);

        // ~/.ssh and friends must be in the denied set — this is the whole point.
        assert!(
            profile
                .filesystem
                .denied
                .iter()
                .any(|g| g.contains("/home")),
            "coding profile must deny /home to block SSH-key theft"
        );

        // Round-trip through YAML must be lossless.
        let reserialized = profile.to_yaml().expect("serialize to yaml");
        let reparsed = Profile::from_yaml(&reserialized).expect("reparse yaml");
        assert_eq!(profile, reparsed, "YAML round-trip must be lossless");

        // Round-trip through JSON must also be lossless (export path).
        let json = profile.to_json().expect("serialize to json");
        let from_json = Profile::from_json(&json).expect("reparse json");
        assert_eq!(profile, from_json, "JSON round-trip must be lossless");
    }

    /// A freshly-defaulted profile must grant essentially nothing.
    #[test]
    fn default_profile_is_deny_by_default() {
        let p = Profile::default();
        assert!(p.network.default_deny);
        assert!(p.network.block_private_ranges);
        assert!(p.network.allow_domains.is_empty());
        assert!(p.capabilities.retain.is_empty());
        assert!(p.processes.allow_exec.is_empty());
        assert!(p.filesystem.readwrite.is_empty());
    }

    /// Wrong schema version must be rejected, not silently accepted.
    #[test]
    fn rejects_unknown_schema_version() {
        let mut p = minimal_valid_coding();
        p.schema_version = 999;
        let err = p.validate().unwrap_err();
        assert!(matches!(
            err,
            ProfileError::UnsupportedSchemaVersion { found: 999, .. }
        ));
    }

    /// A coding profile with no allowed executable is a mistake and must fail.
    #[test]
    fn rejects_coding_profile_with_no_executables() {
        let mut p = minimal_valid_coding();
        p.processes.allow_exec.clear();
        let err = p.validate().unwrap_err();
        assert!(matches!(err, ProfileError::Validation { .. }));
    }

    /// default_deny=false with an empty allow list must be rejected as an
    /// accidental "allow all egress".
    #[test]
    fn rejects_implicit_allow_all_network() {
        let mut p = minimal_valid_coding();
        p.network.default_deny = false;
        p.network.allow_domains.clear();
        assert!(p.validate().is_err());
    }

    /// Content-addressed exec is inactive by default and grants no digests.
    #[test]
    fn exec_policy_inactive_by_default() {
        let p = Profile::default();
        assert!(!p.exec.enforce);
        assert!(p.exec.allow_digests.is_empty());
    }

    /// An ExecDigest round-trips through its `"<algo>:<hex>"` string form, both
    /// standalone and inside a profile (YAML and JSON).
    #[test]
    fn exec_digest_roundtrips_as_string() {
        let s = "sha256:bf7c7360f1d567ad9dfeee7a8749c601c351a46fd60bb6e735aa65883435590c";
        let d: ExecDigest = s.parse().expect("valid digest parses");
        assert_eq!(d.algo(), HashAlgo::Sha256);
        assert_eq!(d.to_string(), s);
        assert_eq!(d.to_bytes().len(), 32);
        assert_eq!(d.to_bytes()[0], 0xbf);

        let mut p = minimal_valid_coding();
        p.exec.enforce = true;
        p.exec.allow_digests.push(d);
        p.validate().expect("profile with a digest is valid");

        let yaml = p.to_yaml().expect("to yaml");
        assert_eq!(Profile::from_yaml(&yaml).expect("from yaml"), p);
        let json = p.to_json().expect("to json");
        assert_eq!(Profile::from_json(&json).expect("from json"), p);
    }

    /// Malformed digests are rejected at construction, never stored.
    #[test]
    fn exec_digest_rejects_malformed() {
        assert!("bf7c7360".parse::<ExecDigest>().is_err()); // no algo prefix
        assert!("md5:abcd".parse::<ExecDigest>().is_err()); // unknown algo
        assert!("sha256:zzzz".parse::<ExecDigest>().is_err()); // non-hex + short
        assert!("sha256:bf7c".parse::<ExecDigest>().is_err()); // too short
        assert!(ExecDigest::new(HashAlgo::Sha256, "a".repeat(64)).is_ok());
        assert!(ExecDigest::new(HashAlgo::Sha256, "a".repeat(63)).is_err());
        // Uppercase hex is accepted and normalized to lowercase.
        let d = ExecDigest::new(HashAlgo::Sha256, "A".repeat(64)).expect("uppercase ok");
        assert_eq!(d.hex(), "a".repeat(64).as_str());
    }

    /// enforce=true with an empty allow-list is a trap and must be rejected.
    #[test]
    fn rejects_enforced_exec_with_no_digests() {
        let mut p = minimal_valid_coding();
        p.exec.enforce = true;
        p.exec.allow_digests.clear();
        assert!(p.validate().is_err());
    }

    /// The IMA algorithm ids must match the kernel contract (SHA-256 == 4),
    /// or the enforcement layer would misinterpret a digest.
    #[test]
    fn hash_algo_ima_ids_match_kernel() {
        assert_eq!(HashAlgo::Sha1.ima_id(), 2);
        assert_eq!(HashAlgo::Sha256.ima_id(), 4);
        assert_eq!(HashAlgo::Sha384.ima_id(), 5);
        assert_eq!(HashAlgo::Sha512.ima_id(), 6);
        assert_eq!(HashAlgo::Sha256.digest_len(), 32);
    }

    fn minimal_valid_coding() -> Profile {
        let mut p = Profile {
            agent_type: AgentType::Coding,
            ..Default::default()
        };
        p.processes.allow_exec.push("/usr/bin/git".to_string());
        p
    }
}

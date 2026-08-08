// crates/ql-cli/src/prune.rs
//
//! `--prune-provider`: narrow a profile's egress allow-list to the model
//! provider the agent is actually configured to use.
//!
//! Bundled multi-provider profiles (goose) ship several provider domains with
//! a "prune to the one you use" note. This automates that prune by reading
//! the agent's own configuration — currently goose's
//! `~/.config/goose/config.yaml` (`GOOSE_PROVIDER:`).
//!
//! ## Invariant: prune can only narrow
//!
//! The config file lives inside the cell's readwrite grant, so an agent can
//! rewrite it between runs. That is safe here by construction:
//!
//! - Provider names map to domains through the compile-time table below.
//!   Config content is never used to *construct* a domain.
//! - Pruning only removes members of the fixed prunable set
//!   ([`PROVIDER_DOMAINS`]); it never adds. Registries, source hosting, and
//!   any non-provider domains are untouched.
//! - An unknown or missing provider leaves the profile exactly as shipped.
//!
//! Worst case, an agent that tampers with its own config narrows itself.

use ql_profile::Profile;
use std::path::{Path, PathBuf};

/// The prunable set: exactly the hosted-provider domains bundled profiles
/// ship. Only members of this list can ever be removed by pruning.
const PROVIDER_DOMAINS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "api.x.ai",
    "openrouter.ai",
];

/// Compile-time map from a goose provider name to its API domain. Config
/// content is only ever *looked up* here, never turned into a domain.
fn provider_domain(provider: &str) -> Option<&'static str> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "anthropic" => Some("api.anthropic.com"),
        "openai" => Some("api.openai.com"),
        "google" | "gemini" => Some("generativelanguage.googleapis.com"),
        "xai" => Some("api.x.ai"),
        "openrouter" => Some("openrouter.ai"),
        _ => None,
    }
}

/// What pruning did, for the operator notice.
#[derive(Debug, PartialEq, Eq)]
pub enum PruneOutcome {
    /// Removed `removed` provider domains; `kept` is the configured
    /// provider's domain.
    Pruned { kept: &'static str, removed: usize },
    /// No goose config was found at the resolved path.
    NoConfig,
    /// The config named a provider outside the compile-time table (e.g. a
    /// local or unsupported provider); the profile is unchanged.
    UnknownProvider(String),
}

/// Narrow `profile.network.allow_domains` to the provider configured in
/// `config_path` (goose's `config.yaml`). See the module docs for why this
/// operation can only ever remove domains.
pub fn prune_provider_domains(profile: &mut Profile, config_path: &Path) -> PruneOutcome {
    let Ok(text) = std::fs::read_to_string(config_path) else {
        return PruneOutcome::NoConfig;
    };
    let Some(provider) = read_goose_provider(&text) else {
        return PruneOutcome::NoConfig;
    };
    let Some(keep) = provider_domain(&provider) else {
        return PruneOutcome::UnknownProvider(sanitize_name(&provider));
    };

    let before = profile.network.allow_domains.len();
    profile
        .network
        .allow_domains
        .retain(|d| d == keep || !PROVIDER_DOMAINS.contains(&d.as_str()));
    let removed = before - profile.network.allow_domains.len();
    PruneOutcome::Pruned {
        kept: keep,
        removed,
    }
}

/// Resolve the goose config path for the invoking user: `SUDO_USER`'s home
/// when running under sudo (the common `ql agent` case), else `$HOME`.
pub fn goose_config_path(sudo_home: Option<PathBuf>) -> Option<PathBuf> {
    let home = sudo_home.or_else(|| std::env::var("HOME").ok().map(PathBuf::from))?;
    Some(home.join(".config/goose/config.yaml"))
}

/// Extract `GOOSE_PROVIDER` from goose's config.yaml. Parsed as YAML via the
/// workspace serde_yaml; only the one string key is read.
fn read_goose_provider(text: &str) -> Option<String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(text).ok()?;
    doc.get("GOOSE_PROVIDER")?.as_str().map(|s| s.to_string())
}

/// A provider name from an agent-writable file may be echoed in an operator
/// notice; strip anything that is not a plain identifier character first.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(32)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn goose_profile() -> Profile {
        let yaml = include_str!("../../../profiles/agents/goose.yaml");
        Profile::from_yaml(yaml).expect("goose profile parses")
    }

    fn write_config(dir: &Path, contents: &str) -> PathBuf {
        let p = dir.join("config.yaml");
        std::fs::write(&p, contents).unwrap();
        p
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ql-prune-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The configured provider's domain survives; the other provider domains
    /// are removed; registries and source hosting are untouched.
    #[test]
    fn prunes_to_configured_provider_and_keeps_registries() {
        let dir = tmpdir("keep");
        let cfg = write_config(&dir, "GOOSE_PROVIDER: anthropic\nGOOSE_MODEL: claude\n");
        let mut p = goose_profile();
        let registries_before: Vec<String> = p
            .network
            .allow_domains
            .iter()
            .filter(|d| !PROVIDER_DOMAINS.contains(&d.as_str()))
            .cloned()
            .collect();

        let out = prune_provider_domains(&mut p, &cfg);
        assert_eq!(
            out,
            PruneOutcome::Pruned {
                kept: "api.anthropic.com",
                removed: 4
            }
        );
        assert!(p
            .network
            .allow_domains
            .iter()
            .any(|d| d == "api.anthropic.com"));
        assert!(!p
            .network
            .allow_domains
            .iter()
            .any(|d| d == "api.openai.com"));
        for r in &registries_before {
            assert!(
                p.network.allow_domains.contains(r),
                "non-provider domain {r} must survive pruning"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An unknown provider (local model, future provider) changes nothing —
    /// fail open to the shipped list rather than guessing a domain.
    #[test]
    fn unknown_provider_is_a_no_op() {
        let dir = tmpdir("unknown");
        let cfg = write_config(&dir, "GOOSE_PROVIDER: ollama\n");
        let mut p = goose_profile();
        let before = p.network.allow_domains.clone();
        let out = prune_provider_domains(&mut p, &cfg);
        assert_eq!(out, PruneOutcome::UnknownProvider("ollama".into()));
        assert_eq!(p.network.allow_domains, before);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Missing config changes nothing.
    #[test]
    fn missing_config_is_a_no_op() {
        let mut p = goose_profile();
        let before = p.network.allow_domains.clone();
        let out = prune_provider_domains(&mut p, Path::new("/nonexistent/config.yaml"));
        assert_eq!(out, PruneOutcome::NoConfig);
        assert_eq!(p.network.allow_domains, before);
    }

    /// Pruning can only remove: a configured provider whose domain is not in
    /// the profile is NOT added — the allow-list never grows.
    #[test]
    fn prune_never_adds_a_domain() {
        let dir = tmpdir("noadd");
        let cfg = write_config(&dir, "GOOSE_PROVIDER: xai\n");
        let mut p = goose_profile();
        // Simulate an operator who already hand-pruned xai away.
        p.network.allow_domains.retain(|d| d != "api.x.ai");
        let before_len = p.network.allow_domains.len();

        let out = prune_provider_domains(&mut p, &cfg);
        assert_eq!(
            out,
            PruneOutcome::Pruned {
                kept: "api.x.ai",
                removed: 4
            }
        );
        assert!(!p.network.allow_domains.iter().any(|d| d == "api.x.ai"));
        assert_eq!(p.network.allow_domains.len(), before_len - 4);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A hostile provider name from the agent-writable config is stripped to
    /// identifier characters before it can reach an operator notice.
    #[test]
    fn hostile_provider_name_is_sanitized() {
        let dir = tmpdir("hostile");
        let cfg = write_config(&dir, "GOOSE_PROVIDER: \"evil\\e[2J;rm -rf\"\n");
        let mut p = goose_profile();
        let out = prune_provider_domains(&mut p, &cfg);
        match out {
            PruneOutcome::UnknownProvider(name) => {
                assert!(!name.contains('\x1b'), "{name}");
                assert!(!name.contains(';'), "{name}");
                assert!(!name.contains(' '), "{name}");
            }
            other => panic!("expected UnknownProvider, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}

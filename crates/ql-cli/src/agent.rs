// crates/ql-cli/src/agent.rs
//
//! `ql agent` — zero-friction containment for known coding agents.
//!
//! `ql agent claude` is sugar for `ql run --agent claude --workspace <cwd>
//! -- claude`: it selects a curated profile *embedded in the binary*, grants
//! the current directory as the workspace, resolves the agent's binary on
//! `PATH`, and delegates to the exact same `ql run` path — so every gate
//! (signature checks, exec-tier selection, broker, audit) applies unchanged.
//!
//! The profiles live in `profiles/agents/*.yaml` and are compiled in with
//! `include_str!`, so a single static `ql` binary contains them; there is
//! nothing to install or point at. `ql agent list` shows what is bundled.
//!
//! Everything after `--` is passed through to the agent unchanged; every
//! recognized `ql run` option before `--` (e.g. `--broker`, `--audit`,
//! `--verbose`) is forwarded.

use std::process::ExitCode;

/// A coding agent with a curated profile bundled into the binary.
pub struct BundledAgent {
    /// The name used on the command line (`ql agent <name>`).
    pub name: &'static str,
    /// The agent's executable, resolved on `PATH`.
    pub binary: &'static str,
    /// One-line description for `ql agent list`.
    pub description: &'static str,
    /// The embedded profile YAML.
    pub yaml: &'static str,
}

/// Every agent with a bundled profile. Kept alphabetical.
pub const AGENTS: &[BundledAgent] = &[
    BundledAgent {
        name: "aider",
        binary: "aider",
        description: "Aider (Anthropic / OpenAI / OpenRouter endpoints)",
        yaml: include_str!("../../../profiles/agents/aider.yaml"),
    },
    BundledAgent {
        name: "claude",
        binary: "claude",
        description: "Anthropic Claude Code",
        yaml: include_str!("../../../profiles/agents/claude.yaml"),
    },
    BundledAgent {
        name: "cline",
        binary: "cline",
        description: "Cline CLI (open-source, provider-agnostic)",
        yaml: include_str!("../../../profiles/agents/cline.yaml"),
    },
    BundledAgent {
        name: "codex",
        binary: "codex",
        description: "OpenAI Codex CLI",
        yaml: include_str!("../../../profiles/agents/codex.yaml"),
    },
    BundledAgent {
        name: "cursor",
        binary: "cursor-agent",
        description: "Cursor CLI (cursor-agent)",
        yaml: include_str!("../../../profiles/agents/cursor.yaml"),
    },
    BundledAgent {
        name: "gemini",
        binary: "gemini",
        description: "Google Gemini CLI",
        yaml: include_str!("../../../profiles/agents/gemini.yaml"),
    },
    BundledAgent {
        name: "opencode",
        binary: "opencode",
        description: "opencode (open-source, provider-agnostic terminal agent)",
        yaml: include_str!("../../../profiles/agents/opencode.yaml"),
    },
];

/// Look up a bundled agent by name.
pub fn bundled(name: &str) -> Option<&'static BundledAgent> {
    AGENTS.iter().find(|a| a.name == name)
}

/// Entry point for `ql agent`.
pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        None | Some("--help") | Some("-h") => {
            print_usage();
            ExitCode::from(2)
        }
        Some("list") => {
            list();
            ExitCode::SUCCESS
        }
        Some(name) => launch(name, &args[1..]),
    }
}

/// Print the bundled-agent table.
fn list() {
    println!("bundled agents (profiles compiled into this binary):\n");
    for a in AGENTS {
        println!(
            "  {:<8} {:<14} {}",
            a.name,
            format!("[{}]", a.binary),
            a.description
        );
    }
    println!(
        "\nusage: ql agent <name> [run options] [-- <extra agent args>]\n\
         inspect a bundled profile: ql validate --agent <name>\n\
         tighten one for your environment: ql learn --out <p.yaml> -- <agent> ..."
    );
}

/// Run a bundled agent: build the `ql run` argument vector and delegate.
fn launch(name: &str, rest: &[String]) -> ExitCode {
    let Some(agent) = bundled(name) else {
        eprintln!("ql agent: unknown agent `{name}`\n");
        list();
        return ExitCode::from(2);
    };

    // Split forwarded run options from extra agent arguments at `--`.
    let sep = rest.iter().position(|a| a == "--");
    let (opts, extra): (&[String], &[String]) = match sep {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, &[]),
    };

    // The agent must exist on PATH before we build a cell around it.
    let Some(binary) = which(agent.binary) else {
        eprintln!(
            "ql agent: `{}` not found on PATH — install {} first",
            agent.binary, agent.description
        );
        return ExitCode::from(2);
    };

    // Workspace defaults to the current directory unless the caller forwarded
    // their own `--workspace`.
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ql agent: cannot resolve current directory: {e}");
            return ExitCode::from(2);
        }
    };

    let mut run_args: Vec<String> = vec!["--agent".into(), agent.name.into()];
    if !opts.iter().any(|a| a == "--workspace") {
        run_args.push("--workspace".into());
        run_args.push(cwd.to_string_lossy().into_owned());
    }
    run_args.extend(opts.iter().cloned());
    run_args.push("--".into());
    run_args.push(binary);
    run_args.extend(extra.iter().cloned());

    crate::run::cmd(&run_args)
}

/// Resolve a binary name against `PATH`. Returns the absolute path, so the
/// command we register and audit is unambiguous.
fn which(binary: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// Print `ql agent` usage.
fn print_usage() {
    eprintln!(
        "USAGE:\n\
         \x20 ql agent list\n\
         \x20 ql agent <name> [run options] [-- <extra agent args>]\n\
         \n\
         Runs a known coding agent inside a containment cell built from a\n\
         curated profile embedded in this binary. The current directory is\n\
         granted as the workspace. All `ql run` options are accepted and\n\
         forwarded (e.g. --broker, --audit <log.jsonl>, --verbose).\n\
         \n\
         EXAMPLES:\n\
         \x20 ql agent claude\n\
         \x20 ql agent claude --broker --audit run.jsonl\n\
         \x20 ql agent codex -- exec \"fix the failing test\""
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ql_profile::Profile;

    /// Every bundled profile must parse, validate, and pass the authoring
    /// lints — the same three gates `ql run` applies. A profile that fails
    /// here would fail at launch for every user of `ql agent`.
    #[test]
    fn bundled_profiles_parse_validate_and_lint() {
        for a in AGENTS {
            let p = Profile::from_yaml(a.yaml)
                .unwrap_or_else(|e| panic!("agents/{}.yaml should parse: {e}", a.name));
            p.validate()
                .unwrap_or_else(|e| panic!("agents/{}.yaml should validate: {e}", a.name));
            p.lint_authoring()
                .unwrap_or_else(|e| panic!("agents/{}.yaml should pass lints: {e}", a.name));
        }
    }

    /// Each bundled profile must deny the well-known secret locations and
    /// default-deny the network with private ranges blocked — the floor no
    /// agent profile may drop below, regardless of which agent it targets.
    #[test]
    fn bundled_profiles_keep_the_secret_and_network_floor() {
        for a in AGENTS {
            let p = Profile::from_yaml(a.yaml).expect("parses");
            for must_deny in [
                "/home/*/.ssh/**",
                "/home/*/.aws/**",
                "/home/*/.gnupg/**",
                "/home/*/.kube/**",
                "/etc/shadow",
                "/var/run/docker.sock",
            ] {
                assert!(
                    p.filesystem.denied.iter().any(|d| d == must_deny),
                    "agents/{}.yaml must deny {must_deny}",
                    a.name
                );
            }
            assert!(
                p.network.default_deny,
                "agents/{}.yaml: network must default-deny",
                a.name
            );
            assert!(
                p.network.block_private_ranges,
                "agents/{}.yaml: private ranges must be blocked",
                a.name
            );
        }
    }

    /// Names and lookups stay consistent.
    #[test]
    fn bundled_lookup_finds_every_agent() {
        for a in AGENTS {
            assert!(bundled(a.name).is_some());
        }
        assert!(bundled("no-such-agent").is_none());
    }
}

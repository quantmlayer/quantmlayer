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
    BundledAgent {
        name: "openhands",
        binary: "openhands",
        description: "OpenHands CLI (All Hands AI; pip/pipx/uv install, model-agnostic)",
        yaml: include_str!("../../../profiles/agents/openhands.yaml"),
    },
    BundledAgent {
        name: "goose",
        binary: "goose",
        description: "goose CLI (Agentic AI Foundation; MCP-native, model-agnostic)",
        yaml: include_str!("../../../profiles/agents/goose.yaml"),
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
            "  {:<9} {:<14} {}",
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

    // Advisory only: if the workspace has a lockfile, mention that `ql compile`
    // can derive egress from it. Purely a notice — it never changes policy, and
    // it is suppressed when the caller already passed their own profile, since
    // that profile may well be a compiled one.
    maybe_hint_compile(&cwd);

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

/// Print a one-line hint when the workspace root holds a recognized lockfile
/// and the caller is using a bundled profile.
///
/// Discoverability without surprise: authority is granted deliberately, never
/// as a side effect of a file existing in a directory. This mentions the tool
/// and stops — it does not compile, apply, or widen anything.
///
/// Note: `ql agent` cannot take `--profile` (it is mutually exclusive with
/// `--agent`), so there is no "already using a compiled profile" case to
/// suppress here. Running a compiled envelope today means
/// `ql run --profile <compiled.yaml> -- <agent>`.
fn maybe_hint_compile(cwd: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(cwd) else {
        return;
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| ql_compile::ecosystem_for_filename(n).is_some())
        .collect();
    if names.is_empty() {
        return;
    }
    names.sort();
    let them = if names.len() == 1 { "it" } else { "them" };
    eprintln!(
        "ql: {} present — `ql compile .` derives egress domains from {them} \
         (see `ql compile --help`)",
        names.join(", ")
    );
}

/// Resolve a binary name against `PATH`. Returns the absolute path, so the
/// command we register and audit is unambiguous.
///
/// Under `sudo`, `PATH` has already been sanitized by sudo's `secure_path`
/// before `ql` starts, so a user-installed agent in `~/.local/bin` (where
/// goose, openhands, aider, etc. land) is invisible on the inherited `PATH`.
/// To avoid a spurious "not found on PATH" for agents that are in fact
/// installed, we additionally search the *invoking* user's local bin dirs,
/// resolved from `SUDO_USER`. This only augments the search — a binary found
/// on the real `PATH` still wins first.
fn which(binary: &str) -> Option<String> {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(binary);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    // sudo fallback: check the invoking user's ~/.local/bin and ~/bin.
    for dir in invoking_user_bin_dirs() {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// The invoking user's local bin directories (`~/.local/bin`, `~/bin`) when
/// running under `sudo`, resolved from `SUDO_USER` via the passwd database.
/// Returns empty when not under sudo, when `SUDO_USER` is unset/root, or when
/// the home directory cannot be resolved — a garbled environment must never
/// select a surprising path.
fn invoking_user_bin_dirs() -> Vec<std::path::PathBuf> {
    let home = match sudo_user_home() {
        Some(h) => h,
        None => return Vec::new(),
    };
    vec![home.join(".local/bin"), home.join("bin")]
}

/// Resolve the invoking (`SUDO_USER`) user's home directory from the passwd
/// database. Returns `None` unless `SUDO_USER` is set to a non-root user whose
/// home resolves. Pure lookup, no side effects.
pub(crate) fn sudo_user_home() -> Option<std::path::PathBuf> {
    let user = std::env::var("SUDO_USER").ok()?;
    if user.is_empty() || user == "root" {
        return None;
    }
    // Read the home field for this user from /etc/passwd. Avoids a libc dep and
    // is sufficient for the local-account case sudo targets.
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        // passwd fields: name:passwd:uid:gid:gecos:home:shell
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first() == Some(&user.as_str()) {
            let home = fields.get(5).copied().unwrap_or("");
            if home.is_empty() {
                return None;
            }
            return Some(std::path::PathBuf::from(home));
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

    /// Each bundled profile must allow the package registries and source
    /// hosting a real coding task hits on its first `npm install` /
    /// `cargo build` / `pip install` / `go mod download` / `git clone`.
    /// v0.2.0 shipped goose without these and the first real project died
    /// at the broker — this pins the floor so that bug class cannot recur.
    #[test]
    fn bundled_profiles_keep_the_registry_floor() {
        for a in AGENTS {
            let p = Profile::from_yaml(a.yaml).expect("parses");
            for must_allow in [
                "pypi.org",
                "files.pythonhosted.org",
                "registry.npmjs.org",
                "crates.io",
                "static.crates.io",
                "index.crates.io",
                "proxy.golang.org",
                "sum.golang.org",
                "github.com",
                "codeload.github.com",
                "objects.githubusercontent.com",
            ] {
                assert!(
                    p.network.allow_domains.iter().any(|d| d == must_allow),
                    "agents/{}.yaml must allow-list {must_allow}",
                    a.name
                );
            }
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

    /// The sudo PATH-fallback must not select a path when SUDO_USER is unset,
    /// empty, or root — a garbled environment must never resolve a binary from
    /// a surprising location. These manipulate process env, so they are
    /// serialized behind a mutex and restore the prior value.
    mod sudo_path_fallback {
        use super::super::sudo_user_home;
        use std::sync::Mutex;

        static ENV_LOCK: Mutex<()> = Mutex::new(());

        fn with_sudo_user<T>(val: Option<&str>, f: impl FnOnce() -> T) -> T {
            let _g = ENV_LOCK.lock().unwrap();
            let prev = std::env::var("SUDO_USER").ok();
            match val {
                Some(v) => std::env::set_var("SUDO_USER", v),
                None => std::env::remove_var("SUDO_USER"),
            }
            let out = f();
            match prev {
                Some(p) => std::env::set_var("SUDO_USER", p),
                None => std::env::remove_var("SUDO_USER"),
            }
            out
        }

        #[test]
        fn unset_sudo_user_resolves_nothing() {
            with_sudo_user(None, || assert!(sudo_user_home().is_none()));
        }

        #[test]
        fn empty_sudo_user_resolves_nothing() {
            with_sudo_user(Some(""), || assert!(sudo_user_home().is_none()));
        }

        #[test]
        fn root_sudo_user_resolves_nothing() {
            with_sudo_user(Some("root"), || assert!(sudo_user_home().is_none()));
        }

        #[test]
        fn nonexistent_sudo_user_resolves_nothing() {
            with_sudo_user(Some("definitely-not-a-real-user-x9z"), || {
                assert!(sudo_user_home().is_none())
            });
        }
    }
}

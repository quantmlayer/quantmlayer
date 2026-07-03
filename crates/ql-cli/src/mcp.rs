// crates/ql-cli/src/mcp.rs
//
//! `ql mcp` — contain the MCP servers an MCP client launches.
//!
//! An MCP client config (Claude Desktop's `claude_desktop_config.json`,
//! Claude Code's `.mcp.json`, Cursor's `mcp.json`, ...) declares stdio
//! servers as a command plus arguments under `mcpServers`. Every one of
//! those servers is third-party code running with the user's privileges.
//!
//! `ql mcp wrap` rewrites each stdio server so the client launches it
//! through `ql run --mcp -- <original command>` instead — the server runs
//! inside a containment cell built from the embedded MCP profile (or a
//! per-config override). This is transparent to the MCP protocol: the cell
//! inherits stdin/stdout, `ql` itself prints only to stderr, so the
//! JSON-RPC stream is untouched.
//!
//! `ql mcp unwrap` reverses the rewrite; `ql mcp list` shows what a config
//! launches and whether each server is currently contained. Everything else
//! in the config (env, other keys, unknown fields) is preserved verbatim.
//! Remote servers (`url`-based, no local process) are reported and left
//! alone — there is no local process to contain.

use serde_json::{Map, Value};
use std::process::ExitCode;

/// The embedded default MCP-server profile (see `profiles/mcp/default.yaml`).
pub const MCP_PROFILE_YAML: &str = include_str!("../../../profiles/mcp/default.yaml");

/// Entry point for `ql mcp`.
pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("wrap") => wrap_or_unwrap(&args[1..], Mode::Wrap),
        Some("unwrap") => wrap_or_unwrap(&args[1..], Mode::Unwrap),
        Some("list") => list(&args[1..]),
        _ => {
            print_usage();
            ExitCode::from(2)
        }
    }
}

/// Which rewrite `wrap_or_unwrap` performs.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Wrap,
    Unwrap,
}

/// Shared driver for `wrap` and `unwrap`: parse the config, rewrite each
/// stdio server, report what happened, and write the result.
fn wrap_or_unwrap(args: &[String], mode: Mode) -> ExitCode {
    let verb = if mode == Mode::Wrap { "wrap" } else { "unwrap" };

    let mut config_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut in_place = false;
    let mut profile: Option<String> = None;
    let mut broker = false;
    let mut audit: Option<String> = None;
    let mut ql_path: Option<String> = None;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out_path = it.next().cloned(),
            "--in-place" => in_place = true,
            "--profile" => profile = it.next().cloned(),
            "--broker" => broker = true,
            "--audit" => audit = it.next().cloned(),
            "--ql" => ql_path = it.next().cloned(),
            other if !other.starts_with("--") && config_path.is_none() => {
                config_path = Some(other.to_string());
            }
            other => {
                eprintln!("ql mcp {verb}: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    let Some(config_path) = config_path else {
        eprintln!("ql mcp {verb}: a config path is required (e.g. .mcp.json)");
        return ExitCode::from(2);
    };
    if in_place && out_path.is_some() {
        eprintln!("ql mcp {verb}: --in-place and --out are mutually exclusive");
        return ExitCode::from(2);
    }
    if !in_place && out_path.is_none() {
        eprintln!("ql mcp {verb}: choose --in-place (writes a timestamped .bak.<secs> backup) or --out <path>");
        return ExitCode::from(2);
    }

    // A per-config profile override must at least exist and parse before we
    // bake its path into every server's launch command.
    if let Some(p) = &profile {
        match std::fs::read_to_string(p) {
            Ok(yaml) => {
                if let Err(e) = ql_profile::Profile::from_yaml(&yaml).and_then(|p| {
                    p.validate()?;
                    Ok(p)
                }) {
                    eprintln!("ql mcp {verb}: --profile {p} is not a valid profile: {e}");
                    return ExitCode::from(2);
                }
            }
            Err(e) => {
                eprintln!("ql mcp {verb}: cannot read --profile {p}: {e}");
                return ExitCode::from(2);
            }
        }
    }

    // The command the client will invoke. Default to this very binary's
    // absolute path so the rewrite works regardless of the client's PATH.
    let ql = match ql_path {
        Some(p) => p,
        None => match std::env::current_exe() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                eprintln!(
                    "ql mcp {verb}: cannot resolve the ql binary path: {e} (pass --ql <path>)"
                );
                return ExitCode::from(2);
            }
        },
    };

    let text = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql mcp {verb}: cannot read {config_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let mut root: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ql mcp {verb}: {config_path} is not valid JSON: {e}");
            return ExitCode::from(2);
        }
    };

    let opts = WrapOptions {
        ql,
        profile,
        broker,
        audit,
    };
    let report = match mode {
        Mode::Wrap => rewrite(&mut root, |name, server| wrap_server(name, server, &opts)),
        Mode::Unwrap => rewrite(&mut root, unwrap_server),
    };
    let Some(report) = report else {
        eprintln!("ql mcp {verb}: {config_path} has no `mcpServers` object");
        return ExitCode::from(2);
    };
    for line in &report {
        eprintln!("ql mcp: {line}");
    }

    let rendered = match serde_json::to_string_pretty(&root) {
        Ok(s) => s + "\n",
        Err(e) => {
            eprintln!("ql mcp {verb}: cannot render config: {e}");
            return ExitCode::from(1);
        }
    };
    let dest = if in_place {
        // Timestamped so repeated --in-place runs never overwrite an earlier
        // backup; epoch seconds keep it dependency-free and sortable.
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup = format!("{config_path}.bak.{secs}");
        if let Err(e) = std::fs::write(&backup, &text) {
            eprintln!("ql mcp {verb}: cannot write backup {backup}: {e} — aborting");
            return ExitCode::from(1);
        }
        eprintln!("ql mcp: original saved to {backup}");
        config_path.clone()
    } else {
        out_path.expect("checked above")
    };
    match std::fs::write(&dest, rendered) {
        Ok(()) => {
            eprintln!("ql mcp: wrote {dest}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ql mcp {verb}: cannot write {dest}: {e}");
            ExitCode::from(1)
        }
    }
}

/// Options baked into each wrapped server's launch command.
struct WrapOptions {
    ql: String,
    profile: Option<String>,
    broker: bool,
    audit: Option<String>,
}

/// Apply `f` to every server under `mcpServers`, collecting report lines.
/// Returns `None` when the config has no `mcpServers` object.
fn rewrite(
    root: &mut Value,
    f: impl Fn(&str, &mut Map<String, Value>) -> String,
) -> Option<Vec<String>> {
    let servers = root.get_mut("mcpServers")?.as_object_mut()?;
    let mut report = Vec::new();
    for (name, server) in servers.iter_mut() {
        match server.as_object_mut() {
            Some(obj) => report.push(f(name, obj)),
            None => report.push(format!("{name}: not an object — skipped")),
        }
    }
    Some(report)
}

/// Is this server entry already launched through `ql run`?
fn is_wrapped(server: &Map<String, Value>) -> bool {
    let cmd = server.get("command").and_then(Value::as_str).unwrap_or("");
    let is_ql = cmd == "ql" || cmd.ends_with("/ql");
    let first_arg = server
        .get("args")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str);
    is_ql && first_arg == Some("run")
}

/// Rewrite one server to launch through `ql run --mcp -- <original>`.
/// Returns the report line.
fn wrap_server(name: &str, server: &mut Map<String, Value>, opts: &WrapOptions) -> String {
    if server.contains_key("url") && !server.contains_key("command") {
        return format!("{name}: remote (url) server — no local process to contain, skipped");
    }
    if is_wrapped(server) {
        return format!("{name}: already wrapped — skipped");
    }
    let Some(command) = server
        .get("command")
        .and_then(Value::as_str)
        .map(String::from)
    else {
        return format!("{name}: no `command` — skipped");
    };
    let orig_args: Vec<Value> = server
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut args: Vec<Value> = vec![Value::from("run")];
    match &opts.profile {
        Some(p) => {
            args.push(Value::from("--profile"));
            args.push(Value::from(p.as_str()));
        }
        None => args.push(Value::from("--mcp")),
    }
    if opts.broker {
        args.push(Value::from("--broker"));
    }
    if let Some(log) = &opts.audit {
        args.push(Value::from("--audit"));
        args.push(Value::from(log.as_str()));
    }
    args.push(Value::from("--"));
    args.push(Value::from(command));
    args.extend(orig_args);

    server.insert("command".into(), Value::from(opts.ql.as_str()));
    server.insert("args".into(), Value::Array(args));
    format!("{name}: wrapped")
}

/// Reverse [`wrap_server`]: restore the original command and arguments.
/// Returns the report line.
fn unwrap_server(name: &str, server: &mut Map<String, Value>) -> String {
    if !is_wrapped(server) {
        return format!("{name}: not wrapped — skipped");
    }
    let args = server
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let Some(sep) = args.iter().position(|a| a.as_str() == Some("--")) else {
        return format!("{name}: wrapped but has no `--` separator — left unchanged");
    };
    let original = &args[sep + 1..];
    let Some(command) = original.first().and_then(Value::as_str).map(String::from) else {
        return format!("{name}: wrapped but has no command after `--` — left unchanged");
    };
    server.insert("command".into(), Value::from(command));
    server.insert("args".into(), Value::Array(original[1..].to_vec()));
    format!("{name}: unwrapped")
}

/// `ql mcp list <config.json>` — show each server and its containment state.
fn list(args: &[String]) -> ExitCode {
    let Some(config_path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("ql mcp list: a config path is required (e.g. .mcp.json)");
        return ExitCode::from(2);
    };
    let text = match std::fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql mcp list: cannot read {config_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let root: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ql mcp list: {config_path} is not valid JSON: {e}");
            return ExitCode::from(2);
        }
    };
    let Some(servers) = root.get("mcpServers").and_then(Value::as_object) else {
        eprintln!("ql mcp list: {config_path} has no `mcpServers` object");
        return ExitCode::from(2);
    };
    println!("{config_path}: {} server(s)", servers.len());
    for (name, server) in servers {
        let Some(obj) = server.as_object() else {
            println!("  {name:<20} (malformed entry)");
            continue;
        };
        let state = if obj.contains_key("url") && !obj.contains_key("command") {
            "remote (url) — cannot contain"
        } else if is_wrapped(obj) {
            "CONTAINED (ql run)"
        } else {
            "uncontained"
        };
        let cmd = obj
            .get("command")
            .and_then(Value::as_str)
            .or_else(|| obj.get("url").and_then(Value::as_str))
            .unwrap_or("?");
        println!("  {name:<20} {state:<28} {cmd}");
    }
    ExitCode::SUCCESS
}

/// Print `ql mcp` usage.
fn print_usage() {
    eprintln!(
        "USAGE:\n\
         \x20 ql mcp list   <config.json>\n\
         \x20 ql mcp wrap   <config.json> (--in-place | --out <path>) [--profile <p.yaml>] [--broker] [--audit <log.jsonl>] [--ql <path>]\n\
         \x20 ql mcp unwrap <config.json> (--in-place | --out <path>)\n\
         \n\
         Rewrites an MCP client config (Claude Desktop, Claude Code .mcp.json,\n\
         Cursor, ...) so every stdio server it launches runs inside a\n\
         containment cell. The default embedded MCP profile denies the\n\
         well-known credential locations and FAILS CLOSED on network egress;\n\
         grant a network-backed server its domains with a --profile override,\n\
         derived from observed behavior: ql learn --out <p.yaml> -- <server cmd>\n\
         \n\
         EXAMPLES:\n\
         \x20 ql mcp wrap ~/.config/Claude/claude_desktop_config.json --in-place\n\
         \x20 ql mcp wrap .mcp.json --in-place --broker --audit mcp.jsonl\n\
         \x20 ql mcp list .mcp.json"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ql_profile::Profile;

    fn opts() -> WrapOptions {
        WrapOptions {
            ql: "/usr/local/bin/ql".into(),
            profile: None,
            broker: false,
            audit: None,
        }
    }

    fn sample() -> Value {
        serde_json::json!({
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": { "GITHUB_TOKEN": "secret" }
                },
                "remote": { "url": "https://mcp.example.com/sse" }
            },
            "otherSetting": true
        })
    }

    /// The embedded MCP profile must pass the same gates `ql run` applies,
    /// keep the secrets floor, and fail closed on network egress.
    #[test]
    fn embedded_mcp_profile_is_valid_and_fails_closed() {
        let p = Profile::from_yaml(MCP_PROFILE_YAML).expect("parses");
        p.validate().expect("validates");
        p.lint_authoring().expect("lints");
        assert!(p.network.default_deny);
        assert!(
            p.network.allow_domains.is_empty(),
            "MCP default must fail closed"
        );
        assert!(p.network.block_private_ranges);
        for must_deny in ["/home/*/.ssh/**", "/home/*/.aws/**", "/etc/shadow"] {
            assert!(p.filesystem.denied.iter().any(|d| d == must_deny));
        }
    }

    /// Wrapping rewrites the stdio server, preserves env and unknown config
    /// keys, and leaves the remote server alone.
    #[test]
    fn wrap_rewrites_stdio_and_skips_remote() {
        let mut cfg = sample();
        let report = rewrite(&mut cfg, |n, s| wrap_server(n, s, &opts())).unwrap();
        assert!(report.iter().any(|l| l == "github: wrapped"));
        assert!(report.iter().any(|l| l.starts_with("remote: remote (url)")));

        let gh = &cfg["mcpServers"]["github"];
        assert_eq!(gh["command"], "/usr/local/bin/ql");
        let args: Vec<&str> = gh["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "run",
                "--mcp",
                "--",
                "npx",
                "-y",
                "@modelcontextprotocol/server-github"
            ]
        );
        assert_eq!(gh["env"]["GITHUB_TOKEN"], "secret"); // untouched
        assert_eq!(cfg["otherSetting"], true); // untouched
        assert_eq!(
            cfg["mcpServers"]["remote"]["url"],
            "https://mcp.example.com/sse"
        );
    }

    /// Wrapping twice must not double-wrap.
    #[test]
    fn wrap_is_idempotent() {
        let mut cfg = sample();
        rewrite(&mut cfg, |n, s| wrap_server(n, s, &opts())).unwrap();
        let report = rewrite(&mut cfg, |n, s| wrap_server(n, s, &opts())).unwrap();
        assert!(report
            .iter()
            .any(|l| l == "github: already wrapped — skipped"));
        let args = cfg["mcpServers"]["github"]["args"].as_array().unwrap();
        assert_eq!(args.iter().filter(|a| a.as_str() == Some("run")).count(), 1);
    }

    /// wrap → unwrap restores the original command and args exactly.
    #[test]
    fn unwrap_restores_original() {
        let mut cfg = sample();
        let original = cfg.clone();
        let o = WrapOptions {
            broker: true,
            audit: Some("mcp.jsonl".into()),
            ..opts()
        };
        rewrite(&mut cfg, |n, s| wrap_server(n, s, &o)).unwrap();
        let report = rewrite(&mut cfg, unwrap_server).unwrap();
        assert!(report.iter().any(|l| l == "github: unwrapped"));
        assert_eq!(cfg, original);
    }

    /// Wrapping with a profile override and broker/audit bakes them into the
    /// launch arguments, before the `--` separator.
    #[test]
    fn wrap_bakes_profile_broker_and_audit() {
        let mut cfg = sample();
        let o = WrapOptions {
            profile: Some("github-mcp.yaml".into()),
            broker: true,
            audit: Some("mcp.jsonl".into()),
            ..opts()
        };
        rewrite(&mut cfg, |n, s| wrap_server(n, s, &o)).unwrap();
        let args: Vec<&str> = cfg["mcpServers"]["github"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "run",
                "--profile",
                "github-mcp.yaml",
                "--broker",
                "--audit",
                "mcp.jsonl",
                "--",
                "npx",
                "-y",
                "@modelcontextprotocol/server-github"
            ]
        );
    }
}

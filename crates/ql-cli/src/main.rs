// crates/ql-cli/src/main.rs
//
//! `ql` — the QuantmLayer command-line front door.
//!
//! Subcommands:
//! * `ql run --profile <p.yaml> [--workspace <dir>] [--verbose] -- <cmd...>`
//!   Run a command inside a containment cell built from the profile.
//! * `ql validate --profile <p.yaml>`
//!   Load a profile, validate it, and print which walls it will apply.
//! * `ql broker --profile <p.yaml> [--listen 127.0.0.1:8080]`
//!   Run the egress broker (allow-list HTTP CONNECT proxy).
//!
//! Argument parsing is intentionally hand-rolled to keep the dependency
//! surface minimal; each subcommand lives in its own module.

mod agent;
mod audit;
mod broker;
mod doctor;
mod exec_tier;
mod export;
mod kill;
mod learn;
mod mcp;
mod observe;
mod policy;
mod profile;
mod registry;
mod run;
mod token;
mod token_bind;
mod token_issue;
mod validate;

use std::process::ExitCode;

/// Crate version, surfaced by `ql version`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => run::cmd(&args[1..]),
        Some("agent") => agent::cmd(&args[1..]),
        Some("mcp") => mcp::cmd(&args[1..]),
        Some("learn") => learn::cmd(&args[1..]),
        Some("validate") => validate::cmd(&args[1..]),
        Some("doctor") => doctor::cmd(&args[1..]),
        Some("profile") => profile::cmd(&args[1..]),
        Some("export") => export::cmd(&args[1..]),
        Some("audit") => audit::cmd(&args[1..]),
        Some("ps") => kill::cmd_ps(&args[1..]),
        Some("kill") => kill::cmd_kill(&args[1..]),
        Some("token") => token::cmd(&args[1..]),
        Some("broker") => broker::cmd(&args[1..]),
        Some("version") | Some("--version") | Some("-V") => {
            println!("ql {VERSION}");
            ExitCode::SUCCESS
        }
        Some("help") | Some("--help") | Some("-h") | None => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("ql: unknown command `{other}`\n");
            print_usage();
            ExitCode::from(2)
        }
    }
}

/// Print top-level usage.
fn print_usage() {
    eprintln!(
        "ql {VERSION} — security runtime for coding agents\n\
         \n\
         USAGE:\n\
         \x20 ql agent    list | <name> [run options] [-- <extra agent args>]   (claude, codex, gemini, aider)\n\
         \x20 ql mcp      list <config.json> | wrap <config.json> (--in-place|--out <path>) [--profile <p.yaml>] [--broker] [--audit <log.jsonl>] | unwrap <config.json> (--in-place|--out <path>)\n\
         \x20 ql run      --profile <p.yaml> | --agent <name> | --mcp [--observe [--strict]] [--workspace <dir>] [--audit <log.jsonl>] [--proposed <p.yaml>] [--issue-token <out.json>] [--system-id <id> [--model-version <v>]] [--require-signed] [--trust-signer <pubkey>]... [--expect-commit <hash>] [--expect-image <digest>] [--verbose] [--broker] -- <cmd...>\n\
         \x20 ql learn    [--out <p.yaml>] [--verbose] -- <cmd...>\n\
         \x20 ql validate --profile <p.yaml> | --agent <name> | --mcp\n\
         \x20 ql doctor   [--json]\n\
         \x20 ql profile  sign <p.yaml> --key <seed-hex> [--out <path>] | verify <p.yaml> [--signer <pubkey>]\n\
         \x20 ql export   --profile <p.yaml> [--format seccomp|docker] [--out <file>]\n\
         \x20 ql audit    verify <log> | append <log> ... | export <log> --out <dir> | rotate <log> --archive-dir <dir> | retention <dir> | keygen\n\
         \x20 ql ps\n\
         \x20 ql kill     <id> [--audit <log.jsonl>]\n\
         \x20 ql token    demo | keygen\n\
         \x20 ql broker   --profile <p.yaml> [--listen 127.0.0.1:8080] [--trust <root-hex>] [--audit <log.jsonl>] [--system-id <id> [--model-version <v>]]\n\
         \x20 ql version\n\
         \n\
         Contain a known coding agent with one command (bundled profile, cwd as workspace):\n\
         \x20 ql agent claude\n\
         \n\
         Contain every MCP server an MCP client launches (Claude Desktop, .mcp.json, ...):\n\
         \x20 ql mcp wrap .mcp.json --in-place\n\
         \n\
         Dry-run an agent WITHOUT enforcing, to see what would break before flipping to enforce:\n\
         \x20 ql run --observe --agent claude -- claude          # report-only; --strict fails CI on any would-deny\n\
         \n\
         Learn a least-privilege profile by observing an agent, then enforce it:\n\
         \x20 ql learn --out agent.yaml -- ./my-agent build\n\
         \x20 ql run --profile agent.yaml -- ./my-agent build\n"
    );
}

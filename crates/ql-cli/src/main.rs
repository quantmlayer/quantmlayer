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

mod broker;
mod learn;
mod run;
mod validate;

use std::process::ExitCode;

/// Crate version, surfaced by `ql version`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => run::cmd(&args[1..]),
        Some("learn") => learn::cmd(&args[1..]),
        Some("validate") => validate::cmd(&args[1..]),
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
         \x20 ql run      --profile <p.yaml> [--workspace <dir>] [--verbose] [--broker] -- <cmd...>\n\
         \x20 ql learn    [--out <p.yaml>] [--verbose] -- <cmd...>\n\
         \x20 ql validate --profile <p.yaml>\n\
         \x20 ql broker   --profile <p.yaml> [--listen 127.0.0.1:8080]\n\
         \x20 ql version\n\
         \n\
         Learn a least-privilege profile by observing an agent, then enforce it:\n\
         \x20 ql learn --out agent.yaml -- ./my-agent build\n\
         \x20 ql run --profile agent.yaml -- ./my-agent build\n"
    );
}

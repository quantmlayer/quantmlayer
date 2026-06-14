// crates/ql-cli/src/token.rs
//
//! `ql token` — agent identity and delegation tokens.
//!
//! * `ql token demo`   — run a self-contained walkthrough: issue a root grant,
//!   attenuate it down to a sub-agent, show a broadening attempt rejected, and
//!   verify a signed action. Nothing is persisted.
//! * `ql token keygen` — print a fresh agent identity (private seed + public id).

use std::process::ExitCode;

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("demo") | None => {
            print!("{}", ql_token::demo());
            ExitCode::SUCCESS
        }
        Some("keygen") => match ql_token::Identity::generate() {
            Ok(id) => {
                println!("seed   {}", id.seed_hex());
                println!("public {}", id.public().to_hex());
                eprintln!("(keep the seed secret; the public id is the agent's identity)");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("ql token keygen: {e}");
                ExitCode::from(1)
            }
        },
        Some("-h") | Some("--help") => {
            eprintln!("usage: ql token demo | ql token keygen");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("ql token: unknown subcommand `{other}` (try: demo, keygen)");
            ExitCode::from(2)
        }
    }
}

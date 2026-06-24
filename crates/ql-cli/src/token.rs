// crates/ql-cli/src/token.rs
//
//! `ql token` — agent identity and delegation tokens.
//!
//! * `ql token demo`   — run a self-contained walkthrough: issue a root grant,
//!   attenuate it down to a sub-agent, show a broadening attempt rejected, and
//!   verify a signed action. Nothing is persisted.
//! * `ql token bind-demo [out.json]` — show a child's containment cell derived
//!   from an attenuated token, strictly narrower than the base profile. With
//!   `out.json`, emit the real signed chain for use with `ql run --token-chain`.
//! * `ql token keygen` — print a fresh agent identity (private seed + public id).

use std::process::ExitCode;

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("demo") | None => {
            print!("{}", ql_token::demo());
            ExitCode::SUCCESS
        }
        Some("bind-demo") => {
            // Optional second arg: a path to emit the real signed chain to, so
            // this doubles as a live fixture for `ql run --token-chain`.
            print!(
                "{}",
                crate::token_bind::bind_demo(args.get(1).map(String::as_str))
            );
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
            eprintln!("usage: ql token demo | ql token bind-demo [out.json] | ql token keygen");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("ql token: unknown subcommand `{other}` (try: demo, bind-demo, keygen)");
            ExitCode::from(2)
        }
    }
}

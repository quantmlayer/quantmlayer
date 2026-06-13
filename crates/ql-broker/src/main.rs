// crates/ql-broker/src/main.rs
//
//! `ql-broker` — run the egress broker from a profile.
//!
//! Usage:
//! ```text
//! ql-broker --profile <path.yaml> [--listen 127.0.0.1:8080]
//! ```
//!
//! Loads the profile, compiles its network section into a [`BrokerPolicy`], and
//! serves an HTTP `CONNECT` proxy. Point an agent's `HTTPS_PROXY` at the listen
//! address; in production the agent's network namespace is wired so the broker
//! is its only route off-host.

use ql_broker::{serve, BrokerPolicy};
use ql_profile::Profile;
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

fn main() -> ExitCode {
    let mut profile_path: Option<String> = None;
    let mut listen = "127.0.0.1:8080".to_string();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => profile_path = args.next(),
            "--listen" => {
                if let Some(v) = args.next() {
                    listen = v;
                }
            }
            "--help" | "-h" => {
                eprintln!("usage: ql-broker --profile <path.yaml> [--listen 127.0.0.1:8080]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("ql-broker: unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let Some(path) = profile_path else {
        eprintln!("ql-broker: --profile <path.yaml> is required");
        return ExitCode::from(2);
    };

    let yaml = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql-broker: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let profile = match Profile::from_yaml(&yaml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ql-broker: invalid profile: {e}");
            return ExitCode::from(2);
        }
    };

    let policy = Arc::new(BrokerPolicy::from_net_policy(&profile.network));
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ql-broker: cannot bind {listen}: {e}");
            return ExitCode::from(1);
        }
    };

    eprintln!(
        "ql-broker: listening on {listen}; {} allow-listed domain(s); default_deny={}, block_private_ranges={}",
        profile.network.allow_domains.len(),
        profile.network.default_deny,
        profile.network.block_private_ranges,
    );

    if let Err(e) = serve(listener, policy) {
        eprintln!("ql-broker: server error: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

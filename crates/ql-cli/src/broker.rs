// crates/ql-cli/src/broker.rs
//
//! `ql broker` — run the egress broker (allow-list HTTP CONNECT proxy) from a
//! profile. Thin wrapper over the `ql-broker` library so `ql` is a single
//! front door; the standalone `ql-broker` binary remains available too.

use ql_broker::{serve, BrokerPolicy};
use ql_profile::Profile;
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

/// Entry point for `ql broker`.
pub fn cmd(args: &[String]) -> ExitCode {
    let mut profile_path: Option<String> = None;
    let mut listen = "127.0.0.1:8080".to_string();

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--profile" => profile_path = it.next().cloned(),
            "--listen" => {
                if let Some(v) = it.next() {
                    listen = v.clone();
                }
            }
            other => {
                eprintln!("ql broker: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    let Some(path) = profile_path else {
        eprintln!("ql broker: --profile <p.yaml> is required");
        return ExitCode::from(2);
    };

    let yaml = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql broker: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let profile = match Profile::from_yaml(&yaml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ql broker: invalid profile: {e}");
            return ExitCode::from(2);
        }
    };

    let policy = Arc::new(BrokerPolicy::from_net_policy(&profile.network));
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ql broker: cannot bind {listen}: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!(
        "ql broker: listening on {listen}; {} allow-listed domain(s)",
        profile.network.allow_domains.len()
    );

    if let Err(e) = serve(listener, policy) {
        eprintln!("ql broker: server error: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

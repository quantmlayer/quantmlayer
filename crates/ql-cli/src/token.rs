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
        Some("delegate") => delegate_cmd(&args[1..]),
        Some("-h") | Some("--help") => {
            eprintln!(
                "usage: ql token demo | ql token bind-demo [out.json] | ql token keygen\n\
                 \x20      ql token delegate --from <parent.json> --out <child.json> \\\n\
                 \x20             [--only-domains a,b] [--only-read g] [--only-write g] \\\n\
                 \x20             [--only-exec p]"
            );
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!(
                "ql token: unknown subcommand `{other}` \
                 (try: demo, bind-demo, keygen, delegate)"
            );
            ExitCode::from(2)
        }
    }
}

/// `ql token delegate` — issue a sub-agent a strictly narrower credential
/// derived from an existing one.
fn delegate_cmd(args: &[String]) -> ExitCode {
    use crate::token_delegate::{delegate_bundle, describe, write_bundle, Narrowing};

    let mut from: Option<String> = None;
    let mut out: Option<String> = None;
    let mut n = Narrowing::default();
    let list = |s: &str| -> Vec<String> {
        s.split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect()
    };

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--from" => from = it.next().cloned(),
            "--out" => out = it.next().cloned(),
            "--only-domains" => n.only_domains = it.next().map(|v| list(v)),
            "--only-read" => n.only_read = it.next().map(|v| list(v)),
            "--only-write" => n.only_write = it.next().map(|v| list(v)),
            "--only-exec" => n.only_exec = it.next().map(|v| list(v)),
            other => {
                eprintln!("ql token delegate: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    let (Some(from), Some(out)) = (from, out) else {
        eprintln!("ql token delegate: --from <parent.json> and --out <child.json> are required");
        return ExitCode::from(2);
    };

    let text = match std::fs::read_to_string(&from) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ql token delegate: cannot read {from}: {e}");
            return ExitCode::from(2);
        }
    };

    // Accept either shape: a single-link bundle from `ql run --issue-token`,
    // or an already-delegated multi-link one. Chaining from a chain is the
    // whole point, so the two must be interchangeable as input.
    let (chain, root, seed) = match parse_parent(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ql token delegate: {e}");
            return ExitCode::from(2);
        }
    };

    let now = now_ms();
    let bundle = match delegate_bundle(&chain, &root, &seed, &n, ql_token::default_expiry(now), now)
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ql token delegate: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = write_bundle(&out, &bundle) {
        eprintln!("ql token delegate: cannot write {out}: {e}");
        return ExitCode::from(1);
    }

    let eff = match ql_token::verify_chain(
        &bundle.chain,
        &[match ql_token::PublicId::from_hex(&bundle.trust_root) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("ql token delegate: {e}");
                return ExitCode::from(1);
            }
        }],
        now,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ql token delegate: issued chain does not verify: {e}");
            return ExitCode::from(1);
        }
    };

    eprintln!(
        "ql token delegate: wrote {out} — {} link(s), child holds {}",
        bundle.chain.len(),
        describe(&eff)
    );
    if n.is_empty() {
        eprintln!(
            "ql token delegate: no narrowing requested, so the child holds the parent's \
             full authority. Pass --only-domains/--only-read/--only-write/--only-exec to \
             reduce it."
        );
    }
    eprintln!(
        "ql token delegate: a token governs what the broker admits, not what the \
         sub-agent's process can do — contain the sub-agent's cell as well."
    );
    ExitCode::SUCCESS
}

/// Read either bundle shape, returning `(chain, trust_root, seed)`.
fn parse_parent(text: &str) -> Result<(Vec<ql_token::Token>, String, String), String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let root = v
        .get("trust_root")
        .and_then(|x| x.as_str())
        .ok_or("missing trust_root")?
        .to_string();
    let seed = v
        .get("subtask_seed")
        .and_then(|x| x.as_str())
        .ok_or("missing subtask_seed")?
        .to_string();

    let chain: Vec<ql_token::Token> = if let Some(c) = v.get("chain") {
        serde_json::from_value(c.clone()).map_err(|e| format!("bad chain: {e}"))?
    } else if let Some(t) = v.get("token") {
        vec![serde_json::from_value(t.clone()).map_err(|e| format!("bad token: {e}"))?]
    } else {
        return Err("credential has neither `chain` nor `token`".into());
    };
    Ok((chain, root, seed))
}

/// Unix milliseconds now.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

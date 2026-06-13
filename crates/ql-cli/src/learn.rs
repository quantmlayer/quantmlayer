// crates/ql-cli/src/learn.rs
//
//! `ql learn` — observe an agent and synthesize a least-privilege profile.
//!
//! Run the agent through the tracer permissively (it is *not* contained during
//! learning), watch what it actually does, and emit a profile tightened to
//! exactly that. The generated profile can then be enforced with `ql run`.

use ql_learn::learn;
use std::process::ExitCode;

/// Entry point for `ql learn`.
pub fn cmd(args: &[String]) -> ExitCode {
    let sep = args.iter().position(|a| a == "--");
    let (opts, command): (&[String], &[String]) = match sep {
        Some(i) => (&args[..i], &args[i + 1..]),
        None => (args, &[]),
    };

    let mut out: Option<String> = None;
    let mut verbose = false;
    let mut it = opts.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = it.next().cloned(),
            "--verbose" => verbose = true,
            other => {
                eprintln!("ql learn: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    if command.is_empty() {
        eprintln!("ql learn: no command given (everything after `--` is the command to observe)");
        return ExitCode::from(2);
    }

    eprintln!("ql learn: observing `{}`...", command.join(" "));
    let outcome = match learn(command) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ql learn: {e}");
            return ExitCode::from(1);
        }
    };

    if verbose {
        let o = &outcome.observation;
        eprintln!(
            "ql learn: observed {} process(es), {} reads, {} writes, {} exec(s), \
             {} connect(s), {} distinct syscall(s)",
            o.process_count,
            o.reads.len(),
            o.writes.len(),
            o.execs.len(),
            o.connects.len(),
            o.syscalls.len(),
        );
    }

    let yaml = match outcome.profile.to_yaml() {
        Ok(y) => y,
        Err(e) => {
            eprintln!("ql learn: could not serialize profile: {e}");
            return ExitCode::from(1);
        }
    };

    // Notes go to stderr so stdout stays a clean profile when piped.
    for note in &outcome.notes {
        eprintln!("ql learn: note — {note}");
    }

    match out {
        Some(path) => match std::fs::write(&path, &yaml) {
            Ok(()) => {
                eprintln!("ql learn: wrote least-privilege profile to {path}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("ql learn: cannot write {path}: {e}");
                ExitCode::from(1)
            }
        },
        None => {
            print!("{yaml}");
            ExitCode::SUCCESS
        }
    }
}

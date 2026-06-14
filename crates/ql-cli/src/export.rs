// crates/ql-cli/src/export.rs
//
//! `ql export` — render a profile into a runtime-agnostic format another
//! sandbox can consume, so the derived least-privilege policy travels with the
//! agent even where QuantmLayer doesn't own the kernel.
//!
//! Formats:
//! * `seccomp` — an OCI/Docker-compatible seccomp profile (JSON), usable by
//!   `docker run --security-opt seccomp=<file>`, containerd, CRI-O, etc.
//! * `docker`  — a `docker run` invocation applying everything Docker can,
//!   with a header documenting exactly what it cannot (those gaps are where
//!   local containment still matters).

use ql_profile::{to_docker_run, to_oci_seccomp, to_oci_seccomp_notes, Profile};
use std::process::ExitCode;

pub fn cmd(args: &[String]) -> ExitCode {
    let mut profile_path: Option<String> = None;
    let mut format = String::from("seccomp");
    let mut out: Option<String> = None;
    let mut image = String::from("ubuntu:22.04");
    let mut seccomp_file = String::from("ql-seccomp.json");

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--profile" => profile_path = it.next().cloned(),
            "--format" => {
                if let Some(f) = it.next() {
                    format = f.clone();
                }
            }
            "--out" => out = it.next().cloned(),
            "--image" => {
                if let Some(i) = it.next() {
                    image = i.clone();
                }
            }
            "--seccomp-file" => {
                if let Some(s) = it.next() {
                    seccomp_file = s.clone();
                }
            }
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("ql export: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    let Some(path) = profile_path else {
        eprintln!("ql export: --profile <p.yaml> is required");
        print_help();
        return ExitCode::from(2);
    };

    let yaml = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql export: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let profile = match Profile::from_yaml(&yaml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ql export: parse error: {e}");
            return ExitCode::from(1);
        }
    };

    let (rendered, notes_to_stderr): (String, Vec<String>) = match format.as_str() {
        "seccomp" => {
            let notes = to_oci_seccomp_notes(&profile);
            let mut lines = Vec::new();
            for e in &notes.enforced {
                lines.push(format!("enforced: {e}"));
            }
            for g in &notes.gaps {
                lines.push(format!("caveat  : {g}"));
            }
            (to_oci_seccomp(&profile), lines)
        }
        "docker" => {
            // The docker script already carries its enforced/gap notes in the
            // header, so just remind the user to generate the seccomp file too.
            (
                to_docker_run(&profile, &image, &seccomp_file),
                vec![format!(
                    "remember to also write the seccomp file: \
                     ql export --profile {path} --format seccomp --out {seccomp_file}"
                )],
            )
        }
        other => {
            eprintln!("ql export: unknown format `{other}` (expected: seccomp, docker)");
            return ExitCode::from(2);
        }
    };

    // Notes go to stderr so stdout stays a clean, pipeable artifact.
    for line in notes_to_stderr {
        eprintln!("ql export: {line}");
    }

    match out {
        Some(p) => match std::fs::write(&p, &rendered) {
            Ok(()) => eprintln!("ql export: wrote {} ({} bytes)", p, rendered.len()),
            Err(e) => {
                eprintln!("ql export: cannot write {p}: {e}");
                return ExitCode::from(2);
            }
        },
        None => print!("{rendered}"),
    }
    ExitCode::SUCCESS
}

fn print_help() {
    eprintln!(
        "ql export — render a profile into a portable, runtime-agnostic format\n\
         \n\
         USAGE:\n\
         \x20 ql export --profile <p.yaml> [--format seccomp|docker] [--out <file>]\n\
         \x20            [--image <image>] [--seccomp-file <name>]\n\
         \n\
         EXAMPLES:\n\
         \x20 ql export --profile agent.yaml --format seccomp --out ql-seccomp.json\n\
         \x20 ql export --profile agent.yaml --format docker  --out run.sh\n"
    );
}

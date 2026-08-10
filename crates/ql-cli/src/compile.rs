// crates/ql-cli/src/compile.rs
//
//! `ql compile` — derive an egress envelope from a project's lockfiles.
//!
//! Reads the recognized lockfiles under a directory, determines which package
//! ecosystems are in play, and emits the registry domains that dependency set
//! legitimately needs — bound to the lockfiles' content hashes. Deterministic:
//! the same lockfiles always produce the same envelope.
//!
//! Three output modes:
//! - default: a human summary of what was found and what it compiled to
//! - `--json`: the machine-readable envelope (`ql.compile.envelope/v1`)
//! - `--profile <in> --out <out>`: write a copy of the profile with the
//!   compiled envelope merged into its `allow_domains` (or replacing them,
//!   with `--replace`), and the contributing lockfiles pinned by hash
//!
//! See `ql-compile`'s crate docs for why lockfile *content* can never
//! introduce a domain.

use ql_compile::{compile, CompileError, Envelope, LockfileVcs};
use ql_profile::Profile;
use std::path::Path;
use std::process::ExitCode;

/// Run `ql compile`.
pub fn cmd(args: &[String]) -> ExitCode {
    let mut root = ".".to_string();
    let mut json = false;
    let mut profile_in: Option<String> = None;
    let mut out: Option<String> = None;
    let mut replace = false;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => json = true,
            "--profile" => profile_in = it.next().cloned(),
            "--out" => out = it.next().cloned(),
            "--replace" => replace = true,
            "-h" | "--help" => {
                print_usage();
                return ExitCode::from(0);
            }
            other if other.starts_with('-') => {
                eprintln!("ql compile: unknown option `{other}`");
                print_usage();
                return ExitCode::from(2);
            }
            other => root = other.to_string(),
        }
    }

    if out.is_some() && profile_in.is_none() {
        eprintln!("ql compile: --out requires --profile <in.yaml>");
        return ExitCode::from(2);
    }
    if profile_in.is_some() && out.is_none() {
        eprintln!("ql compile: --profile requires --out <out.yaml>");
        return ExitCode::from(2);
    }

    let envelope = match compile(Path::new(&root)) {
        Ok(e) => e,
        Err(CompileError::NoLockfiles) => {
            eprintln!(
                "ql compile: no recognized lockfile under `{root}`. Looked for Cargo.lock, \
                 package-lock.json, requirements.txt, go.sum and friends."
            );
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("ql compile: {e}");
            return ExitCode::from(1);
        }
    };

    // Writing a profile: apply the envelope and serialize.
    if let (Some(src), Some(dst)) = (profile_in.as_deref(), out.as_deref()) {
        return write_profile(&envelope, src, dst, replace);
    }

    if json {
        print!("{}", envelope.to_json());
    } else {
        print_human(&envelope);
    }
    ExitCode::from(0)
}

/// Apply the envelope to `src` and write the result to `dst`.
fn write_profile(env: &Envelope, src: &str, dst: &str, replace: bool) -> ExitCode {
    let text = match std::fs::read_to_string(src) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ql compile: cannot read {src}: {e}");
            return ExitCode::from(2);
        }
    };
    let mut profile = match Profile::from_yaml(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ql compile: {src} is not a valid profile: {e}");
            return ExitCode::from(2);
        }
    };

    // A signed profile must not be silently rewritten: the signature covers
    // the allow-list, so applying an envelope would invalidate it. Refuse and
    // let the operator re-sign deliberately.
    if profile.signature.is_some() {
        eprintln!(
            "ql compile: {src} carries a signature; applying an envelope would invalidate it. \
             Compile from the unsigned source profile and re-sign the result."
        );
        return ExitCode::from(2);
    }

    let before = profile.network.allow_domains.clone();
    // Merge is the default: the asymmetry favours a slightly-wider profile
    // over an agent that cannot reach its model provider on the first run.
    if replace {
        env.apply_to_replacing(&mut profile);
    } else {
        env.apply_to(&mut profile);
    }

    // The compiled profile must still be a valid, deny-by-default profile.
    if let Err(e) = profile.validate() {
        eprintln!("ql compile: compiled profile failed validation: {e}");
        return ExitCode::from(1);
    }

    let yaml = match profile.to_yaml() {
        Ok(y) => y,
        Err(e) => {
            eprintln!("ql compile: cannot serialize profile: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = std::fs::write(dst, yaml) {
        eprintln!("ql compile: cannot write {dst}: {e}");
        return ExitCode::from(1);
    }

    let removed: Vec<&String> = before
        .iter()
        .filter(|d| !profile.network.allow_domains.contains(d))
        .collect();
    eprintln!(
        "ql compile: wrote {dst} — {} domain(s) from {} lockfile(s); envelope {}",
        profile.network.allow_domains.len(),
        env.lockfiles.len(),
        &env.envelope_hash[..16]
    );
    if !removed.is_empty() {
        // Every dropped domain is named, never truncated: the whole point of
        // naming them is so an operator notices their model-provider endpoint
        // is gone, and a truncated list can hide exactly that.
        eprintln!(
            "ql compile: --replace dropped {} pre-existing domain(s):",
            removed.len()
        );
        for d in &removed {
            eprintln!("ql compile:   dropped {d}");
        }
    }
    warn_vcs(env);
    report_skipped(env);
    eprintln!("ql compile: next: ql run --profile {dst} -- <your agent command>");
    ExitCode::from(0)
}

/// Human-readable summary.
fn print_human(env: &Envelope) {
    println!("compiled envelope {}", &env.envelope_hash[..16]);
    println!();
    println!("lockfiles ({}):", env.lockfiles.len());
    for l in &env.lockfiles {
        println!(
            "  {:<28} {:<6} {}",
            l.path.display(),
            l.ecosystem.token(),
            &l.sha256[..16]
        );
    }
    println!();
    println!("domains ({}):", env.domains.len());
    for d in &env.domains {
        println!("  {d}");
    }
    println!();
    println!(
        "Deterministic: the same lockfiles always compile to this envelope. Domains come \
         from a fixed per-ecosystem table — lockfile contents never become domains."
    );
    println!();
    println!("Apply to a profile: ql compile <dir> --profile <in.yaml> --out <out.yaml>");
    warn_vcs(env);
    report_skipped(env);
}

/// Name any contributing lockfile whose VCS state is not clean. The
/// "compiled from the committed lockfile" framing is only true when the
/// lockfile is actually committed, so say so rather than assume it.
fn warn_vcs(env: &Envelope) {
    if env.unverified_vcs.is_empty() {
        return;
    }
    for (path, state) in &env.unverified_vcs {
        let what = match state {
            LockfileVcs::Dirty => "has uncommitted changes",
            LockfileVcs::Unknown => "is not in a git repository (or git is unavailable)",
            LockfileVcs::Clean => continue,
        };
        eprintln!("ql compile: warning — {} {what}", path.display());
    }
    eprintln!(
        "ql compile: this envelope was compiled from the working tree, not a committed \
         state. (It can still only ever contain ecosystem registries — lockfile contents \
         never become domains.)"
    );
}

/// Report lockfiles found but not compiled, so the root-preference rule is
/// legible rather than discovered.
fn report_skipped(env: &Envelope) {
    if env.skipped.is_empty() {
        return;
    }
    eprintln!(
        "ql compile: found {} lockfile(s), compiled {} at the project root; skipped {}:",
        env.lockfiles.len() + env.skipped.len(),
        env.lockfiles.len(),
        env.skipped.len()
    );
    for l in env.skipped.iter().take(5) {
        eprintln!("ql compile:   skipped {}", l.path.display());
    }
    if env.skipped.len() > 5 {
        eprintln!("ql compile:   … and {} more", env.skipped.len() - 5);
    }
}

fn print_usage() {
    eprintln!(
        "usage: ql compile [<dir>] [--json] [--profile <in.yaml> --out <out.yaml>] \
         [--replace]\n\
         \n\
         Derives an egress envelope from a project's dependency lockfiles: the registry\n\
         domains that dependency set legitimately needs, bound to the lockfiles' content\n\
         hashes. Deterministic — the same lockfiles always produce the same envelope.\n\
         \n\
           <dir>              project root to scan (default: .)\n\
           --json             emit the envelope as JSON (ql.compile.envelope/v1)\n\
           --profile <in>     profile to apply the envelope to (requires --out)\n\
           --out <out>        where to write the compiled profile\n\
           --replace          replace allow_domains instead of merging into them\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ql-cli-compile-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A signed profile is refused rather than silently rewritten — the
    /// signature covers the allow-list.
    #[test]
    fn refuses_to_rewrite_a_signed_profile() {
        let d = tmpdir("signed");
        std::fs::write(d.join("Cargo.lock"), "x\n").unwrap();
        let env = compile(&d).unwrap();

        let mut p = Profile::from_yaml(include_str!("../../../profiles/coding.yaml")).unwrap();
        p.signature = Some(ql_profile::ProfileSignature {
            algorithm: "ed25519".into(),
            public_key: "00".repeat(32),
            value: "00".repeat(64),
        });
        let src = d.join("signed.yaml");
        std::fs::write(&src, p.to_yaml().unwrap()).unwrap();
        let dst = d.join("out.yaml");

        let _ = write_profile(&env, src.to_str().unwrap(), dst.to_str().unwrap(), false);
        // The observable contract: no output is produced for a signed input.
        assert!(!dst.exists(), "must not write an output for a signed input");
        std::fs::remove_dir_all(&d).ok();
    }

    /// The compiled profile round-trips: written YAML parses back with the
    /// envelope's domains.
    #[test]
    fn compiled_profile_round_trips_with_envelope_domains() {
        let d = tmpdir("roundtrip");
        std::fs::write(d.join("Cargo.lock"), "x\n").unwrap();
        let env = compile(&d).unwrap();

        let p = Profile::from_yaml(include_str!("../../../profiles/coding.yaml")).unwrap();
        let src = d.join("in.yaml");
        std::fs::write(&src, p.to_yaml().unwrap()).unwrap();
        let dst = d.join("out.yaml");

        let _ = write_profile(&env, src.to_str().unwrap(), dst.to_str().unwrap(), false);
        assert!(
            dst.exists(),
            "unsigned input must produce an output profile"
        );

        let written = Profile::from_yaml(&std::fs::read_to_string(&dst).unwrap()).unwrap();
        // Default is merge: every compiled domain is present, and the
        // profile's original domains survive.
        for want in &env.domains {
            assert!(
                written.network.allow_domains.contains(want),
                "missing {want}"
            );
        }
        for had in &p.network.allow_domains {
            assert!(
                written.network.allow_domains.contains(had),
                "merge must not drop pre-existing {had}"
            );
        }
        assert!(written.network.default_deny, "must stay deny-by-default");
        // The lockfiles are pinned, so a cell can verify them at start-up.
        assert_eq!(
            written.approved_for.as_ref().unwrap().lockfiles.len(),
            env.lockfiles.len()
        );

        // --replace narrows to exactly the compiled domains.
        let dst2 = d.join("out-replace.yaml");
        let _ = write_profile(&env, src.to_str().unwrap(), dst2.to_str().unwrap(), true);
        let replaced = Profile::from_yaml(&std::fs::read_to_string(&dst2).unwrap()).unwrap();
        assert_eq!(replaced.network.allow_domains, env.domains);
        std::fs::remove_dir_all(&d).ok();
    }
}

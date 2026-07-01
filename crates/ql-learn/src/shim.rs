// crates/ql-learn/src/shim.rs
//
//! Shebang / multi-call-binary resolution.
//!
//! On distros that ship coreutils or busybox as one multi-call binary, a name
//! like `/bin/true` is a `#!` shim into an interpreter such as
//! `/usr/bin/coreutils`. Executing the shim produces TWO exec events the kernel
//! gates independently — its `bprm_check` LSM hook fires for the script and
//! again for the interpreter — so a content-addressed allow-list must contain
//! BOTH digests or the interpreter exec is denied. This was observed live on
//! GKE Container-Optimized OS: `/bin/true` (the shim) allowed, `/usr/bin/coreutils`
//! (the interpreter) denied, the cell fail-closing with EPERM.
//!
//! `ptrace` only ever records one side of the shim — the entry binary resolves
//! via `/proc/<pid>/exe` to the *interpreter*, while a child `execve` records
//! the *script* path argument — so [`resolve_shim_interpreters`] resolves the
//! chain during learning to capture the full set, and [`exec_shim_gaps`] uses
//! the same resolution to warn when a hand-authored profile approves a shim but
//! not the interpreter it execs into.

use std::collections::BTreeSet;

use ql_profile::{HashAlgo, Profile};

use crate::digest::sha256_file_hex;

/// Depth bound for following a shebang chain. No legitimate shim nests deeply;
/// this is a backstop against a pathological or cyclic chain (cycles are also
/// caught structurally by the "already seen" guards in the callers).
const MAX_SHIM_DEPTH: usize = 8;

/// Read a file's `#!` interpreter, if it is a shebang script.
///
/// Returns the absolute interpreter path — the first whitespace-delimited token
/// after `#!` — or `None` when the file is not a shebang script, the interpreter
/// is not absolute (a relative interpreter cannot be content-addressed), or the
/// file cannot be read. Only the first 256 bytes are consulted, matching the
/// kernel's `BINPRM_BUF_SIZE` limit on the shebang line.
pub fn resolve_shebang_interpreter(path: &str) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; 256];
    let n = f.read(&mut buf).ok()?;
    let rest = buf[..n].strip_prefix(b"#!")?;
    let line = &rest[..rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len())];
    let interp: Vec<u8> = line
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .take_while(|b| !b.is_ascii_whitespace())
        .collect();
    let interp = String::from_utf8(interp).ok()?;
    interp.starts_with('/').then_some(interp)
}

/// Expand a set of exec paths with the interpreters of any `#!` shims among
/// them, following the shebang chain (an interpreter may itself be a script)
/// with a depth bound and cycle guard. Returns only the NEW absolute interpreter
/// paths not already in `execs`, so the caller can union them into the observed
/// exec set before hashing — capturing the full exec chain the kernel gates.
pub fn resolve_shim_interpreters(execs: &BTreeSet<String>) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for start in execs.iter().filter(|p| p.starts_with('/')) {
        let mut current = start.clone();
        for _ in 0..MAX_SHIM_DEPTH {
            match resolve_shebang_interpreter(&current) {
                Some(interp)
                    if interp != current
                        && !execs.contains(&interp)
                        && !found.contains(&interp) =>
                {
                    found.insert(interp.clone());
                    current = interp;
                }
                _ => break,
            }
        }
    }
    found
}

/// Advisory checks for `ql validate`: flag a profile that approves a `#!` shim in
/// `processes.allow_exec` but not the interpreter it execs into.
///
/// Best-effort and filesystem-dependent — it reads the named binaries on THIS
/// host — so callers treat the result as warnings, never hard errors: the author
/// may be targeting a different distro. An interpreter counts as covered if its
/// path is also in `allow_exec`, or (when `exec.enforce`) its sha256 is present
/// in `exec.allow_digests`.
pub fn exec_shim_gaps(profile: &Profile) -> Vec<String> {
    let mut gaps = Vec::new();
    for path in &profile.processes.allow_exec {
        let mut current = path.clone();
        for _ in 0..MAX_SHIM_DEPTH {
            let Some(interp) = resolve_shebang_interpreter(&current) else {
                break;
            };
            if interp == current {
                break;
            }
            let covered_by_path = profile.processes.allow_exec.contains(&interp);
            let covered_by_digest = profile.exec.enforce
                && sha256_file_hex(&interp).is_some_and(|hex| {
                    profile
                        .exec
                        .allow_digests
                        .iter()
                        .any(|d| d.algo() == HashAlgo::Sha256 && d.hex() == hex)
                });
            if !covered_by_path && !covered_by_digest {
                gaps.push(format!(
                    "`{path}` is a #! shim into `{interp}`, which is not approved. On \
                     multi-call-binary distros (e.g. GKE COS, BusyBox) the interpreter execs as \
                     a separate event that content-addressed enforcement denies. Add `{interp}` \
                     to processes.allow_exec (re-running `ql learn` now resolves shims)."
                ));
                break; // one gap per shim chain is enough signal
            }
            current = interp;
        }
    }
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qllearn-shim-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> String {
        let p = dir.join(name);
        std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
        p.to_str().unwrap().to_string()
    }

    #[test]
    fn resolves_absolute_shebang_interpreter() {
        let dir = tempdir("resolve");
        let shim = write(
            &dir,
            "true",
            b"#!/usr/bin/coreutils --coreutils-prog-shebang=true\n",
        );
        assert_eq!(
            resolve_shebang_interpreter(&shim).as_deref(),
            Some("/usr/bin/coreutils")
        );
    }

    #[test]
    fn ignores_non_shebang_relative_and_missing() {
        let dir = tempdir("nonshebang");
        let elf = write(&dir, "bin", b"\x7fELF\x02\x01\x01\x00rest of a binary");
        assert_eq!(resolve_shebang_interpreter(&elf), None);
        let rel = write(&dir, "rel", b"#!bin/sh\n");
        assert_eq!(resolve_shebang_interpreter(&rel), None);
        assert_eq!(resolve_shebang_interpreter("/no/such/file/xyzzy"), None);
    }

    #[test]
    fn expands_exec_set_with_interpreter() {
        let dir = tempdir("expand");
        let shim = write(&dir, "true", b"#!/usr/bin/coreutils\n");
        let execs: BTreeSet<String> = [shim].into_iter().collect();
        let extra = resolve_shim_interpreters(&execs);
        assert!(extra.contains("/usr/bin/coreutils"));
    }

    fn profile_with_allow_exec(paths: &[&str]) -> Profile {
        // Only schema_version and agent_type are required; every policy section
        // is `#[serde(default)]`, so exec.enforce defaults to false and the
        // advisory exercises the path-coverage branch. allow_exec is set below.
        let mut p = Profile::from_yaml("schema_version: 1\nagent_type: coding\n")
            .expect("fixture profile parses");
        p.processes.allow_exec = paths.iter().map(|s| s.to_string()).collect();
        p
    }

    #[test]
    fn flags_uncovered_shim_and_clears_when_interpreter_approved() {
        let dir = tempdir("gaps");
        let shim = write(&dir, "true", b"#!/usr/bin/coreutils\n");

        // Approves the shim path but not the interpreter -> one gap.
        let p = profile_with_allow_exec(&[&shim]);
        let gaps = exec_shim_gaps(&p);
        assert_eq!(gaps.len(), 1, "expected one shim gap, got {gaps:?}");
        assert!(gaps[0].contains("/usr/bin/coreutils"));

        // Approving the interpreter path too clears the gap.
        let p = profile_with_allow_exec(&[&shim, "/usr/bin/coreutils"]);
        assert!(exec_shim_gaps(&p).is_empty());
    }
}

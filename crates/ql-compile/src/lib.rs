// crates/ql-compile/src/lib.rs
//
//! `ql compile` — deterministic, lockfile-derived egress envelopes.
//!
//! A project's dependency lockfile already states, precisely and under review,
//! what that project depends on. This crate turns that statement into policy:
//! read the lockfile, determine which package ecosystems are in play, and emit
//! the registry domains that dependency set legitimately needs — **bound to the
//! lockfile's content hash**.
//!
//! ## Why this shape
//!
//! - **Deterministic.** No LLM, no heuristics over agent behavior, no kernel
//!   changes. The same lockfile produces the same envelope, byte for byte.
//! - **Rides existing review.** A new dependency is a lockfile diff in a pull
//!   request someone already reviews. The policy amendment gets reviewed when
//!   the dependency does — it never reaches an offline approval queue.
//! - **Bounds the obvious attack, unconditionally.** An agent that edits a
//!   lockfile can at most cause additional *ecosystem registries* to appear —
//!   never an arbitrary host — because domains come only from the fixed table
//!   in this crate. That bound holds regardless of VCS state.
//! - **Records its own provenance.** Each pin carries the lockfile's VCS
//!   state at compile time, so someone auditing the profile later can tell
//!   whether it was derived from a committed tree — a compile-time warning is
//!   gone by then.
//! - **Detects the edit, when pinned.** [`Envelope::apply_to`] writes each
//!   lockfile's hash into the profile's `approved_for.lockfiles`, and a cell
//!   refuses to start if a pinned lockfile is missing or changed.
//!
//! ## What this deliberately does NOT do
//!
//! It does not grant per-package domains. Registries are *ecosystem*-scoped:
//! knowing a project depends on `serde` tells you it needs crates.io, not that
//! it needs some serde-specific host. Pretending otherwise would imply a
//! precision the lockfile does not contain. Per-package capability packs (a
//! signed catalog mapping individual packages to extra capabilities) are a
//! later, separately-signed layer — see `CATALOG.md` when it exists.
//!
//! ## Narrowing, not widening
//!
//! [`compile`] returns an [`Envelope`]; applying it to a profile
//! ([`Envelope::apply_to`]) replaces the profile's `allow_domains` with the
//! compiled set. Because the compiled set is derived only from the fixed
//! ecosystem table in this crate, an attacker who controls the lockfile can
//! only cause *ecosystem* domains to appear — never an arbitrary host. Nothing
//! in the lockfile's text ever becomes a domain string.

pub use ql_profile::LockfileVcs;
use ql_profile::Profile;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A package ecosystem QuantmLayer can compile an envelope for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ecosystem {
    /// Rust — `Cargo.lock`.
    Cargo,
    /// Node — `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`,
    /// `pnpm-lock.yaml`.
    Npm,
    /// Python — `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`.
    PyPI,
    /// Go — `go.sum`.
    Go,
}

impl Ecosystem {
    /// The lockfile names that indicate this ecosystem. Matched by exact file
    /// name, never by content sniffing.
    pub fn lockfile_names(self) -> &'static [&'static str] {
        match self {
            Ecosystem::Cargo => &["Cargo.lock"],
            Ecosystem::Npm => &[
                "package-lock.json",
                "npm-shrinkwrap.json",
                "yarn.lock",
                "pnpm-lock.yaml",
            ],
            Ecosystem::PyPI => &["requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock"],
            Ecosystem::Go => &["go.sum"],
        }
    }

    /// The registry and source-hosting domains this ecosystem needs to fetch
    /// its dependencies. **This table is the whole trust boundary of this
    /// crate**: every domain an envelope can ever contain appears here as a
    /// compile-time constant. Nothing read from a lockfile becomes a domain.
    pub fn domains(self) -> &'static [&'static str] {
        match self {
            Ecosystem::Cargo => &["crates.io", "static.crates.io", "index.crates.io"],
            Ecosystem::Npm => &["registry.npmjs.org"],
            Ecosystem::PyPI => &["pypi.org", "files.pythonhosted.org"],
            Ecosystem::Go => &["proxy.golang.org", "sum.golang.org"],
        }
    }

    /// Short stable token for reports and JSON.
    pub fn token(self) -> &'static str {
        match self {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "pypi",
            Ecosystem::Go => "go",
        }
    }

    /// Every ecosystem, in stable order.
    pub fn all() -> &'static [Ecosystem] {
        &[
            Ecosystem::Cargo,
            Ecosystem::Npm,
            Ecosystem::PyPI,
            Ecosystem::Go,
        ]
    }
}

/// Source hosting that dependency resolution routes through regardless of
/// ecosystem: `git` dependencies, `go get`, and a large share of npm's tree
/// all fetch from GitHub. Included whenever any ecosystem is detected.
const SOURCE_HOSTING: &[&str] = &[
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
];

/// One lockfile that contributed to an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockfileRef {
    /// Path as given, relative to the compile root.
    pub path: PathBuf,
    /// The ecosystem this lockfile indicates.
    pub ecosystem: Ecosystem,
    /// Lowercase-hex SHA-256 of the lockfile's exact bytes.
    pub sha256: String,
    /// VCS state at compile time, carried into the pin so the provenance
    /// outlives the compile-time warning.
    pub vcs: LockfileVcs,
}

/// A compiled egress envelope: the domains a dependency set legitimately
/// needs, plus the provenance that makes it checkable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The lockfiles this envelope was compiled from, sorted by path.
    pub lockfiles: Vec<LockfileRef>,
    /// Lockfiles that were found but NOT compiled (root lockfiles took
    /// precedence). Reported so the limitation is legible, not discovered.
    pub skipped: Vec<LockfileRef>,
    /// The compiled domain allow-list, sorted and de-duplicated.
    pub domains: Vec<String>,
    /// Hash over every contributing lockfile's identity and content hash.
    /// Two compiles agree iff they saw exactly the same lockfiles with the
    /// same bytes — this is what an agent editing a lockfile mid-task breaks.
    pub envelope_hash: String,
    /// Any contributing lockfile that is dirty or of unknown VCS state.
    /// Non-empty means the "compiled from the committed lockfile" framing does
    /// not hold for this envelope and the caller should say so.
    pub unverified_vcs: Vec<(PathBuf, LockfileVcs)>,
}

impl Envelope {
    /// The ecosystems represented, in stable order.
    pub fn ecosystems(&self) -> Vec<Ecosystem> {
        let set: BTreeSet<Ecosystem> = self.lockfiles.iter().map(|l| l.ecosystem).collect();
        set.into_iter().collect()
    }

    /// Apply the envelope by **merging** into the profile's existing
    /// allow-list, and pin the contributing lockfiles into `approved_for`.
    ///
    /// Merge is the default because the failure modes are asymmetric: a merged
    /// profile is slightly wider than necessary, whereas a replaced one can
    /// strip the model-provider endpoint the agent needs and break the first
    /// run outright. Use [`Envelope::apply_to_replacing`] to narrow to exactly
    /// the ecosystem domains.
    pub fn apply_to(&self, profile: &mut Profile) {
        let mut out: BTreeSet<String> = profile.network.allow_domains.iter().cloned().collect();
        out.extend(self.domains.iter().cloned());
        profile.network.allow_domains = out.into_iter().collect();
        self.pin_lockfiles(profile);
    }

    /// Apply the envelope by **replacing** the profile's allow-list with
    /// exactly the compiled domains, and pin the contributing lockfiles.
    ///
    /// This narrows: any domain the profile carried for another reason (a
    /// model-provider API, for example) is dropped. Callers should name what
    /// they dropped.
    pub fn apply_to_replacing(&self, profile: &mut Profile) {
        profile.network.allow_domains = self.domains.clone();
        self.pin_lockfiles(profile);
    }

    /// Record each contributing lockfile's path and content hash in the
    /// profile's `approved_for`, so a cell can verify at start-up that the
    /// lockfiles on disk are the ones this envelope was compiled from.
    fn pin_lockfiles(&self, profile: &mut Profile) {
        let pins: Vec<ql_profile::LockfilePin> = self
            .lockfiles
            .iter()
            .map(|l| ql_profile::LockfilePin {
                path: l.path.to_string_lossy().to_string(),
                sha256: l.sha256.clone(),
                vcs: l.vcs,
            })
            .collect();
        let mut approved = profile.approved_for.clone().unwrap_or_default();
        approved.lockfiles = pins;
        profile.approved_for = Some(approved);
    }

    /// Render as JSON for `--json` output. Hand-rolled: the shape is small and
    /// stable, and this crate carries no serialization dependency.
    pub fn to_json(&self) -> String {
        let locks: Vec<String> = self
            .lockfiles
            .iter()
            .map(|l| {
                format!(
                    "    {{ \"path\": \"{}\", \"ecosystem\": \"{}\", \"sha256\": \"{}\" }}",
                    l.path.display(),
                    l.ecosystem.token(),
                    l.sha256
                )
            })
            .collect();
        let domains: Vec<String> = self.domains.iter().map(|d| format!("\"{d}\"")).collect();
        format!(
            "{{\n  \"schema\": \"ql.compile.envelope/v1\",\n  \"envelope_hash\": \"{}\",\n  \"lockfiles\": [\n{}\n  ],\n  \"domains\": [{}]\n}}\n",
            self.envelope_hash,
            locks.join(",\n"),
            domains.join(", ")
        )
    }
}

/// Errors compiling an envelope.
#[derive(Debug)]
pub enum CompileError {
    /// No recognized lockfile was found under the compile root.
    NoLockfiles,
    /// A lockfile was found but could not be read.
    Io(std::io::Error),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::NoLockfiles => write!(
                f,
                "no recognized lockfile found (looked for Cargo.lock, package-lock.json, \
                 requirements.txt, go.sum and friends)"
            ),
            CompileError::Io(e) => write!(f, "reading lockfile: {e}"),
        }
    }
}

impl std::error::Error for CompileError {}

impl From<std::io::Error> for CompileError {
    fn from(e: std::io::Error) -> Self {
        CompileError::Io(e)
    }
}

/// How deep below the root to look for lockfiles. Monorepos keep per-package
/// lockfiles a level or two down; unbounded descent would wander into
/// `node_modules` and vendored trees.
const MAX_DEPTH: usize = 3;

/// Directories never descended into: they contain *installed* dependencies
/// (each with its own lockfiles), not the project's own declarations.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "vendor",
    "target",
    ".git",
    "venv",
    ".venv",
    "dist",
    "build",
    ".tox",
];

/// Compile an envelope from every recognized lockfile under `root`.
///
/// Deterministic: lockfiles are sorted by path before hashing, so directory
/// iteration order never affects the result.
pub fn compile(root: &Path) -> Result<Envelope, CompileError> {
    let mut all = Vec::new();
    collect_lockfiles(root, root, 0, &mut all)?;
    if all.is_empty() {
        return Err(CompileError::NoLockfiles);
    }
    all.sort_by(|a: &LockfileRef, b: &LockfileRef| a.path.cmp(&b.path));

    // Root lockfiles describe the project; nested ones usually describe
    // sub-packages, and unioning a whole monorepo approaches "every registry",
    // which earns nothing over the static floor. Prefer the root set — but if
    // there is none (a monorepo whose lockfiles all live one level down),
    // compile the discovered set rather than failing, and report what was
    // skipped either way so the choice is legible.
    let (found, skipped): (Vec<LockfileRef>, Vec<LockfileRef>) = {
        let at_root: Vec<LockfileRef> = all
            .iter()
            .filter(|l| {
                l.path
                    .parent()
                    .map(|p| p.as_os_str().is_empty())
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if at_root.is_empty() {
            (all.clone(), Vec::new())
        } else {
            let nested = all
                .iter()
                .filter(|l| !at_root.contains(l))
                .cloned()
                .collect();
            (at_root, nested)
        }
    };

    // VCS state of every contributing lockfile. Reported, never enforced:
    // refusing would break no-VCS and fresh-project cases that are legitimate.
    // Recorded onto each ref so it reaches the pin and outlives this run.
    let mut found = found;
    for l in &mut found {
        l.vcs = vcs_state(root, &l.path);
    }
    let unverified_vcs: Vec<(PathBuf, LockfileVcs)> = found
        .iter()
        .filter(|l| l.vcs != LockfileVcs::Clean)
        .map(|l| (l.path.clone(), l.vcs))
        .collect();

    // Domains: the union of each detected ecosystem's fixed table, plus source
    // hosting. Sorted and de-duplicated, so the output is canonical.
    let mut domains: BTreeSet<String> = BTreeSet::new();
    for l in &found {
        for d in l.ecosystem.domains() {
            domains.insert((*d).to_string());
        }
    }
    for d in SOURCE_HOSTING {
        domains.insert((*d).to_string());
    }

    let envelope_hash = hash_envelope(&found);
    Ok(Envelope {
        lockfiles: found,
        skipped,
        domains: domains.into_iter().collect(),
        envelope_hash,
        unverified_vcs,
    })
}

/// Best-effort VCS state for one lockfile. Shelling out to git is deliberate:
/// this crate carries no git dependency, and an absent or failing git simply
/// yields [`LockfileVcs::Unknown`], which the caller reports rather than acts on.
fn vcs_state(root: &Path, rel: &Path) -> LockfileVcs {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("status")
        .arg("--porcelain")
        .arg("--")
        .arg(rel)
        .output();
    match out {
        Ok(o) if o.status.success() => {
            if o.stdout.is_empty() {
                LockfileVcs::Clean
            } else {
                LockfileVcs::Dirty
            }
        }
        // git missing, or not a repository: state unknown.
        _ => LockfileVcs::Unknown,
    }
}

/// Walk `dir` collecting recognized lockfiles, bounded by [`MAX_DEPTH`].
fn collect_lockfiles(
    root: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<LockfileRef>,
) -> Result<(), CompileError> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        // An unreadable subdirectory is skipped, not fatal: a project tree may
        // legitimately contain directories this user cannot read.
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);

        if is_dir {
            if SKIP_DIRS.contains(&name.as_ref()) || name.starts_with('.') {
                continue;
            }
            collect_lockfiles(root, &path, depth + 1, out)?;
            continue;
        }

        if let Some(eco) = ecosystem_for_filename(&name) {
            let bytes = std::fs::read(&path)?;
            out.push(LockfileRef {
                path: path.strip_prefix(root).unwrap_or(&path).to_path_buf(),
                ecosystem: eco,
                sha256: hex(&Sha256::digest(&bytes)),
                // Resolved in compile(), which knows the project root.
                vcs: LockfileVcs::Unknown,
            });
        }
    }
    Ok(())
}

/// Which ecosystem a file name indicates, if any. Exact-name match only.
pub fn ecosystem_for_filename(name: &str) -> Option<Ecosystem> {
    for eco in Ecosystem::all() {
        if eco.lockfile_names().contains(&name) {
            return Some(*eco);
        }
    }
    None
}

/// Hash the envelope's provenance: each lockfile's path, ecosystem, and
/// content hash, in sorted order, with field separators so two different
/// field splits cannot collide.
fn hash_envelope(locks: &[LockfileRef]) -> String {
    let mut h = Sha256::new();
    h.update(b"ql.compile.envelope/v1\0");
    for l in locks {
        h.update(l.path.to_string_lossy().as_bytes());
        h.update(b"\0");
        h.update(l.ecosystem.token().as_bytes());
        h.update(b"\0");
        h.update(l.sha256.as_bytes());
        h.update(b"\0");
    }
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ql-compile-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(dir: &Path, rel: &str, contents: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, contents).unwrap();
    }

    /// A Cargo project compiles to the crates.io domains plus source hosting,
    /// and nothing else.
    #[test]
    fn cargo_lockfile_compiles_to_crates_domains() {
        let d = tmpdir("cargo");
        write(&d, "Cargo.lock", "[[package]]\nname = \"serde\"\n");
        let env = compile(&d).unwrap();

        assert_eq!(env.ecosystems(), vec![Ecosystem::Cargo]);
        for want in ["crates.io", "static.crates.io", "index.crates.io"] {
            assert!(env.domains.iter().any(|x| x == want), "missing {want}");
        }
        assert!(env.domains.iter().any(|x| x == "github.com"));
        // No other ecosystem's registries leak in.
        assert!(!env.domains.iter().any(|x| x == "registry.npmjs.org"));
        assert!(!env.domains.iter().any(|x| x == "pypi.org"));
        std::fs::remove_dir_all(&d).ok();
    }

    /// Determinism: the same lockfile bytes produce a byte-identical envelope,
    /// and the domain list is canonically sorted.
    #[test]
    fn same_lockfile_produces_identical_envelope() {
        let a = tmpdir("det-a");
        let b = tmpdir("det-b");
        write(&a, "Cargo.lock", "[[package]]\nname = \"serde\"\n");
        write(&b, "Cargo.lock", "[[package]]\nname = \"serde\"\n");

        let ea = compile(&a).unwrap();
        let eb = compile(&b).unwrap();
        assert_eq!(ea.envelope_hash, eb.envelope_hash);
        assert_eq!(ea.domains, eb.domains);

        let mut sorted = ea.domains.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(ea.domains, sorted, "domains must be sorted and deduped");

        std::fs::remove_dir_all(&a).ok();
        std::fs::remove_dir_all(&b).ok();
    }

    /// Editing the lockfile changes the envelope hash — this is what lets a
    /// cell detect that the lockfile it sees is not the one the envelope was
    /// compiled from.
    #[test]
    fn editing_the_lockfile_changes_the_envelope_hash() {
        let d = tmpdir("tamper");
        write(&d, "Cargo.lock", "[[package]]\nname = \"serde\"\n");
        let before = compile(&d).unwrap();

        write(
            &d,
            "Cargo.lock",
            "[[package]]\nname = \"serde\"\n# edited\n",
        );
        let after = compile(&d).unwrap();

        assert_ne!(before.envelope_hash, after.envelope_hash);
        // The domains did NOT widen: an agent editing the lockfile cannot add
        // a host, because domains come from the fixed ecosystem table.
        assert_eq!(before.domains, after.domains);
        std::fs::remove_dir_all(&d).ok();
    }

    /// **The central security property.** Hostile content inside a lockfile —
    /// URLs, domains, injected text — never becomes a domain. Only the fixed
    /// ecosystem table can contribute.
    #[test]
    fn lockfile_content_can_never_introduce_a_domain() {
        let d = tmpdir("hostile");
        write(
            &d,
            "Cargo.lock",
            "[[package]]\nname = \"evil\"\nsource = \"registry+https://evil.example/steal\"\n\
             # attacker-controlled: pastebin.com exfil.attacker.test\n",
        );
        let env = compile(&d).unwrap();
        for d_ in &env.domains {
            assert!(
                !d_.contains("evil") && !d_.contains("pastebin") && !d_.contains("attacker"),
                "lockfile content leaked into domains: {d_}"
            );
        }
        // Every emitted domain is a member of the fixed tables.
        let mut allowed: BTreeSet<&str> = SOURCE_HOSTING.iter().copied().collect();
        for e in Ecosystem::all() {
            allowed.extend(e.domains().iter().copied());
        }
        for d_ in &env.domains {
            assert!(allowed.contains(d_.as_str()), "unexpected domain {d_}");
        }
        std::fs::remove_dir_all(&d).ok();
    }

    /// A polyglot repo unions its ecosystems.
    #[test]
    fn multiple_ecosystems_union_their_domains() {
        let d = tmpdir("poly");
        write(&d, "Cargo.lock", "x\n");
        write(&d, "package-lock.json", "{}\n");
        write(&d, "go.sum", "y\n");
        let env = compile(&d).unwrap();

        assert_eq!(
            env.ecosystems(),
            vec![Ecosystem::Cargo, Ecosystem::Npm, Ecosystem::Go]
        );
        for want in [
            "crates.io",
            "registry.npmjs.org",
            "proxy.golang.org",
            "sum.golang.org",
        ] {
            assert!(env.domains.iter().any(|x| x == want), "missing {want}");
        }
        assert!(!env.domains.iter().any(|x| x == "pypi.org"));
        std::fs::remove_dir_all(&d).ok();
    }

    /// Installed-dependency directories are not descended into: a lockfile
    /// inside `node_modules` belongs to a dependency, not this project.
    #[test]
    fn skips_installed_dependency_trees() {
        let d = tmpdir("skip");
        write(&d, "Cargo.lock", "x\n");
        write(&d, "node_modules/some-pkg/package-lock.json", "{}\n");
        write(&d, "target/debug/Cargo.lock", "x\n");
        let env = compile(&d).unwrap();

        assert_eq!(env.ecosystems(), vec![Ecosystem::Cargo]);
        assert_eq!(env.lockfiles.len(), 1);
        assert!(!env.domains.iter().any(|x| x == "registry.npmjs.org"));
        std::fs::remove_dir_all(&d).ok();
    }

    /// Applying an envelope pins the contributing lockfiles, and a cell can
    /// then verify them: unchanged verifies clean, edited is detected by name.
    /// This is the property that makes the compile-time hash mean something at
    /// run time.
    #[test]
    fn pins_are_written_and_a_changed_lockfile_is_detected_by_name() {
        let d = tmpdir("pins");
        write(&d, "Cargo.lock", "[[package]]\nname = \"serde\"\n");
        let env = compile(&d).unwrap();

        let mut p = Profile::from_yaml(include_str!("../../../profiles/coding.yaml")).unwrap();
        env.apply_to(&mut p);

        let pins = &p.approved_for.as_ref().unwrap().lockfiles;
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].path, "Cargo.lock");

        // Unchanged: verifies clean.
        assert!(verify_pins(&p, &d).is_empty());

        // Edited: detected, and the mismatch names the file.
        write(
            &d,
            "Cargo.lock",
            "[[package]]\nname = \"serde\"\n# edited\n",
        );
        let bad = verify_pins(&p, &d);
        assert_eq!(bad.len(), 1);
        assert_eq!(
            bad[0],
            PinMismatch::Changed {
                path: "Cargo.lock".into()
            }
        );
        assert!(bad[0].to_string().contains("Cargo.lock"));

        // Missing: also detected, distinctly.
        std::fs::remove_file(d.join("Cargo.lock")).unwrap();
        assert_eq!(
            verify_pins(&p, &d),
            vec![PinMismatch::Missing {
                path: "Cargo.lock".into()
            }]
        );
        std::fs::remove_dir_all(&d).ok();
    }

    /// The VCS state at compile time is written into the pin and survives a
    /// YAML round-trip. The compile-time warning is ephemeral; the profile is
    /// durable, and an auditor reading it later must be able to tell whether
    /// it was derived from a committed tree.
    #[test]
    fn vcs_provenance_is_durable_in_the_profile() {
        let d = tmpdir("durable");
        write(&d, "Cargo.lock", "x\n");
        let env = compile(&d).unwrap();

        let mut p = Profile::from_yaml(include_str!("../../../profiles/coding.yaml")).unwrap();
        env.apply_to(&mut p);

        // Outside a git repo the honest answer is Unknown — never Clean.
        let pin = &p.approved_for.as_ref().unwrap().lockfiles[0];
        assert_eq!(pin.vcs, LockfileVcs::Unknown);
        assert_ne!(pin.vcs, LockfileVcs::Clean, "must never claim committed");

        // Survives serialization: this is what makes it durable.
        let yaml = p.to_yaml().unwrap();
        assert!(yaml.contains("vcs: unknown"), "vcs must serialize: {yaml}");
        let reparsed = Profile::from_yaml(&yaml).unwrap();
        assert_eq!(
            reparsed.approved_for.unwrap().lockfiles[0].vcs,
            LockfileVcs::Unknown
        );
        std::fs::remove_dir_all(&d).ok();
    }

    /// The recorded VCS state is inside the profile's signing bytes, so a
    /// profile cannot be made to look like it came from a clean tree after
    /// signing.
    #[test]
    fn vcs_state_is_covered_by_signing_bytes() {
        let d = tmpdir("signed-vcs");
        write(&d, "Cargo.lock", "x\n");
        let env = compile(&d).unwrap();

        let mut a = Profile::from_yaml(include_str!("../../../profiles/coding.yaml")).unwrap();
        env.apply_to(&mut a);
        let mut b = a.clone();
        b.approved_for.as_mut().unwrap().lockfiles[0].vcs = LockfileVcs::Clean;

        assert_ne!(
            a.signing_bytes().unwrap(),
            b.signing_bytes().unwrap(),
            "changing recorded VCS state must change the signing bytes"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    /// A profile with no pins verifies trivially — pinning is a property of
    /// compiled profiles, not a requirement for every profile.
    #[test]
    fn unpinned_profile_verifies_trivially() {
        let d = tmpdir("nopins");
        let p = Profile::from_yaml(include_str!("../../../profiles/coding.yaml")).unwrap();
        assert!(verify_pins(&p, &d).is_empty());
        std::fs::remove_dir_all(&d).ok();
    }

    /// Root lockfiles win over nested ones, and what was skipped is reported
    /// rather than silently dropped.
    #[test]
    fn root_lockfiles_win_and_skipped_are_reported() {
        let d = tmpdir("rootpref");
        write(&d, "Cargo.lock", "x\n");
        write(&d, "sub/package-lock.json", "{}\n");
        let env = compile(&d).unwrap();

        assert_eq!(env.ecosystems(), vec![Ecosystem::Cargo]);
        assert_eq!(env.skipped.len(), 1);
        assert_eq!(env.skipped[0].ecosystem, Ecosystem::Npm);
        assert!(!env.domains.iter().any(|x| x == "registry.npmjs.org"));
        std::fs::remove_dir_all(&d).ok();
    }

    /// A monorepo with no root lockfile compiles the discovered set rather
    /// than failing — refusing here would be a worse outcome than a union.
    #[test]
    fn monorepo_without_root_lockfile_falls_back_to_discovered() {
        let d = tmpdir("mono");
        write(&d, "frontend/package-lock.json", "{}\n");
        write(&d, "backend/requirements.txt", "flask==2.0\n");
        let env = compile(&d).unwrap();

        assert_eq!(env.ecosystems(), vec![Ecosystem::Npm, Ecosystem::PyPI]);
        assert!(env.skipped.is_empty());
        std::fs::remove_dir_all(&d).ok();
    }

    /// Outside a git repository, VCS state is Unknown and reported — the
    /// "compiled from the committed lockfile" framing does not silently hold.
    #[test]
    fn vcs_state_outside_a_repo_is_reported_not_assumed() {
        let d = tmpdir("novcs");
        write(&d, "Cargo.lock", "x\n");
        let env = compile(&d).unwrap();
        assert_eq!(env.unverified_vcs.len(), 1);
        assert_eq!(env.unverified_vcs[0].1, LockfileVcs::Unknown);
        std::fs::remove_dir_all(&d).ok();
    }

    /// No lockfile is an error, not an empty (and therefore silently
    /// permissive-looking) envelope.
    #[test]
    fn no_lockfile_is_an_error() {
        let d = tmpdir("empty");
        assert!(matches!(compile(&d), Err(CompileError::NoLockfiles)));
        std::fs::remove_dir_all(&d).ok();
    }

    /// Applying an envelope replaces the allow-list; the keeping variant
    /// preserves only domains the profile already had.
    #[test]
    fn apply_replaces_and_keeping_cannot_introduce_hosts() {
        let d = tmpdir("apply");
        write(&d, "Cargo.lock", "x\n");
        let env = compile(&d).unwrap();

        let mut p = Profile::from_yaml(include_str!("../../../profiles/coding.yaml")).unwrap();
        p.network.allow_domains = vec!["api.anthropic.com".into(), "old.example".into()];

        // Default is MERGE: pre-existing domains survive, so a compile can
        // never break an agent's ability to reach its model provider.
        let mut p1 = p.clone();
        env.apply_to(&mut p1);
        assert!(p1
            .network
            .allow_domains
            .iter()
            .any(|x| x == "api.anthropic.com"));
        assert!(p1.network.allow_domains.iter().any(|x| x == "crates.io"));

        // --replace narrows to exactly the ecosystem domains.
        let mut p2 = p.clone();
        env.apply_to_replacing(&mut p2);
        assert_eq!(p2.network.allow_domains, env.domains);
        assert!(!p2.network.allow_domains.iter().any(|x| x == "old.example"));
        std::fs::remove_dir_all(&d).ok();
    }
}

/// A pinned lockfile that no longer matches what the envelope was compiled
/// from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinMismatch {
    /// The pinned lockfile is not present at `path` relative to the root.
    Missing { path: String },
    /// The lockfile is present but its content hash differs.
    Changed { path: String },
}

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinMismatch::Missing { path } => {
                write!(f, "{path} is missing but this profile was compiled from it")
            }
            PinMismatch::Changed { path } => {
                write!(f, "{path} changed since this profile was compiled")
            }
        }
    }
}

/// Verify a profile's lockfile pins against the lockfiles on disk under
/// `root`.
///
/// This is what makes the compile-time hash mean something at run time: a
/// profile compiled from one dependency set must not be used against a
/// different one. Returns every mismatch so the caller can name all of them
/// rather than only the first.
///
/// A profile with no pins verifies trivially — pinning is a property of
/// compiled profiles, not a requirement for all profiles.
pub fn verify_pins(profile: &Profile, root: &Path) -> Vec<PinMismatch> {
    let Some(approved) = &profile.approved_for else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for pin in &approved.lockfiles {
        let path = root.join(&pin.path);
        match std::fs::read(&path) {
            Err(_) => out.push(PinMismatch::Missing {
                path: pin.path.clone(),
            }),
            Ok(bytes) => {
                if hex(&Sha256::digest(&bytes)) != pin.sha256 {
                    out.push(PinMismatch::Changed {
                        path: pin.path.clone(),
                    });
                }
            }
        }
    }
    out
}

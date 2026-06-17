// crates/ql-cli/src/profile.rs
//
//! `ql profile` — author-time operations on permission profiles.
//!
//! * `ql profile sign <profile.yaml> --key <seed-hex-file> [--out <path>]`
//!   Attach an Ed25519 signature from an authorizing party (e.g. a security
//!   admin). The signature covers the profile's canonical bytes — everything
//!   but the signature field — so a later reader can prove who approved the
//!   policy the kernel will enforce.
//! * `ql profile verify <profile.yaml> [--signer <pubkey-hex>]`
//!   Check the attached signature; with `--signer`, additionally require it to
//!   come from a specific key. Separation of duties: a developer cannot widen a
//!   profile they were handed without invalidating the signature.
//!
//! Mint a signing key with `ql audit keygen --out <file>`.

use ql_profile::{ApprovedFor, Profile, ProfileSignature};
use std::process::ExitCode;

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("sign") => sign(&args[1..]),
        Some("verify") => verify(&args[1..]),
        Some("-h") | Some("--help") | None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("ql profile: unknown subcommand `{other}`");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn sign(args: &[String]) -> ExitCode {
    let mut path: Option<&str> = None;
    let mut key: Option<&str> = None;
    let mut out: Option<&str> = None;
    let mut approve_commit: Option<String> = None;
    let mut approve_image: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--key" => key = it.next().map(String::as_str),
            "--out" => out = it.next().map(String::as_str),
            "--approve-commit" => approve_commit = it.next().cloned(),
            "--approve-image" => approve_image = it.next().cloned(),
            s if !s.starts_with('-') && path.is_none() => path = Some(s),
            other => {
                eprintln!("ql profile sign: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    let Some(path) = path else {
        eprintln!("ql profile sign: a profile path is required");
        return ExitCode::from(2);
    };
    let Some(key) = key else {
        eprintln!("ql profile sign: --key <seed-hex-file> is required");
        return ExitCode::from(2);
    };

    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql profile sign: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let mut profile = match Profile::from_yaml(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ql profile sign: {e}");
            return ExitCode::from(1);
        }
    };
    // If the signer attests an approval context, set it before computing the
    // bytes to sign, so the signature covers it. Flags are authoritative over
    // any approved_for already in the file.
    if approve_commit.is_some() || approve_image.is_some() {
        profile.approved_for = Some(ApprovedFor {
            commit: approve_commit,
            image_digest: approve_image,
        });
    }
    // Sign the canonical bytes (profile minus any existing signature), so
    // re-signing replaces a prior signature rather than nesting under it.
    let bytes = match profile.signing_bytes() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ql profile sign: {e}");
            return ExitCode::from(1);
        }
    };
    let seed = match std::fs::read_to_string(key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql profile sign: cannot read key {key}: {e}");
            return ExitCode::from(2);
        }
    };
    let id = match ql_token::Identity::from_seed_hex(seed.trim()) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("ql profile sign: invalid key {key}: {e}");
            return ExitCode::from(1);
        }
    };
    let pubkey = id.public().to_hex();
    profile.signature = Some(ProfileSignature {
        algorithm: "ed25519".to_string(),
        public_key: pubkey.clone(),
        value: id.sign(&bytes),
    });

    let yaml = match profile.to_yaml() {
        Ok(y) => y,
        Err(e) => {
            eprintln!("ql profile sign: {e}");
            return ExitCode::from(1);
        }
    };
    let dest = out.unwrap_or(path);
    if let Err(e) = std::fs::write(dest, yaml) {
        eprintln!("ql profile sign: cannot write {dest}: {e}");
        return ExitCode::from(2);
    }
    println!(
        "signed {dest} with key {}…",
        &pubkey[..16.min(pubkey.len())]
    );
    ExitCode::SUCCESS
}

fn verify(args: &[String]) -> ExitCode {
    let mut path: Option<&str> = None;
    let mut signer: Option<&str> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--signer" => signer = it.next().map(String::as_str),
            s if !s.starts_with('-') && path.is_none() => path = Some(s),
            other => {
                eprintln!("ql profile verify: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    let Some(path) = path else {
        eprintln!("ql profile verify: a profile path is required");
        return ExitCode::from(2);
    };

    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ql profile verify: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let profile = match Profile::from_yaml(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ql profile verify: {e}");
            return ExitCode::from(1);
        }
    };
    let Some(sig) = profile.signature.clone() else {
        eprintln!("{path}: UNSIGNED — no signature attached");
        return ExitCode::from(1);
    };
    let bytes = match profile.signing_bytes() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ql profile verify: {e}");
            return ExitCode::from(1);
        }
    };
    let pid = match ql_token::PublicId::from_hex(&sig.public_key) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ql profile verify: bad public key in signature: {e}");
            return ExitCode::from(1);
        }
    };
    if pid.verify(&bytes, &sig.value).is_err() {
        eprintln!("{path}: INVALID — signature does not match profile contents");
        return ExitCode::from(1);
    }
    if let Some(expected) = signer {
        if !sig.public_key.eq_ignore_ascii_case(expected) {
            eprintln!(
                "{path}: WRONG SIGNER — signed by {}…, expected {}…",
                &sig.public_key[..16.min(sig.public_key.len())],
                &expected[..16.min(expected.len())]
            );
            return ExitCode::from(1);
        }
    }
    println!(
        "{path}: VALID — signed by {}… ({})",
        &sig.public_key[..16.min(sig.public_key.len())],
        sig.algorithm
    );
    ExitCode::SUCCESS
}

fn print_help() {
    eprintln!(
        "ql profile — author-time operations on permission profiles\n\
         \n\
         USAGE:\n\
         \x20 ql profile sign <profile.yaml> --key <seed-hex-file> [--out <path>]\n\
         \x20                  [--approve-commit <hash>] [--approve-image <digest>]\n\
         \x20 ql profile verify <profile.yaml> [--signer <pubkey-hex>]\n\
         \n\
         The signature covers the profile minus the signature field, so a signed\n\
         profile cannot be widened without invalidating it. Mint a key with\n\
         `ql audit keygen --out <file>`.\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_excluded_from_its_own_bytes() {
        // Attaching a signature must not change the bytes the signature covers,
        // or verification could never round-trip.
        let p = Profile::default();
        let bare = p.signing_bytes().unwrap();
        let mut signed = p.clone();
        signed.signature = Some(ProfileSignature {
            algorithm: "ed25519".to_string(),
            public_key: "ab".to_string(),
            value: "cd".to_string(),
        });
        assert_eq!(bare, signed.signing_bytes().unwrap());
    }

    #[test]
    fn approved_for_is_covered_by_the_signature() {
        // approved_for is part of signing_bytes, so changing it changes the bytes
        // a signature commits to — binding the policy to its approved context.
        let a = Profile {
            approved_for: Some(ApprovedFor {
                commit: Some("aaa".to_string()),
                image_digest: None,
            }),
            ..Default::default()
        };
        let mut b = a.clone();
        b.approved_for = Some(ApprovedFor {
            commit: Some("bbb".to_string()),
            image_digest: None,
        });
        assert_ne!(a.signing_bytes().unwrap(), b.signing_bytes().unwrap());
    }

    #[test]
    fn sign_then_verify_roundtrips_and_detects_tamper() {
        let dir = std::env::temp_dir().join(format!("ql-psign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let profile_path = dir.join("p.yaml");
        std::fs::write(&profile_path, Profile::default().to_yaml().unwrap()).unwrap();

        let id = ql_token::Identity::generate().unwrap();
        let key_path = dir.join("admin.key");
        std::fs::write(&key_path, id.seed_hex()).unwrap();

        // Sign in place.
        let _ = sign(&[
            profile_path.to_str().unwrap().to_string(),
            "--key".to_string(),
            key_path.to_str().unwrap().to_string(),
        ]);

        // The signed profile parses, carries a signature, and verifies.
        let signed = Profile::from_yaml(&std::fs::read_to_string(&profile_path).unwrap()).unwrap();
        let sig = signed.signature.clone().expect("signature attached");
        let pid = ql_token::PublicId::from_hex(&sig.public_key).unwrap();
        let bytes = signed.signing_bytes().unwrap();
        let ok = pid.verify(&bytes, &sig.value).is_ok();
        assert!(ok);

        // Tamper: change the policy after signing — the signature must break.
        let mut tampered = signed.clone();
        tampered.network.default_deny = !tampered.network.default_deny;
        let sig2 = tampered.signature.clone().unwrap();
        let pid2 = ql_token::PublicId::from_hex(&sig2.public_key).unwrap();
        let bytes2 = tampered.signing_bytes().unwrap();
        let broken = pid2.verify(&bytes2, &sig2.value).is_err();
        assert!(broken);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

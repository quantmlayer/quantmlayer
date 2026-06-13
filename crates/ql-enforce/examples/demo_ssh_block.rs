// crates/ql-enforce/examples/demo_ssh_block.rs
//
//! Visible demo of the SSH-key-theft block — the "record the video" artifact.
//!
//! Run with:
//! ```text
//! cargo run -p ql-enforce --example demo_ssh_block
//! ```
//!
//! It plants a fake key, shows it is readable on the host, then shows the same
//! read FAILING inside a QuantmLayer cell — while the host file stays intact.

use ql_enforce::standard_coding_cell;
use ql_profile::Profile;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::temp_dir().join(format!("ql-demo-{}", std::process::id()));
    let ssh = base.join("home/dev/.ssh");
    fs::create_dir_all(&ssh)?;
    let key = ssh.join("id_rsa");
    fs::write(&key, "-----BEGIN OPENSSH PRIVATE KEY-----\n(secret)\n")?;
    let key_str = key.to_str().unwrap().to_string();
    let home_glob = base.join("home").to_str().unwrap().to_string();

    println!("== QuantmLayer demo: blocking SSH-key theft by a coding agent ==\n");

    println!("[host] A coding agent would normally read this freely:");
    println!("       $ cat {key_str}");
    println!("       {}", fs::read_to_string(&key)?.trim());
    println!();

    let mut profile = Profile::from_yaml(include_str!("../../../profiles/coding.yaml"))?;
    profile.filesystem.denied = vec![format!("{home_glob}/**")];

    println!("[cell] Same read, but now inside a QuantmLayer containment cell:");
    println!("       $ quantmlayer run --profile coding -- cat {key_str}");
    print!("       ");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    let cell = standard_coding_cell(profile)?;
    let code = cell.run(&["/bin/cat".into(), key_str.clone()])?;

    println!();
    if code == 0 {
        println!("\n[FAIL] the key was readable inside the cell — containment did not hold.");
    } else {
        println!("\n[OK] the agent could not read the key (exit {code}). Theft blocked.");
    }

    // Prove the host is untouched.
    println!(
        "[host] The real key is still present and intact: {}",
        fs::read_to_string(&key)?.trim()
    );

    let _ = fs::remove_dir_all(&base);
    Ok(())
}

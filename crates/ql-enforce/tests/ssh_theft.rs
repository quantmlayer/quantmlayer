// crates/ql-enforce/tests/ssh_theft.rs
//
//! Integration test: the SSH-key-theft block.
//!
//! This is the load-bearing proof of Step 2. We plant a fake private key under
//! a `/home` path, then run two commands:
//!
//! 1. A `cat` of the key INSIDE a cell — must FAIL (the file is hidden).
//! 2. A control read of a permitted path INSIDE a cell — must SUCCEED.
//!
//! We also assert the host file is untouched afterwards, proving the cage is
//! contained to its namespace.
//!
//! These tests require the ability to create user+mount namespaces. They are
//! marked `#[ignore]` by default so they don't fail in CI environments that
//! forbid unprivileged namespaces; run them explicitly with:
//!
//! ```text
//! cargo test -p ql-enforce -- --ignored
//! ```

use ql_enforce::standard_coding_cell;
use ql_profile::Profile;
use std::fs;
use std::path::Path;

/// Load the bundled coding profile, but retarget its denied/allowed paths to a
/// temp sandbox so the test is hermetic and never touches real user data.
fn test_profile(home_dir: &str, work_dir: &str) -> Profile {
    let mut p = Profile::from_yaml(include_str!("../../../profiles/coding.yaml"))
        .expect("coding.yaml parses");
    // Hide our fake home; allow our temp workspace. Keep it minimal & explicit.
    p.filesystem.denied = vec![format!("{home_dir}/**")];
    p.filesystem.readwrite = vec![format!("{work_dir}/**")];
    p
}

#[test]
#[ignore = "requires unprivileged user+mount namespaces; run with --ignored"]
fn ssh_key_theft_is_blocked_inside_cell() {
    // Arrange: a fake home with a planted private key, and a workspace file.
    let base = std::env::temp_dir().join(format!("ql-test-{}", std::process::id()));
    let home = base.join("home/victim");
    let ssh = home.join(".ssh");
    let work = base.join("workspace");
    fs::create_dir_all(&ssh).unwrap();
    fs::create_dir_all(&work).unwrap();
    let key_path = ssh.join("id_rsa");
    fs::write(&key_path, "TOP_SECRET_PRIVATE_KEY").unwrap();
    fs::write(work.join("ok.txt"), "safe to read").unwrap();

    let home_str = base.join("home").to_str().unwrap().to_string();
    let work_str = work.to_str().unwrap().to_string();
    let key_str = key_path.to_str().unwrap().to_string();

    // Act 1: try to read the key inside the cell. Expect non-zero (blocked).
    let profile = test_profile(&home_str, &work_str);
    let cell = standard_coding_cell(profile).expect("cell builds");
    let theft_code = cell
        .run(&["/bin/cat".into(), key_str.clone()])
        .expect("cell runs");

    assert_ne!(
        theft_code, 0,
        "reading the SSH key inside the cell must FAIL, but cat exited 0"
    );

    // Act 2: control — reading a permitted workspace file should succeed.
    let profile2 = test_profile(&home_str, &work_str);
    let cell2 = standard_coding_cell(profile2).expect("cell builds");
    let ok_code = cell2
        .run(&[
            "/bin/cat".into(),
            work.join("ok.txt").to_str().unwrap().to_string(),
        ])
        .expect("cell runs");
    assert_eq!(ok_code, 0, "reading a permitted file should succeed");

    // Assert: the host file is untouched — containment stayed in its namespace.
    assert!(
        Path::new(&key_str).exists(),
        "host key file must still exist after the cell ran"
    );
    assert_eq!(
        fs::read_to_string(&key_str).unwrap(),
        "TOP_SECRET_PRIVATE_KEY",
        "host key contents must be unchanged"
    );

    // Cleanup.
    let _ = fs::remove_dir_all(&base);
}

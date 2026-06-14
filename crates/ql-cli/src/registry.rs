// crates/ql-cli/src/registry.rs
//
//! A tiny on-disk registry of running cells, so `ql ps` can list them and
//! `ql kill` can target one from another terminal.
//!
//! Each `ql run` writes one handle file (its own pid plus metadata) into a
//! per-user runtime directory, and removes it when the agent exits. The handle
//! records the `ql run` pid — the parent of the contained agent — because
//! killing that process tree revokes the agent and everything it spawned.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A registered, running cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handle {
    pub id: String,
    /// The `ql run` process pid (parent of the contained agent).
    pub pid: u32,
    pub command: String,
    pub profile: String,
    pub started_ms: u64,
    pub brokered: bool,
}

/// Per-user runtime directory for handles. Prefers `$XDG_RUNTIME_DIR`, falls
/// back to a uid-scoped temp dir so it never collides between users.
pub fn runtime_dir() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_RUNTIME_DIR") {
        if !x.is_empty() {
            return PathBuf::from(x).join("quantmlayer");
        }
    }
    let uid = unsafe { libc::getuid() };
    std::env::temp_dir().join(format!("quantmlayer-{uid}"))
}

fn handle_path(id: &str) -> PathBuf {
    runtime_dir().join(format!("{id}.json"))
}

/// Write a handle for a running cell.
pub fn register(h: &Handle) -> std::io::Result<()> {
    let dir = runtime_dir();
    std::fs::create_dir_all(&dir)?;
    let json = serde_json::to_string(h).unwrap_or_default();
    std::fs::write(handle_path(&h.id), json)
}

/// Remove a handle (cell has exited or been killed).
pub fn deregister(id: &str) {
    let _ = std::fs::remove_file(handle_path(id));
}

/// Look up one handle by id.
pub fn get(id: &str) -> Option<Handle> {
    let s = std::fs::read_to_string(handle_path(id)).ok()?;
    serde_json::from_str(&s).ok()
}

/// All registered handles (may include stale ones; check [`pid_alive`]).
pub fn list() -> Vec<Handle> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(runtime_dir()) {
        for e in rd.flatten() {
            if e.path().extension().is_some_and(|x| x == "json") {
                if let Ok(s) = std::fs::read_to_string(e.path()) {
                    if let Ok(h) = serde_json::from_str::<Handle>(&s) {
                        out.push(h);
                    }
                }
            }
        }
    }
    out.sort_by_key(|a| a.started_ms);
    out
}

/// Is `pid` still a live process? (`kill(pid, 0)`: Ok or EPERM => alive.)
pub fn pid_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as i32, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

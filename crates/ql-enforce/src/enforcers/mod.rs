// crates/ql-enforce/src/enforcers/mod.rs
//
//! Concrete [`crate::Enforcer`] implementations — one containment wall each.
//!
//! Adding a new wall means adding a module here and a re-export below; no
//! existing enforcer is modified. Current walls:
//!
//! * [`namespace::NamespaceEnforcer`] — fresh user + mount namespaces.
//! * [`mount::MountEnforcer`] — hides denied filesystem paths.
//! * [`cgroup::CgroupEnforcer`] — caps process count and memory (anti fork-bomb).
//! * [`seccomp::SeccompEnforcer`] — blocks never-legitimate syscalls.
//! * [`network::NetworkEnforcer`] — default-deny network (anti SSRF/metadata).
//!
//! Planned (later steps): capabilities, landlock. (Allow-listed egress is
//! provided by the separate `ql-broker` crate, not as an enforcer here.)

pub mod cgroup;
pub mod mount;
pub mod namespace;
pub mod network;
pub mod seccomp;

pub use cgroup::CgroupEnforcer;
pub use mount::MountEnforcer;
pub use namespace::NamespaceEnforcer;
pub use network::NetworkEnforcer;
pub use seccomp::SeccompEnforcer;

// crates/ql-broker/src/lib.rs
//
//! # ql-broker
//!
//! The QuantmLayer egress broker: an HTTP `CONNECT` proxy that enforces a
//! profile's network policy. It is the *allow-list* half of the network story
//! — `ql-enforce`'s network namespace provides the default-deny floor (no raw
//! route off-host), and this broker provides the narrow, audited path out for
//! the domains a profile permits, while refusing private/link-local addresses
//! (defeating cloud-metadata SSRF and DNS-rebinding).
//!
//! Unlike `ql-enforce`, this crate is pure userspace with no OS-specific code,
//! so the same broker runs anywhere the agent's control plane runs.
//!
//! ```no_run
//! use ql_broker::{BrokerPolicy, serve};
//! use std::net::TcpListener;
//! use std::sync::Arc;
//!
//! # fn main() -> std::io::Result<()> {
//! let profile = ql_profile::Profile::from_yaml(/* ... */ "schema_version: 1\nagent_type: coding").unwrap();
//! let policy = Arc::new(BrokerPolicy::from_net_policy(&profile.network));
//! let listener = TcpListener::bind("127.0.0.1:0")?;
//! serve(listener, policy)?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod nonce;
mod policy;
mod proxy;

pub use policy::{is_blocked_ip, AuditSink, BrokerPolicy, Decision};
pub use proxy::{handle_connection, serve};

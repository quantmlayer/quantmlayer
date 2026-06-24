// crates/ql-enforce/src/enforcers/network.rs
//
//! [`NetworkEnforcer`]: cuts the agent off from the network by default.
//!
//! This is the wall that stops cloud-metadata SSRF (`169.254.169.254` →
//! steal IAM credentials) and reaching internal/private services. It places
//! the agent in a fresh **network namespace** (`CLONE_NEWNET`). A new network
//! namespace contains only a loopback device and *no route to anything else*,
//! so the agent has no egress at all: it cannot reach the metadata endpoint,
//! private RFC-1918 ranges, or the public internet.
//!
//! ## Default-deny, then broker
//!
//! This implements the profile's `default_deny: true` (and trivially its
//! `block_private_ranges: true`, since nothing is routable). The complementary
//! piece — *allow-listed* egress for `allow_domains` (e.g. letting an agent
//! reach `pypi.org` but not the metadata endpoint) — is provided by the
//! `ql-broker` crate: an HTTP `CONNECT` proxy that checks the destination
//! domain against the allow-list and refuses private/link-local IPs. Wired in,
//! the agent's netns routes only to the broker (`HTTPS_PROXY=http://<broker>`),
//! so the broker is the single, audited egress point. Default-deny here is the
//! security floor; the broker opens the narrow, vetted path out.
//!
//! ## Loopback
//!
//! A freshly created network namespace starts with loopback **down**. Many
//! contained programs expect a working `127.0.0.1`, so we bring `lo` up
//! (best-effort). This does not weaken isolation: loopback never leaves the
//! namespace.

use crate::context::ChildContext;
use crate::enforcer::Enforcer;
use crate::error::Result;
use nix::sched::CloneFlags;
use ql_profile::Profile;

/// Isolates the agent's network: a private network namespace with no uplink.
#[derive(Debug, Default)]
pub struct NetworkEnforcer {
    /// When set (brokered mode), the agent is given a `veth` uplink to the
    /// broker by the cell's parent hook, and these proxy environment variables
    /// are exported so its HTTP(S) traffic flows through the broker.
    proxy_url: Option<String>,
}

impl NetworkEnforcer {
    /// Create a default-deny network enforcer (no egress).
    pub fn new() -> Self {
        NetworkEnforcer { proxy_url: None }
    }

    /// Create a brokered network enforcer: the netns is still created (and a
    /// veth uplink is wired by the cell's parent hook), and the agent's
    /// `HTTPS_PROXY`/`HTTP_PROXY` are pointed at `proxy_url` so its egress is
    /// allow-list enforced by the broker.
    pub fn with_proxy(proxy_url: String) -> Self {
        NetworkEnforcer {
            proxy_url: Some(proxy_url),
        }
    }

    /// Bring the loopback interface up inside the current network namespace.
    ///
    /// Uses the classic `SIOCSIFFLAGS` ioctl. Best-effort: a failure here does
    /// not weaken the security property (no external route exists regardless),
    /// so we log and continue rather than fail the cell closed.
    fn bring_loopback_up() -> Result<()> {
        // ifreq layout for the flags ioctls: a 16-byte interface name followed
        // by the flags union. We pad to the full `struct ifreq` size (40 bytes
        // on 64-bit Linux) so the kernel reads/writes within our buffer.
        #[repr(C)]
        struct IfReqFlags {
            name: [libc::c_char; libc::IFNAMSIZ],
            flags: libc::c_short,
            _pad: [u8; 22],
        }

        // SAFETY: we open a datagram socket purely as an ioctl handle, issue
        // two well-formed ioctls against a correctly-sized ifreq, and close it.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if fd < 0 {
                return Ok(()); // best-effort: cannot get a handle, skip.
            }

            let mut req = IfReqFlags {
                name: [0; libc::IFNAMSIZ],
                flags: 0,
                _pad: [0; 22],
            };
            // Interface name "lo".
            req.name[0] = b'l' as libc::c_char;
            req.name[1] = b'o' as libc::c_char;

            // Read current flags, then OR in UP|RUNNING and write them back.
            if libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut req) == 0 {
                req.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
                let _ = libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &req);
            }
            libc::close(fd);
        }
        Ok(())
    }
}

impl Enforcer for NetworkEnforcer {
    fn name(&self) -> &'static str {
        "network"
    }

    /// Phase 1 (parent): request a network namespace whenever the profile
    /// denies network by default. If a profile opted into open networking
    /// (`default_deny: false`), we request nothing and the agent shares the
    /// host network.
    fn required_namespaces(&self, profile: &Profile) -> CloneFlags {
        if profile.network.default_deny {
            CloneFlags::CLONE_NEWNET
        } else {
            CloneFlags::empty()
        }
    }

    /// Phase 2b (in-namespace): bring loopback up inside the new netns. The
    /// isolation itself comes from the namespace having no other interface;
    /// this step only restores a usable `127.0.0.1`.
    fn apply_in_namespace(&self, profile: &Profile, _ctx: &ChildContext) -> Result<()> {
        if profile.network.default_deny {
            Self::bring_loopback_up()?;
        }
        // Brokered mode: export proxy variables so the agent's HTTP(S) egress
        // is directed at the broker (the only reachable address). We set both
        // upper- and lower-case forms, since tools disagree on which they read.
        if let Some(url) = &self.proxy_url {
            for key in [
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy",
                "ALL_PROXY",
            ] {
                std::env::set_var(key, url);
            }
            // The metadata IP and broker host must never be proxied around; but
            // we keep NO_PROXY empty here so *everything* goes via the broker.
            std::env::set_var("NO_PROXY", "");
            std::env::set_var("no_proxy", "");
        }
        Ok(())
    }
}

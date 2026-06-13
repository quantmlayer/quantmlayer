// crates/ql-broker/src/policy.rs
//
//! The egress policy engine — the broker's brain.
//!
//! Given a destination host (and, after resolution, its IP addresses), this
//! decides whether the agent may reach it. Two independent checks must both
//! pass:
//!
//! 1. **Allow-list** (`default_deny` + `allow_domains`): the host must match an
//!    allowed domain. Checked *before* DNS so a denied host never even triggers
//!    a lookup.
//! 2. **Private-range block** (`block_private_ranges`): none of the resolved
//!    IPs may be loopback, RFC-1918 private, link-local (this is where the
//!    cloud-metadata endpoint `169.254.169.254` lives), CGNAT, or other
//!    non-public space. This second check defeats DNS-rebinding, where an
//!    allow-listed name resolves to an internal address.
//!
//! The IP checks are written out explicitly on octets/segments rather than
//! relying on unstable standard-library helpers, because this is exactly the
//! kind of security-critical logic that should be auditable at a glance.

use ql_profile::NetPolicy;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The outcome of evaluating a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The destination is permitted.
    Allow,
    /// The destination is refused, with a short human-readable reason.
    Deny(&'static str),
}

/// An egress policy compiled from a profile's [`NetPolicy`].
#[derive(Debug, Clone)]
pub struct BrokerPolicy {
    default_deny: bool,
    allow_domains: Vec<String>,
    block_private_ranges: bool,
}

impl BrokerPolicy {
    /// Build a broker policy from a profile's network section.
    pub fn from_net_policy(np: &NetPolicy) -> Self {
        BrokerPolicy {
            default_deny: np.default_deny,
            allow_domains: np.allow_domains.clone(),
            block_private_ranges: np.block_private_ranges,
        }
    }

    /// Is this host permitted by the allow-list (ignoring its resolved IPs)?
    ///
    /// A host matches a domain `d` if it equals `d` or is a subdomain
    /// (`*.d`). When `default_deny` is false the allow-list is not consulted.
    pub fn host_allowed(&self, host: &str) -> bool {
        if !self.default_deny {
            return true;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.allow_domains.iter().any(|d| {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            host == d || host.ends_with(&format!(".{d}"))
        })
    }

    /// Evaluate a destination given its host and the IPs it resolved to.
    pub fn evaluate(&self, host: &str, resolved: &[IpAddr]) -> Decision {
        if !self.host_allowed(host) {
            return Decision::Deny("host not in allow-list");
        }
        if self.block_private_ranges {
            if resolved.is_empty() {
                return Decision::Deny("host did not resolve");
            }
            if resolved.iter().any(is_blocked_ip) {
                return Decision::Deny("resolves to a private/link-local address");
            }
        }
        Decision::Allow
    }
}

/// Is this IP in a range an agent must never reach directly?
///
/// Covers loopback, the cloud-metadata link-local range, RFC-1918, CGNAT,
/// documentation/benchmark ranges, multicast/reserved, and the IPv6
/// equivalents (including IPv4-mapped addresses, to prevent bypass).
pub fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(ip: &Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    matches!(
        (a, b),
        (0, _)              // 0.0.0.0/8 "this network"
        | (10, _)           // 10.0.0.0/8 private
        | (100, 64..=127)   // 100.64.0.0/10 CGNAT
        | (127, _)          // 127.0.0.0/8 loopback
        | (169, 254)        // 169.254.0.0/16 link-local — cloud metadata
        | (172, 16..=31)    // 172.16.0.0/12 private
        | (192, 168)        // 192.168.0.0/16 private
        | (198, 18..=19)    // 198.18.0.0/15 benchmarking
        | (224..=239, _)    // 224.0.0.0/4 multicast
        | (240..=255, _)    // 240.0.0.0/4 reserved + 255.255.255.255 broadcast
    )
        // Documentation ranges (TEST-NET-1/2/3) — never legitimate egress.
        || matches!(ip.octets(), [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
        // 192.0.0.0/24 IETF protocol assignments.
        || matches!(ip.octets(), [192, 0, 0, _])
}

fn is_blocked_v6(ip: &Ipv6Addr) -> bool {
    // IPv4-mapped (::ffff:a.b.c.d): unwrap and apply the v4 rules so a mapped
    // private address cannot slip through.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_v4(&v4);
    }
    let s = ip.segments();
    *ip == Ipv6Addr::LOCALHOST        // ::1 loopback
        || *ip == Ipv6Addr::UNSPECIFIED // ::
        || (s[0] & 0xfe00) == 0xfc00   // fc00::/7 unique-local
        || (s[0] & 0xffc0) == 0xfe80   // fe80::/10 link-local
        || (s[0] & 0xff00) == 0xff00   // ff00::/8 multicast
        || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_metadata_and_private_v4() {
        for s in [
            "169.254.169.254", // cloud metadata
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "192.0.2.2", // TEST-NET-1 (our sandbox's own IP)
        ] {
            assert!(is_blocked_ip(&ip(s)), "{s} should be blocked");
        }
    }

    #[test]
    fn allows_public_v4() {
        for s in ["8.8.8.8", "1.1.1.1", "151.101.0.223"] {
            assert!(!is_blocked_ip(&ip(s)), "{s} should be allowed");
        }
    }

    #[test]
    fn blocks_private_v6_including_mapped() {
        for s in [
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_blocked_ip(&ip(s)), "{s} should be blocked");
        }
        assert!(
            !is_blocked_ip(&ip("2606:4700:4700::1111")),
            "public v6 allowed"
        );
    }

    #[test]
    fn allow_list_matches_subdomains_only_on_boundary() {
        let p = BrokerPolicy {
            default_deny: true,
            allow_domains: vec!["pypi.org".into()],
            block_private_ranges: true,
        };
        assert!(p.host_allowed("pypi.org"));
        assert!(p.host_allowed("files.pypi.org"));
        assert!(!p.host_allowed("evil.com"));
        assert!(!p.host_allowed("notpypi.org")); // no false suffix match
    }

    #[test]
    fn evaluate_combines_both_checks() {
        let p = BrokerPolicy {
            default_deny: true,
            allow_domains: vec!["pypi.org".into()],
            block_private_ranges: true,
        };
        // Allowed host, public IP → allow.
        assert_eq!(
            p.evaluate("pypi.org", &[ip("151.101.0.223")]),
            Decision::Allow
        );
        // Allowed host that resolves to a private IP (rebinding) → deny.
        assert_eq!(
            p.evaluate("pypi.org", &[ip("169.254.169.254")]),
            Decision::Deny("resolves to a private/link-local address")
        );
        // Disallowed host → deny before resolution matters.
        assert_eq!(
            p.evaluate("169.254.169.254", &[ip("169.254.169.254")]),
            Decision::Deny("host not in allow-list")
        );
    }
}

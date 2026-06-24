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

use crate::nonce::{NonceCheck, NonceStore};
use ql_audit::{AuditEvent, AuditLog, Decision as AuditDecision, SystemIdentity};
use ql_profile::NetPolicy;
use ql_token::{authorize, Action, AuthzRequest, PublicId};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// The outcome of evaluating a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The destination is permitted.
    Allow,
    /// The destination is refused, with a short human-readable reason.
    Deny(&'static str),
}

/// A serialized, tamper-evident sink for egress decisions. Appends are
/// serialized through a mutex so concurrent connections cannot corrupt the
/// hash chain.
#[derive(Debug)]
pub struct AuditSink {
    path: PathBuf,
    lock: Mutex<()>,
}

impl AuditSink {
    /// Create a sink writing to `path`.
    pub fn new(path: impl Into<PathBuf>) -> Arc<Self> {
        Arc::new(AuditSink {
            path: path.into(),
            lock: Mutex::new(()),
        })
    }

    fn record(&self, ev: AuditEvent) {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut log = std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|s| AuditLog::from_jsonl(&s).ok())
            .unwrap_or_default();
        if log.append(ev).is_ok() {
            if let Ok(text) = log.to_jsonl() {
                let _ = std::fs::write(&self.path, text);
            }
        }
    }
}

/// An egress policy compiled from a profile's [`NetPolicy`].
#[derive(Debug, Clone)]
pub struct BrokerPolicy {
    default_deny: bool,
    allow_domains: Vec<String>,
    block_private_ranges: bool,
    /// Trusted root authorities for token-gated egress. Empty means token
    /// gating is off and only the static allow-list applies.
    trusted_roots: Vec<PublicId>,
    /// Optional tamper-evident audit sink for egress decisions.
    audit: Option<Arc<AuditSink>>,
    /// The AI system egress decisions are attributed to in the audit log (EU AI
    /// Act Article 12 actor identity). `None` leaves the records unattributed.
    system: Option<SystemIdentity>,
    /// Per-leaf-token anti-replay state for token-gated egress, shared across
    /// connection threads. A signed action is admitted only if its nonce is
    /// fresh for its leaf token (see [`crate::nonce`]).
    nonce_store: Arc<NonceStore>,
    /// Canary (honeytoken) destinations: hosts nothing legitimate should ever
    /// contact. A CONNECT to one is, by construction, an exfiltration/misuse
    /// attempt — denied unconditionally and recorded as a distinct, high-signal
    /// `canary.triggered` event, ahead of and regardless of the allow-list or
    /// token gate. Empty means the feature is off.
    canary_destinations: Vec<String>,
    /// Optional label for the planted canary, recorded in the trip's audit detail.
    canary_id: Option<String>,
}

impl BrokerPolicy {
    /// Build a broker policy from a profile's network section.
    pub fn from_net_policy(np: &NetPolicy) -> Self {
        BrokerPolicy {
            default_deny: np.default_deny,
            allow_domains: np.allow_domains.clone(),
            block_private_ranges: np.block_private_ranges,
            trusted_roots: Vec::new(),
            audit: None,
            system: None,
            nonce_store: Arc::new(NonceStore::new()),
            canary_destinations: Vec::new(),
            canary_id: None,
        }
    }

    /// Require a valid signed delegation token for egress, rooted in one of
    /// `roots`. With this set, the static allow-list is replaced by the token's
    /// capability (the private-range block still always applies).
    pub fn with_token_gating(mut self, roots: Vec<PublicId>) -> Self {
        self.trusted_roots = roots;
        self
    }

    /// Record every egress decision to a tamper-evident audit log.
    pub fn with_audit(mut self, sink: Arc<AuditSink>) -> Self {
        self.audit = Some(sink);
        self
    }

    /// Attribute audited egress decisions to an AI system (EU AI Act Art. 12).
    pub fn with_system(mut self, system: SystemIdentity) -> Self {
        self.system = Some(system);
        self
    }

    /// Register canary (honeytoken) destinations. Any CONNECT to one is a
    /// tripwire: always denied and recorded as a distinct, high-signal
    /// `canary.triggered` event, ahead of and regardless of the allow-list or
    /// token gate. `id` is an optional label for the planted credential, carried
    /// in the audit detail. Additive; an empty host list leaves the feature off.
    pub fn with_canaries(mut self, hosts: Vec<String>, id: Option<String>) -> Self {
        self.canary_destinations = hosts;
        self.canary_id = id;
        self
    }

    /// Is token-gating enabled?
    pub fn token_gated(&self) -> bool {
        !self.trusted_roots.is_empty()
    }

    /// Decide whether a CONNECT to `host:port` is authorized, given the optional
    /// authorization blob from the request. In token-gated mode the blob must
    /// carry a valid chain + signed `net.connect` action for `host`; otherwise
    /// the static allow-list decides. Every decision is audit-logged if a sink
    /// is configured.
    pub fn authorize_connect(
        &self,
        host: &str,
        port: u16,
        auth: Option<&str>,
        now_ms: u64,
    ) -> Decision {
        // Canary tripwire takes precedence over every other rule. A connection to
        // a canary destination is, by construction, an exfiltration/misuse attempt,
        // so it is refused before the allow-list or token gate is even consulted
        // (and, like every deny, before any DNS lookup). It is recorded as a
        // distinct, high-signal `canary.triggered` event rather than a generic
        // egress deny, and so it returns here without falling through to the
        // ordinary `egress.connect` logging below.
        if self.is_canary(host) {
            self.record_canary(host, port);
            return Decision::Deny("canary destination (exfiltration attempt blocked)");
        }

        let decision = if self.token_gated() {
            match auth {
                None => Decision::Deny("missing authorization token"),
                Some(blob) => match AuthzRequest::from_hex(blob) {
                    Err(_) => Decision::Deny("malformed authorization token"),
                    Ok(req) => match authorize(&req, &self.trusted_roots, now_ms) {
                        Ok(Action::NetConnect { domain }) if host_matches(host, &domain) => {
                            // Chain and action are valid and authorize this
                            // host; the final gate is per-leaf anti-replay.
                            self.admit_unless_replay(&req, now_ms)
                        }
                        Ok(_) => Decision::Deny("token does not authorize this host"),
                        Err(_) => Decision::Deny("invalid authorization token"),
                    },
                },
            }
        } else if self.host_allowed(host) {
            Decision::Allow
        } else {
            Decision::Deny("host not in allow-list")
        };

        if let Some(sink) = &self.audit {
            let (dec, detail) = match &decision {
                Decision::Allow => (AuditDecision::Allow, String::new()),
                Decision::Deny(r) => (AuditDecision::Deny, r.to_string()),
            };
            sink.record(AuditEvent {
                ts_millis: AuditLog::now_millis(),
                actor: "broker".into(),
                action: "egress.connect".into(),
                target: format!("{host}:{port}"),
                decision: dec,
                detail,
                system: self.system.clone(),
            });
        }
        decision
    }

    /// Per-leaf anti-replay gate. The signed action commits to its leaf token,
    /// so `(leaf hash, nonce)` is the replay key: admit the action iff that
    /// nonce is fresh for the leaf, otherwise refuse it as a replayed token.
    /// Assumes the chain was already verified by `authorize` (hence non-empty).
    fn admit_unless_replay(&self, req: &AuthzRequest, now_ms: u64) -> Decision {
        let leaf = req
            .chain
            .last()
            .expect("authorize verified a non-empty chain");
        match self.nonce_store.check_and_record(
            &leaf.hash(),
            req.action.body.nonce,
            leaf.body.not_after_ms,
            now_ms,
        ) {
            NonceCheck::Fresh => Decision::Allow,
            NonceCheck::Replay => Decision::Deny("replayed authorization token"),
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

    /// Does `host` match a registered canary destination? Uses the same
    /// exact/`*.suffix` semantics as the allow-list ([`host_matches`]) so a
    /// canary covers its subdomains too, and so there is only one host matcher.
    fn is_canary(&self, host: &str) -> bool {
        self.canary_destinations
            .iter()
            .any(|c| host_matches(host, c))
    }

    /// Record a tripped canary as a distinct, high-signal `canary.triggered`
    /// event in the same tamper-evident log as every other egress decision, so
    /// `ql audit verify` covers it and a reviewer sees it in sequence. No-op when
    /// no audit sink is configured (the trip is still denied regardless).
    fn record_canary(&self, host: &str, port: u16) {
        if let Some(sink) = &self.audit {
            let detail = match &self.canary_id {
                Some(id) => format!("canary_id={id} verdict=blocked (exfiltration attempt)"),
                None => "verdict=blocked (exfiltration attempt)".to_string(),
            };
            sink.record(AuditEvent {
                ts_millis: AuditLog::now_millis(),
                actor: "broker".into(),
                action: "canary.triggered".into(),
                target: format!("{host}:{port}"),
                decision: AuditDecision::Deny,
                detail,
                system: self.system.clone(),
            });
        }
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

/// Does `host` match a granted `domain` (exact or subdomain)?
fn host_matches(host: &str, domain: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    h == d || h.ends_with(&format!(".{d}"))
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
            trusted_roots: vec![],
            audit: None,
            system: None,
            nonce_store: Arc::new(NonceStore::new()),
            canary_destinations: vec![],
            canary_id: None,
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
            trusted_roots: vec![],
            audit: None,
            system: None,
            nonce_store: Arc::new(NonceStore::new()),
            canary_destinations: vec![],
            canary_id: None,
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

    fn net(allow: &[&str]) -> NetPolicy {
        NetPolicy {
            default_deny: true,
            allow_domains: allow.iter().map(|s| s.to_string()).collect(),
            block_private_ranges: true,
        }
    }

    /// A canary destination is denied as a tripwire and takes precedence over the
    /// allow-list: even when the same host is explicitly allow-listed, the canary
    /// check (which runs first) refuses it. Subdomains of a canary trip it too.
    #[test]
    fn canary_denies_and_outranks_allow_list() {
        let canary = "canary.test";
        // The canary host is ALSO allow-listed here, so a pass means the canary
        // check ran first and outranked the allow-list.
        let p = BrokerPolicy::from_net_policy(&net(&[canary, "pypi.org"]))
            .with_canaries(vec![canary.into()], Some("aws-key-7".into()));
        let tripped = Decision::Deny("canary destination (exfiltration attempt blocked)");

        let on_canary = p.authorize_connect(canary, 443, None, 0);
        let on_sub = p.authorize_connect("sub.canary.test", 443, None, 0);
        let on_allowed = p.authorize_connect("pypi.org", 443, None, 0);
        let on_other = p.authorize_connect("evil.com", 443, None, 0);

        assert_eq!(on_canary, tripped); // allow-listed, but the canary wins
        assert_eq!(on_sub, tripped); // subdomains of a canary trip too
        assert_eq!(on_allowed, Decision::Allow); // a normal host is unaffected
        assert_eq!(on_other, Decision::Deny("host not in allow-list")); // plain deny
    }

    /// A canary trip writes exactly one distinct `canary.triggered` record (and no
    /// generic `egress.connect`), chained into the tamper-evident log.
    #[test]
    fn canary_emits_one_distinct_audit_event() {
        let dir = std::env::temp_dir().join(format!("qlbk-canary-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("egress.jsonl");
        let _ = std::fs::remove_file(&log);

        let p = BrokerPolicy::from_net_policy(&net(&["pypi.org"]))
            .with_canaries(vec!["canary.test".into()], Some("aws-key-7".into()))
            .with_audit(AuditSink::new(&log));
        let _ = p.authorize_connect("canary.test", 443, None, 0);

        let text = std::fs::read_to_string(&log).unwrap();
        let parsed = AuditLog::from_jsonl(&text).unwrap();
        assert!(parsed.verify().is_ok());

        let mut trips = 0;
        let mut generic = 0;
        for r in parsed.records() {
            match r.event.action.as_str() {
                "canary.triggered" => {
                    trips += 1;
                    assert_eq!(r.event.target, "canary.test:443");
                    assert!(matches!(r.event.decision, AuditDecision::Deny));
                    assert!(r.event.detail.contains("aws-key-7"));
                }
                "egress.connect" => generic += 1,
                _ => {}
            }
        }
        // Exactly one distinct event; the canary path short-circuits generic logging.
        assert_eq!(trips, 1);
        assert_eq!(generic, 0);
        let _ = std::fs::remove_file(&log);
    }
}

#[cfg(test)]
mod token_gating_tests {
    use super::*;
    use ql_token::{delegate, issue_root, sign_action, Capability, Identity, SignedAction, Token};

    fn gated_policy(roots: Vec<PublicId>) -> BrokerPolicy {
        BrokerPolicy {
            default_deny: true,
            allow_domains: vec![],
            block_private_ranges: true,
            trusted_roots: roots,
            audit: None,
            system: None,
            nonce_store: Arc::new(NonceStore::new()),
            canary_destinations: vec![],
            canary_id: None,
        }
    }

    /// Mint an authorization: root grants `agent` net access to `domain`, then
    /// `agent` signs a connect action for `connect_host`.
    fn authz(root: &Identity, agent: &Identity, domain: &str, connect_host: &str) -> String {
        let cap = Capability {
            net_domains: vec![domain.into()],
            ..Default::default()
        };
        let rt = issue_root(root, &agent.public(), cap, 0).unwrap();
        let action = sign_action(
            agent,
            Action::NetConnect {
                domain: connect_host.into(),
            },
            &rt.hash(),
            1,
        )
        .unwrap();
        ql_token::AuthzRequest {
            chain: vec![rt],
            action,
        }
        .to_hex()
        .unwrap()
    }

    #[test]
    fn valid_token_authorizes_its_granted_host() {
        let root = Identity::generate().unwrap();
        let agent = Identity::generate().unwrap();
        let p = gated_policy(vec![root.public()]);
        let blob = authz(&root, &agent, "pypi.org", "pypi.org");
        assert_eq!(
            p.authorize_connect("pypi.org", 443, Some(&blob), 0),
            Decision::Allow
        );
    }

    #[test]
    fn replayed_authorization_is_rejected() {
        let root = Identity::generate().unwrap();
        let agent = Identity::generate().unwrap();
        let p = gated_policy(vec![root.public()]);
        // authz mints nonce 1; this first presentation is fresh and allowed.
        let blob = authz(&root, &agent, "pypi.org", "pypi.org");
        assert_eq!(
            p.authorize_connect("pypi.org", 443, Some(&blob), 0),
            Decision::Allow
        );
        // Re-presenting the identical signed action (same leaf, same nonce) is a
        // replay and is refused — even though the token itself is still valid.
        assert_eq!(
            p.authorize_connect("pypi.org", 443, Some(&blob), 0),
            Decision::Deny("replayed authorization token")
        );
    }

    #[test]
    fn fresh_nonce_admitted_then_old_nonce_replays() {
        let root = Identity::generate().unwrap();
        let agent = Identity::generate().unwrap();
        let p = gated_policy(vec![root.public()]);

        // Several actions on the SAME leaf token, signed with rising nonces.
        let cap = Capability {
            net_domains: vec!["pypi.org".into()],
            ..Default::default()
        };
        let rt = issue_root(&root, &agent.public(), cap, 0).unwrap();
        let blob_with = |nonce: u64| {
            let action = sign_action(
                &agent,
                Action::NetConnect {
                    domain: "pypi.org".into(),
                },
                &rt.hash(),
                nonce,
            )
            .unwrap();
            ql_token::AuthzRequest {
                chain: vec![rt.clone()],
                action,
            }
            .to_hex()
            .unwrap()
        };

        // nonce 1 then nonce 2: both fresh, both admitted.
        assert_eq!(
            p.authorize_connect("pypi.org", 443, Some(&blob_with(1)), 0),
            Decision::Allow
        );
        assert_eq!(
            p.authorize_connect("pypi.org", 443, Some(&blob_with(2)), 0),
            Decision::Allow
        );
        // Returning to nonce 1 is now a replay (below the high-water mark).
        assert_eq!(
            p.authorize_connect("pypi.org", 443, Some(&blob_with(1)), 0),
            Decision::Deny("replayed authorization token")
        );
    }

    #[test]
    fn missing_token_is_denied_when_gated() {
        let root = Identity::generate().unwrap();
        let p = gated_policy(vec![root.public()]);
        assert_eq!(
            p.authorize_connect("pypi.org", 443, None, 0),
            Decision::Deny("missing authorization token")
        );
    }

    #[test]
    fn token_for_other_host_does_not_authorize() {
        let root = Identity::generate().unwrap();
        let agent = Identity::generate().unwrap();
        let p = gated_policy(vec![root.public()]);
        // granted + signed for pypi.org, but the agent tries evil.com
        let blob = authz(&root, &agent, "pypi.org", "evil.com");
        assert!(matches!(
            p.authorize_connect("evil.com", 443, Some(&blob), 0),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn token_from_untrusted_root_is_denied() {
        let root = Identity::generate().unwrap();
        let rogue = Identity::generate().unwrap();
        let agent = Identity::generate().unwrap();
        // policy trusts `root`, but the token is rooted in `rogue`
        let p = gated_policy(vec![root.public()]);
        let blob = authz(&rogue, &agent, "pypi.org", "pypi.org");
        assert!(matches!(
            p.authorize_connect("pypi.org", 443, Some(&blob), 0),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn attenuated_subagent_cannot_exceed_grant() {
        // root → A (net pypi.org); A → B attenuated to NO network.
        let root = Identity::generate().unwrap();
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let a_cap = Capability {
            net_domains: vec!["pypi.org".into()],
            ..Default::default()
        };
        let rt = issue_root(&root, &a.public(), a_cap, 0).unwrap();
        let b_cap = Capability::default(); // no network
        let bt = delegate(&rt, &a, &b.public(), b_cap, 0).unwrap();
        // B signs a connect it was not granted
        let action = sign_action(
            &b,
            Action::NetConnect {
                domain: "pypi.org".into(),
            },
            &bt.hash(),
            1,
        )
        .unwrap();
        let blob = ql_token::AuthzRequest {
            chain: vec![rt, bt],
            action,
        }
        .to_hex()
        .unwrap();
        let p = gated_policy(vec![root.public()]);
        assert!(matches!(
            p.authorize_connect("pypi.org", 443, Some(&blob), 0),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn audit_sink_records_each_decision() {
        let root = Identity::generate().unwrap();
        let agent = Identity::generate().unwrap();
        let dir = std::env::temp_dir().join(format!("qlbk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("egress.jsonl");
        let _ = std::fs::remove_file(&log);
        let p = gated_policy(vec![root.public()])
            .with_audit(AuditSink::new(&log))
            .with_system(SystemIdentity::ai_system("coding-agent-prod", None));

        let blob = authz(&root, &agent, "pypi.org", "pypi.org");
        let _ = p.authorize_connect("pypi.org", 443, Some(&blob), 0); // allow
        let _ = p.authorize_connect("evil.com", 443, None, 0); // deny

        let text = std::fs::read_to_string(&log).unwrap();
        let parsed = AuditLog::from_jsonl(&text).unwrap();
        assert_eq!(parsed.records().len(), 2);
        assert!(parsed.verify().is_ok());
        // Each egress decision is attributed to the AI system (EU AI Act Art. 12).
        for r in parsed.records() {
            let sys = r.event.system.as_ref().expect("egress record attributed");
            assert_eq!(sys.system_id, "coding-agent-prod");
        }
        let _ = std::fs::remove_file(&log);
    }

    // silence unused warnings for imports only used to build fixtures
    #[allow(dead_code)]
    fn _types(_: Token, _: SignedAction) {}
}

// crates/ql-learn/src/risk.rs
//
//! Turn a synthesized profile and its observation into a reviewable
//! [`ql_risk::RiskReport`]: every grant the profile proposes, classified by
//! risk, with the reason it exists. Emitted next to the profile by `ql learn`,
//! it is what turns "here is a profile" into "here is a profile you can review."

use crate::observation::Observation;
use ql_profile::Profile;
use ql_risk::{Context, GrantKind, GrantRisk, RiskReport};
use std::net::IpAddr;
use std::path::Path;

/// Build a [`RiskReport`] for `profile`. `obs` supplies the agent's observed
/// network egress (the profile itself is default-deny), and `project_root` —
/// the directory the agent was launched in, if known — lets project-local paths
/// classify as allow-candidates instead of generic home paths.
pub fn build_risk_report(
    profile: &Profile,
    obs: &Observation,
    project_root: Option<&Path>,
) -> RiskReport {
    let ctx = Context {
        project_root: project_root.and_then(|p| p.to_str()).map(str::to_string),
    };

    let mut grants: Vec<GrantRisk> = Vec::new();
    for g in &profile.filesystem.readonly {
        grants.push(GrantRisk::classify(g.as_str(), GrantKind::FsRead, &ctx));
    }
    for g in &profile.filesystem.readwrite {
        grants.push(GrantRisk::classify(g.as_str(), GrantKind::FsWrite, &ctx));
    }
    for g in &profile.filesystem.denied {
        grants.push(GrantRisk::classify(g.as_str(), GrantKind::FsDenied, &ctx));
    }
    for p in &profile.processes.allow_exec {
        grants.push(GrantRisk::classify(p.as_str(), GrantKind::Exec, &ctx));
    }
    for s in &profile.syscalls.deny {
        grants.push(GrantRisk::classify(
            s.as_str(),
            GrantKind::SyscallDenied,
            &ctx,
        ));
    }
    // Network egress comes from the observation, not the profile: the profile is
    // default-deny, but the agent's observed external connects are exactly what
    // an operator decides whether to allow-list.
    for (ip, port) in &obs.connects {
        if is_external(ip) {
            let endpoint = format!("{ip}:{port}");
            grants.push(GrantRisk::classify(endpoint, GrantKind::NetEgress, &ctx));
        }
    }

    let agent = format!("{:?}", profile.agent_type).to_lowercase();
    RiskReport::new(agent, grants)
}

/// Whether `ip` is off the local host (not loopback or link-local).
fn is_external(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local(),
        IpAddr::V6(v6) => !v6.is_loopback(),
    }
}

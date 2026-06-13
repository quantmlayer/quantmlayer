// crates/ql-enforce/src/veth.rs
//
//! Wiring a `veth` pair into the contained agent's network namespace.
//!
//! By itself, the [`crate::enforcers::network::NetworkEnforcer`] gives the agent
//! an empty network namespace (default-deny: no route off-host). To grant the
//! agent *brokered* egress — reach allow-listed domains, nothing else — we give
//! it a single point-to-point link to the host whose only peer is the egress
//! broker. The agent gets no default route, so its only reachable address is
//! the broker; everything else (the metadata endpoint, the public internet) is
//! unrouteable.
//!
//! This setup must run in the **parent** (host namespaces, real root) acting on
//! the child by pid, which is exactly what the cell's parent hook is for:
//!
//! ```text
//!   host netns                         agent netns
//!   ----------                         -----------
//!   [broker] <-- 10.x.x.1/30  veth  10.x.x.2/30  (only route)
//! ```
//!
//! Interface manipulation is delegated to `iproute2` (`ip`) and `nsenter`,
//! which are present on essentially every Linux host; a production build could
//! instead speak netlink directly to drop even that dependency.

use crate::error::{EnforceError, Result};
use nix::unistd::Pid;
use std::process::Command;

/// Addressing/naming for one cell's point-to-point uplink to the broker.
#[derive(Debug, Clone)]
pub struct VethPlan {
    /// Host-side interface name (<= 15 chars).
    pub host_if: String,
    /// Cell-side interface name (moved into the child netns).
    pub cell_if: String,
    /// Host-side address in CIDR form, e.g. `10.71.4.1/30`.
    pub host_cidr: String,
    /// Cell-side address in CIDR form, e.g. `10.71.4.2/30`.
    pub cell_cidr: String,
    /// The bare host IP the broker is reachable at (e.g. `10.71.4.1`).
    pub host_ip: String,
}

impl VethPlan {
    /// Build a plan on a unique private /30, derived from a seed (e.g. pid) so
    /// concurrent cells don't collide on link names or subnets.
    pub fn for_seed(seed: u32) -> Self {
        // /30 in 10.<a>.<b>.0; host=.1, cell=.2. Keep names <= 15 chars.
        let a = ((seed >> 8) & 0xff) as u8;
        let b = (seed & 0xff) as u8;
        let tag = seed & 0xffff;
        VethPlan {
            host_if: format!("qlh{tag:04x}"),
            cell_if: format!("qlc{tag:04x}"),
            host_cidr: format!("10.{a}.{b}.1/30"),
            cell_cidr: format!("10.{a}.{b}.2/30"),
            host_ip: format!("10.{a}.{b}.1"),
        }
    }
}

/// Wire the veth pair into the child's network namespace and bring both ends
/// up. Run from the parent (host namespaces) against the child by pid.
pub fn wire(child: Pid, plan: &VethPlan) -> Result<()> {
    let pid = child.as_raw().to_string();

    // 1. Create the pair in the host netns.
    ip(&[
        "link",
        "add",
        &plan.host_if,
        "type",
        "veth",
        "peer",
        "name",
        &plan.cell_if,
    ])?;
    // 2. Move the cell end into the child's network namespace.
    ip(&["link", "set", &plan.cell_if, "netns", &pid])?;
    // 3. Address + raise the host end.
    ip(&["addr", "add", &plan.host_cidr, "dev", &plan.host_if])?;
    ip(&["link", "set", &plan.host_if, "up"])?;
    // 4. Inside the child netns: address + raise the cell end and loopback.
    //    No default route is added, so the broker (the /30 peer) is the only
    //    reachable address.
    nsenter_ip(
        &pid,
        &["addr", "add", &plan.cell_cidr, "dev", &plan.cell_if],
    )?;
    nsenter_ip(&pid, &["link", "set", &plan.cell_if, "up"])?;
    nsenter_ip(&pid, &["link", "set", "lo", "up"])?;
    Ok(())
}

/// Remove the veth pair (deleting the host end removes its peer too). Safe to
/// call even if the link is already gone.
pub fn teardown(plan: &VethPlan) {
    let _ = Command::new("ip")
        .args(["link", "del", &plan.host_if])
        .output();
}

/// Run an `ip` subcommand, mapping a non-zero exit to a structured error.
fn ip(args: &[&str]) -> Result<()> {
    run("ip", args, &[])
}

/// Run `ip` inside the network namespace of `pid` via `nsenter -t <pid> -n`.
fn nsenter_ip(pid: &str, ip_args: &[&str]) -> Result<()> {
    let mut args: Vec<&str> = vec!["-t", pid, "-n", "ip"];
    args.extend_from_slice(ip_args);
    run("nsenter", &args, ip_args)
}

/// Spawn a command and turn failure into an `EnforceError` carrying stderr.
fn run(program: &str, args: &[&str], ctx: &[&str]) -> Result<()> {
    let out = Command::new(program).args(args).output().map_err(|e| {
        EnforceError::enforcer(
            "network",
            format!("could not run `{program}` (is iproute2 installed?): {e}"),
        )
    })?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let what = if ctx.is_empty() {
            args.join(" ")
        } else {
            ctx.join(" ")
        };
        Err(EnforceError::enforcer(
            "network",
            format!("`{program} {what}` failed: {}", stderr.trim()),
        ))
    }
}

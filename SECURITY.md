# Security Policy

QuantmLayer is a security product: a kernel-enforced containment runtime for
autonomous coding agents. A vulnerability here means an agent can do something
its profile says it cannot. We treat every such report as a containment failure
and prioritize it accordingly.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately via either channel:

- **GitHub private vulnerability reporting** (preferred):
  [Report a vulnerability](https://github.com/quantmlayer/quantmlayer/security/advisories/new)
- **Email:** contact@quantmlayer.com — put `SECURITY` in the subject line.

Include what you can of the following; a proof-of-concept profile plus the
command that escapes it is the ideal report:

- The wall you bypassed (mount / seccomp / network / cgroups / exec) or the
  component affected (broker, MCP gateway, learner, audit chain, token layer).
- Kernel version, distro, and posture (rootless + AppArmor profile, rootless +
  lifted restriction, or root) — containment behavior is posture-dependent.
- The profile used and the exact command or syscall sequence that demonstrates
  the escape.
- Whether `ql doctor` reported the relevant wall as active on your host.

## What counts as a vulnerability

- Any read, write, exec, or network egress that a correctly-loaded profile
  denies but the agent achieves anyway (a wall bypass).
- The cell reporting a wall as enforced when it is not (a silent
  fail-open — the design contract is fail-closed).
- Tampering with the hash-chained audit log without `ql audit verify`
  detecting it.
- Broadening a delegation token beyond its parent grant.
- The broker permitting egress to a denied domain or to link-local /
  metadata ranges.
- MCP gateway allowing a gated or schema-invalid `tools/call` through.

Out of scope: attacks requiring root on the host outside the cell, kernel
0-days (report those to the kernel security team — though we would appreciate
a heads-up if QuantmLayer is the demonstration vehicle), profiles that
explicitly grant the access in question, and walls that `ql doctor` and the
cell startup output already reported as unavailable on the host.

## Our commitment

- Acknowledgment within **48 hours**, an initial assessment within **7 days**.
- A fix or documented mitigation for confirmed wall bypasses as the top
  priority ahead of feature work.
- Credit in the release notes and advisory if you want it (tell us how to
  attribute you, or that you prefer anonymity).
- No legal action against good-faith research conducted against your own
  systems. Please give us a reasonable window to ship a fix before public
  disclosure; we will propose a coordinated disclosure date in our first
  substantive reply, defaulting to 90 days.

## Supported versions

Pre-1.0, only the latest release and `main` receive security fixes.

| Version        | Supported |
| -------------- | --------- |
| latest release | yes       |
| `main`         | yes       |
| older tags     | no        |

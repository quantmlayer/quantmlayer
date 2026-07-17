<p align="center">
  <a href="https://quantmlayer.com">
    <img src="docs/demo/ql-logo.png" alt="QuantmLayer" width="96" height="96">
  </a>
</p>

<h1 align="center">QuantmLayer</h1>

<p align="center">
  <b>Kernel-enforced containment for AI coding agents.</b><br>
  <a href="https://quantmlayer.com">quantmlayer.com</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="demo/">Demo</a> ·
  <a href="SECURITY.md">Security</a>
</p>

[![CI](https://github.com/quantmlayer/quantmlayer/actions/workflows/ci.yml/badge.svg)](https://github.com/quantmlayer/quantmlayer/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.96](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://www.rust-lang.org)
![tests](https://img.shields.io/badge/tests-186%20passing-brightgreen.svg)
![agents](https://img.shields.io/badge/agents-claude%20%C2%B7%20codex%20%C2%B7%20gemini%20%C2%B7%20aider%20%C2%B7%20cline%20%C2%B7%20cursor%20%C2%B7%20opencode-blueviolet.svg)

**A security runtime for coding agents.** We don't secure what agents *say* — we secure what agents are *allowed to do*.

An autonomous coding agent runs with your shell's privileges: it can read `~/.ssh/id_rsa`, exfiltrate secrets, exhaust the host, ptrace other processes, or hit the cloud-metadata endpoint to steal cloud credentials. QuantmLayer wraps the agent in a kernel-enforced containment cell built from a portable, declarative profile, so a compromised or prompt-injected agent can't reach anything it wasn't explicitly granted.

> **▶ See it in 37 seconds:** [`demo/`](demo/) runs the whole loop — *learn* a least-privilege profile by watching a coding agent, then watch the **same** profile block an SSH-key theft the agent never performed.
>
> ![QuantmLayer demo](demo/ql-hero.gif)


## Quickstart

```sh
# Install the static binary (x86_64 or aarch64, auto-detected; no runtime
# deps) + AppArmor profile:
curl -fsSL https://raw.githubusercontent.com/quantmlayer/quantmlayer/main/scripts/install.sh | sh
# ...or build from source:
cargo build --release

# ONE COMMAND — contain a known coding agent with a curated profile that is
# embedded in the `ql` binary (nothing to install or point at). The current
# directory becomes the workspace; SSH/AWS/GPG/kube/gcloud credentials are
# invisible; network egress is allow-listed to the agent's own endpoints
# plus package registries. Bundled: claude, codex, gemini, aider, cline,
# cursor, opencode.
ql agent claude
ql agent codex --broker --audit run.jsonl   # brokered egress + audit trail
ql agent list                                # what's bundled
ql validate --agent claude                   # inspect a bundled profile

# MCP SERVERS — an MCP server is third-party code your MCP client runs with
# YOUR shell's privileges. One command rewrites a client config (Claude
# Desktop, Claude Code .mcp.json, Cursor, ...) so every stdio server it
# launches runs inside a containment cell. Transparent to the protocol:
# the JSON-RPC stream over stdin/stdout passes through the cell untouched.
# The default MCP profile hides credentials and FAILS CLOSED on network
# egress — grant a network-backed server its domains via a per-config
# profile override, derived with `ql learn` rather than guessed.
ql mcp wrap ~/.config/Claude/claude_desktop_config.json --in-place
ql mcp wrap .mcp.json --in-place --broker --audit mcp.jsonl
ql mcp list .mcp.json                        # who is contained, who is not
ql mcp unwrap .mcp.json --in-place           # reverse the rewrite

# INSPECTION GATEWAY — beyond containing the server process, inspect the
# JSON-RPC stream itself. `ql mcp gateway` is a stdio proxy that validates
# each tools/call against the server's advertised schema (rejecting unknown
# tools, missing required args, wrong types) and blocks tools gated as
# state-changing unless allow-listed. Denied calls never reach the server;
# every decision (allow + deny) can be written to a hash-chained audit log.
ql mcp gateway --gate delete_file --audit gw.jsonl -- <server cmd>
# Compose both layers in one wrap: server runs INSIDE the cell AND behind
# the gateway (ql run --mcp -- ql mcp gateway ... -- <server>):
ql mcp wrap .mcp.json --in-place --gateway --gate delete_file

# THE MOAT — learn a least-privilege profile by observing an agent, then
# enforce it. The generated profile reruns the agent fine but denies everything
# it never needed (SSH keys, ptrace, network, binaries it never ran, ...):
ql learn --out agent.yaml -- ./my-agent build
ql run   --profile agent.yaml -- ./my-agent build

# ON-RAMP — dry-run without enforcing. `--observe` traces the agent and
# reports what enforce mode WOULD have denied, writing a would-deny report to
# a NOT-ENFORCING audit log, so you can see a profile is right before it
# blocks real work. `--strict` exits non-zero on any would-deny (a CI gate):
ql run --observe --agent claude -- claude
ql run --observe --strict --profile agent.yaml -- ./my-agent build

# Run a coding agent inside a containment cell:
ql run --profile profiles/coding.yaml -- my-agent --task "fix the failing test"

# Same, but with brokered egress: the agent's ONLY network route is the
# broker, which allows the profile's domains (e.g. pypi.org) and refuses
# everything else, including the cloud-metadata endpoint:
ql run --broker --profile profiles/coding.yaml -- my-agent --task "..."

# Preflight: which containment walls does THIS host actually give you, and which
# exec-enforcement tier (kernel BPF-LSM vs userspace seccomp-notify)? Read-only —
# reads /proc and /sys, loads nothing. Add --json for a machine-readable matrix:
ql doctor

# Inspect what a profile will enforce:
ql validate --profile profiles/coding.yaml

# Export the learned policy to a portable format other runtimes consume — an
# OCI/Docker seccomp profile, or a `docker run` invocation. Each export is
# explicit about what the target can and can't enforce (the gaps are where
# local containment still matters):
ql export --profile agent.yaml --format seccomp --out ql-seccomp.json
ql export --profile agent.yaml --format docker  --out run.sh

# Tamper-evident audit log: append hash-chained records of what the agent
# attempted (e.g. egress decisions), then verify the chain. Anyone you hand the
# log to can verify it wasn't altered — they don't have to trust the producer:
ql audit append run.log --actor broker --action egress.connect \
  --target 169.254.169.254:80 --decision deny --detail "cloud metadata blocked"
ql audit verify run.log

# Kill switch: list running cells, then revoke one instantly and completely —
# the agent and every process it spawned — recording the revocation in the log:
ql ps
ql kill <id> --audit run.log

# Agent identity + delegation tokens: authority that only narrows down the
# agent tree (Ed25519). The demo issues a grant, attenuates it to a sub-agent,
# and shows a broadening attempt rejected:
ql token demo

# Run the egress broker on its own (allow-listed network access):
ql broker --profile profiles/coding.yaml --listen 127.0.0.1:8080
```

`ql run` is transparent: the command's output passes through and `ql` exits with the command's own exit code.

## What it blocks

Every row below is measured by a reproducible benchmark (`make benchmark`) — never asserted. **Docker** is a default `docker run` with the workspace mounted (no hardening flags); each attack's exact scenario and target wall is documented under [`benchmark/`](benchmark/), and the live scorecard is regenerated into [`benchmark/RESULTS.md`](benchmark/RESULTS.md) on every run.

| Attack | Wall | No containment | Docker | QuantmLayer |
|---|---|---|---|---|
| SSH private-key theft | mount | vulnerable | blocked | blocked |
| Read secrets outside the workspace | mount | vulnerable | blocked | blocked |
| Resource exhaustion (fork bomb) | cgroups | vulnerable | vulnerable | blocked |
| Cross-process memory read / ptrace | seccomp | vulnerable | vulnerable | blocked |
| Cloud-metadata SSRF | network | vulnerable | vulnerable | blocked |
| Run an unauthorized tool (content-addressed exec) | exec | vulnerable | vulnerable | blocked |

A default container blocks the two filesystem attacks (separate container filesystem) but is exposed to the fork bomb, cross-process `ptrace`, and metadata SSRF — each of which needs a flag the operator must know to add (`--pids-limit`, a tightened seccomp profile, `--network none`). The last row is the sharpest: **content-addressed execution has no container flag to add.** A default container runs any binary it ships; QuantmLayer hashes every binary at `execve` and admits only those on the learned allow-list, so a tool the agent never used — a freshly dropped payload, a `curl` pulled in by a prompt injection — cannot start, denied by the kernel on content. QuantmLayer derives and applies all of these restrictions automatically, from the agent's observed behavior, on the real host filesystem with no separate image.

The exec row needs more than the others to reproduce: a kernel with BPF-LSM + IMA (check with [`scripts/ql-kernel-probe.sh`](scripts/ql-kernel-probe.sh)), an `lsm`-feature build, and root to load the BPF program — `cargo build --release -p ql-bench --features lsm && sudo ./target/release/ql-bench`. A default (toolchain-free) `make benchmark` runs the other five rows and honestly reports the exec row's QuantmLayer cell as `unsupported` rather than a fake block.

### What it costs

Containment this thorough is cheap enough to apply per invocation. On our dev VM (root, all walls), full least-privilege adds roughly **0.6 ms** per agent run over launching the binary uncontained — the five standard walls (mount, namespace, cgroup, seccomp, network) are effectively free. The content-addressed exec wall is the one cost driver: loading and attaching its BPF-LSM program adds about **15 ms** per cold cell. Even so, the heaviest configuration — all six walls — cold-starts roughly **9× faster than a fresh `docker run`** (~16 ms vs ~150 ms, container image pre-pulled); without the exec wall a cell starts well over 100× faster than a container.

These are per-invocation *cold-start* numbers: every call builds a fresh cell, with no pooling. The exec wall's BPF program is loaded per cell today; a long-lived broker that loads it once and attaches it to each cell's cgroup drives that ~15 ms toward zero — just as `docker exec` into a long-lived container amortizes a container's startup. The figures are host-specific and generated, never asserted: see [`benchmark/OVERHEAD.md`](benchmark/OVERHEAD.md) and reproduce with `make overhead` (or, for the exec row, an `lsm` build run as root).

## How this differs from cloud sandboxes

Cloud sandboxes solve a related problem a different way: they run the agent on a **separate remote machine**. That gives strong host isolation — your laptop's files, SSH keys, and other secrets are never present on the remote sandbox, so there is nothing there to steal, and a runaway process is contained to a rented machine rather than yours. For running untrusted, AI-*generated* code, that model is a great fit.

The trade-offs are the other side of the same coin:

- The agent operates on a copy on someone else's infrastructure, not on your **real local files** — you sync code up and results back, which doesn't fit an agent meant to work directly in your existing repo, toolchain, and environment.
- You **entrust execution and your code** to a third-party cloud.
- Isolation stops at the host boundary, not *within* the sandbox: unless the provider restricts it, an agent inside the sandbox still has broad latitude over that machine's resources and network (including, potentially, the cloud instance-metadata endpoint).

QuantmLayer is built for the opposite situation: contain an agent running **locally, on your own machine and your real files**, with a least-privilege profile learned from its behavior — no remote machine, no code-sync, no third-party trust. The two approaches are complementary; this benchmark scores host-threat containment, which is QuantmLayer's domain, so remote-execution sandboxes are described here rather than scored as a column.

## How this differs from prompt-injection defenses

A separate line of defense — exemplified by Google DeepMind's **CaMeL** ("Defeating Prompt Injections by Design," extending Simon Willison's Dual-LLM pattern) — keeps a quarantined, untrusted model from taking privileged action by having the *orchestration layer* hold the boundary: a privileged LLM plans from the trusted query, a quarantined LLM processes untrusted data with no tool access, and a custom interpreter tracks data provenance and enforces capability policies before each tool call. It's a strong, well-regarded design, and it's solving an adjacent problem to ours.

QuantmLayer makes the quarantine boundary a **kernel** boundary rather than an interpreter boundary. Where CaMeL trusts the surrounding Python interpreter to hold the air gap, QuantmLayer runs the untrusted work in a **zero-capability cell that can return text and nothing else** — no files, no network, no exec — enforced below userspace by namespaces, seccomp, and BPF-LSM rather than by orchestration discipline. If the interpreter has a bug, that boundary can leak; the kernel boundary does not depend on the interpreter being correct.

To be precise about scope: we harden the **quarantine** half of that model — making the untrusted boundary a kernel boundary. We do **not** replicate CaMeL's privileged-side contribution, its capability and data-flow provenance tracking through the trusted interpreter. The claim is "we make the quarantine boundary a kernel boundary," not "we are CaMeL, but better."

## Where it fits: OWASP Agentic Top 10 and EU AI Act

QuantmLayer is a **runtime containment and evidence** layer. It governs what an agent is *allowed to do* on the host — not what the model *thinks* or *says*. That scope maps cleanly onto part of the [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/): the risks that manifest as **actions** are addressed by a specific wall; the risks that live inside the model's reasoning are explicitly **out of scope**, and are marked so below rather than papered over. Each "addressed" row points at a wall that is measured in the [What it blocks](#what-it-blocks) benchmark, not asserted.

| OWASP Agentic risk | QuantmLayer | How |
|---|---|---|
| Tool misuse / unexpected code execution | **Addressed** | Content-addressed `execve` (exec wall) admits only binaries on the learned allow-list; a dropped payload or injection-pulled tool cannot start. |
| MCP tool-call abuse (out-of-contract / unauthorized state change) | **Addressed** | The MCP inspection gateway (`ql mcp gateway`) validates each `tools/call` against the server's advertised schema and blocks tools gated as state-changing unless allow-listed; denied calls never reach the server, and every decision is auditable. |
| Privilege compromise / escalation | **Addressed** | Dropped capabilities + seccomp deny-list + user-namespace mapping; the agent holds only the rights its profile grants. |
| Resource / availability abuse | **Addressed** | cgroups caps (pids/memory/cpu) contain fork bombs and exhaustion. |
| Identity abuse (non-human identity) | **Partial** | Ed25519 agent identity with attenuating delegation (`ql-token`): authority only ever *narrows* down the agent tree, kernel-bound to the cell. Vault-issued ephemeral credentials are on the roadmap, not shipped. |
| Unexpected RCE / privileged data access | **Addressed** | mount wall makes out-of-workspace secrets (`~/.ssh`, cloud creds) invisible; network wall blocks the cloud-metadata SSRF path. |
| Cascading failures / rogue agent action | **Partial** | Kill switch (`ql kill`) revokes an agent and its whole process tree instantly; per-subtask containment bounds blast radius. Does not prevent an in-profile action from being wrong. |
| Memory poisoning | **Out of scope** | A model-context / reasoning risk; QuantmLayer governs actions, not model memory. |
| Goal hijacking / intent manipulation | **Out of scope** | Prompt-layer risk. QuantmLayer's value here is *downstream*: even a fully hijacked agent can only take actions its profile permits — but detecting the hijack itself is not what this layer does. |

**On prompt injection specifically:** QuantmLayer does not detect or block prompt injection — that is a model-layer problem. What it does is make injection *less consequential*: a subverted agent still cannot read a secret the mount wall hid, reach a domain the broker denied, or run a binary the exec wall didn't admit. The containment holds regardless of *why* the agent tried.

**EU AI Act (Article 12 logging).** The Act's high-risk-system logging obligations take effect **August 2026**. QuantmLayer's audit layer is a technical substrate for that record-keeping: every governed action (`exec.run`/`exec.deny`, egress decisions, policy changes) is written to a **hash-chained, tamper-evident log**, each record stamped with the `ai_system` identity (`system_id`, `model_version`) and independently verifiable by a third party with no QuantmLayer dependency (`ql audit export` ships a stdlib-only verifier). This is a **strong technical control that produces the evidence Article 12 is about — not a turnkey or certified compliance product**; the legal determination of compliance is the deployer's, made with counsel. Full control-by-control detail is maintained in a separate mapping document.

## Agent identity, enforced

An agent's identity in QuantmLayer is an **Ed25519 keypair** — the public key *is* the identity, and every action or delegation is a signature the holder of the private key produced. On top of that sit **attenuating delegation tokens**: when a planner agent spawns a coder, and the coder spawns a reviewer, each hands down a token that can only *narrow* authority, never broaden it. That monotonic-narrowing property is enforced, not conventional — a delegated token that tries to grant a right its parent didn't hold is rejected (`attenuation violation`).

The tokens are **bound to the containment cell**: a profile can be narrowed by the token that launches it, before the cell is built, so the credential and the enforcement are the same decision. This is non-human identity with **zero standing privilege** — an agent holds exactly the rights its token carries for exactly the subtask it runs, checked at the kernel boundary rather than trusted by convention. `ql token demo` walks the full issue → attenuate → reject-broadening path.

*Scope note: this is the identity and delegation substrate. Integration with enterprise secret vaults (Vault, AWS Secrets Manager, CyberArk) to issue ephemeral, auto-revoked credentials is on the roadmap, not yet shipped.*

## Architecture

The system is a small Cargo workspace of focused crates:

- **`ql-profile`** — the portable, OS-independent policy model (pure data; no OS dependencies). A profile declares filesystem, network, syscall, capability, and resource rules.
- **`ql-learn`** — the *learning* half, and the moat. It traces an agent's real syscalls (`openat`/`open` with read/write intent, `execve`, `connect`) via `ptrace`, then synthesizes a least-privilege profile from what the agent actually needed. Enforcement is mechanical; deciding *what* to enforce is the defensible part. This is the dynamic counterpart to Decap's static capability derivation.
- **`ql-enforce`** — the Linux enforcement engine. Each containment mechanism is an `Enforcer` (mount, namespaces, cgroups, seccomp, network, and — behind the `lsm` feature — content-addressed `execve`), composed into a `Cell` that forks, applies the walls, and execs the agent. Fail-closed: if a wall can't be applied, the agent doesn't run.
- **`ql-lsm`** — the content-addressed exec wall: a sleepable BPF-LSM program that hashes each binary at `execve` (via the kernel's IMA) and permits only the digests on the profile's allow-list, so a binary the agent never ran is denied by content, not by name. Beyond that allow/deny, it enforces per-binary **argv-deny** rules: for an *approved* binary, a specific denied argument (say, a destructive flag) is matched against the **committed** argv and the offending process is killed by the kernel (`bpf_send_signal`). This is a post-commit **detect-and-kill**, deliberately distinct from the pre-execution digest allow/deny — the sound, tamper-free argv is only readable once the new image is installed, so the wall kills the invocation at that point rather than claiming to prevent it beforehand. Built behind `ql-enforce`'s `lsm` feature and excluded from the default workspace because it needs a BPF/`clang` toolchain to compile — every other crate builds with no special tooling.
- **`ql-broker`** — an egress broker (HTTP `CONNECT` proxy) that enforces the profile's domain allow-list and refuses private/link-local addresses. Optionally *token-gated*: with `--trust`, egress requires a valid signed delegation token (`ql-token`) whose capability permits the destination, and every decision is written to a tamper-evident audit log (`ql-audit`). Pure userspace, not Linux-specific.
- **`ql-bench`** — the benchmark harness ("credibility engine") that runs the attack catalog against each backend and emits the scorecard above.
- **`ql-cli`** — the `ql` command-line front door over all of the above.

The split is deliberate: `ql-profile` is the portable contract, `ql-enforce` is where all OS-specific code lives, and `ql-broker` is OS-portable. A future macOS (Seatbelt) or Windows (AppContainer/Job Objects) backend would implement the same `Enforcer` contract against the same profiles.

## Platform support

The kernel containment layer targets Linux and works on every current enterprise kernel (RHEL 8/9, all current Ubuntu LTS, Amazon Linux) — namespaces, mount isolation, classic seccomp-bpf, and cgroups (both v1 and v2 are supported). Where a host lacks a specific control, that wall degrades to a clearly-reported "unsupported" rather than failing the whole cell. The content-addressed exec wall is the one with stricter requirements: it needs a kernel built with BPF-LSM and IMA (Linux ≥ 5.7 with `bpf` in the active LSM list) and is compiled only in an `lsm`-feature build; where either is missing, exec enforcement reports "unsupported" like any other wall while the rest of the cell holds. The broker is pure userspace and runs anywhere. Brokered egress (`ql run --broker`) additionally uses `iproute2` (the ubiquitous `ip` tool) to wire the veth uplink.

**Validated on managed-cloud node images.** The strict-requirement question — "does my cloud node actually have BPF-LSM + IMA?" — is answered by measurement, not assumption. On **Amazon Linux 2023**, the default Amazon EKS node OS (kernel 6.18), a real `ql run` enforces the Tier-1 BPF-LSM exec wall with **no node reconfiguration**: `bpf` is already in the active LSM list, and content-addressed deny-by-default works with the stock IMA setup — no custom AMI and no IMA policy needed (verified live: an approved binary runs, an unapproved one is denied at `execve`). **Google Container-Optimized OS**, the default GKE node OS (kernel 6.6), ships BPF-LSM active the same way and is Tier-1-capable. Run `ql doctor` on any node to see the tier it resolves, or [`scripts/ql-kernel-probe.sh`](scripts/ql-kernel-probe.sh) for the full read-only kernel-capability report.

Both **x86-64** and **aarch64** (ARM64) are supported, including profile learning: syscall numbers are resolved per-architecture and the tracer reads registers via the architecture's native ptrace interface, so `ql learn` works on Apple Silicon VMs and AWS Graviton as well as on x86-64 hosts.

## Deployment & posture

The cell builds itself out of unprivileged user namespaces, so it needs the capability to *use* a user namespace. On hardened kernels — Ubuntu 24.04, and 22.04 running the 6.8+ HWE kernel — AppArmor restricts that by default: a program may create a user namespace but is denied capabilities inside it. When that bites, `ql run` does the right thing and **refuses to run the agent uncontained**, reporting exactly which wall failed rather than silently running with a hole in the cage.

There are three supported postures:

1. **Rootless + AppArmor profile (recommended).** Install the binary and the bundled profile (`sudo make install && sudo make install-apparmor`). `ql` is then granted `userns` while every other program on the host stays protected — nothing is weakened system-wide. This is the same mechanism Ubuntu ships for Chrome and flatpak. Requires AppArmor 4.x userspace.
2. **Rootless + lifted restriction (quick, for dev).** `echo 0 | sudo tee /proc/sys/kernel/apparmor_restrict_unprivileged_userns`. Fast, but it relaxes the protection for *every* program on the host, so it isn't appropriate for shared or production machines.
3. **Root.** Running `ql run` under `sudo` has the needed capabilities unconditionally, and additionally enables the cgroup resource limits (see below). Simplest to demo; the launcher itself runs as root.

Which walls are active in each posture:

| Wall | Rootless (+profile or lifted) | Root |
|---|---|---|
| Filesystem hiding (mount) | ✅ | ✅ |
| Syscall denial (seccomp) | ✅ | ✅ |
| Network default-deny / egress broker | ✅ | ✅ |
| Resource limits (cgroups: pids/memory) | ⚠️ only with cgroup delegation | ✅ |
| Content-addressed exec (BPF-LSM) | ❌ needs root + `lsm` build | ✅ with a BPF-LSM/IMA kernel |

The cgroup wall is the one exception to rootless parity: writing cgroup limits needs either root or a delegated cgroup subtree (e.g. a `systemd` user slice with `Delegate=yes`). Without it, that wall degrades to a clearly-printed "unavailable" warning and the cell continues — so on a stock rootless host the file/syscall/network containment is fully in force, but the fork-bomb / memory limits are not. Run under root (or set up delegation) when resource limits matter. The exec wall is gated similarly: loading its BPF-LSM program needs root and a BPF-LSM/IMA kernel, and it is compiled only in an `lsm`-feature build — so it is inactive in the default rootless posture and active when you run a `--features lsm` build as root.

## Development

```sh
make check       # fmt + clippy + tests (the CI gate)
make test        # workspace tests
make test-priv   # includes the privileged namespace integration tests
make benchmark   # run the attack benchmark and render the scorecard
```

Every source file begins with a comment naming its path, and the enforcement path contains no panics — a wall that can't be applied returns a structured error and the cell fails closed.

## License

Apache-2.0. See [LICENSE](LICENSE).

One documented exception: [`scripts/lsm-enforce/enforce.bpf.c`](scripts/lsm-enforce/enforce.bpf.c)
is **GPL-2.0-only**, because it uses the GPL-only kernel helper
`bpf_ima_file_hash` and the kernel requires the loaded BPF object to declare a
GPL-compatible license. That file is a standalone program loaded into the
kernel at runtime — it is compiled to a BPF object, not linked into the `ql`
binary — so the `ql` binary and every other file in this repository remain
Apache-2.0. Third-party dependency licenses are inventoried in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

Contributions are accepted under the same terms with a required DCO sign-off —
see [CONTRIBUTING.md](CONTRIBUTING.md).

# QuantmLayer

**A security runtime for coding agents.** We don't secure what agents *say* — we secure what agents are *allowed to do*.

An autonomous coding agent runs with your shell's privileges: it can read `~/.ssh/id_rsa`, exfiltrate secrets, exhaust the host, ptrace other processes, or hit the cloud-metadata endpoint to steal cloud credentials. QuantmLayer wraps the agent in a kernel-enforced containment cell built from a portable, declarative profile, so a compromised or prompt-injected agent can't reach anything it wasn't explicitly granted.

> **▶ See it in 90 seconds:** [`demo/`](demo/) runs the whole loop — *learn* a least-privilege profile by watching a coding agent, then watch the **same** profile block an SSH-key theft the agent never performed.
>
> <!-- After recording (see demo/README.md): drop the GIF in and uncomment -->
> <!-- ![QuantmLayer demo](demo/quantmlayer-demo.gif) -->

The defensible idea is the **learning**: enforcement alone is infrastructure, but automatically deriving a correct least-privilege profile from an agent's real behavior — so no human writes the rules — is what makes the containment usable at scale.

## Quickstart

```sh
cargo build --release

# THE MOAT — learn a least-privilege profile by observing an agent, then
# enforce it. The generated profile reruns the agent fine but denies everything
# it never needed (SSH keys, ptrace, network, ...):
ql learn --out agent.yaml -- ./my-agent build
ql run   --profile agent.yaml -- ./my-agent build

# Run a coding agent inside a containment cell:
ql run --profile profiles/coding.yaml -- my-agent --task "fix the failing test"

# Same, but with brokered egress: the agent's ONLY network route is the
# broker, which allows the profile's domains (e.g. pypi.org) and refuses
# everything else, including the cloud-metadata endpoint:
ql run --broker --profile profiles/coding.yaml -- my-agent --task "..."

# Inspect what a profile will enforce:
ql validate --profile profiles/coding.yaml

# Run the egress broker on its own (allow-listed network access):
ql broker --profile profiles/coding.yaml --listen 127.0.0.1:8080
```

`ql run` is transparent: the command's output passes through and `ql` exits with the command's own exit code.

## What it blocks

Every row below is measured by a reproducible benchmark (`make benchmark`) — never asserted. **Docker** is a default `docker run` with the workspace mounted (no hardening flags); see the Methodology note in [`benchmark/RESULTS.md`](benchmark/RESULTS.md) for the exact configuration each tool is given and why.

| Attack | Wall | No containment | Docker | QuantmLayer |
|---|---|---|---|---|
| SSH private-key theft | mount | vulnerable | blocked | blocked |
| Read secrets outside the workspace | mount | vulnerable | blocked | blocked |
| Resource exhaustion (fork bomb) | cgroups | vulnerable | vulnerable | blocked |
| Cross-process memory read / ptrace | seccomp | vulnerable | vulnerable | blocked |
| Cloud-metadata SSRF | network | vulnerable | vulnerable | blocked |

A default container blocks the two filesystem attacks (separate container filesystem) but is exposed to the fork bomb, cross-process `ptrace`, and metadata SSRF — each of which needs a flag the operator must know to add (`--pids-limit`, a tightened seccomp profile, `--network none`). QuantmLayer derives and applies the equivalent restrictions automatically, from the agent's observed behavior, on the real host filesystem with no separate image.

## How this differs from cloud sandboxes (E2B, Daytona)

Cloud sandboxes like [E2B](https://e2b.dev) and [Daytona](https://daytona.io) solve a related problem a different way: they run the agent on a **separate remote machine**. That gives strong host isolation — your laptop's files, SSH keys, and other secrets are never present on the remote sandbox, so there is nothing there to steal, and a runaway process is contained to a rented machine rather than yours. For running untrusted, AI-*generated* code, that model is a great fit.

The trade-offs are the other side of the same coin:

- The agent operates on a copy on someone else's infrastructure, not on your **real local files** — you sync code up and results back, which doesn't fit an agent meant to work directly in your existing repo, toolchain, and environment.
- You **entrust execution and your code** to a third-party cloud.
- Isolation stops at the host boundary, not *within* the sandbox: unless the provider restricts it, an agent inside the sandbox still has broad latitude over that machine's resources and network (including, potentially, the cloud instance-metadata endpoint).

QuantmLayer is built for the opposite situation: contain an agent running **locally, on your own machine and your real files**, with a least-privilege profile learned from its behavior — no remote machine, no code-sync, no third-party trust. The two approaches are complementary; this benchmark scores host-threat containment, which is QuantmLayer's domain, so remote-execution sandboxes are described here rather than scored as a column.

## Architecture

The system is a small Cargo workspace of focused crates:

- **`ql-profile`** — the portable, OS-independent policy model (pure data; no OS dependencies). A profile declares filesystem, network, syscall, capability, and resource rules.
- **`ql-learn`** — the *learning* half, and the moat. It traces an agent's real syscalls (`openat`/`open` with read/write intent, `execve`, `connect`) via `ptrace`, then synthesizes a least-privilege profile from what the agent actually needed. Enforcement is mechanical; deciding *what* to enforce is the defensible part. This is the dynamic counterpart to Decap's static capability derivation.
- **`ql-enforce`** — the Linux enforcement engine. Each containment mechanism is an `Enforcer` (mount, namespaces, cgroups, seccomp, network), composed into a `Cell` that forks, applies the walls, and execs the agent. Fail-closed: if a wall can't be applied, the agent doesn't run.
- **`ql-broker`** — an egress broker (HTTP `CONNECT` proxy) that enforces the profile's domain allow-list and refuses private/link-local addresses. Pure userspace, not Linux-specific.
- **`ql-bench`** — the benchmark harness ("credibility engine") that runs the attack catalog against each backend and emits the scorecard above.
- **`ql-cli`** — the `ql` command-line front door over all of the above.

The split is deliberate: `ql-profile` is the portable contract, `ql-enforce` is where all OS-specific code lives, and `ql-broker` is OS-portable. A future macOS (Seatbelt) or Windows (AppContainer/Job Objects) backend would implement the same `Enforcer` contract against the same profiles.

## Platform support

The kernel containment layer targets Linux and works on every current enterprise kernel (RHEL 8/9, all current Ubuntu LTS, Amazon Linux) — namespaces, mount isolation, classic seccomp-bpf, and cgroups (both v1 and v2 are supported). Where a host lacks a specific control, that wall degrades to a clearly-reported "unsupported" rather than failing the whole cell. The broker is pure userspace and runs anywhere. Brokered egress (`ql run --broker`) additionally uses `iproute2` (the ubiquitous `ip` tool) to wire the veth uplink.

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

The cgroup wall is the one exception to rootless parity: writing cgroup limits needs either root or a delegated cgroup subtree (e.g. a `systemd` user slice with `Delegate=yes`). Without it, that wall degrades to a clearly-printed "unavailable" warning and the cell continues — so on a stock rootless host the file/syscall/network containment is fully in force, but the fork-bomb / memory limits are not. Run under root (or set up delegation) when resource limits matter.

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

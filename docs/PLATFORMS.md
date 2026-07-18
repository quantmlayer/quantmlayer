# Running QuantmLayer on Windows and macOS

QuantmLayer's walls are Linux kernel primitives — user namespaces, mount
namespaces, seccomp, cgroups v2, and (for the content-verified exec wall) a
BPF-LSM. There is no native Windows or macOS build, and there won't be a
watered-down one: a port that swapped in weaker primitives would quietly break
the one promise the project makes — that every containment claim is measured and
reproducible.

Instead, Windows and macOS users run the **real** Linux cell inside a Linux
environment the OS already provides. This is the same approach Docker Desktop
takes, and it gives you full wall fidelity — on macOS, arguably *stronger*
isolation, because a hardware VM boundary sits underneath the kernel walls.

Your coding agent runs where you already run it (Claude Code, Codex, Cursor's
terminal, etc.); `ql` contains it from inside the Linux environment.

## Windows — WSL2 (recommended, and where most Windows devs already are)

WSL2 is a real Linux kernel, so `ql` runs natively inside it. Most Windows
developers already run their coding agents under WSL2; if you do, there is
almost nothing new to set up.

1. Install/enable WSL2 with a recent distro (Ubuntu 22.04+ recommended):

   ```powershell
   wsl --install -d Ubuntu
   wsl --update      # ensure the latest WSL2 kernel
   ```

2. Inside the WSL2 shell, install `ql` the normal way:

   ```sh
   curl -fsSL https://quantmlayer.com/install.sh | sh
   ```

3. Check what the WSL2 kernel actually gives you — always run this first. It
   never enforces anything; it just reports your real tier:

   ```sh
   ql doctor
   ```

### What to expect on WSL2

`ql doctor` reports each wall honestly; WSL2 kernels vary by Windows build, so
read its output rather than trusting this table. In general:

| Wall | WSL2 status |
| ---- | ----------- |
| Mount / filesystem | Works (user + mount namespaces are enabled). |
| Seccomp | Works. |
| Cgroups (pids/mem/cpu limits) | Works on modern cgroups-v2 WSL2 kernels; older builds may not delegate a writable controller — `ql doctor` confirms, and `ql` degrades gracefully if it can't. |
| Network / brokered egress | Works (userspace broker + veth). |
| Content-verified exec (BPF-LSM) | Usually **unavailable** — stock WSL2 kernels often ship without BPF-LSM. `ql doctor` reports the exec tier you actually get; `ql` falls back to the seccomp-notify exec supervisor or, failing that, reports exec as not content-verified. It fails closed, never pretends. |

If you need the BPF-LSM exec wall on Windows, either build a custom WSL2 kernel
with `CONFIG_BPF_LSM=y` and `lsm=...,bpf` on the kernel command line, or use a
full Linux VM (below). For most design-partner evaluations the default WSL2
tier is enough to demonstrate the mount, seccomp, cgroups, and egress walls.

### Running an agent

From the WSL2 shell, in your project directory:

```sh
ql agent claude          # contain Claude Code with its bundled profile
# or, generally:
ql run --agent claude -- claude
```

Keep your repo on the Linux filesystem (`~/project`, not `/mnt/c/...`) for
correct permissions and much better performance.

## macOS — a Linux VM (full wall fidelity)

macOS's own sandbox (Seatbelt) is unrelated to QuantmLayer's model, so on macOS
you run `ql` inside a lightweight Linux VM. Two good options:

### Option A: Lima (lightweight, CLI-native)

[Lima](https://github.com/lima-vm/lima) runs a Linux VM with your working
directory mounted, close to how Docker Desktop works under the hood.

```sh
brew install lima
limactl start           # accept the default Ubuntu template
lima                    # drop into the Linux VM shell
# inside the VM:
curl -fsSL https://quantmlayer.com/install.sh | sh
ql doctor
```

On Apple Silicon this is an arm64 Linux guest; `ql` ships an aarch64 build, so
the installer picks it up automatically.

### Option B: any Linux VM (UTM, Multipass, a cloud dev box)

Any Linux VM you can SSH into works identically — install with the one-liner and
run `ql doctor`. A cloud Linux dev environment (the way many teams already run
agents) is often the simplest path and matches your eventual CI target.

### Exec tier on macOS VMs

A stock cloud/UTM Ubuntu image frequently has BPF-LSM available, so you may get
the full content-verified exec wall in a macOS VM even though you won't on
stock WSL2 — again, let `ql doctor` be the source of truth.

## The honest summary

- **Linux host / CI runner:** native, full fidelity. This is the production
  target and needs nothing from this page.
- **Windows:** run inside WSL2 — near-native, most walls active, exec wall
  depends on the WSL2 kernel. `ql doctor` tells you exactly what you get.
- **macOS:** run inside a Linux VM (Lima/UTM/cloud) — full fidelity, hardware
  isolation underneath.

Whatever the platform, `ql doctor` reports the real tier and `ql` fails closed
rather than asserting a wall it cannot enforce. That property is the whole
point, and it holds identically on WSL2 and in a VM.

## For maintainers: the roadmap position

The architecture already anticipates native backends: `ql-profile` is the
portable contract and all OS-specific code is isolated in `ql-enforce` behind
an `Enforcer` interface (see the Architecture section of the README). A native
macOS (Seatbelt/Endpoint Security) or Windows (AppContainer/WDAC) backend would
implement that same interface against the same profiles and the same benchmark
harness. That is a deliberate future-work item, not a gap in the current model —
the VM path above delivers full enforcement on all three platforms today.

# QuantmLayer Attack Benchmark

This file is **generated** — do not edit by hand. It is overwritten (along with
`results.json`) every time the harness runs, so any results here reflect a real,
live run on the machine that produced them rather than a hand-maintained claim.

Each row is an attack a compromised coding agent might attempt. `blocked` means
containment held; `vulnerable` means the host was exposed; `unsupported` means
the wall exists but this build/host could not exercise it (e.g. a non-`lsm`
build, or a missing kernel controller); `pending` means the wall is not built.

## Regenerate

```sh
# The three filesystem/cgroup/seccomp/network rows (No containment, Docker,
# QuantmLayer) run without the exec wall:
cargo run -p ql-bench

# To also measure the content-addressed exec row (the column QuantmLayer holds
# alone — Docker runs any binary it ships), build the exec wall and run as root
# on a host with BPF-LSM + IMA (see scripts/ql-kernel-probe.sh):
sudo cargo run -p ql-bench --features lsm
```

The harness writes the Markdown table here and the machine-readable matrix to
`results.json`. Paste the table into a PR or read it from stdout — but let the
harness produce it, so an acquirer can re-run and get the same file.

Backends compared: **No containment** (baseline), **Docker** (a default
`docker run` agent container, no hardening flags), and **QuantmLayer**. See each
`benchmark/<attack-id>/README.md` for the per-attack scenario and target wall.

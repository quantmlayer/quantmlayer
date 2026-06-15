# Attack: Run an unauthorized tool (content-addressed exec)

**Scenario:** A prompt-injected coding agent shells out to a tool it never used during learning — `curl`, `scp`, a freshly dropped payload — to exfiltrate data or pivot. In this benchmark the secret is left fully readable; the only question under test is whether the unlearned binary may run at all.

**Target wall:** `exec` — the BPF-LSM exec enforcer hashes every binary at `execve` and admits only content digests on the learned allow-list. The shell (the cell's entry point) is allowed; the unlearned tool is denied with `EPERM` in the kernel, by bytes rather than by name. No container runtime content-addresses `execve`, so a default Docker container runs the tool and is `vulnerable` here — this is the row QuantmLayer holds alone.

**Status:** Runnable. Measured live by `ql-bench`. The QuantmLayer column requires a `--features lsm` build and root to load the BPF program; in a default (toolchain-free) build that column reports `unsupported` rather than a fake block.

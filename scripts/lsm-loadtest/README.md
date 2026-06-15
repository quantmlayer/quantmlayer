# BPF-LSM load test

A tiny, **non-enforcing** harness that answers — on *your* kernel, by actually
loading programs rather than guessing — the two questions the read-only probe
(`scripts/ql-kernel-probe.sh`) cannot:

1. **Is `bpf_ima_file_hash` real and callable here?** `bpftool feature probe`
   under-reports LSM-only helpers, so its "not advertised" is not proof of
   absence. Loading a sleepable LSM program that *calls* the helper is the
   authoritative check.
2. **Can we attach to the exec hook `bprm_check_security` cgroup-scoped**
   (`BPF_LSM_CGROUP`), or must the enforcer be a global program that filters by
   cgroup with `bpf_current_task_under_cgroup`?

## Safety

Both programs are **transparent**: they return the incoming LSM verdict
unchanged and never block an exec. The cgroup program is attached only to a
fresh, empty cgroup the loader creates and removes, so it cannot affect any
real process. Nothing here enforces anything.

## Prereqs

`bpftool` and `cargo` are already on the VM (per the probe). Install the rest:

```sh
sudo apt install clang llvm libbpf-dev
```

The host must have `bpf` in its active LSM stack (`cat /sys/kernel/security/lsm`
shows `...,bpf`) — which `probe2` confirmed.

## Run

```sh
cd scripts/lsm-loadtest
make run        # builds vmlinux.h + the BPF object + skeleton + loader, runs as root
```

## Reading the result

- **Test 1 PASS** → the sleepable LSM attach works *and* `bpf_ima_file_hash` is
  present; if the runtime line shows `rc>0` with a digest, IMA hashing on exec
  is viable. This is the green light for the IMA-based, content-addressed exec
  policy.
- **Test 2 PASS** → `BPF_LSM_CGROUP` can attach to this hook (non-sleepable).
- **Test 3** settles the architecture fork: does `BPF_LSM_CGROUP` compose with
  *sleepable* (required by `bpf_ima_file_hash`)? **PASS** → the hashing enforcer
  may attach directly to the cell's cgroup (scoped by construction, no host-wide
  hook). **FAIL** → use a global sleepable program + `bpf_current_task_under_cgroup`,
  which Test 1 already validates. Either way you're unblocked.

The `Design read:` block at the end states the recommended enforcer shape based
on which tests passed.

## Notes

- `bpf_ima_file_hash` returns the **hash algorithm id** (`enum hash_algo`:
  2=SHA1, 4=SHA256, 5=SHA384, 6=SHA512) on success, **not** a byte count. The
  digest length follows from the algorithm. (rc=4 ⇒ SHA-256, 32 bytes.)
- `BPF_LSM_CGROUP` programs must return a value in **[0, 1]** (0 = reject,
  1 = allow), unlike plain LSM's 0/-ERRNO. Returning anything else fails
  verification at load.
- `bpf_ima_file_hash` is **sleepable-only and GPL-only**, so the hashing program
  uses `SEC("lsm.s/…")` and the object declares `GPL`. Because `BPF_LSM_CGROUP`
  programs can't be sleepable, the enforcer hashes from a *global* sleepable LSM
  program and scopes to the cell with `bpf_current_task_under_cgroup` — gating
  the (expensive) hash behind that cheap check so it never runs host-wide.
- The eventual `ql-lsm` crate's loader (aya vs libbpf-rs) is a separate decision,
  informed by these results.

# Content-addressed exec enforcer (demo)

This is the **enforcing** counterpart to `../lsm-loadtest`. The load test proved
the mechanism loads, attaches, and hashes; this proves the actual security
property: **deny-by-default content-addressed exec**. A binary whose SHA-256 is
on the allow-list runs; anything else is blocked at `execve` with `EPERM`.

It is the kernel half of the moat. The allow-list it enforces is exactly the
`ExecPolicy.allow_digests` that `ql learn` produces in userspace — and we
confirmed those digests are byte-identical to what `bpf_ima_file_hash` computes
in-kernel (`sha256sum /bin/true` == the load test's IMA digest).

## What it does

A sleepable `BPF_LSM_CGROUP` program on `bprm_check_security`, attached to one
cgroup. For each exec of a task in that cgroup it hashes the binary and looks the
digest up in a `BPF_MAP_TYPE_HASH` allow-list: present → allow (return 1), absent
or un-hashable → deny (return 0 → `EPERM`).

## Safety

The enforcer is attached to a **fresh demo cgroup the loader creates**, and only
the loader's own forked children are placed in it — no existing process on the
host is affected. The cgroup and the temporary copy are removed on exit. Nothing
host-wide is gated.

## Prereqs

Same as the load test (already installed on the VM): `clang llvm libbpf-dev`,
plus `bpftool`. `bpf` must be in the active LSM stack (`probe2` confirmed it).

## Run

```sh
cd scripts/lsm-enforce
make run        # builds, then runs as root approving sha256(/bin/true)
```

## Expected output

```
Execs inside the contained cgroup:
  [PASS] /bin/true (approved digest)                  -> ALLOWED
  [PASS] copy of /bin/true (same bytes, new name)     -> ALLOWED
  [PASS] /bin/ls (NOT approved)                       -> DENIED
```

- **`/bin/true` ALLOWED** — its digest is on the list.
- **copy ALLOWED** — a byte-identical copy at a different path has the *same*
  digest, so it's approved. This is the point of content-addressing: we trust
  the bytes, not the name. (A *modified* binary would have a new digest → denied.)
- **`/bin/ls` DENIED** — not on the list, blocked with `EPERM`. This is the
  "an agent that pulls in or compiles a new binary can't run it" property.

Three `PASS` lines = content-addressed enforcement works end to end on this
kernel. Any `FAIL`/`ERROR` line prints the underlying `errno`; send me the output
and I'll adjust.

## Notes

- The copy lives in `/var/tmp` (a persistent fs, not tmpfs) so IMA hashes it the
  same way it hashes `/bin/true`.
- The loader takes approved digests as hex on the command line; `make run` passes
  `sha256(/bin/true)`. In the real `ql-lsm` crate (increment 3b) these come from
  a `Profile`'s `ExecPolicy.allow_digests` instead.
- This harness stays in C+libbpf — the exact toolchain the load test validated —
  to isolate the new risk to the enforcement logic. Increment 3b wraps this
  proven program in the `ql-lsm` Rust crate (libbpf-rs loader, profile-driven).

// scripts/lsm-enforce/enforce.bpf.c
//
// QuantmLayer — content-addressed exec ENFORCER (cgroup-scoped).
//
// A sleepable BPF_LSM_CGROUP program on the exec hook bprm_check_security.
// For every exec of a task inside the cgroup this is attached to, it hashes the
// binary's contents via bpf_ima_file_hash (SHA-256) and looks the digest up in
// a hash map of approved digests:
//
//   * digest present  -> return 1 (ALLOW)
//   * digest absent    -> return 0 (DENY; the execve fails with EPERM)
//   * hash unavailable -> return 0 (DENY; fail closed)
//
// Deny-by-default: an empty allow-list denies every exec. This is the kernel
// half of the moat — the loader fills `allowlist` from a profile's
// ExecPolicy.allow_digests (which `ql learn` produced), so the agent's
// demonstrated executable set runs and nothing else does.
//
// SCOPE (stated honestly): this pins *which* binaries may execute, not what
// they do. An approved interpreter can still run arbitrary scripts; that is the
// seccomp / filesystem / network walls' job, not exec hashing's.
//
// LICENSE: bpf_ima_file_hash is a GPL-only helper, so this object declares GPL.
// That governs only this .bpf.c object; the rest of QuantmLayer is Apache-2.0.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define SHA256_LEN 32

// The allow-list: key = 32-byte SHA-256 digest, value = 1 (presence = approved).
// Using key_size/value_size (rather than __type) keeps the byte-array key clean.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, SHA256_LEN);
    __uint(value_size, 1);
} allowlist SEC(".maps");

// Sleepable (set via BPF_F_SLEEPABLE by the loader) because bpf_ima_file_hash
// may sleep. lsm_cgroup return convention: 1 = allow, 0 = reject.
SEC("lsm_cgroup/bprm_check_security")
int BPF_PROG(enforce_exec, struct linux_binprm *bprm, int ret)
{
    __u8 digest[SHA256_LEN] = {};

    long rc = bpf_ima_file_hash(bprm->file, digest, sizeof(digest));
    if (rc < 0)
        return 0; // could not hash -> fail closed (deny)

    if (bpf_map_lookup_elem(&allowlist, digest))
        return 1; // approved content -> allow

    return 0; // unknown content -> deny-by-default
}

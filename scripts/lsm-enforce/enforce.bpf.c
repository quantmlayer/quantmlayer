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
#define COMM_LEN 16

// The allow-list: key = 32-byte SHA-256 digest, value = 1 (presence = approved).
// Using key_size/value_size (rather than __type) keeps the byte-array key clean.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, SHA256_LEN);
    __uint(value_size, 1);
} allowlist SEC(".maps");

// Per-exec audit event streamed to userspace for the tamper-evident log. Field
// order is largest-first so the Rust `#[repr(C)]` mirror has the same layout
// without padding surprises: ktime 0..8, digest 8..40, comm 40..56, pid 56..60,
// allowed 60, hashed 61; the tail pads to an 8-byte boundary (size = 64).
struct exec_event {
    __u64 ktime; // ns since boot (bpf_ktime_get_ns); userspace maps it to wall time
    __u8 digest[SHA256_LEN];
    char comm[COMM_LEN];
    __u32 pid;
    __u8 allowed; // 1 = allowed, 0 = denied
    __u8 hashed;  // 1 = content hashed, 0 = hash unavailable (the deny reason)
};

// Single stream of exec decisions for userspace to record. 64 KiB; if userspace
// falls behind and it fills, bpf_ringbuf_reserve returns NULL and we skip the
// record — logging never changes or blocks the enforcement decision.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// Sleepable (set via BPF_F_SLEEPABLE by the loader) because bpf_ima_file_hash
// may sleep. lsm_cgroup return convention: 1 = allow, 0 = reject.
SEC("lsm_cgroup/bprm_check_security")
int BPF_PROG(enforce_exec, struct linux_binprm *bprm, int ret)
{
    __u8 digest[SHA256_LEN] = {};
    int hashed = 0;
    int allow = 0;

    long rc = bpf_ima_file_hash(bprm->file, digest, sizeof(digest));
    if (rc >= 0) {
        hashed = 1;
        if (bpf_map_lookup_elem(&allowlist, digest))
            allow = 1; // approved content -> allow
    }
    // rc < 0: could not hash -> allow stays 0 -> deny-by-default (fail closed)

    // Best-effort audit record of this exec decision. The logging path must
    // never change or gate the decision: if the ring is full, skip the record.
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memset(e, 0, sizeof(*e));
        e->ktime = bpf_ktime_get_ns();
        if (hashed)
            __builtin_memcpy(e->digest, digest, SHA256_LEN);
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->allowed = allow;
        e->hashed = hashed;
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return allow; // 1 = allow, 0 = deny-by-default
}

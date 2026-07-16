// SPDX-License-Identifier: GPL-2.0-only
//
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
// LICENSE: bpf_ima_file_hash is a GPL-only helper, so the loaded BPF object
// must declare a GPL-compatible license; accordingly this single source file is
// licensed GPL-2.0-only (see the SPDX tag above). It is a standalone program
// loaded into the kernel, not linked into the `ql` binary; every other file in
// QuantmLayer remains Apache-2.0 (see LICENSE and the License section of the
// README).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// BPF_ANY (create-or-update map flag) is a UAPI #define, not a BTF type, so it
// is not guaranteed to come through vmlinux.h. Define it defensively.
#ifndef BPF_ANY
#define BPF_ANY 0
#endif

// SIGKILL is a UAPI #define, likewise not guaranteed via vmlinux.h.
#ifndef SIGKILL
#define SIGKILL 9
#endif

// Max bytes of an argv element we match an argv-deny rule against. Tokens like
// "push", "-rf", "install", "-g" sit well under this; longer tokens cannot be
// enforced kernel-side (the loader skips them).
#define ARGV_TOKEN_MAX 32

#define SHA256_LEN 32
#define COMM_LEN 16
// Bytes of committed argv captured post-exec (see capture_argv). NUL-separated,
// as in /proc/<pid>/cmdline; longer command lines are truncated in the record.
#define ARGV_MAX 1024

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

// pid_tgid -> the SHA-256 digest enforce_exec computed for this exec. Populated
// by enforce_exec (which is cgroup-attached, so only the cell's execs land here)
// on ALLOW, and consumed + deleted by capture_argv at sched_process_exec. It
// serves two purposes: it scopes the system-wide sched_process_exec hook to this
// cell, and it carries the digest forward so a (later) argv-deny check can key on
// it. LRU bounds any leak from an allowed exec that never reaches the post hook.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, SHA256_LEN);
} inflight SEC(".maps");

// The committed argv of one cell exec, captured AFTER the exec commits (so it is
// the immutable copy the new process sees, not the racy pre-exec userspace copy).
// Field order is largest-first so the Rust mirror has the same layout without
// padding: digest 0..32, pid 32..36, len 36..40, argv 40..(40+ARGV_MAX).
struct argv_event {
    __u8 digest[SHA256_LEN]; // the exec's content digest (from inflight)
    __u32 pid;               // thread-group id that exec'd
    __u32 len;               // bytes of argv captured (<= ARGV_MAX)
    __u8 killed;             // 1 = a post-commit argv-deny rule matched -> SIGKILL
    char argv[ARGV_MAX];     // committed argv bytes, NUL-separated
};

// Committed-argv records streamed to userspace. Larger ring than `events` since
// each record is ~1 KiB; on overflow the producer drops, never blocks the exec.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} argv_events SEC(".maps");

// Per-binary argv-deny rules (the Tier-1 single-token subset of the profile's
// argv_deny). Key = the binary's content digest plus one denied argv token
// (NUL-padded); presence = deny that invocation. The loader fills this from the
// profile; matching is a fixed-size map lookup, so the BPF side avoids any
// string compare. Multi-token `all_of` rules are not represented here (they stay
// userspace/Tier-2 only); the loader skips them.
struct argv_deny_key {
    __u8 digest[SHA256_LEN];
    char token[ARGV_TOKEN_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct argv_deny_key);
    __type(value, __u8);
} argv_deny SEC(".maps");

// Per-CPU scratch holding one exec's committed argv for matching. A map value
// has a verifier-known size, so the bpf_loop callback can index it within
// bounds — unlike a ringbuf pointer carried through a callback ctx. Per-CPU and
// single-entry: each exec runs the match to completion in one non-preemptible
// program invocation before the next reuses the slot.
struct argv_buf {
    char buf[ARGV_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct argv_buf);
} argv_scratch SEC(".maps");

// State threaded through the bpf_loop match: the deny key (digest prefilled,
// token built up as we walk), how far to scan, the current token length, and
// whether a rule matched.
struct argv_match_ctx {
    __u32 scan;
    __u32 tok_len;
    __u8 killed;
    struct argv_deny_key key;
};

// One bpf_loop step over the committed argv. Walks byte i: builds the current
// NUL-delimited token into key.token, and at each token boundary looks up
// (digest, token) in argv_deny. A hit records the kill and stops the loop; the
// actual SIGKILL is sent by the caller, in plain program context. Verified once
// by bpf_loop (not per-iteration), which is what keeps the program within the
// instruction budget. Returns 1 to stop, 0 to continue.
static long match_argv_byte(__u32 i, void *vctx)
{
    struct argv_match_ctx *c = vctx;
    if (i >= c->scan)
        return 1;

    __u32 zero = 0;
    struct argv_buf *b = bpf_map_lookup_elem(&argv_scratch, &zero);
    if (!b)
        return 1;

    char ch = b->buf[i & (ARGV_MAX - 1)]; // mask keeps the index provably in range
    if (ch != 0) {
        if (c->tok_len < ARGV_TOKEN_MAX - 1) {
            c->key.token[c->tok_len] = ch;
            c->tok_len++;
        }
        return 0;
    }

    if (c->tok_len > 0 && bpf_map_lookup_elem(&argv_deny, &c->key)) {
        c->killed = 1;
        return 1;
    }
    __builtin_memset(c->key.token, 0, ARGV_TOKEN_MAX);
    c->tok_len = 0;
    return 0;
}

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

    // Tier-1 argv read primitive setup: on ALLOW, stash this exec's digest keyed
    // by pid_tgid so the post-commit sched_process_exec hook (capture_argv) can
    // find it — scoping that system-wide hook to this cell and carrying the
    // digest forward. Denied execs fail and never reach sched_process_exec.
    if (allow && hashed) {
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        bpf_map_update_elem(&inflight, &pid_tgid, digest, BPF_ANY);
    }

    return allow; // 1 = allow, 0 = deny-by-default
}

// Tier-1 committed-argv capture + detect-and-kill. Runs AFTER an exec commits,
// so the new mm is installed and the committed argv is readable at
// current->mm->arg_start..arg_end (the immutable copy /proc/<pid>/cmdline
// exposes) — unlike bprm_check_security, where it still lives in bprm->mm. We
// stream it for audit and match it against argv_deny; a hit SIGKILLs the
// offending task post-commit. Scoped to the cell by `inflight`: only execs that
// went through the cgroup-attached enforce_exec are present, everything else
// returns early.
SEC("tp_btf/sched_process_exec")
int BPF_PROG(capture_argv, struct task_struct *task)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u8 *digest = bpf_map_lookup_elem(&inflight, &pid_tgid);
    if (!digest)
        return 0; // not a cell exec (or already consumed)

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        __u64 arg_start = BPF_CORE_READ(mm, arg_start);
        __u64 arg_end = BPF_CORE_READ(mm, arg_end);
        if (arg_end > arg_start) {
            __u64 span = arg_end - arg_start;
            if (span >= ARGV_MAX)
                span = ARGV_MAX - 1; // keep < buffer size for the verifier
            __u32 len = (__u32)span;

            struct argv_event *e =
                bpf_ringbuf_reserve(&argv_events, sizeof(*e), 0);
            if (e) {
                // No full-struct memset: clang cannot inline memset over a
                // ~1 KiB record and BPF has no memset call. Every reported field
                // is written explicitly; argv bytes past `len` are unspecified
                // and userspace reads only `len` of them.
                __builtin_memcpy(e->digest, digest, SHA256_LEN);
                e->pid = pid_tgid >> 32;
                e->len = len;
                e->killed = 0;
                // The arg pages were just populated by this exec, so the read
                // does not fault; on any failure report no argv (len = 0) rather
                // than submit uninitialized bytes as if they were argv.
                __u32 scan = len;
                if (bpf_probe_read_user(e->argv, len, (const void *)arg_start) < 0) {
                    e->len = 0;
                    scan = 0;
                }
                if (scan >= ARGV_MAX)
                    scan = ARGV_MAX - 1; // belt-and-braces for the read below

                // Post-commit argv-deny match (single-token subset). Copy the
                // committed argv into per-CPU scratch and walk it with bpf_loop:
                // for each NUL-delimited element, look up (digest, token) in
                // argv_deny. A hit is a denied invocation of an approved binary;
                // record it and SIGKILL the offending task. bpf_loop verifies the
                // body once (not 1024x), which keeps the program in budget; the
                // map does the token comparison, so there is no memcmp.
                __u32 zero = 0;
                struct argv_buf *sb = bpf_map_lookup_elem(&argv_scratch, &zero);
                if (sb && scan > 0 &&
                    bpf_probe_read_user(sb->buf, scan, (const void *)arg_start) == 0) {
                    struct argv_match_ctx mc;
                    __builtin_memset(&mc, 0, sizeof(mc));
                    mc.scan = scan;
                    __builtin_memcpy(mc.key.digest, digest, SHA256_LEN);
                    bpf_loop(ARGV_MAX, match_argv_byte, &mc, 0);
                    if (mc.killed) {
                        bpf_send_signal(SIGKILL);
                        e->killed = 1;
                    }
                }

                bpf_ringbuf_submit(e, 0);
            }
        }
    }

    bpf_map_delete_elem(&inflight, &pid_tgid);
    return 0;
}

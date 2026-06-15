// scripts/lsm-loadtest/probe.bpf.c
//
// QuantmLayer — BPF-LSM load test programs (NON-ENFORCING, safe to run).
//
// Two programs, both on the exec hook `bprm_check_security`:
//
//   global_check  — a *sleepable* global LSM program (SEC "lsm.s/..."). It
//     calls bpf_ima_file_hash() on the binary being exec'd and records the
//     result in a one-element array map. It returns `ret` unchanged, so it is
//     fully transparent: it never overrides another LSM's decision and never
//     blocks an exec. If it LOADS + ATTACHES, that proves (a) a sleepable LSM
//     program attaches to this hook here and (b) the verifier accepts
//     bpf_ima_file_hash — i.e. the helper is really present and callable.
//
//   cgroup_check  — the same hook as a BPF_LSM_CGROUP program
//     (SEC "lsm_cgroup/..."). The loader attaches it to a *fresh, empty* test
//     cgroup. Whether the attach SUCCEEDS answers the open design question:
//     is bprm_check_security attachable cgroup-scoped, or must we enforce with
//     a global program + bpf_current_task_under_cgroup?
//
// SAFETY: both programs are transparent (return the incoming `ret`). The
// cgroup program is attached only to an empty cgroup the loader creates and
// removes, so it cannot affect any real process on the host.
//
// LICENSE NOTE: bpf_ima_file_hash is a GPL-only, sleepable-only helper, so
// THIS BPF OBJECT declares "GPL" in its license section. That governs only
// this .bpf.c object; the rest of QuantmLayer remains Apache-2.0.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define DIGEST_MAX 64

struct ima_result {
    __u64 hits;     // execs observed while attached
    __s64 last_rc;  // bpf_ima_file_hash return: >0 digest size on success, <0 errno
    __u8  digest[DIGEST_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ima_result);
} ima_out SEC(".maps");

// Sleepable global LSM on the exec hook. `.s` = sleepable, required because
// bpf_ima_file_hash may sleep (it computes the file hash on demand).
SEC("lsm.s/bprm_check_security")
int BPF_PROG(global_check, struct linux_binprm *bprm, int ret)
{
    __u32 k = 0;
    struct ima_result *r = bpf_map_lookup_elem(&ima_out, &k);
    if (r) {
        long rc = bpf_ima_file_hash(bprm->file, r->digest, sizeof(r->digest));
        r->last_rc = rc;
        r->hits += 1;
    }
    return ret; // transparent — never overrides another LSM's verdict.
}

// Cgroup-scoped variant. Attach-feasibility test only.
//
// BPF_LSM_CGROUP programs use a DIFFERENT return convention than plain LSM: the
// verifier requires the return value to be in [0, 1] (0 = reject, 1 = allow),
// not the 0/-ERRNO of regular lsm. Returning the incoming `ret` (an arbitrary
// int) is rejected at load. We return 1 (allow) — and since the loader attaches
// this only to an empty cgroup, "allow" is both correct and harmless.
SEC("lsm_cgroup/bprm_check_security")
int BPF_PROG(cgroup_check, struct linux_binprm *bprm, int ret)
{
    return 1;
}

// Test 3: does BPF_LSM_CGROUP compose with *sleepable* (which bpf_ima_file_hash
// requires)? Same hook, cgroup-scoped, but the loader marks it sleepable via
// BPF_F_SLEEPABLE and it calls the IMA helper. If this loads + attaches, the
// hashing enforcer can attach directly to the cell's cgroup (cleaner, scoped by
// construction). If it doesn't, we use a global sleepable program + a manual
// bpf_current_task_under_cgroup filter. Returns 1 (allow) per the [0,1] rule.
SEC("lsm_cgroup/bprm_check_security")
int BPF_PROG(cgroup_hash_check, struct linux_binprm *bprm, int ret)
{
    __u32 k = 0;
    struct ima_result *r = bpf_map_lookup_elem(&ima_out, &k);
    if (r) {
        long rc = bpf_ima_file_hash(bprm->file, r->digest, sizeof(r->digest));
        r->last_rc = rc;
        r->hits += 1;
    }
    return 1;
}

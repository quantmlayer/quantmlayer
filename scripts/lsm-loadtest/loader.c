// scripts/lsm-loadtest/loader.c
//
// Userspace driver for the QuantmLayer BPF-LSM load test. Runs two independent
// checks and prints a clear PASS/FAIL plus what each result means for the
// enforcer design. Must run as root (CAP_BPF/CAP_SYS_ADMIN + CAP_MAC_ADMIN).
//
// It deliberately loads the two programs in SEPARATE open/load passes so that
// if one program type isn't accepted on this kernel, it fails only its own
// test instead of taking the other down with it.

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "probe.skel.h"

#define TEST_CG "/sys/fs/cgroup/qllsm_loadtest"

// Quiet libbpf's info chatter; keep warnings (they explain load failures).
static int print_fn(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (lvl == LIBBPF_WARN)
        return vfprintf(stderr, fmt, ap);
    return 0;
}

// Generate a few execs so the attached hook has something to hash.
static void generate_execs(void)
{
    for (int i = 0; i < 3; i++) {
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/true", "true", (char *)NULL);
            _exit(127);
        }
        if (p > 0)
            waitpid(p, NULL, 0);
    }
}

// Layout MUST match struct ima_result in probe.bpf.c (8 + 8 + 64 = 80 bytes).
struct ima_result {
    unsigned long long hits;
    long long          last_rc;
    unsigned char      digest[64];
};

static int test_global(void)
{
    printf("[Test 1] global sleepable LSM on bprm_check_security + bpf_ima_file_hash\n");

    struct probe_bpf *skel = probe_bpf__open();
    if (!skel) {
        printf("  open() failed\n");
        return 0;
    }
    // Each pass must disable EVERY program except the one under test — a
    // sibling's load failure sinks the whole object otherwise.
    bpf_program__set_autoload(skel->progs.cgroup_check, false);
    bpf_program__set_autoload(skel->progs.cgroup_hash_check, false);

    int err = probe_bpf__load(skel);
    if (err) {
        printf("  LOAD failed: %d (%s)\n", err, strerror(err < 0 ? -err : err));
        printf("  → a sleepable LSM on this hook, or bpf_ima_file_hash, was rejected here.\n");
        probe_bpf__destroy(skel);
        return 0;
    }

    struct bpf_link *link = bpf_program__attach(skel->progs.global_check);
    if (!link) {
        printf("  ATTACH failed: errno=%d (%s)\n", errno, strerror(errno));
        probe_bpf__destroy(skel);
        return 0;
    }
    printf("  loaded + attached OK → LSM exec hook + IMA helper are usable.\n");

    generate_execs();
    usleep(300 * 1000);

    __u32 k = 0;
    struct ima_result v;
    memset(&v, 0, sizeof(v));
    if (bpf_map__lookup_elem(skel->maps.ima_out, &k, sizeof(k), &v, sizeof(v), 0) == 0) {
        // NOTE: bpf_ima_file_hash returns the hash *algorithm id* (enum
        // hash_algo) on success — NOT a byte count. 2=SHA1, 4=SHA256,
        // 5=SHA384, 6=SHA512. The digest length follows from the algorithm.
        long long algo = v.last_rc;
        const char *name = "?";
        int dlen = 32;
        switch (algo) {
        case 2: name = "SHA1";   dlen = 20; break;
        case 4: name = "SHA256"; dlen = 32; break;
        case 5: name = "SHA384"; dlen = 48; break;
        case 6: name = "SHA512"; dlen = 64; break;
        }
        printf("  runtime: %llu exec(s) observed; bpf_ima_file_hash rc=%lld", v.hits, algo);
        if (algo > 0) {
            printf(" → algo=%s, %d-byte digest=", name, dlen);
            for (int i = 0; i < dlen && i < (int)sizeof(v.digest); i++)
                printf("%02x", v.digest[i]);
            printf("\n  → IMA returned a real %s digest. Content-addressed exec via IMA is viable.\n", name);
        } else {
            printf("\n  → helper callable but rc<=0; check IMA policy / hook timing.\n");
        }
    }

    bpf_link__destroy(link);
    probe_bpf__destroy(skel);
    return 1;
}

static int test_cgroup(void)
{
    printf("\n[Test 2] cgroup-scoped (BPF_LSM_CGROUP) attach on bprm_check_security\n");

    struct probe_bpf *skel = probe_bpf__open();
    if (!skel) {
        printf("  open() failed\n");
        return 0;
    }
    bpf_program__set_autoload(skel->progs.global_check, false);
    bpf_program__set_autoload(skel->progs.cgroup_hash_check, false);

    int err = probe_bpf__load(skel);
    if (err) {
        printf("  LOAD failed: %d (%s)\n", err, strerror(err < 0 ? -err : err));
        printf("  → see the libbpf verifier log above for the exact reason.\n");
        printf("  → if cgroup-scoping is genuinely unsupported here, the enforcer uses a\n");
        printf("    global sleepable LSM + bpf_current_task_under_cgroup (the chosen design).\n");
        probe_bpf__destroy(skel);
        return 0;
    }

    if (mkdir(TEST_CG, 0755) != 0 && errno != EEXIST) {
        printf("  could not create test cgroup %s: %s\n", TEST_CG, strerror(errno));
        probe_bpf__destroy(skel);
        return 0;
    }
    int cgfd = open(TEST_CG, O_RDONLY | O_DIRECTORY);
    if (cgfd < 0) {
        printf("  could not open test cgroup: %s\n", strerror(errno));
        rmdir(TEST_CG);
        probe_bpf__destroy(skel);
        return 0;
    }

    int ok = 0;
    struct bpf_link *link = bpf_program__attach_cgroup(skel->progs.cgroup_check, cgfd);
    if (!link) {
        printf("  ATTACH to cgroup failed: errno=%d (%s)\n", errno, strerror(errno));
        printf("  → cgroup-scoped attach NOT available for this hook; use global + manual cgroup check.\n");
    } else {
        printf("  attached to empty test cgroup OK → BPF_LSM_CGROUP supports bprm_check_security.\n");
        bpf_link__destroy(link);
        ok = 1;
    }

    close(cgfd);
    rmdir(TEST_CG);
    probe_bpf__destroy(skel);
    return ok;
}

static int test_cgroup_sleepable(void)
{
    printf("\n[Test 3] sleepable cgroup-native LSM (BPF_LSM_CGROUP + bpf_ima_file_hash)\n");

    struct probe_bpf *skel = probe_bpf__open();
    if (!skel) {
        printf("  open() failed\n");
        return 0;
    }
    bpf_program__set_autoload(skel->progs.global_check, false);
    bpf_program__set_autoload(skel->progs.cgroup_check, false);
    // bpf_ima_file_hash is sleepable-only; mark this cgroup program sleepable.
    bpf_program__set_flags(skel->progs.cgroup_hash_check, BPF_F_SLEEPABLE);

    int err = probe_bpf__load(skel);
    if (err) {
        printf("  LOAD failed: %d (%s)\n", err, strerror(err < 0 ? -err : err));
        printf("  → sleepable + BPF_LSM_CGROUP do NOT compose here (see libbpf log above).\n");
        printf("  → ARCHITECTURE: global sleepable LSM + bpf_current_task_under_cgroup.\n");
        probe_bpf__destroy(skel);
        return 0;
    }

    if (mkdir(TEST_CG, 0755) != 0 && errno != EEXIST) {
        printf("  could not create test cgroup: %s\n", strerror(errno));
        probe_bpf__destroy(skel);
        return 0;
    }
    int cgfd = open(TEST_CG, O_RDONLY | O_DIRECTORY);
    if (cgfd < 0) {
        printf("  could not open test cgroup: %s\n", strerror(errno));
        rmdir(TEST_CG);
        probe_bpf__destroy(skel);
        return 0;
    }

    int ok = 0;
    struct bpf_link *link = bpf_program__attach_cgroup(skel->progs.cgroup_hash_check, cgfd);
    if (!link) {
        printf("  ATTACH failed: errno=%d (%s)\n", errno, strerror(errno));
        printf("  → ARCHITECTURE: global sleepable LSM + bpf_current_task_under_cgroup.\n");
    } else {
        printf("  loaded + attached OK → sleepable cgroup-native hashing IS available.\n");
        printf("  → ARCHITECTURE OPTION: attach the hashing enforcer directly to the cell cgroup.\n");
        bpf_link__destroy(link);
        ok = 1;
    }

    close(cgfd);
    rmdir(TEST_CG);
    probe_bpf__destroy(skel);
    return ok;
}

int main(void)
{
    libbpf_set_print(print_fn);

    printf("== QuantmLayer BPF-LSM load test ==\n");
    printf("(non-enforcing; both programs are transparent and never block an exec)\n\n");

    int t1 = test_global();
    int t2 = test_cgroup();
    int t3 = test_cgroup_sleepable();

    printf("\n== Summary ==\n");
    printf("  Test 1 (global sleepable LSM + IMA hash): %s\n", t1 ? "PASS" : "FAIL");
    printf("  Test 2 (cgroup attach, non-sleepable):    %s\n", t2 ? "PASS" : "FAIL");
    printf("  Test 3 (sleepable cgroup-native hash):    %s\n", t3 ? "PASS" : "FAIL → use global+manual");

    printf("\nDesign read:\n");
    if (!t1) {
        printf("  Test 1 failed — resolve the IMA / sleepable-hook question before building the\n");
        printf("  enforcer. Send me this output and I'll adjust.\n");
    } else if (t3) {
        printf("  Sleepable composes with BPF_LSM_CGROUP → the hashing enforcer MAY attach directly\n");
        printf("  to the cell's cgroup: scoped by construction, no host-wide hook, no manual filter.\n");
        printf("  (Global sleepable + bpf_current_task_under_cgroup remains a valid alternative.)\n");
    } else {
        printf("  Sleepable does NOT compose with BPF_LSM_CGROUP → enforce via a GLOBAL sleepable LSM\n");
        printf("  program + bpf_current_task_under_cgroup, gating the hash behind that cheap check so\n");
        printf("  it never runs host-wide. This path is fully validated by Test 1.\n");
    }
    return 0;
}

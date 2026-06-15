// scripts/lsm-enforce/loader.c
//
// Loader + self-contained demo for the content-addressed exec enforcer.
//
// Usage:   sudo ./enforce <approved-sha256-hex> [<approved-sha256-hex>...]
//
// It loads the enforcer, fills the allow-list with the digests given on the
// command line, attaches the program to a fresh demo cgroup, then runs three
// execs *inside that cgroup* to demonstrate the policy:
//
//   1. /bin/true                — approved digest        -> expect ALLOWED
//   2. a byte-identical copy     — same content, new name -> expect ALLOWED
//      (proves we trust the bytes, not the path)
//   3. /bin/ls                  — not approved           -> expect DENIED
//
// Only the loader's own forked children are placed in the cgroup, so the host
// is unaffected. The cgroup and the temp copy are removed on exit. `make run`
// passes sha256(/bin/true) as the approved digest.

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

#include "enforce.skel.h"

#define CG "/sys/fs/cgroup/ql-enforce-demo"
#define COPY "/var/tmp/ql-true-copy" // /var/tmp: persistent fs, not tmpfs
#define DENIED_SENTINEL 42           // child exit code when its exec was blocked
#define SHA256_LEN 32                // must match enforce.bpf.c

static int print_fn(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (lvl == LIBBPF_WARN)
        return vfprintf(stderr, fmt, ap);
    return 0;
}

// Decode `2*n` lowercase/upper hex chars into `out[n]`. Returns 0 on success.
static int hex_to_bytes(const char *hex, __u8 *out, size_t n)
{
    if (strlen(hex) != n * 2)
        return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1)
            return -1;
        out[i] = (__u8)v;
    }
    return 0;
}

// Fork a child, move it into the demo cgroup, exec `path`.
// Returns 1 = ran (allowed), 0 = denied (EPERM), -1 = setup error.
static int try_exec_in_cgroup(const char *path)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        // Child: join the cgroup *before* exec, so the hook governs this exec.
        int fd = open(CG "/cgroup.procs", O_WRONLY);
        if (fd < 0)
            _exit(70);
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "%d\n", getpid());
        if (write(fd, buf, n) < 0) {
            close(fd);
            _exit(71);
        }
        close(fd);
        // Silence an allowed program's stdout so the demo output stays clean.
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            close(devnull);
        }
        execl(path, path, (char *)NULL);
        // Reaching here means exec was blocked (or otherwise failed).
        fprintf(stderr, "      execl(%s) blocked: %s\n", path, strerror(errno));
        _exit(errno == EPERM ? DENIED_SENTINEL : 73);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status))
        return -1;
    int code = WEXITSTATUS(status);
    if (code == DENIED_SENTINEL)
        return 0; // denied
    if (code >= 70 && code <= 73)
        return -1; // setup error in child
    return 1;      // the program ran -> allowed
}

static void report(const char *label, int got, int expect_allow)
{
    const char *res = got == 1 ? "ALLOWED" : (got == 0 ? "DENIED" : "ERROR");
    int ok = (got == (expect_allow ? 1 : 0));
    printf("  [%s] %-48s -> %s\n", ok ? "PASS" : "FAIL", label, res);
}

int main(int argc, char **argv)
{
    libbpf_set_print(print_fn);
    if (argc < 2) {
        fprintf(stderr, "usage: %s <approved-sha256-hex>...\n", argv[0]);
        return 2;
    }

    printf("== QuantmLayer content-addressed exec enforcer (demo) ==\n");
    printf("(deny-by-default; only the loader's children are placed in the cgroup)\n\n");

    struct enforce_bpf *skel = enforce_bpf__open();
    if (!skel) {
        fprintf(stderr, "open() failed\n");
        return 1;
    }
    // bpf_ima_file_hash is sleepable-only; mark the program sleepable.
    bpf_program__set_flags(skel->progs.enforce_exec, BPF_F_SLEEPABLE);
    if (enforce_bpf__load(skel)) {
        fprintf(stderr, "load failed (see libbpf log above)\n");
        enforce_bpf__destroy(skel);
        return 1;
    }

    // Fill the allow-list from the digests on the command line.
    int mapfd = bpf_map__fd(skel->maps.allowlist);
    for (int i = 1; i < argc; i++) {
        __u8 key[SHA256_LEN];
        if (hex_to_bytes(argv[i], key, SHA256_LEN) != 0) {
            fprintf(stderr, "  ignoring malformed digest: %s\n", argv[i]);
            continue;
        }
        __u8 one = 1;
        if (bpf_map_update_elem(mapfd, key, &one, BPF_ANY) != 0)
            fprintf(stderr, "  map update failed for %s: %s\n", argv[i], strerror(errno));
        else
            printf("  approved digest: %s\n", argv[i]);
    }

    // Create the demo cgroup and attach the enforcer to it.
    if (mkdir(CG, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s\n", CG, strerror(errno));
        enforce_bpf__destroy(skel);
        return 1;
    }
    int cgfd = open(CG, O_RDONLY | O_DIRECTORY);
    if (cgfd < 0) {
        fprintf(stderr, "open %s: %s\n", CG, strerror(errno));
        rmdir(CG);
        enforce_bpf__destroy(skel);
        return 1;
    }
    struct bpf_link *link = bpf_program__attach_cgroup(skel->progs.enforce_exec, cgfd);
    if (!link) {
        fprintf(stderr, "attach to cgroup failed: %s\n", strerror(errno));
        close(cgfd);
        rmdir(CG);
        enforce_bpf__destroy(skel);
        return 1;
    }
    printf("  enforcer attached to %s\n\n", CG);

    // A byte-identical copy of /bin/true: same content => same digest =>
    // approved, even under a different name. Proves we trust bytes, not paths.
    if (system("cp /bin/true " COPY " && chmod +x " COPY) != 0)
        fprintf(stderr, "  warning: could not stage %s\n", COPY);

    printf("Execs inside the contained cgroup:\n");
    report("/bin/true (approved digest)", try_exec_in_cgroup("/bin/true"), 1);
    report("copy of /bin/true (same bytes, new name)", try_exec_in_cgroup(COPY), 1);
    report("/bin/ls (NOT approved)", try_exec_in_cgroup("/bin/ls"), 0);

    printf("\nExpected: ALLOWED, ALLOWED, DENIED — content is the key, not the path.\n");

    // Cleanup.
    bpf_link__destroy(link);
    close(cgfd);
    rmdir(CG);
    unlink(COPY);
    enforce_bpf__destroy(skel);
    return 0;
}

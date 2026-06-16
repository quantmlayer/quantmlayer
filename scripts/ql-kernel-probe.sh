#!/usr/bin/env bash
# scripts/ql-kernel-probe.sh
#
# QuantmLayer — Step 0 kernel-floor probe (read-only).
#
# Purpose: read off the machine, empirically, everything needed to decide
# whether content-addressed execve enforcement (BPF-LSM + a kernel-computed
# file digest) is possible here, and via which hash source (IMA vs fs-verity).
# It also inventories the build tooling so the follow-up *load test* (a tiny
# BPF program that actually attaches to bprm_check_security, incl. the
# BPF_LSM_CGROUP attach question) can be written knowing what this box has.
#
# It is non-destructive: it only reads. It never loads a BPF program, never
# enables verity on a file, never changes kernel state. The one thing it
# CANNOT answer — does a cgroup-scoped LSM program actually attach to
# bprm_check_security — is called out at the end as the load test's job.
#
# Run as your normal user first; a few checks read more when run with sudo
# (kernel config, IMA, BTF perms vary by distro). The script reports which
# checks would benefit from root rather than failing.
#
# Usage:   bash ql-kernel-probe.sh
#          sudo bash ql-kernel-probe.sh > probe.txt 2>&1   # fuller, capture it

# Deliberately NOT using `set -e`: a failed probe must report and continue,
# never abort the run. `set -u` catches our own typos.
set -u

# ---- tiny reporting helpers ------------------------------------------------
c_ok=$'\033[32m'; c_no=$'\033[31m'; c_wa=$'\033[33m'; c_in=$'\033[36m'; c_z=$'\033[0m'
[ -t 1 ] || { c_ok=; c_no=; c_wa=; c_in=; c_z=; }   # no colour when piped

# --json emits ONLY a machine-readable capability object on stdout (for the
# portability-matrix runner); default mode prints the human report.
JSON_MODE=no; [ "${1:-}" = "--json" ] && JSON_MODE=yes

ok()   { [ "$JSON_MODE" = yes ] && return 0; printf '  %s[ OK ]%s %s\n'  "$c_ok" "$c_z" "$*"; }
no()   { [ "$JSON_MODE" = yes ] && return 0; printf '  %s[ NO ]%s %s\n'  "$c_no" "$c_z" "$*"; }
warn() { [ "$JSON_MODE" = yes ] && return 0; printf '  %s[ !! ]%s %s\n'  "$c_wa" "$c_z" "$*"; }
info() { [ "$JSON_MODE" = yes ] && return 0; printf '  %s[ .. ]%s %s\n'  "$c_in" "$c_z" "$*"; }
hdr()  { [ "$JSON_MODE" = yes ] && return 0; printf '\n%s== %s ==%s\n' "$c_in" "$*" "$c_z"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Verdict flags, filled in as we go, summarised at the end.
V_LSM_ACTIVE=unknown        # bpf in the active LSM stack
V_BPF_LSM_CFG=unknown       # CONFIG_BPF_LSM
V_BTF=unknown               # /sys/kernel/btf/vmlinux present (CO-RE)
V_IMA=unknown               # IMA configured + initialised
V_VERITY=unknown            # fs-verity configured + a binary fs supports it
V_CGROUP_BPF=unknown        # CONFIG_CGROUP_BPF (LSM_CGROUP prereq)
V_HELPER_IMA=unknown        # bpf_ima_file_hash advertised
V_HELPER_VERITY=unknown     # bpf_get_fsverity_digest advertised
V_BUILD=unknown             # clang + bpftool + libbpf headers present
V_CGROUP_V2=unknown         # unified cgroup v2 hierarchy
V_PIDS=unknown              # pids controller (fork-bomb wall)
V_USERNS=unknown            # user namespaces usable (clone3 + CLONE_NEWUSER)
V_VETH=unknown              # veth + NET_NS + ip (brokered egress uplink)
V_SECCOMP=unknown           # seccomp filtering
V_SECCOMP_NOTIFY=unknown    # seccomp user-notification (>= 5.0)
V_LANDLOCK=unknown          # Landlock (optional fs hardening, >= 5.13)
OS_PRETTY=unknown           # distro pretty name

am_root=no; [ "$(id -u)" = 0 ] && am_root=yes

if [ "$JSON_MODE" != yes ]; then
  printf '%s' "QuantmLayer kernel-floor probe"
  printf '   (root=%s)\n' "$am_root"
  date 2>/dev/null
fi

# ---------------------------------------------------------------------------
hdr "A. Kernel & platform"
KREL="$(uname -r 2>/dev/null)"; KARCH="$(uname -m 2>/dev/null)"
info "kernel : ${KREL:-unknown}   arch : ${KARCH:-unknown}"
# Parse major.minor for version gates.
kmaj=0; kmin=0
if [[ "$KREL" =~ ^([0-9]+)\.([0-9]+) ]]; then
  kmaj="${BASH_REMATCH[1]}"; kmin="${BASH_REMATCH[2]}"
fi
kver=$(( kmaj * 1000 + kmin ))
if   [ "$kver" -ge 6000 ]; then ok "kernel >= 6.0  → BPF_LSM_CGROUP is in-tree (cgroup-scoped LSM possible)"
elif [ "$kver" -ge 5007 ]; then warn "kernel 5.7–5.x → global BPF-LSM only; BPF_LSM_CGROUP needs >= 6.0"
else no "kernel < 5.7 → no BPF-LSM at all (would need a newer kernel)"; fi
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release 2>/dev/null
  OS_PRETTY="${PRETTY_NAME:-unknown}"
  info "distro : $OS_PRETTY"
fi

# ---------------------------------------------------------------------------
hdr "B. LSM activation  (THE gate — is bpf an active LSM?)"
LSM_FILE=/sys/kernel/security/lsm
if [ ! -d /sys/kernel/security ] || [ -z "$(ls -A /sys/kernel/security 2>/dev/null)" ]; then
  warn "securityfs not mounted/empty; try: sudo mount -t securityfs none /sys/kernel/security"
fi
if [ -r "$LSM_FILE" ]; then
  LSM="$(cat "$LSM_FILE" 2>/dev/null)"
  info "active LSMs: $LSM"
  case ",$LSM," in
    *,bpf,*) ok "bpf IS in the active LSM stack → BPF-LSM programs can attach, no reboot needed"
             V_LSM_ACTIVE=yes ;;
    *)       no  "bpf is NOT active → enforcement needs boot param 'lsm=...,bpf' + reboot"
             V_LSM_ACTIVE=no ;;
  esac
else
  warn "cannot read $LSM_FILE (try sudo); LSM activation undetermined"
fi
if [ -r /proc/cmdline ]; then
  CMDLSM="$(tr ' ' '\n' < /proc/cmdline | grep '^lsm=' || true)"
  [ -n "$CMDLSM" ] && info "boot cmdline LSM: $CMDLSM" || info "no explicit lsm= on cmdline (kernel default stack in use)"
fi

# ---------------------------------------------------------------------------
hdr "C. Kernel config"
CFG=""
if [ -r /proc/config.gz ] && have zcat; then CFG="zcat /proc/config.gz"
elif [ -r "/boot/config-$KREL" ];        then CFG="cat /boot/config-$KREL"
fi
cfg_get() { [ -n "$CFG" ] && $CFG 2>/dev/null | grep -E "^$1=" | head -1; }
if [ -z "$CFG" ]; then
  warn "no readable kernel config (/proc/config.gz or /boot/config-$KREL); rerun with sudo, or install the config"
else
  info "config source: $CFG"
  for opt in CONFIG_BPF_SYSCALL CONFIG_BPF_LSM CONFIG_DEBUG_INFO_BTF \
             CONFIG_CGROUP_BPF CONFIG_IMA CONFIG_IMA_DEFAULT_HASH_SHA256 \
             CONFIG_INTEGRITY CONFIG_FS_VERITY CONFIG_FS_VERITY_BUILTIN_SIGNATURES \
             CONFIG_USER_NS CONFIG_NAMESPACES CONFIG_NET_NS CONFIG_VETH \
             CONFIG_SECCOMP CONFIG_SECCOMP_FILTER CONFIG_SECURITY_LANDLOCK; do
    line="$(cfg_get "$opt")"
    if [ -n "$line" ]; then ok "$line"; else no "$opt is not set (=n / absent)"; fi
  done
  case "$(cfg_get CONFIG_BPF_LSM)" in *=y) V_BPF_LSM_CFG=yes;; *) V_BPF_LSM_CFG=no;; esac
  case "$(cfg_get CONFIG_CGROUP_BPF)" in *=y) V_CGROUP_BPF=yes;; *) V_CGROUP_BPF=no;; esac
fi

# ---------------------------------------------------------------------------
hdr "D. BTF  (CO-RE requirement for a portable LSM object)"
if [ -r /sys/kernel/btf/vmlinux ]; then
  sz=$(stat -c%s /sys/kernel/btf/vmlinux 2>/dev/null || echo 0)
  ok "/sys/kernel/btf/vmlinux present (${sz} bytes) → CO-RE programs will build/load"
  V_BTF=yes
else
  no "/sys/kernel/btf/vmlinux absent → CO-RE unavailable; would need vmlinux BTF or a non-CO-RE build"
  V_BTF=no
fi

# ---------------------------------------------------------------------------
hdr "E. IMA  (hash source option 1: bpf_ima_file_hash — content-trust anywhere)"
if [ -d /sys/kernel/security/ima ]; then
  ok "/sys/kernel/security/ima present → IMA subsystem initialised"
  V_IMA=yes
  meas=/sys/kernel/security/ima/ascii_runtime_measurements
  if [ -r "$meas" ]; then
    n=$(wc -l < "$meas" 2>/dev/null || echo 0)
    info "runtime measurement list readable (${n} entries)"
  else
    info "measurement list not readable as this user (need sudo to inspect) — not required for bpf_ima_file_hash, which hashes on demand"
  fi
else
  no "/sys/kernel/security/ima absent → IMA not active; bpf_ima_file_hash path unavailable here"
  V_IMA=no
fi

# ---------------------------------------------------------------------------
hdr "F. fs-verity  (hash source option 2: bpf_get_fsverity_digest — sealed-location trust)"
if have fsverity; then info "fsverity tool: $(command -v fsverity)"; else warn "fsverity userspace tool not installed (apt: fsverity / f2fs-tools|e2fsprogs)"; fi
# Where do agent binaries actually live? Check the fs backing /usr/bin.
BINFS="$(df --output=fstype /usr/bin 2>/dev/null | tail -1 | tr -d ' ')"
BINSRC="$(df --output=source /usr/bin 2>/dev/null | tail -1 | tr -d ' ')"
info "/usr/bin is on: ${BINFS:-unknown}  (${BINSRC:-?})"
verity_fs=no
case "$BINFS" in
  ext4|f2fs|btrfs) verity_fs=maybe ;;
esac
if [ "$verity_fs" = maybe ] && [ "$BINFS" = ext4 ] && have tune2fs && [ -n "$BINSRC" ]; then
  if tune2fs -l "$BINSRC" 2>/dev/null | grep -qi 'verity'; then
    ok "ext4 on $BINSRC has the 'verity' feature enabled"
    V_VERITY=yes
  else
    no "ext4 on $BINSRC does NOT have the 'verity' feature (tune2fs -O verity needed, offline)"
    V_VERITY=no
  fi
elif [ "$verity_fs" = maybe ]; then
  warn "$BINFS can support verity, but couldn't confirm the feature flag read-only (need sudo/tune2fs)"
  V_VERITY=maybe
else
  no "the fs under /usr/bin ($BINFS) doesn't support fs-verity → would need binaries on a verity-capable fs"
  V_VERITY=no
fi
info "NOTE: fs-verity semantics = 'approved bytes run only from their sealed original'; a copied binary loses its seal → denied (good for the copy-rename demo). IMA = 'approved content runs anywhere'. Pick deliberately; this is policy, not just ops weight."

# ---------------------------------------------------------------------------
hdr "G. BPF helper / program-type availability"
if have bpftool; then
  info "bpftool: $(bpftool version 2>/dev/null | head -1)"
  # `feature probe` can be large + want root; narrow + timeout it.
  FP="$( (timeout 25 bpftool feature probe kernel 2>/dev/null) || true )"
  if [ -z "$FP" ]; then
    warn "bpftool feature probe returned nothing (often needs sudo) — rerun with sudo to confirm helpers"
  else
    echo "$FP" | grep -qi 'program_type lsm.*GO\|eBPF program_type lsm is available' && ok "program type 'lsm' is available" \
      || { echo "$FP" | grep -qi 'lsm' && info "lsm referenced in feature probe (inspect manually)" || no "program type 'lsm' not advertised"; }
    if echo "$FP" | grep -qi 'ima_file_hash'; then ok "helper bpf_ima_file_hash advertised"; V_HELPER_IMA=yes
      else no "bpf_ima_file_hash not advertised"; V_HELPER_IMA=no; fi
    if echo "$FP" | grep -qi 'fsverity_digest'; then ok "helper bpf_get_fsverity_digest advertised"; V_HELPER_VERITY=yes
      else no "bpf_get_fsverity_digest not advertised"; V_HELPER_VERITY=no; fi
    echo "$FP" | grep -qi 'current_task_under_cgroup' && info "bpf_current_task_under_cgroup advertised (global-attach + manual cgroup-check fallback is viable)"
    # bpf_ima_file_hash / bpf_get_fsverity_digest are LSM-program-only helpers.
    # bpftool confirms a helper by loading a synthetic probe program OF THAT TYPE;
    # for LSM it often cannot build a valid attach, so it UNDER-REPORTS these even
    # when present. A "not advertised" here is therefore NOT proof of absence —
    # only the load test (an actual lsm program that calls the helper) is
    # authoritative. (And if bpf isn't yet an active LSM per section B, no LSM
    # probe can load at all, so the negative is doubly unreliable.)
    if { [ "$V_HELPER_IMA" = no ] || [ "$V_HELPER_VERITY" = no ]; }; then
      warn "LSM-only helper negative(s) above are UNCONFIRMED: bpftool under-probes LSM helpers. Confirm with scripts/lsm-loadtest (the load test), not bpftool."
    fi
  fi
else
  warn "bpftool absent → cannot directly confirm helpers. Install: apt install linux-tools-common linux-tools-$KREL (or bpftool)."
  info "Inference: kernel $KREL with CONFIG_BPF_LSM=y and CONFIG_IMA=y normally ships bpf_ima_file_hash (>=5.11) and bpf_get_fsverity_digest (>=6.1). Confirm with bpftool before relying on it."
fi

# ---------------------------------------------------------------------------
hdr "H. Build tooling  (for the follow-up load test I'll write next)"
tool_clang=no; have clang && { tool_clang=yes; ok "clang: $(clang --version 2>/dev/null | head -1)"; } || warn "clang absent (needed to compile the BPF object: apt install clang llvm)"
have bpftool && ok "bpftool present (skeleton gen / attach)" || warn "bpftool absent (skeleton gen)"
libbpf=no
for h in /usr/include/bpf/libbpf.h /usr/include/bpf/bpf_helpers.h; do [ -r "$h" ] && libbpf=yes; done
if [ "$libbpf" = yes ]; then ok "libbpf headers present (/usr/include/bpf/)"; else warn "libbpf-dev headers absent (apt install libbpf-dev)"; fi
have pahole && info "pahole: $(pahole --version 2>/dev/null)" || info "pahole absent (only needed if regenerating BTF)"
have cargo && info "cargo present ($(cargo --version 2>/dev/null)) → aya (pure-Rust eBPF) loader is an option" || info "cargo absent on this box"
if [ "$tool_clang" = yes ] && [ "$libbpf" = yes ]; then V_BUILD=yes; else V_BUILD=partial; fi

# ---------------------------------------------------------------------------
hdr "I. cgroup v2  (resource walls: pids anti-forkbomb, memory, cpu)"
if [ -r /sys/fs/cgroup/cgroup.controllers ]; then
  ctrls="$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null)"
  ok "unified cgroup v2 at /sys/fs/cgroup (controllers: $ctrls)"
  V_CGROUP_V2=yes
  case " $ctrls " in
    *" pids "*) ok "pids controller present → fork-bomb wall available"; V_PIDS=yes ;;
    *)          no "pids controller absent → fork-bomb wall degraded"; V_PIDS=no ;;
  esac
else
  warn "cgroup v2 unified hierarchy not detected at /sys/fs/cgroup (hybrid/v1?) — resource walls degraded"
  V_CGROUP_V2=no; V_PIDS=no
fi

# ---------------------------------------------------------------------------
hdr "J. User namespaces  (the cell builds with clone3 + CLONE_NEWUSER)"
userns_cfg="$(cfg_get CONFIG_USER_NS)"
[ -n "$userns_cfg" ] && ok "$userns_cfg" || info "CONFIG_USER_NS unknown (no readable config)"
maxuserns="$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo unknown)"
info "user.max_user_namespaces = $maxuserns"
unpriv="$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo unset)"
[ "$unpriv" != unset ] && info "kernel.unprivileged_userns_clone = $unpriv"
if [ "$maxuserns" = 0 ]; then
  no "user namespaces disabled (max_user_namespaces=0) — cell cannot create a userns"
  V_USERNS=no
elif [ "$unpriv" = 0 ] && [ "$am_root" != yes ]; then
  warn "unprivileged userns disabled; cell needs root or unprivileged_userns_clone=1"
  V_USERNS=restricted
elif [ -z "$userns_cfg" ] && [ "$maxuserns" = unknown ]; then
  warn "user namespace support undetermined (need readable config or sudo)"
  V_USERNS=unknown
else
  ok "user namespaces available"
  V_USERNS=yes
fi

# ---------------------------------------------------------------------------
hdr "K. seccomp  (syscall-filter wall; notify = userspace supervision)"
actions=/proc/sys/kernel/seccomp/actions_avail
if [ -r "$actions" ]; then
  ok "seccomp filtering available (actions: $(cat "$actions" 2>/dev/null))"
  V_SECCOMP=yes
else
  sc_cfg="$(cfg_get CONFIG_SECCOMP_FILTER)"
  if [ -n "$sc_cfg" ]; then ok "$sc_cfg (actions_avail not readable)"; V_SECCOMP=yes
  else warn "seccomp filter support undetermined"; V_SECCOMP=unknown; fi
fi
if [ "$kver" -ge 5000 ]; then
  ok "kernel >= 5.0 → seccomp user-notification (notify) available"; V_SECCOMP_NOTIFY=yes
else
  no "kernel < 5.0 → no seccomp user-notification"; V_SECCOMP_NOTIFY=no
fi

# ---------------------------------------------------------------------------
hdr "L. Network namespace + veth  (the brokered-egress uplink)"
netns_cfg="$(cfg_get CONFIG_NET_NS)"; veth_cfg="$(cfg_get CONFIG_VETH)"
[ -n "$netns_cfg" ] && ok "$netns_cfg" || info "CONFIG_NET_NS unknown"
veth_ok=no
if [ -n "$veth_cfg" ]; then
  case "$veth_cfg" in
    *=y | *=m) ok "$veth_cfg → veth available"; veth_ok=yes ;;
    *)         no "$veth_cfg" ;;
  esac
elif [ -d /sys/module/veth ]; then
  ok "veth module loaded"; veth_ok=yes
else
  info "veth support undetermined (no config; try: sudo modprobe veth)"
fi
if have ip; then ok "iproute2 'ip' present (veth setup)"; else warn "'ip' (iproute2) absent — brokered veth setup needs it"; fi
if [ "$veth_ok" = yes ] && have ip; then V_VETH=yes
elif have ip; then V_VETH=maybe
else V_VETH=no; fi

# ---------------------------------------------------------------------------
hdr "M. Landlock  (optional fs hardening; the current cell uses mount ns, not Landlock)"
ll_cfg="$(cfg_get CONFIG_SECURITY_LANDLOCK)"
if [ "$kver" -lt 5013 ]; then
  no "kernel < 5.13 → Landlock unavailable"; V_LANDLOCK=no
elif [ -r "$LSM_FILE" ] && grep -q 'landlock' "$LSM_FILE" 2>/dev/null; then
  ok "landlock in the active LSM stack → available"; V_LANDLOCK=yes
elif [ -n "$ll_cfg" ]; then
  case "$ll_cfg" in
    *=y) info "CONFIG_SECURITY_LANDLOCK=y but not in active lsm stack (add to lsm=)"; V_LANDLOCK=restricted ;;
    *)   no "$ll_cfg"; V_LANDLOCK=no ;;
  esac
else
  info "Landlock status undetermined (need readable config or sudo)"; V_LANDLOCK=unknown
fi
info "NOTE: the current cell enforces fs boundaries via mount namespaces, not Landlock; this row is for future hardening."

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Machine-readable capability object (one row of the portability matrix).
emit_json() {
  js() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
  local rootbool; [ "$am_root" = yes ] && rootbool=true || rootbool=false
  printf '{\n'
  printf '  "schema": "ql-probe/1",\n'
  printf '  "host": {"kernel": "%s", "arch": "%s", "distro": "%s", "root": %s},\n' \
    "$(js "${KREL:-unknown}")" "$(js "${KARCH:-unknown}")" "$(js "$OS_PRETTY")" "$rootbool"
  printf '  "walls": {\n'
  printf '    "cgroup_v2": "%s",\n'        "$V_CGROUP_V2"
  printf '    "pids_controller": "%s",\n'  "$V_PIDS"
  printf '    "user_namespaces": "%s",\n'  "$V_USERNS"
  printf '    "network_veth": "%s",\n'     "$V_VETH"
  printf '    "seccomp": "%s",\n'          "$V_SECCOMP"
  printf '    "seccomp_notify": "%s",\n'   "$V_SECCOMP_NOTIFY"
  printf '    "landlock": "%s",\n'         "$V_LANDLOCK"
  printf '    "exec_bpf_lsm": "%s"\n'      "$V_LSM_ACTIVE"
  printf '  },\n'
  printf '  "exec_wall_detail": {\n'
  printf '    "config_bpf_lsm": "%s",\n'   "$V_BPF_LSM_CFG"
  printf '    "btf": "%s",\n'              "$V_BTF"
  printf '    "cgroup_bpf": "%s",\n'       "$V_CGROUP_BPF"
  printf '    "ima": "%s",\n'              "$V_IMA"
  printf '    "ima_helper": "%s",\n'       "$V_HELPER_IMA"
  printf '    "verity": "%s",\n'           "$V_VERITY"
  printf '    "verity_helper": "%s"\n'     "$V_HELPER_VERITY"
  printf '  },\n'
  printf '  "build_tooling": "%s"\n'       "$V_BUILD"
  printf '}\n'
}

# In machine-readable mode, emit the capability object and stop here.
if [ "$JSON_MODE" = yes ]; then emit_json; exit 0; fi

hdr "VERDICT"
say() { printf '  %-26s %s\n' "$1" "$2"; }
say "BPF-LSM active (no reboot):" "$V_LSM_ACTIVE"
say "CONFIG_BPF_LSM:"            "$V_BPF_LSM_CFG"
say "BTF / CO-RE:"              "$V_BTF"
say "CONFIG_CGROUP_BPF:"        "$V_CGROUP_BPF"
say "IMA usable:"               "$V_IMA  (helper advertised: $V_HELPER_IMA)"
say "fs-verity usable:"         "$V_VERITY  (helper advertised: $V_HELPER_VERITY)"
say "build tooling:"            "$V_BUILD"

echo
if [ "$V_LSM_ACTIVE" = no ]; then
  warn "GATE NOT MET: bpf isn't an active LSM. Stage B (enforcement) is blocked until you reboot with 'lsm=' including bpf."
  info "Stage A (non-enforcing exec *tracer* via tracepoint+ringbuf) does NOT need BPF-LSM and still delivers the live exec-map telemetry. We can start there."
elif [ "$V_LSM_ACTIVE" = yes ] && [ "$V_BTF" = yes ]; then
  ok "GATE MET: BPF-LSM is active and BTF is present. Stage B enforcement is feasible on this box."
  if [ "$V_IMA" = yes ] && [ "$V_VERITY" != yes ]; then
    info "Recommended hash source here: IMA (bpf_ima_file_hash) — content-trust, no per-binary sealing, broadest coverage."
  elif [ "$V_VERITY" = yes ] && [ "$V_IMA" != yes ]; then
    info "Recommended hash source here: fs-verity (bpf_get_fsverity_digest) — sealed-location trust; the copy-rename demo is more dramatic."
  elif [ "$V_IMA" = yes ] && [ "$V_VERITY" = yes ]; then
    info "Both hash sources available. Default to IMA for operability; keep fs-verity for the demo. Decide per the semantics note in section F."
  else
    warn "Neither IMA nor fs-verity confirmed usable for the digest — resolve hashing source before Stage B."
  fi
else
  warn "Mixed/unknown gate state — see sections B and D above."
fi

echo
info "STILL OPEN (this script cannot answer it — needs a load test):"
info "  Does a *cgroup-scoped* LSM program (BPF_LSM_CGROUP) actually attach to bprm_check_security,"
info "  or must we use a global program + bpf_current_task_under_cgroup? That requires loading a tiny"
info "  program against this kernel. Send me this probe's output and I'll write that load test next,"
info "  matched to the tooling found in section H."
echo
info "Reminder: nothing here was enforced or changed. Read-only probe complete."

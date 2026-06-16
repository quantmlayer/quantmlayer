#!/usr/bin/env bash
# scripts/ql-matrix-run.sh
#
# QuantmLayer portability-matrix runner.
#
# On ONE host, collect a single tagged results bundle:
#   - capability.json   the six-wall probe (ql-kernel-probe.sh --json)
#   - benchmark/        ql-bench RESULTS.md + results.json (6 attacks x backends)
#   - OVERHEAD.md       ql-overhead (baseline vs docker vs cell, +/- exec wall)
#   - env.txt           uname / os-release / cpu / mem / virt / toolchain
#   - manifest.json     what ran, per-step ok/fail/skip, features, versions
#
# Designed for "spin up a cloud VM, run one command, get a matrix row." It fails
# soft: a host where the build or a tool step fails still yields the capability
# row and a manifest recording exactly what happened.
#
# IMPORTANT (policy): result bundles are research DATA and are written OUTSIDE
# the repo by default ($HOME/quantmlayer-matrix), so they can never be staged or
# committed. Override with --out or $QL_MATRIX_OUT.
#
# Usage:
#   bash scripts/ql-matrix-run.sh                 # build (as you) + collect
#   bash scripts/ql-matrix-run.sh --install-deps  # best-effort apt/dnf + rustup
#   bash scripts/ql-matrix-run.sh --no-docker --iters 2000 --out /tmp/ql-rows
#
# Run as your NORMAL user (cargo needs your rustup toolchain); the runner uses
# sudo only for the privileged benchmark/overhead steps.

set -u

# ---- options ---------------------------------------------------------------
INSTALL_DEPS=no
NO_DOCKER=no
ITERS=
OUT_ROOT="${QL_MATRIX_OUT:-$HOME/quantmlayer-matrix}"
while [ $# -gt 0 ]; do
  case "$1" in
    --install-deps) INSTALL_DEPS=yes ;;
    --no-docker)    NO_DOCKER=yes ;;
    --iters)        shift; ITERS="${1:-}" ;;
    --out)          shift; OUT_ROOT="${1:-$OUT_ROOT}" ;;
    -h|--help)
      echo "usage: bash scripts/ql-matrix-run.sh [--install-deps] [--no-docker] [--iters N] [--out DIR]"
      exit 0 ;;
    *) echo "ql-matrix: unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

log() { printf '[ql-matrix] %s\n' "$*"; }
json() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# Repo root = parent of this script's dir; build + probe paths are relative to it.
REPO="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"
if [ -z "$REPO" ] || [ ! -f "$REPO/Cargo.toml" ]; then
  echo "ql-matrix: cannot locate repo root (run from inside the checkout)" >&2
  exit 2
fi
cd "$REPO"

# sudo for privileged steps only; empty when already root.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

# ---- host tag --------------------------------------------------------------
ARCH="$(uname -m 2>/dev/null || echo unknown)"
KREL="$(uname -r 2>/dev/null || echo unknown)"
DISTRO=unknown; DVER=
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release 2>/dev/null
  DISTRO="${ID:-unknown}"; DVER="${VERSION_ID:-}"
fi
sanitize() { printf '%s' "$1" | tr ' /:+' '____' | tr -cd 'A-Za-z0-9._-'; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || echo nodate)"
TAG="$(sanitize "$ARCH")-$(sanitize "${DISTRO}${DVER}")-$(sanitize "$KREL")-$STAMP"
BUNDLE="$OUT_ROOT/$TAG"
mkdir -p "$BUNDLE" || { echo "ql-matrix: cannot create $BUNDLE" >&2; exit 2; }
log "host: $ARCH / ${DISTRO}${DVER} / $KREL"
log "bundle: $BUNDLE"

# Step outcomes for the manifest.
STEP_PROBE=skip; STEP_BUILD=skip; STEP_BENCH=skip; STEP_OVERHEAD=skip
FEATURES=none

# ---- optional dependency install (best-effort) -----------------------------
install_deps() {
  log "installing build deps (best-effort; needs sudo + network)"
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -y \
      && $SUDO apt-get install -y build-essential clang llvm libbpf-dev \
           bpftool pkg-config libelf-dev zlib1g-dev curl || true
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y gcc make clang llvm libbpf-devel bpftool \
           elfutils-libelf-devel zlib-devel pkgconf-pkg-config curl || true
  elif command -v yum >/dev/null 2>&1; then
    $SUDO yum install -y gcc make clang llvm libbpf-devel bpftool \
           elfutils-libelf-devel zlib-devel curl || true
  else
    log "no apt/dnf/yum found — install clang/libbpf/bpftool manually"
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    log "cargo absent — installing rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || true
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env" 2>/dev/null || true
  fi
}
[ "$INSTALL_DEPS" = yes ] && install_deps

# ---- environment snapshot --------------------------------------------------
{
  echo "# uname";        uname -a 2>/dev/null
  echo; echo "# os-release"; cat /etc/os-release 2>/dev/null
  echo; echo "# virt";    (systemd-detect-virt 2>/dev/null || echo n/a)
  echo; echo "# cpu";     (lscpu 2>/dev/null || grep -m1 'model name' /proc/cpuinfo 2>/dev/null)
  echo; echo "# nproc";   (nproc 2>/dev/null || echo unknown)
  echo; echo "# mem";     (free -h 2>/dev/null || grep -i memtotal /proc/meminfo 2>/dev/null)
  echo; echo "# rustc";   (rustc --version 2>/dev/null || echo absent)
  echo; echo "# cargo";   (cargo --version 2>/dev/null || echo absent)
  echo; echo "# clang";   (clang --version 2>/dev/null | head -1 || echo absent)
  echo; echo "# docker";  (docker --version 2>/dev/null || echo absent)
} > "$BUNDLE/env.txt" 2>&1

# ---- capability probe ------------------------------------------------------
CAP="$BUNDLE/capability.json"
log "probing kernel capabilities"
# Prefer a privileged probe: kernel config, IMA, and the LSM stack read more
# completely as root (this matters on RHEL / Amazon Linux, where those files are
# not world-readable). Prompt once if needed; fall back to an unprivileged probe
# only if sudo is unavailable.
if [ -n "$SUDO" ] && $SUDO bash scripts/ql-kernel-probe.sh --json >"$CAP" 2>"$BUNDLE/probe.err"; then
  STEP_PROBE=ok
elif bash scripts/ql-kernel-probe.sh --json >"$CAP" 2>>"$BUNDLE/probe.err"; then
  STEP_PROBE=ok
  [ -n "$SUDO" ] && log "probe ran unprivileged (sudo unavailable); some walls may read 'unknown'"
else
  STEP_PROBE=fail
fi

# Decide the exec wall from the probe verdict (only attempt lsm where it's active).
EXEC_LSM="$(sed -n 's/.*"exec_bpf_lsm": "\([^"]*\)".*/\1/p' "$CAP" 2>/dev/null | head -1)"
[ -z "$EXEC_LSM" ] && EXEC_LSM=unknown
log "exec wall (BPF-LSM) per probe: $EXEC_LSM"

# ---- build -----------------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  log "cargo not found — skipping build/bench/overhead (rerun with --install-deps)"
  STEP_BUILD=fail
else
  if [ "$EXEC_LSM" = yes ]; then
    log "building with --features lsm (exec wall active here)"
    if cargo build --release -p ql-cli --features lsm  >"$BUNDLE/build.log" 2>&1 \
       && cargo build --release -p ql-bench --features lsm >>"$BUNDLE/build.log" 2>&1; then
      STEP_BUILD=ok; FEATURES=lsm
    else
      log "lsm build failed — falling back to standard walls (see build.log)"
    fi
  fi
  if [ "$STEP_BUILD" != ok ]; then
    log "building default (standard five walls)"
    if cargo build --release -p ql-cli  >>"$BUNDLE/build.log" 2>&1 \
       && cargo build --release -p ql-bench >>"$BUNDLE/build.log" 2>&1; then
      STEP_BUILD=ok; FEATURES=default
    else
      STEP_BUILD=fail; FEATURES=none
    fi
  fi
fi

# ---- benchmark -------------------------------------------------------------
if [ "$STEP_BUILD" = ok ] && [ -x target/release/ql-bench ]; then
  log "running ql-bench (sudo; 6 attacks x backends)"
  if $SUDO ./target/release/ql-bench --out "$BUNDLE/benchmark" >"$BUNDLE/bench.log" 2>&1; then
    STEP_BENCH=ok
  else
    STEP_BENCH=fail
  fi
fi

# ---- overhead --------------------------------------------------------------
if [ "$STEP_BUILD" = ok ] && [ -x target/release/ql-overhead ]; then
  log "running ql-overhead (sudo)"
  OARGS=(--md "$BUNDLE/OVERHEAD.md")
  [ -n "$ITERS" ] && OARGS+=(--iters "$ITERS")
  if [ "$NO_DOCKER" = yes ] || ! command -v docker >/dev/null 2>&1; then
    OARGS+=(--no-docker)
  fi
  if $SUDO ./target/release/ql-overhead "${OARGS[@]}" >"$BUNDLE/overhead.log" 2>&1; then
    STEP_OVERHEAD=ok
  else
    STEP_OVERHEAD=fail
  fi
fi

# ---- manifest --------------------------------------------------------------
cat > "$BUNDLE/manifest.json" <<EOF
{
  "schema": "ql-matrix/1",
  "tag": "$(json "$TAG")",
  "host": {
    "arch": "$(json "$ARCH")",
    "distro": "$(json "${DISTRO}${DVER}")",
    "kernel": "$(json "$KREL")"
  },
  "timestamp": "$(json "$STAMP")",
  "features": "$(json "$FEATURES")",
  "exec_bpf_lsm": "$(json "$EXEC_LSM")",
  "steps": {
    "probe": "$STEP_PROBE",
    "build": "$STEP_BUILD",
    "benchmark": "$STEP_BENCH",
    "overhead": "$STEP_OVERHEAD"
  },
  "rustc": "$(json "$(rustc --version 2>/dev/null || echo absent)")",
  "docker": "$(json "$(docker --version 2>/dev/null || echo absent)")"
}
EOF

# ---- summary ---------------------------------------------------------------
log "done."
printf '  %-10s %s\n' probe "$STEP_PROBE"
printf '  %-10s %s (features: %s)\n' build "$STEP_BUILD" "$FEATURES"
printf '  %-10s %s\n' benchmark "$STEP_BENCH"
printf '  %-10s %s\n' overhead "$STEP_OVERHEAD"
log "bundle written to: $BUNDLE"
if [ "$STEP_BUILD" != ok ]; then
  log "partial bundle (build did not complete) — capability row + env still captured"
fi

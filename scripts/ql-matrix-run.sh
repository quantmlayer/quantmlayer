#!/usr/bin/env bash
# ql-matrix-run.sh — collect ONE QuantmLayer capability bundle for this host.
#
# Run this on each substrate you want in the portability matrix (bare metal,
# Docker-in-EC2, an EKS/GKE pod, ...). It captures `ql doctor --json` plus a
# little host/substrate metadata into <out>/<label>.json. Copy the bundles back
# to one machine and run ql-matrix-table.py over them.
#
# Usage:
#   scripts/ql-matrix-run.sh [LABEL] [--out DIR] [--ql PATH] [--sudo]
# Examples:
#   scripts/ql-matrix-run.sh aarch64-baremetal
#   scripts/ql-matrix-run.sh docker-ec2-x86 --sudo
#   scripts/ql-matrix-run.sh eks-pod --ql /usr/local/bin/ql
set -euo pipefail

LABEL=""
OUT="ql-matrix"
QL="./target/release/ql"
USE_SUDO=0

while [ $# -gt 0 ]; do
  case "$1" in
    --out)  OUT="$2"; shift 2 ;;
    --ql)   QL="$2"; shift 2 ;;
    --sudo) USE_SUDO=1; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *)  LABEL="$1"; shift ;;
  esac
done

substrate_hint() {
  if [ -f /.dockerenv ]; then echo "docker"; return; fi
  if grep -qaE 'kubepods|kubernetes' /proc/1/cgroup 2>/dev/null; then echo "k8s"; return; fi
  if grep -qaE 'docker|containerd|libpod' /proc/1/cgroup 2>/dev/null; then echo "container"; return; fi
  echo "host"
}

HINT="$(substrate_hint)"
if [ -z "$LABEL" ]; then
  LABEL="${HINT}-$(uname -m)-$(hostname 2>/dev/null || echo host)"
fi
# Sanitise label for use as a filename.
LABEL="$(printf '%s' "$LABEL" | tr ' /\\' '___')"

mkdir -p "$OUT"

if [ ! -x "$QL" ] && ! command -v "$QL" >/dev/null 2>&1; then
  echo "error: ql binary not found at '$QL' (use --ql PATH)" >&2
  exit 1
fi

if [ "$USE_SUDO" = 1 ]; then
  DOCTOR_JSON="$(sudo "$QL" doctor --json)"
  ROOT=true
else
  DOCTOR_JSON="$("$QL" doctor --json)"
  ROOT=false
fi

OUTFILE="$OUT/$LABEL.json"
cat > "$OUTFILE" <<EOF
{
  "label": "$LABEL",
  "collected_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "ran_as_root": $ROOT,
  "substrate_hint": "$HINT",
  "doctor": $DOCTOR_JSON
}
EOF

echo "wrote $OUTFILE  (substrate=$HINT, root=$ROOT)"

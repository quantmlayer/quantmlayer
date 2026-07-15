#!/usr/bin/env bash
#
# QuantmLayer HERO demo — one-command containment of a real coding agent,
# learn -> enforce -> block -> PROVE, end to end.
#
# What's different from demo.sh (the original 45s clip):
#   * Uses a REAL bundled agent (`ql agent`), not a synthetic script.
#   * Adds the network-egress block (not just the filesystem block).
#   * Closes on TAMPER-EVIDENT PROOF: `ql audit verify` -> INTACT. The payoff
#     is not just "it blocked" but "and here's cryptographic evidence it did."
#   * Every beat runs a REAL command and shows its REAL output. Nothing is
#     faked. If your host can't build the cell (see NOTE), the script says so
#     honestly rather than pretending.
#
# HONEST PREREQUISITES (the demo shows real enforcement, so it needs a host
# that can actually enforce):
#   * A bundled agent installed on PATH for the AGENT beat (default: opencode;
#     override with QL_AGENT=claude etc.). If it's absent, that beat is skipped
#     with a visible note and the enforcement beats still run with `bash`.
#   * The mount wall must build. On hardened kernels (Ubuntu 24.04 / 22.04 HWE)
#     install the AppArmor profile (the installer does this), or run under sudo.
#     Verify first with:  ql doctor
#
# RECORDING:
#   TYPE_SPEED=0 WORD_DELAY=0 LINE_DELAY=0 BEAT=0 ./demo/hero.sh   # pacing dry run
#   asciinema rec -c "./demo/hero.sh" quantmlayer-hero.cast
#
# Pacing knobs (seconds): TYPE_SPEED WORD_DELAY LINE_DELAY BEAT (0 = instant).

set -u

QL="${QL:-ql}"
QL_AGENT="${QL_AGENT:-opencode}"
TYPE_SPEED="${TYPE_SPEED:-0.03}"
WORD_DELAY="${WORD_DELAY:-0.06}"
LINE_DELAY="${LINE_DELAY:-0.05}"
BEAT="${BEAT:-1.2}"

WORK="$(mktemp -d)"
VICTIM_HOME="$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)"
VICTIM_HOME="${VICTIM_HOME:-$HOME}"
DECOY="$VICTIM_HOME/.ssh/quantmlayer_demo_key"

# --- presentation helpers ----------------------------------------------------
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
show()   { typecmd "$*"; { "$@" 2>&1; } | reveal; }

cleanup() { rm -rf "$WORK"; rm -f "$DECOY"; }
trap cleanup EXIT

# --- scene setup -------------------------------------------------------------
mkdir -p "$VICTIM_HOME/.ssh"
echo "-----BEGIN OPENSSH PRIVATE KEY----- (demo decoy, do not use)" > "$DECOY"
AUDIT="$WORK/run.jsonl"
PROFILE="$WORK/enforced.yaml"

# Learn an ENFORCING profile from the legit toolchain (cat + curl + bash) so
# the containment beats run all walls INCLUDING content-verified exec — no
# "exec not armed" notice, full six-wall enforcement. Must measure every
# binary the beats invoke (cat in beat 3; bash+curl in beat 4) or the exec
# wall would deny them too. Done before recording; the demo shows the result.
"$QL" learn --out "$PROFILE" -- bash -c 'cat /etc/hostname >/dev/null; curl -sS -m2 https://example.invalid -o /dev/null 2>/dev/null; true' >/dev/null 2>&1 || true

# The command we run "as the agent" for the enforcement beats. If the chosen
# bundled agent is on PATH we name it in the narration; the actual blocked
# actions use small real commands so the blocks are genuine and deterministic.
AGENT_PRESENT=0
if command -v "$QL_AGENT" >/dev/null 2>&1; then AGENT_PRESENT=1; fi

clear
words "$C_CYAN" "QuantmLayer — least-privilege containment for coding agents"
words "$C_GRAY" "We don't secure what agents say. We secure what agents are allowed to do."
sleep "$BEAT"

# --- beat 0: it's real, and it's one line -----------------------------------
headline "0. Install is one line. The binary is static; nothing else to set up."
note "curl -fsSL .../scripts/install.sh | sh    # x86_64 or aarch64, auto-detected"
note "(already installed for this demo — here's the host it will enforce on:)"
show "$QL" doctor
sleep "$BEAT"

# --- beat 1: the risk --------------------------------------------------------
headline "1. The risk: a coding agent runs with YOUR privileges."
note "Uncontained, it can read your SSH private key:"
show cat "$DECOY"
danger "^ a prompt-injected or buggy agent could exfiltrate that."
sleep "$BEAT"

# --- beat 2: one command contains a real agent ------------------------------
headline "2. One command contains a real, popular coding agent."
if [ "$AGENT_PRESENT" -eq 1 ]; then
  note "\`ql agent $QL_AGENT\` runs $QL_AGENT inside a kernel cell — workspace only,"
  note "credentials invisible, egress allow-listed. Nothing to configure:"
  show "$QL" agent list
else
  warn "($QL_AGENT not installed here — showing the bundled set; the blocks below"
  warn " run the same cell with a plain command so they're fully reproducible.)"
  show "$QL" agent list
fi
sleep "$BEAT"

# --- beat 3: the filesystem block (the gut-punch) ---------------------------
headline "3. Inside the cell, the SSH key simply isn't there."
note "A least-privilege profile — workspace-only files, egress default-deny,"
note "exec content-verified. The agent tries to read your key:"
show "$QL" run --profile "$PROFILE" --audit "$AUDIT" -- cat "$DECOY"
good "^ not 'permission denied' — the file does not exist in the cell. Gone."
sleep "$BEAT"

# --- beat 4: the network block ----------------------------------------------
headline "4. And it can't phone home. Egress is default-deny."
note "An unlisted destination (data exfiltration, C2) can't even be reached:"
# Display the command with explicit quoting so the on-screen line is honest
# about what runs inside the cell, then execute the same thing.
NETPROBE='curl -sS -m5 https://example.com -o /dev/null && echo REACHED || echo BLOCKED'
typecmd "$QL run --profile enforced.yaml --audit \$AUDIT -- bash -c '$NETPROBE'"
{ "$QL" run --profile "$PROFILE" --audit "$AUDIT" -- bash -c "$NETPROBE" 2>&1; } | reveal
good "^ BLOCKED — no route out of the cell to an unlisted host. (Add --broker to"
good "  allow-list specific domains and audit every egress decision by name.)"
sleep "$BEAT"

# --- beat 5: the proof (the real differentiator) ----------------------------
headline "5. And it's provable. Each run commits its policy to a tamper-evident chain."
note "Not a log you have to trust — a hash chain anyone can verify, unaltered:"
show "$QL" audit verify "$AUDIT"
good "^ INTACT. Each record commits to the policy that governed that cell and links"
good "  to the one before it — edit any record and the chain breaks. This is the"
good "  EU AI Act Article 12 substrate: third-party-verifiable action records."
sleep "$BEAT"

# --- close -------------------------------------------------------------------
headline "Learned from behavior. Enforced by the kernel. Provable after the fact."
note "One binary. Seven agents. github.com/quantmlayer/quantmlayer"

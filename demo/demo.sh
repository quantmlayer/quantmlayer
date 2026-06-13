#!/usr/bin/env bash
#
# QuantmLayer demo — the learn -> enforce -> block loop, end to end.
#
# Designed to be screen-/asciinema-recorded: commands are "typed" character by
# character, narration appears word by word, and long output (the generated
# profile) is revealed line by line, so nothing dumps instantly and the whole
# thing stays readable on playback.
#
#   ./demo/demo.sh                          # uses the installed `ql`
#   QL=./target/release/ql ./demo/demo.sh   # use a dev build instead
#
# Pacing knobs (seconds) — tune to taste, then record:
#   TYPE_SPEED  per-character delay while "typing" a command   (default .03)
#   WORD_DELAY  per-word delay for narration lines             (default .06)
#   LINE_DELAY  per-line delay when revealing long output      (default .05)
#   BEAT        pause between the five beats                   (default 1.2)
# Set them all to 0 for an instant dry run:  TYPE_SPEED=0 WORD_DELAY=0 \
#   LINE_DELAY=0 BEAT=0 ./demo/demo.sh

set -u

QL="${QL:-ql}"
TYPE_SPEED="${TYPE_SPEED:-0.03}"
WORD_DELAY="${WORD_DELAY:-0.06}"
LINE_DELAY="${LINE_DELAY:-0.05}"
BEAT="${BEAT:-${DEMO_PAUSE:-1.2}}"

WORK="$(mktemp -d)"
DECOY="$HOME/.ssh/quantmlayer_demo_key"

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

cleanup() { rm -rf "$WORK"; rm -f "$DECOY"; }
trap cleanup EXIT

# --- scene setup -------------------------------------------------------------
mkdir -p "$HOME/.ssh"
echo "-----BEGIN OPENSSH PRIVATE KEY----- (demo decoy, do not use)" > "$DECOY"

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
words "$C_GRAY" "We don't secure what agents say. We secure what agents are allowed to do."
sleep "$BEAT"

headline "1. The risk: a coding agent runs with your full privileges."
note  "With no containment, it can read your SSH private key:"
show cat "$DECOY"
danger "^ a prompt-injected or buggy agent could exfiltrate that."
sleep "$BEAT"

headline "2. LEARN a least-privilege profile by observing the agent run once."
note  "No rules written by hand — we watch what it actually does:"
show "$QL" learn --verbose --out "$WORK/agent.yaml" -- /bin/sh "$AGENT"
sleep "$BEAT"

headline "3. The profile QuantmLayer generated."
note  "Note what it DENIES — secrets and dangerous syscalls the agent never touched:"
show cat "$WORK/agent.yaml"
sleep "$BEAT"

headline "4. The agent runs normally under its own learned profile."
show "$QL" run --profile "$WORK/agent.yaml" -- /bin/sh "$AGENT"
good "^ exit 0 — real work still gets done."
sleep "$BEAT"

headline "5. The SAME profile blocks SSH-key theft the agent never performed."
show "$QL" run --profile "$WORK/agent.yaml" -- cat "$DECOY"
good "^ the key is simply not there inside the cell. Blast radius: contained."
sleep "$BEAT"

headline "Containment is LEARNED from behavior and holds regardless of intent."
note "github.com/quantmlayer/quantmlayer"

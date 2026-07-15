#!/usr/bin/env bash
# validate-agents.sh — field-validate QuantmLayer agent profiles on a clean host.
#
# WHY THIS EXISTS
#   Enforcement validation (the cell actually blocking secrets/network) needs a
#   host where the mount wall can build. Nested/virtualized guests (e.g. some
#   Parallels/VM configs on Apple Silicon) deny mount(MS_PRIVATE /) even as root,
#   so full enforcement can't be proven there. A plain cloud Ubuntu VM works.
#   This script runs the full observe -> broker -> enforce check for the three
#   newer profiles (opencode, cursor, cline).
#
# WHERE TO RUN
#   A standard Linux host with cgroup v2 delegation and unrestricted mounts:
#   a fresh DigitalOcean / Hetzner / EC2 (t4g.small is aarch64, matches an
#   Apple-Silicon build) Ubuntu 22.04/24.04 box. NOT a nested Parallels guest.
#
# USAGE
#   1) Build or copy the `ql` binary onto the host (path in QL below).
#   2) Install whichever agents you want to validate (see INSTALL NOTES).
#   3) chmod +x validate-agents.sh && ./validate-agents.sh
#
# It does not modify the profiles; it prints what each run found so you can fold
# any missing domains into profiles/agents/<agent>.yaml by hand.

set -u

QL="${QL:-./target/debug/ql}"          # path to the ql binary
TASK="${TASK:-list the files in this directory}"   # a tiny, safe task
LEARN_TASK="${LEARN_TASK:-print hello and exit}"   # for the learn pass

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# agent name -> the command to run it non-interactively.
declare -A RUN=(
  [opencode]="opencode run \"$TASK\""
  [cline]="cline \"$TASK\""
  [cursor]="cursor-agent chat \"$TASK\""
)
# agent name -> the binary to check on PATH.
declare -A BIN=(
  [opencode]="opencode"
  [cline]="cline"
  [cursor]="cursor-agent"
)

say "host preflight: ql doctor (needs sudo for full wall availability)"
sudo "$QL" doctor || { echo "doctor failed — fix the host before validating"; exit 1; }

for agent in opencode cline cursor; do
  bin="${BIN[$agent]}"
  run="${RUN[$agent]}"

  say "agent: $agent"
  if ! have "$bin"; then
    echo "  SKIP — '$bin' not on PATH (install it to validate this one)"
    continue
  fi

  echo "  [1/3] observe (file + exec walls; expect 0 would-deny) ..."
  eval "$QL run --agent $agent --observe -- $run" 2>&1 | \
    grep -E "would-deny|observe summary|trace error" || true

  echo "  [2/3] observe --broker (per-domain network decisions) ..."
  echo "        -> note any domain shown as denied/unknown; fold it into"
  echo "           profiles/agents/$agent.yaml allow_domains if legitimate."
  eval "$QL run --agent $agent --observe --broker -- $run" 2>&1 | \
    grep -E "broker|domain|deny|allow|endpoint" || true

  echo "  [3/3] ENFORCE (the real cell — should run clean if profile is right) ..."
  echo "        Ctrl-C if it hangs; a wall error here is a real finding."
  sudo "$QL" run --agent "$agent" -- bash -c '
    echo "  IN-CELL: agent cell built";
    echo -n "  ssh read: "; ls ~/.ssh >/dev/null 2>&1 && echo "VISIBLE (BAD)" || echo "denied (good)";
    echo -n "  net (example.com, not allow-listed): ";
    curl -sS -m 5 https://example.com -o /dev/null 2>/dev/null && echo "REACHED (check profile)" || echo "blocked (good)";
  ' 2>&1 | grep -E "IN-CELL|ssh read|net |failed|refusing" || true
done

say "done"
echo "For each agent above: 0 would-deny + ssh denied + example.com blocked = profile validated."
echo "Any domain the --broker step flagged as needed goes into the profile's allow_domains."
echo
echo "INSTALL NOTES (run before this script, for whichever you want to test):"
echo "  opencode : curl -fsSL https://opencode.ai/install | bash   (then: source ~/.bashrc; opencode auth login)"
echo "  cline    : npm i -g cline                                   (then configure a provider)"
echo "  cursor   : needs a Cursor subscription; install cursor-agent per Cursor's CLI docs"

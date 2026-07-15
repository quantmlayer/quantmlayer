#!/usr/bin/env bash
#
# QuantmLayer MCP GATEWAY demo (Tier 3) — for the MCP-aware audience.
#
# THESIS: An MCP server is third-party code your MCP client runs with your
# privileges, and the MCP protocol enforces NOTHING at the call layer — a
# rug-pulled or buggy server can issue malformed or unauthorized tool calls and
# the host model executes them. `ql mcp gateway` sits in the JSON-RPC stream and
# makes each `tools/call` prove itself: it must match the server's advertised
# schema, and a tool gated as state-changing must be allow-listed. Denied calls
# never reach the server; every decision is auditable.
#
# This demo uses a tiny fake MCP server (a shell loop) so it runs anywhere with
# no real server or provider needed. Every gateway decision below is REAL — the
# actual `ql mcp gateway` binary makes them.
#
# RECORDING:
#   TYPE_SPEED=0 WORD_DELAY=0 LINE_DELAY=0 BEAT=0 ./demo/mcp.sh    # pacing dry run
#   asciinema rec -c "./demo/mcp.sh" ql-mcp.cast
#
# Pacing knobs (seconds): TYPE_SPEED WORD_DELAY LINE_DELAY BEAT (0 = instant).

set -u

QL="${QL:-ql}"
TYPE_SPEED="${TYPE_SPEED:-0.03}"
WORD_DELAY="${WORD_DELAY:-0.06}"
LINE_DELAY="${LINE_DELAY:-0.05}"
BEAT="${BEAT:-1.4}"

WORK="$(mktemp -d)"
SERVER="$WORK/fake-mcp-server.sh"
AUDIT="$WORK/gateway.jsonl"

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

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# --- a tiny real MCP server: advertises read_file + delete_file, echoes calls -
cat > "$SERVER" <<'SRV'
#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *tools/list*)
      echo '{"jsonrpc":"2.0","id":"__ql_gateway_tools_list__","result":{"tools":[{"name":"read_file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}},{"name":"delete_file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}]}}' ;;
    *) echo "SERVER EXECUTED: $line" ;;
  esac
done
SRV
chmod +x "$SERVER"

# helper: send one tools/call line through the gateway and show what happens
send() { printf '%s\n' "$1"; }

clear
words "$C_CYAN" "QuantmLayer MCP gateway — make every tool call prove itself"
words "$C_GRAY" "An MCP server is third-party code. The protocol trusts it. We don't."
sleep "$BEAT"

# --- beat 1: the gap --------------------------------------------------------
headline "1. MCP enforces nothing at the call layer."
note "A server that's buggy — or rug-pulled after you trusted it — can issue"
note "malformed or unauthorized tool calls, and your model just runs them."
sleep "$BEAT"

# --- beat 2: the gateway inspects a stream of calls -------------------------
headline "2. Put a gateway in the JSON-RPC stream. Each tools/call must prove itself."
note "The server advertises read_file + delete_file. We gate delete_file as"
note "state-changing (not allow-listed) and send four calls — one good, three not:"
typecmd "ql mcp gateway --gate delete_file --audit \$AUDIT -- <server>"
{
  send '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}'
  send '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":1234}}}'
  send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exfiltrate","arguments":{}}}'
  send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/important"}}}'
} | "$QL" mcp gateway --gate delete_file --audit "$AUDIT" -- "$SERVER" 2>&1 | reveal
sleep "$BEAT"

# --- beat 3: read the verdicts ----------------------------------------------
headline "3. One reached the server. Three never did."
good "  read_file(/etc/hosts)   -> forwarded  (valid, in-contract)"
danger "  read_file(path=1234)    -> DENIED     (schema: path must be a string)"
danger "  exfiltrate()            -> DENIED     (unknown tool, not advertised)"
danger "  delete_file(/important) -> DENIED     (gated state-change, not allowed)"
note "Denied calls got a JSON-RPC error and never touched the server."
sleep "$BEAT"

# --- beat 4: the audit ------------------------------------------------------
headline "4. Every decision — allow and deny — is tamper-evident."
typecmd "$QL audit verify \$AUDIT"
{ "$QL" audit verify "$AUDIT" 2>&1; } | reveal
good "^ INTACT. Tool names and verdicts recorded; argument VALUES are not"
good "  (they can carry secrets). Evidence without leakage."
sleep "$BEAT"

# --- close ------------------------------------------------------------------
headline "Contain the server process. Inspect the calls. Prove both."
note "ql mcp wrap --gateway  composes the cell AND the gateway in one command."
note "github.com/quantmlayer/quantmlayer"

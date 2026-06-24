#!/usr/bin/env bash
#
# QuantmLayer honeytoken (canary) demo.
#
# Plant a credential the agent has no legitimate reason to use. When something
# tries to USE it — i.e. connect to the canary's destination — the broker blocks
# the connection in flight (before any DNS lookup) and writes a distinct, signed
# `canary.triggered` entry to the tamper-evident audit log.
#
# This is DESTINATION-based detection: a canary host is one nothing legitimate
# ever contacts, so a CONNECT to it is, by construction, a true positive — zero
# false positives, no model, no classifier. The value is the unambiguous signal
# plus court-quality signed evidence, not detection cleverness. We do NOT inspect
# payload bytes (that would be TLS-intercepting DLP, deliberately out of scope):
# "caught in flight" means the connection to the canary endpoint is refused and
# recorded, not that a secret was spotted in a payload.
#
# Build, then run from the repo root:
#   cargo build -p ql-cli
#   ./demo/honeytoken-demo.sh
# Overrides:
#   QL=./target/debug/ql PORT=18080 ./demo/honeytoken-demo.sh

set -u

QL="${QL:-./target/debug/ql}"
PORT="${PORT:-18080}"
PROXY="http://127.0.0.1:${PORT}"
LOG="$(mktemp -t honeytoken-XXXXXX.jsonl)"
CANARY="canary.examplecorp.test"
CANARY_ID="aws-key-7"
PROFILE="profiles/coding.yaml"

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

if [ ! -x "$QL" ]; then
  echo "error: '$QL' not found or not executable. Build first: cargo build -p ql-cli" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "error: this demo uses curl as the injected agent's egress client." >&2
  exit 1
fi

# 1. Plant the canary credential in the agent's workspace (demo scaffolding, not
#    product). A fake AWS key whose endpoint is the canary destination — it looks
#    usable, so a prompt-injected agent takes the bait.
WS="$(mktemp -d -t agent-ws-XXXXXX)"
mkdir -p "$WS/.aws"
SECRET="$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
cat > "$WS/.aws/credentials" <<EOF
[default]
aws_access_key_id = AKIA_HONEYTOKEN_DO_NOT_USE
aws_secret_access_key = ${SECRET}
# endpoint: https://${CANARY}
EOF
say "Planted a canary AWS credential in the agent workspace"
echo "   ${WS}/.aws/credentials  (endpoint -> ${CANARY})"

# 2. Start the broker with the canary armed, auditing to a fresh log.
say "Starting broker: allow-list egress + canary '${CANARY}' (id ${CANARY_ID})"
"$QL" broker --profile "$PROFILE" --listen "127.0.0.1:${PORT}" \
  --canary "$CANARY" --canary-id "$CANARY_ID" --audit "$LOG" &
BROKER=$!
trap 'kill "$BROKER" 2>/dev/null; rm -rf "$WS"' EXIT
sleep 1

# 3. The agent is prompt-injected and tries to exfiltrate the credential to the
#    canary destination. Every TLS egress is a CONNECT through the broker; curl
#    stands in for the injected agent's outbound attempt.
say "Injected agent tries to use the canary credential -> CONNECT ${CANARY}:443"
curl -sS -m 5 -o /dev/null -x "$PROXY" "https://${CANARY}" 2>&1 | sed 's/^/   curl: /'

# 4. Contrast: an ordinary disallowed domain (not a canary) — the noise a plain
#    allow-list miss produces.
say "For contrast: an ordinary disallowed domain (allow-list miss = noise)"
curl -sS -m 5 -o /dev/null -x "$PROXY" "https://not-allowed.example.com" 2>&1 | sed 's/^/   curl: /'

sleep 0.5

# 5. Show the audit log: the canary hit is a NAMED, high-signal event, distinct
#    from the generic egress deny, and the chain verifies.
say "Audit log integrity"
"$QL" audit verify "$LOG"
echo
echo "   canary.triggered  (the signal: unambiguous intrusion, signed):"
grep '"canary.triggered"' "$LOG" | sed 's/^/     /'
echo "   egress.connect deny  (the noise: a routine allow-list miss):"
grep '"egress.connect"' "$LOG" | sed 's/^/     /'

say "The agent took the bait, was stopped before a byte left the box, with signed proof of exactly what it tried."
echo "audit log: ${LOG}"

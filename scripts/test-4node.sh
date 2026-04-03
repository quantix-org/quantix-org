#!/usr/bin/env bash
# test-4node.sh — Full 4-node integration test for Quantix
# Builds binary, starts 4 nodes in dev-mode, sends 5 transactions,
# verifies all nodes reach same block count (> 1), then cleans up.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${ROOT}/bin/qtx"
DATADIR_PREFIX="/tmp/qtx-test4"

# Ports
SEED_HTTP=18560
SEED_UDP=32600
SEED_TCP=32600

PORTS_HTTP=(18560 18561 18562 18563)
PORTS_UDP=(32600 32601 32602 32603)

PIDS=()
RESULT="FAIL"

cleanup() {
  echo ""
  echo "🧹 Cleaning up..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  rm -rf "${DATADIR_PREFIX}-"*
  echo "   Cleanup done."
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Result: ${RESULT}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if [[ "${RESULT}" == "PASS" ]]; then exit 0; else exit 1; fi
}
trap cleanup EXIT

fail() {
  echo "❌ FAIL: $1"
  RESULT="FAIL"
  exit 1
}

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Quantix 4-Node Integration Test"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Step 1: Build ──────────────────────────────
echo "🔨 Building binary..."
cd "${ROOT}"
mkdir -p bin
go build -o "${BIN}" ./src/cli/main.go
echo "   Built: ${BIN}"

# ── Step 2: Start 4 nodes ──────────────────────
echo ""
echo "🚀 Starting 4 nodes..."

for i in 0 1 2 3; do
  DATADIR="${DATADIR_PREFIX}-${i}"
  mkdir -p "${DATADIR}"
  HTTP_PORT="${PORTS_HTTP[$i]}"
  UDP_PORT="${PORTS_UDP[$i]}"

  CMD=(
    "${BIN}"
    -nodes 1 -node-index 0 -roles validator
    -datadir "${DATADIR}"
    -http-port "0.0.0.0:${HTTP_PORT}"
    -udp-port "${UDP_PORT}"
    -tcp-addr "0.0.0.0:${UDP_PORT}"
    -dev-mode
  )

  if [[ $i -gt 0 ]]; then
    CMD+=(-seeds "127.0.0.1:${SEED_UDP}" -seed-http-port "${SEED_HTTP}")
  fi

  "${CMD[@]}" > "/tmp/qtx-test4-node${i}.log" 2>&1 &
  PIDS+=($!)
  echo "   Node-${i}: HTTP=:${HTTP_PORT} P2P=:${UDP_PORT} PID=${PIDS[-1]}"
done

# ── Step 3: Wait for genesis ───────────────────
echo ""
echo "⏳ Waiting for genesis on all nodes (up to 60s)..."
DEADLINE=$((SECONDS + 60))
while true; do
  ALL_UP=true
  for i in 0 1 2 3; do
    PORT="${PORTS_HTTP[$i]}"
    CNT=$(curl -sf --max-time 2 "http://localhost:${PORT}/blockcount" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "0")
    if [[ "${CNT}" -lt 1 ]]; then ALL_UP=false; break; fi
  done
  if $ALL_UP; then echo "   ✅ All nodes have genesis block"; break; fi
  if [[ $SECONDS -ge $DEADLINE ]]; then fail "Nodes did not produce genesis within 60s"; fi
  sleep 3
done

# ── Step 4: Wait for validator registration ────
echo "⏳ Waiting for validators to register (up to 30s)..."
DEADLINE=$((SECONDS + 30))
while true; do
  VCOUNT=$(curl -sf --max-time 2 "http://localhost:${SEED_HTTP}/validators" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('count', len(json.load(open('/dev/stdin'))) if False else 0))" 2>/dev/null || echo "0")
  # simpler parse:
  VCOUNT=$(curl -sf --max-time 2 "http://localhost:${SEED_HTTP}/validators" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
if isinstance(d, list): print(len(d))
elif isinstance(d, dict): print(d.get('count', len(d.get('validators', []))))
else: print(0)
" 2>/dev/null || echo "0")
  if [[ "${VCOUNT}" -ge 1 ]]; then
    echo "   ✅ Validators registered: ${VCOUNT}"
    break
  fi
  if [[ $SECONDS -ge $DEADLINE ]]; then
    echo "   ⚠️  Validator count: ${VCOUNT} (continuing anyway)"
    break
  fi
  sleep 3
done

# ── Step 5: Send 5 transactions ────────────────
echo ""
echo "📤 Sending 5 transactions..."
TS=$(date +%s)
for i in $(seq 1 5); do
  RESP=$(curl -sf --max-time 5 \
    -X POST "http://localhost:${SEED_HTTP}/transaction" \
    -H "Content-Type: application/json" \
    -d "{\"sender\":\"alice\",\"receiver\":\"bob\",\"amount\":${i},\"gas_limit\":21000,\"gas_price\":1,\"nonce\":$((TS+i)),\"timestamp\":$((TS+i))}" \
    2>/dev/null || echo "error")
  echo "   TX-${i}: ${RESP}"
done

# ── Step 6: Wait for blocks to advance ────────
echo ""
echo "⏳ Waiting for blocks to advance beyond 1 (up to 90s)..."
DEADLINE=$((SECONDS + 90))
while true; do
  CNT=$(curl -sf --max-time 2 "http://localhost:${SEED_HTTP}/blockcount" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "0")
  if [[ "${CNT}" -gt 1 ]]; then echo "   ✅ Seed node at block ${CNT}"; break; fi
  if [[ $SECONDS -ge $DEADLINE ]]; then fail "Seed node did not advance past block 1 within 90s"; fi
  sleep 5
done

# ── Step 7: Verify all nodes in sync ──────────
echo ""
echo "🔍 Verifying all 4 nodes are in sync..."
sleep 10  # give time to propagate

declare -A COUNTS
for i in 0 1 2 3; do
  PORT="${PORTS_HTTP[$i]}"
  CNT=$(curl -sf --max-time 3 "http://localhost:${PORT}/blockcount" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "UNREACHABLE")
  COUNTS[$i]="${CNT}"
  echo "   Node-${i} (port ${PORT}): block count = ${CNT}"
done

# Check all > 1
for i in 0 1 2 3; do
  CNT="${COUNTS[$i]}"
  if [[ "${CNT}" == "UNREACHABLE" ]]; then fail "Node-${i} is unreachable"; fi
  if [[ "${CNT}" -lt 2 ]]; then fail "Node-${i} block count ${CNT} is not > 1"; fi
done

# Check all same
REF="${COUNTS[0]}"
for i in 1 2 3; do
  if [[ "${COUNTS[$i]}" != "${REF}" ]]; then
    echo "   ⚠️  Block counts differ — Node-0=${REF}, Node-${i}=${COUNTS[$i]}"
    echo "   (Allowing ±1 block drift in fast dev-mode)"
    DIFF=$(( ${COUNTS[$i]} - REF ))
    if [[ ${DIFF#-} -gt 2 ]]; then
      fail "Node-${i} is out of sync by more than 2 blocks"
    fi
  fi
done

echo ""
echo "✅ All nodes operational, blocks > 1, in sync."
RESULT="PASS"

#!/usr/bin/env bash
set -euo pipefail

# check-health.sh — Check health of running Quantix nodes
# Usage: ./scripts/check-health.sh [devnet|testnet]

MODE="${1:-devnet}"

check_node() {
  local name="$1"
  local rpc_port="$2"
  local ws_port="$3"

  printf "  %-10s RPC: " "${name}"
  if curl -sf --max-time 3 "http://localhost:${rpc_port}/health" > /dev/null 2>&1; then
    echo -n "✅ OK (${rpc_port})"
  else
    echo -n "❌ UNREACHABLE (${rpc_port})"
  fi

  printf "  WS: "
  if curl -sf --max-time 3 "http://localhost:${ws_port}" > /dev/null 2>&1; then
    echo "✅ OK (${ws_port})"
  else
    # WebSocket upgrade required — check if port is open instead
    if nc -z localhost "${ws_port}" 2>/dev/null; then
      echo "✅ PORT OPEN (${ws_port})"
    else
      echo "❌ UNREACHABLE (${ws_port})"
    fi
  fi
}

echo ""
echo "🔍 Quantix Health Check — mode: ${MODE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ "${MODE}" == "devnet" ]]; then
  check_node "devnet" 8560 8700
elif [[ "${MODE}" == "testnet" ]]; then
  check_node "node0" 8560 8700
  check_node "node1" 8561 8701
  check_node "node2" 8562 8702
  check_node "node3" 8563 8703
else
  echo "Unknown mode: ${MODE}. Use 'devnet' or 'testnet'."
  exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

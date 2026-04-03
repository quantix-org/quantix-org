#!/usr/bin/env bash
set -euo pipefail

# check-health.sh — Check /blockcount, validator count, and sync status
# Usage: ./scripts/check-health.sh [devnet|testnet]

MODE="${1:-devnet}"

# Collect block count from a node; returns the numeric count or "UNREACHABLE"
get_blockcount() {
  local port="$1"
  local raw
  if raw=$(curl -sf --max-time 3 "http://localhost:${port}/blockcount" 2>/dev/null); then
    python3 -c "import sys,json; print(json.load(sys.stdin)['count'])" <<< "${raw}" 2>/dev/null || echo "UNREACHABLE"
  else
    echo "UNREACHABLE"
  fi
}

# Check a single node — prints status line, echoes blockcount
check_node() {
  local name="$1"
  local port="$2"
  local count
  count=$(get_blockcount "${port}")
  printf "  %-18s " "${name}:"
  if [[ "${count}" == "UNREACHABLE" ]]; then
    echo "❌ UNREACHABLE  (http://localhost:${port}/blockcount)"
    echo "UNREACHABLE"
  else
    echo "✅ OK  — block count: ${count}"
    echo "${count}"
  fi
}

echo ""
echo "🔍 Quantix Health Check — ${MODE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

OVERALL="HEALTHY"

if [[ "${MODE}" == "devnet" ]]; then
  # ── Devnet: single node ────────────────────
  output=$(check_node "quantix-devnet" 8560)
  # last line is the count
  CNT=$(echo "${output}" | tail -1)
  if [[ "${CNT}" == "UNREACHABLE" ]]; then OVERALL="DEGRADED"; fi

elif [[ "${MODE}" == "testnet" ]]; then
  # ── Testnet: 4 validators ─────────────────
  PORTS=(8560 8561 8562 8563)
  NAMES=(validator-0 validator-1 validator-2 validator-3)
  COUNTS=()

  for i in 0 1 2 3; do
    # check_node prints two lines: the status line + the raw count
    # We capture just the raw count (last line of its output)
    output=$(check_node "${NAMES[$i]}" "${PORTS[$i]}")
    CNT=$(echo "${output}" | tail -1)
    COUNTS+=("${CNT}")
    if [[ "${CNT}" == "UNREACHABLE" ]]; then OVERALL="DEGRADED"; fi
  done

  echo ""

  # ── Validator count from seed node ────────
  printf "  %-18s " "validator-count:"
  VRESP=$(curl -sf --max-time 3 "http://localhost:8560/validators" 2>/dev/null || echo "")
  if [[ -z "${VRESP}" ]]; then
    echo "❌ UNREACHABLE"
    OVERALL="DEGRADED"
  else
    VCOUNT=$(python3 -c "
import sys, json
d = json.loads('''${VRESP}''')
if isinstance(d, list):
    print(len(d))
elif isinstance(d, dict):
    print(d.get('count', len(d.get('validators', []))))
else:
    print(0)
" 2>/dev/null || echo "?")
    echo "✅ ${VCOUNT} validator(s) registered"
  fi

  echo ""

  # ── Sync check ────────────────────────────
  echo "  Sync status:"
  # Find a reference count (first reachable node)
  REF=""
  for CNT in "${COUNTS[@]}"; do
    if [[ "${CNT}" != "UNREACHABLE" ]]; then REF="${CNT}"; break; fi
  done

  if [[ -z "${REF}" ]]; then
    echo "  ❌ No reachable nodes to compare"
    OVERALL="DEGRADED"
  else
    IN_SYNC=true
    for i in 0 1 2 3; do
      CNT="${COUNTS[$i]}"
      if [[ "${CNT}" == "UNREACHABLE" ]]; then
        IN_SYNC=false
        continue
      fi
      DIFF=$(( CNT - REF ))
      ABS=${DIFF#-}
      if [[ ${ABS} -gt 2 ]]; then
        IN_SYNC=false
        echo "  ⚠️  ${NAMES[$i]} is out of sync (block ${CNT} vs ref ${REF})"
        OVERALL="DEGRADED"
      fi
    done
    if $IN_SYNC; then
      echo "  ✅ All nodes in sync (block ~${REF})"
    fi
  fi

else
  echo "Unknown mode '${MODE}'. Use 'devnet' or 'testnet'."
  exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ "${OVERALL}" == "HEALTHY" ]]; then
  echo "  Status: ✅ HEALTHY"
else
  echo "  Status: ⚠️  DEGRADED"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "🚀 Starting Quantix testnet (4 validators)..."
cd "${ROOT}"

mkdir -p data/validator-{0,1,2,3}
docker-compose -f docker-compose-testnet.yml up --build -d

echo ""
echo "✅ Testnet is up!"
echo ""
printf "  %-12s %-26s %-10s\n" "NODE" "RPC API" "P2P"
printf "  %-12s %-26s %-10s\n" "────────────" "──────────────────────────" "──────────"
printf "  %-12s %-26s %-10s\n" "validator-0" "http://localhost:8560" ":32307"
printf "  %-12s %-26s %-10s\n" "validator-1" "http://localhost:8561" ":32308"
printf "  %-12s %-26s %-10s\n" "validator-2" "http://localhost:8562" ":32309"
printf "  %-12s %-26s %-10s\n" "validator-3" "http://localhost:8563" ":32310"
echo ""
echo "Logs: ./scripts/logs.sh testnet"
echo "Stop: docker-compose -f docker-compose-testnet.yml down"

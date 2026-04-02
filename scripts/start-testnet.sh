#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "🚀 Starting Quantix testnet (4 nodes)..."
cd "${REPO_ROOT}"

docker compose -f docker-compose-testnet.yml up --build -d

echo ""
echo "✅ Testnet running!"
echo ""
echo "  Node  | RPC API               | WebSocket          | P2P"
echo "  ------|-----------------------|--------------------|----------"
echo "  node0 | http://localhost:8560 | ws://localhost:8700| :32421"
echo "  node1 | http://localhost:8561 | ws://localhost:8701| :32431"
echo "  node2 | http://localhost:8562 | ws://localhost:8702| :32441"
echo "  node3 | http://localhost:8563 | ws://localhost:8703| :32451"
echo ""
echo "Logs : docker compose -f docker-compose-testnet.yml logs -f"
echo "Stop : docker compose -f docker-compose-testnet.yml down"

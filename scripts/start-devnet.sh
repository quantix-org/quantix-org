#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "🚀 Starting Quantix devnet..."
cd "${REPO_ROOT}"

docker compose up --build -d

echo ""
echo "✅ Devnet running!"
echo "   RPC API  : http://localhost:8560"
echo "   WebSocket: ws://localhost:8700"
echo "   P2P      : :32421"
echo ""
echo "Logs: docker compose logs -f"
echo "Stop: docker compose down"

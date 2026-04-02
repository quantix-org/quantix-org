#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "⚠️  Resetting Quantix testnet — all chain data will be wiped!"
read -rp "Are you sure? (yes/N): " confirm
if [[ "${confirm}" != "yes" ]]; then
  echo "Aborted."
  exit 0
fi

cd "${REPO_ROOT}"

echo "🛑 Stopping testnet containers..."
docker compose -f docker-compose-testnet.yml down -v --remove-orphans

echo "🗑️  Removing named volumes..."
docker volume rm quantix_node0-data quantix_node1-data quantix_node2-data quantix_node3-data 2>/dev/null || true

echo "✅ Testnet reset complete. Run ./scripts/start-testnet.sh to start fresh."

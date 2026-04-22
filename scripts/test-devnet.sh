#!/bin/bash
# Quantix Devnet Test Script
# Starts a 3-node local devnet, funds wallets, and tests transfers

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_DIR/data/devnet"
WALLET_DIR="$PROJECT_DIR/testnet-wallets"

# Wallet addresses (from testnet-wallets/)
WALLET1="xAAcRj265En1EYT3c8sRecAzDnmck6F2mTDM2zTBGHdY"
WALLET2="x5Fukm46f3HurmwyjXLDPRVnRMfmc5WxTAnfXmipMCU5H"
WALLET3="x5wkbxfDEoTZ284vnCD2c3bumJS8ZQRaqM25dgEtFxcMZ"
WALLET4="x5A2rG8KgBXnEp85q9cWYWwV8csE1Ewt4GTWNW87ZGE26"
WALLET5="x8Cbqq66dD1PjbY9CL5QEJqVKn3RWyKWCeJCUEqWhGyeB"

# RPC endpoints
RPC1="http://127.0.0.1:8545"
RPC2="http://127.0.0.1:8546"
RPC3="http://127.0.0.1:8547"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING:${NC} $1"; }
error() { echo -e "${RED}[$(date '+%H:%M:%S')] ERROR:${NC} $1"; }

cleanup() {
    log "Stopping nodes..."
    pkill -f "quantix.*node.*pbft" 2>/dev/null || true
    rm -rf "$DATA_DIR"
}

trap cleanup EXIT

# Clean previous data
log "Cleaning previous devnet data..."
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

cd "$PROJECT_DIR"

# Build if needed
if [ ! -f "./quantix" ]; then
    log "Building Quantix..."
    go build -o quantix ./src/cli/main.go
fi

# Start Node 1 (primary validator)
log "Starting Node 1 (validator)..."
./quantix node \
    --role=validator \
    --tcp-addr=127.0.0.1:30303 \
    --udp-port=30304 \
    --http-port=127.0.0.1:8545 \
    --datadir="$DATA_DIR/node1" \
    --node-index=0 \
    --nodes=3 \
    --pbft \
    --network=devnet &
NODE1_PID=$!
log "Node 1 started (PID: $NODE1_PID)"

sleep 3

# Start Node 2
log "Starting Node 2 (validator)..."
./quantix node \
    --role=validator \
    --tcp-addr=127.0.0.1:30305 \
    --udp-port=30306 \
    --http-port=127.0.0.1:8546 \
    --datadir="$DATA_DIR/node2" \
    --node-index=1 \
    --nodes=3 \
    --pbft \
    --network=devnet \
    --seeds=127.0.0.1:30304 &
NODE2_PID=$!
log "Node 2 started (PID: $NODE2_PID)"

sleep 2

# Start Node 3
log "Starting Node 3 (validator)..."
./quantix node \
    --role=validator \
    --tcp-addr=127.0.0.1:30307 \
    --udp-port=30308 \
    --http-port=127.0.0.1:8547 \
    --datadir="$DATA_DIR/node3" \
    --node-index=2 \
    --nodes=3 \
    --pbft \
    --network=devnet \
    --seeds=127.0.0.1:30304,127.0.0.1:30306 &
NODE3_PID=$!
log "Node 3 started (PID: $NODE3_PID)"

# Wait for nodes to sync
log "Waiting for nodes to sync (15s)..."
sleep 15

# Check node health
log "Checking node health..."
for rpc in $RPC1 $RPC2 $RPC3; do
    BLOCK=$(curl -s -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"qtx_blockNumber","params":[],"id":1}' \
        "$rpc" 2>/dev/null | jq -r '.result // "error"')
    if [ "$BLOCK" != "error" ] && [ -n "$BLOCK" ]; then
        log "  $rpc: Block $BLOCK ✓"
    else
        warn "  $rpc: Not responding"
    fi
done

# Check balances
log "Checking wallet balances..."
for wallet in $WALLET1 $WALLET2 $WALLET3 $WALLET4 $WALLET5; do
    BALANCE=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"qtx_getBalance\",\"params\":[\"$wallet\",\"latest\"],\"id\":1}" \
        "$RPC1" 2>/dev/null | jq -r '.result // "0x0"')
    log "  $wallet: $BALANCE"
done

# Test transfer (if balances exist)
log ""
log "=== Transfer Test ==="
log "From: $WALLET1"
log "To: $WALLET2"
log "Amount: 100 QTX"

# Note: This would need signing with the private key
# For now, just show the expected command
log ""
log "To send a transaction, use:"
log "  ./quantix send-tx --from=$WALLET1 --to=$WALLET2 --amount=100 --rpc=$RPC1 --key=$WALLET_DIR/wallet_1_xAAcRj265En1.json"

log ""
log "=== Devnet Running ==="
log "Node 1: $RPC1 (PID: $NODE1_PID)"
log "Node 2: $RPC2 (PID: $NODE2_PID)"
log "Node 3: $RPC3 (PID: $NODE3_PID)"
log ""
log "Press Ctrl+C to stop..."

# Keep running
wait

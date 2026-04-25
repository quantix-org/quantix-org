# Quantix Validator Guide

> **Version:** 1.0 · **Network:** devnet / testnet / mainnet  
> **Maintained by:** F.R.I.D.A.Y. — Quantix DevOps

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Install from Source](#2-install-from-source)
3. [Configure Your Node](#3-configure-your-node)
4. [Join devnet / testnet](#4-join-devnet--testnet)
5. [Monitor with Grafana](#5-monitor-with-grafana)
6. [FAQ](#6-faq)

---

## 1. System Requirements

### Minimum (devnet / solo validator)

| Resource | Minimum               | Recommended      |
| -------- | --------------------- | ---------------- |
| CPU      | 2 cores               | 4 cores          |
| RAM      | 2 GB                  | 8 GB             |
| Disk     | 20 GB SSD             | 100 GB NVMe      |
| OS       | Linux (Ubuntu 22.04+) | Ubuntu 22.04 LTS |
| Network  | 10 Mbps               | 100 Mbps         |
| Go       | 1.24+                 | latest           |
| Docker   | 24+ (optional)        | latest           |

### Recommended (testnet / production)

| Resource | Value                 |
| -------- | --------------------- |
| CPU      | 8 cores               |
| RAM      | 16 GB                 |
| Disk     | 500 GB NVMe           |
| Network  | 1 Gbps with static IP |
| Uptime   | 99.9% SLA             |

### Open Ports

| Port  | Protocol | Purpose        | Exposure                                 |
| ----- | -------- | -------------- | ---------------------------------------- |
| 8560  | TCP      | HTTP RPC API   | 🔒 Restrict to trusted IPs in production |
| 8700  | TCP      | WebSocket      | 🔒 Restrict to trusted IPs in production |
| 32307 | TCP/UDP  | P2P networking | 🌐 Public (required for peer discovery)  |

> ⚠️ **SEC-D01 — Production Firewall Required**: The HTTP RPC port (8560) and WebSocket
> port (8700) must **not** be publicly exposed in production. Use `ufw` or `iptables` to
> restrict these ports to trusted operator IPs only. Only port 32307 (P2P) should be
> publicly accessible.
>
> ```bash
> # Example: restrict RPC to a single operator IP
> sudo ufw allow from <YOUR_OPERATOR_IP> to any port 8560
> sudo ufw allow from <YOUR_OPERATOR_IP> to any port 8700
> sudo ufw allow 32307  # P2P must be public
> sudo ufw enable
> ```

---

## 2. Install from Source

### 2.1 Prerequisites

```bash
# Install Go 1.24+
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version  # should print go1.24.x

# Install build dependencies
sudo apt update && sudo apt install -y git curl make build-essential
```

### 2.2 Clone and Build

```bash
git clone https://github.com/quantix-org/quantix-org.git
cd quantix
make build
# or manually:
go build -o bin/quantix .
go build -o bin/qtx ./cmd/qtx/
```

### 2.3 Verify Installation

```bash
./bin/quantix --version
./bin/qtx --help
```

---

## 3. Configure Your Node

### 3.1 Data Directory

```bash
mkdir -p ~/.quantix/data
```

### 3.2 Key Flags

| Flag              | Default         | Description                      |
| ----------------- | --------------- | -------------------------------- |
| `-datadir`        | `./data`        | Path to chain data               |
| `-http-port`      | `0.0.0.0:8560`  | HTTP RPC listen address          |
| `-udp-port`       | `32307`         | P2P UDP port                     |
| `-tcp-addr`       | `0.0.0.0:32307` | P2P TCP listen address           |
| `-nodes`          | `1`             | Total validators in network      |
| `-node-index`     | `0`             | This validator's index (0-based) |
| `-roles`          | `validator`     | Comma-separated role list        |
| `-seeds`          | _(none)_        | Seed peer addresses              |
| `-seed-http-port` | _(none)_        | HTTP port of seed node           |

### 3.3 Environment Variables

| Variable          | Values                         | Description            |
| ----------------- | ------------------------------ | ---------------------- |
| `QUANTIX_NETWORK` | `devnet`, `testnet`, `mainnet` | Network identifier     |
| `QUANTIX_ENV`     | `devnet`, `testnet`, `mainnet` | Deployment environment |

---

## 4. Join devnet / testnet

### 4.1 Quick Start — Single Node devnet (Docker)

```bash
git clone https://github.com/quantix-org/quantix-org.git
cd quantix
docker compose up --build -d
# Check health
curl http://localhost:8560/blockcount
```

### 4.2 Join Testnet (4-Validator, Docker)

```bash
# Boot all 4 validators
docker compose -f docker-compose-testnet.yml up --build -d

# Verify all are running
docker compose -f docker-compose-testnet.yml ps

# Follow logs for validator-0
docker logs -f quantix-validator-0
```

### 4.3 Join Testnet (Bare Metal — Additional Validator)

If you're joining an existing testnet with a known seed node:

```bash
# Example: joining as validator-1, seed is at 1.2.3.4:32307
./bin/quantix \
  -nodes 4 \
  -node-index 1 \
  -roles validator,validator,validator,validator \
  -datadir ~/.quantix/data \
  -http-port 0.0.0.0:8561 \
  -udp-port 32308 \
  -tcp-addr 0.0.0.0:32308 \
  -seeds "1.2.3.4:32307" \
  -seed-http-port 8560
```

### 4.4 Verify Sync

```bash
# Check block count
curl http://localhost:8560/blockcount

# Check peer count
curl http://localhost:8560/peers

# Monitor logs
./scripts/logs.sh devnet
```

### 4.5 Run Load Test

```bash
# After node is live:
bash scripts/load-test.sh
# Expected: PASS ≥500 tx/s
```

---

## 5. Monitor with Grafana

### 5.1 Start Monitoring Stack

```bash
docker compose -f docker-compose-monitoring.yml up -d
```

This starts:

- **Prometheus** → `http://localhost:9090`
- **Grafana** → `http://localhost:3000` (default: `admin` / `admin`) — ⚠️ **Change the default password immediately** (`admin` → strong password) before exposing Grafana to any network

### 5.2 Import the Dashboard

1. Open Grafana at `http://localhost:3000`
2. Login → **Dashboards → Import**
3. Upload `deploy/grafana/quantix-dashboard.json`
4. Select **Prometheus** as datasource
5. Click **Import**

### 5.3 Dashboard Panels

| Panel                   | Type                    | Metric                                 |
| ----------------------- | ----------------------- | -------------------------------------- |
| Block Height            | Line chart              | `quantix_block_height`                 |
| Transactions Per Second | Gauge                   | `rate(quantix_transactions_total[1m])` |
| Mempool Size            | Gauge                   | `quantix_mempool_size`                 |
| Peer Count              | Stat                    | `quantix_peers_connected`              |
| Block Time Distribution | Histogram (p50/p95/p99) | `quantix_block_time_seconds`           |
| Validator Count         | Stat                    | `quantix_validators_active`            |

### 5.4 Alerting Recommendations

| Alert        | Condition                  | Severity |
| ------------ | -------------------------- | -------- |
| Low TPS      | `tx/s < 100` for 5m        | Warning  |
| No blocks    | Block height unchanged 60s | Critical |
| Peer loss    | Peers < 2                  | Warning  |
| Mempool full | Mempool > 9000             | Warning  |
| Node down    | HTTP `/blockcount` fails   | Critical |

---

## 6. FAQ

**Q: Why isn't my node producing blocks?**  
A: Ensure all expected validators are online and connected. Check with `curl http://localhost:8560/peers`. A 4-validator network needs ≥ 3 online for consensus.

**Q: My node stuck at block 0?**  
A: If joining an existing network, make sure `-seeds` and `-seed-http-port` are set correctly. The seed node must be healthy before you start.

**Q: What is `-dev-mode`?**  
A: Dev mode skips DHT peer discovery and uses a simplified startup, suitable for local testing only. **Production nodes must NOT use `-dev-mode`** — it's removed from all production Docker configs.

**Q: How do I reset chain data?**  
A: `bash scripts/reset.sh` — or manually: `docker compose down && rm -rf data/`

**Q: Can I run multiple validators on one machine?**  
A: Yes, using different ports and data directories. Use `docker-compose-testnet.yml` as a template. Not recommended for mainnet (single point of failure).

**Q: What post-quantum crypto does Quantix use?**  
A: SPHINCS+ (stateless hash-based signatures) via the bundled `SPHINCSPLUS-golang` module. See `src/crypto/` for details.

**Q: How do I upgrade my node?**  
A:

```bash
git pull
go build -o bin/quantix .
# or with Docker:
docker compose pull && docker compose up --build -d
```

**Q: Where are logs?**  
A: Use `./scripts/logs.sh devnet` or `docker logs -f quantix-devnet`.

**Q: How do I check if I'm in sync?**  
A: Compare your block height with a known peer: `curl http://<peer-ip>:8560/blockcount`.

---

_Built with 🔬 by the Quantix team · F.R.I.D.A.Y. DevOps v3_

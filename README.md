# Quantix Protocol

**Quantix** is a post-quantum blockchain protocol written in Go, secured by SPHINCS+/STHINCS cryptography and powered by PBFT consensus with stake-weighted RANDAO leader election.

---

## ✨ Features

- 🔐 **Post-Quantum Cryptography** — SPHINCS+ & STHINCS signatures, resistant to quantum computing attacks
- ⚡ **PBFT Consensus** — Byzantine fault-tolerant finality with stake-weighted voting
- 🎲 **RANDAO + VDF** — Verifiable delay function for unpredictable, unbiasable leader election
- 🖥️ **Quantix Virtual Machine (QVM)** — Stack-based smart contract execution with OP_RETURN support
- 🔗 **ZK-STARK Proofs** — Zero-knowledge computation verification via libSTARK
- 🌐 **DHT P2P Networking** — Kademlia-style peer discovery with encrypted handshakes
- 💰 **QTX Token** — Native token with geometric-decay inflation and on-chain validator economics

---

## 🪙 Token: QTX

| Unit | Value | Description |
|------|-------|-------------|
| `nQTX` | 1 | Base unit (nano-QTX) |
| `gQTX` | 10⁹ nQTX | Giga-QTX |
| `QTX` | 10¹⁸ nQTX | 1 full token |

- **Max Supply**: 5,000,000,000 QTX (5 billion)
- **Block Reward**: 5 QTX per block
- **Annual Inflation**: 5% year 1, decays by 0.8× per year
- **Min Validator Stake**: 32 QTX (mainnet)
- **Address prefix**: `qtx1...`

---

## ⚙️ System Requirements

### Minimum — Running a Node

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 4 cores, 2.0 GHz | 8 cores, 3.0 GHz+ |
| **RAM** | 4 GB | 8 GB+ |
| **Disk** | 20 GB SSD | 100 GB NVMe SSD |
| **OS** | Ubuntu 22.04 / Debian 12 / macOS 13+ | Ubuntu 24.04 LTS |
| **Go** | 1.22+ | 1.24+ |
| **Network** | 10 Mbps stable | 100 Mbps+ |

> ⚠️ **HDD not recommended** — LevelDB state storage requires low-latency random I/O. SSD is strongly preferred.

### Minimum — Development & Building

| Component | Minimum | Notes |
|-----------|---------|-------|
| **CPU** | 2 cores, 2.5 GHz | Argon2 in QtxHash is CPU-intensive |
| **RAM** | 2 GB | 4 GB recommended for full test suite |
| **Disk** | 5 GB | Go module cache + build artifacts |
| **Go** | 1.22+ | Required; 1.24+ recommended |

### Minimum — Running Tests

| Component | Minimum | Notes |
|-----------|---------|-------|
| **CPU** | 4 cores, 2.5 GHz+ | `src/core` tests are Argon2-heavy |
| **RAM** | 4 GB | Consensus tests spawn multiple goroutines |
| **Go** | 1.22+ | |

> 💡 **Tip for test environments**: Set `QUANTIX_TEST=1` to activate lightweight Argon2 parameters (8 KB memory, 1 iteration instead of 64 KB / 2 iterations). This reduces test runtime by ~8× without affecting algorithm correctness.
>
> ```bash
> QUANTIX_TEST=1 go test ./...
> ```

### Per-Environment Chain Parameters

| Parameter | Devnet | Testnet | Mainnet |
|-----------|--------|---------|---------|
| Chain ID | 73310 | 17331 | 7331 |
| Block time | 2s | 5s | 10s |
| Min stake | 1 QTX | 32 QTX | 32 QTX |
| Block gas limit | 50M | 20M | 10M |
| Max block size | 8 MB | 4 MB | 2 MB |

---

## 🚀 Getting Started

### Build

```bash
git clone https://github.com/quantix-org/quantix-org.git
cd quantix-org
go mod tidy
go build ./...
```

### Run Tests

```bash
# Fast (recommended for CI / low-resource machines)
QUANTIX_TEST=1 go test $(go list ./... | grep -v '/gui') -timeout 120s

# Full (production-equivalent Argon2 params, needs 4+ core 2.5GHz+)
go test $(go list ./... | grep -v '/gui') -timeout 600s
```

### Run a Devnet Node

```bash
go run src/cli/main.go --network devnet --port 32309
```

---

## 🏗️ Architecture

```
quantix-org/
├── src/
│   ├── core/           # Blockchain engine, genesis, block execution
│   ├── consensus/      # PBFT + PoS + RANDAO/VDF
│   ├── crypto/         # SPHINCS+, STHINCS, WOTS, ZK-STARK
│   ├── qtxhash/        # QtxHash — Argon2id + SHA-512/256 + SHAKE-256
│   ├── policy/         # Tokenomics, inflation, validator economics
│   ├── state/          # State machine replication (SMR)
│   ├── p2p/            # Peer discovery, DHT routing
│   ├── dht/            # Kademlia DHT
│   ├── pool/           # Mempool
│   ├── rpc/            # JSON-RPC server
│   ├── bind/           # HTTP + WebSocket API
│   ├── accounts/       # Wallet, keystore, BIP44 (coin type: 7331)
│   ├── core/svm/       # Quantix Virtual Machine
│   └── core/stark/     # ZK-STARK proof system
```

---

## 🔐 Cryptography

| Primitive | Algorithm | Purpose |
|-----------|-----------|---------|
| Signature | STHINCS (SPHINCS+ variant) | Transaction & consensus signing |
| Hash | QtxHash (Argon2id + SHA-512/256 + SHAKE-256) | Block hash, tx ID, address |
| KDF | Argon2id | Key derivation, salt generation |
| ZKP | ZK-STARK (libSTARK) | Computation proofs |
| OTS | WOTS (Winternitz) | SPHINCS+ hypertree component |
| Randomness | RANDAO + VDF (Wesolowski) | Leader election |

---

## 📋 QIPS — Quantix Implementation Proposals

Protocol improvements are tracked in [quantix-org/QIPS](https://github.com/quantix-org/QIPS).

| QIPS | Title | Status |
|------|-------|--------|
| QIPS-0007 | QTX Denomination Standard (nQTX/gQTX/QTX) | ✅ Implemented |
| QIPS-0011 | Consensus — PBFT + RANDAO | ✅ Implemented |
| QIPS-0012 | Staking & Validator Economics | ✅ Implemented |
| QIPS-0013 | ZK-STARK Integration | 🔄 In Progress |
| QIPS-0014 | Cross-Chain Interoperability | 📋 Draft |
| QIPS-0015 | On-Chain Governance | 📋 Draft |

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

© 2024 Quantix Team

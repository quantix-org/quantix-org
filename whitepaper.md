# Quantix Protocol

## A Post-Quantum Secure Blockchain for the AI Era

**Version:** 1.0.0  
**Date:** April 2026  
**Website:** https://qpqb.org  
**Repository:** https://github.com/quantix-org/quantix-org

---

## Abstract

Quantix is a Layer 1 blockchain protocol engineered from the ground up to withstand quantum computing attacks. By integrating NIST-standardized post-quantum cryptographic primitives—including SPHINCS+ signatures, ZK-STARK proofs, and lattice-based hash functions—Quantix provides a mathematically-enforced security foundation that remains sound even as quantum computers become practically viable.

Built in Go for performance and maintainability, Quantix combines PBFT consensus with stake-weighted RANDAO leader election and Verifiable Delay Functions (VDF) to achieve Byzantine fault tolerance, unpredictable block production, and rapid finality. The protocol is designed for the convergence of AI and blockchain, where autonomous agents require trustless, quantum-secure infrastructure for economic coordination.

This whitepaper presents the cryptographic foundations, consensus mechanism, virtual machine architecture, and economic model that together form the Quantix Protocol.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Cryptographic Foundations](#2-cryptographic-foundations)
3. [Consensus Mechanism](#3-consensus-mechanism)
4. [Quantix Virtual Machine (QVM)](#4-quantix-virtual-machine-qvm)
5. [Tokenomics](#5-tokenomics)
6. [Network Architecture](#6-network-architecture)
7. [Roadmap](#7-roadmap)
8. [Conclusion](#8-conclusion)

---

## 1. Introduction

### 1.1 The Quantum Threat

Current blockchain networks rely on cryptographic primitives—primarily ECDSA signatures and SHA-256 hashing—that are vulnerable to quantum attacks. Shor's algorithm, executable on a sufficiently powerful quantum computer, can break elliptic curve cryptography in polynomial time. Grover's algorithm provides quadratic speedup for brute-force attacks on hash functions.

While large-scale fault-tolerant quantum computers remain years away, the threat is imminent for several reasons:

1. **Harvest Now, Decrypt Later:** Adversaries can capture encrypted data and signed transactions today, waiting to decrypt them once quantum capability arrives.

2. **Long-Lived Assets:** Blockchain addresses holding value for decades must remain secure against future threats.

3. **Infrastructure Inertia:** Migrating cryptographic infrastructure takes years. The time to act is now.

### 1.2 Design Philosophy

Quantix is built on four principles:

1. **Quantum-First Security:** Every cryptographic component is selected for post-quantum resistance, not retrofitted.

2. **No Trusted Setup:** All proof systems and random number generation are transparent and verifiable without requiring trust in a ceremony.

3. **Practical Performance:** Post-quantum primitives have larger signatures and slower operations. Quantix optimizes for real-world throughput without compromising security.

4. **AI-Native Design:** As autonomous agents become economic actors, Quantix provides the trustless substrate they need for secure, verifiable computation.

---

## 2. Cryptographic Foundations

### 2.1 Digital Signatures: SPHINCS+ / STHINCS

Quantix uses **SPHINCS+** (Stateless Hash-Based Signature Scheme), a NIST-standardized post-quantum signature algorithm, implemented as **STHINCS** (Sphinx Thin Hash-based Signature) with blockchain-specific optimizations.

#### Why SPHINCS+?

- **Hash-Based Security:** Security relies only on the collision resistance of hash functions, not on number-theoretic assumptions vulnerable to Shor's algorithm.
- **Stateless Design:** Unlike XMSS or LMS, SPHINCS+ requires no state management between signatures, simplifying implementation and eliminating state synchronization risks.
- **NIST Standardization:** Selected in NIST's Post-Quantum Cryptography standardization process (FIPS 205).

#### Parameter Sets

| Parameter Set | Security Level    | Signature Size | Public Key | Signing Time |
| ------------- | ----------------- | -------------- | ---------- | ------------ |
| SPHINCS+-128f | Level 1 (128-bit) | 7,856 bytes    | 32 bytes   | ~20ms        |
| SPHINCS+-192f | Level 3 (192-bit) | 16,224 bytes   | 48 bytes   | ~40ms        |
| SPHINCS+-256f | Level 5 (256-bit) | 29,792 bytes   | 64 bytes   | ~80ms        |

**Quantix Default:** SPHINCS+-256f (SHA-256 variant, robust mode) for maximum security margin.

#### Trade-offs

SPHINCS+ signatures are significantly larger than ECDSA (~64 bytes). Quantix addresses this through:

- **Signature Aggregation:** ZK-STARK proofs batch-verify multiple signatures
- **Efficient Encoding:** Optimized serialization reduces on-chain footprint
- **Block Gas Pricing:** Signature verification costs reflect computational reality

### 2.2 Hash Function: QtxHash

Quantix employs **QtxHash**, a custom memory-hard hash function designed for resistance to both classical and quantum brute-force attacks.

#### Algorithm

```
QtxHash(data) = Finalize(Mix(SHAKE256(SHA-512/256(Argon2id(data)))))
```

**Components:**

1. **Argon2id** (memory-hard KDF): Prevents ASIC acceleration
   - Memory: 64 KB
   - Iterations: 2
   - Parallelism: 1

2. **SHA-512/256**: Truncated SHA-512 providing 256-bit output with 512-bit internal state

3. **SHAKE-256**: Extendable-output function for variable-length derivations

4. **Mixing Function**: 1000 rounds of non-commutative transformations with prime constants to maximize diffusion and Grover resistance

#### Security Properties

- **Memory-Hard:** Argon2id prevents GPU/ASIC optimization
- **Collision Resistant:** 256-bit security from SHA-512/256
- **Grover Resistant:** Multiple rounds increase quantum brute-force cost
- **Avalanche Effect:** Single-bit input changes cascade to ~50% output change

### 2.3 Zero-Knowledge Proofs: ZK-STARKs

Quantix integrates **ZK-STARKs** (Scalable Transparent ARguments of Knowledge) for:

- Batched signature verification proofs
- Private computation verification
- Light client state proofs

#### Why STARKs over SNARKs?

| Property      | ZK-STARK | ZK-SNARK                |
| ------------- | -------- | ----------------------- |
| Trusted Setup | **No**   | Yes                     |
| Post-Quantum  | **Yes**  | No (relies on pairings) |
| Proof Size    | ~100 KB  | ~200 bytes              |
| Verification  | Fast     | Very fast               |
| Prover Time   | Slower   | Faster                  |

**Quantix prioritizes transparency and quantum resistance over proof size.**

#### Implementation

Quantix uses a custom STARK implementation with:

- **AIR (Algebraic Intermediate Representation):** Computation traces encoded as polynomial constraints
- **FRI (Fast Reed-Solomon IOP):** Proof of polynomial low-degree
- **Fiat-Shamir Transform:** Non-interactive proofs via hash-based challenges

Signature verification traces are committed to Merkle trees, enabling batch proofs of thousands of SPHINCS+ verifications.

### 2.4 Additional Primitives

| Primitive        | Algorithm    | Purpose                              |
| ---------------- | ------------ | ------------------------------------ |
| Key Derivation   | Argon2id     | Wallet encryption, salt generation   |
| Random Beacon    | RANDAO + VDF | Leader election, on-chain randomness |
| Merkle Trees     | SHA3-256     | State commitments, transaction roots |
| Address Encoding | Bech32       | Human-readable addresses (`qtx1...`) |

---

## 3. Consensus Mechanism

### 3.1 Overview

Quantix achieves consensus through **PBFT (Practical Byzantine Fault Tolerance)** with **stake-weighted leader election** using RANDAO and VDF.

**Key Properties:**

- **BFT Safety:** Tolerates up to ⅓ Byzantine validators
- **Deterministic Finality:** Blocks are final once committed (no probabilistic confirmation)
- **Stake-Weighted Participation:** Voting power proportional to stake
- **Unpredictable Leaders:** VDF prevents look-ahead grinding attacks

### 3.2 Validator Set

Validators must stake a minimum of **32 QTX** to participate. The validator set is:

- **Capped:** Maximum 100 active validators (Phase 1)
- **Dynamic:** Validators can join/leave with unbonding period
- **Slashable:** Misbehavior results in stake penalties

#### Validator Economics

| Parameter              | Value             |
| ---------------------- | ----------------- |
| Minimum Stake          | 32 QTX            |
| Unbonding Period       | 14 days           |
| Slashing (Double Sign) | 5%                |
| Slashing (Downtime)    | 1%                |
| Commission Rate        | 5% (configurable) |

### 3.3 Leader Election: RANDAO + VDF

Each slot's block proposer is selected through a two-stage process:

#### Stage 1: RANDAO Seed

Validators contribute entropy by revealing pre-committed random values:

```
seed_n = SHA3(seed_{n-1} || reveal_1 || reveal_2 || ... || reveal_k)
```

**Weakness of RANDAO alone:** The last revealer can see the seed before revealing and choose to withhold, biasing the outcome.

#### Stage 2: VDF Delay

To prevent manipulation, the RANDAO output passes through a **Verifiable Delay Function**:

```
output = VDF(seed, T)
```

**VDF Properties:**

- **Sequential:** Cannot be parallelized; must compute T sequential operations
- **Verifiable:** Output can be verified quickly with a proof
- **Deterministic:** Same input always produces same output

**Quantix VDF Implementation:**

- **Class Group VDF** (Wesolowski construction)
- **Discriminant:** 1024-bit, derived deterministically from genesis block
- **Delay Parameter:** T = 2²⁰ (~1 million squarings, ~10ms)

The VDF ensures that even if an adversary controls multiple validators, they cannot compute the leader election outcome faster than honest participants.

### 3.4 PBFT Consensus Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         PBFT Phases                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   PROPOSE          PREPARE           COMMIT           REPLY     │
│                                                                 │
│   Leader ──────►  Validators ──────► Validators ──────► Finality│
│   broadcasts      verify block,      2/3 prepare,     block     │
│   block           broadcast          broadcast        committed │
│                   PREPARE            COMMIT                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

1. **Propose:** Slot leader broadcasts block
2. **Prepare:** Validators verify and broadcast PREPARE vote
3. **Commit:** Upon 2/3 PREPARE, validators broadcast COMMIT vote
4. **Finality:** Upon 2/3 COMMIT, block is finalized

**View Change:** If the leader fails or is Byzantine, validators trigger a view change to elect a new leader.

### 3.5 Block Parameters

| Network | Chain ID | Block Time | Block Gas Limit | Max Block Size |
| ------- | -------- | ---------- | --------------- | -------------- |
| Mainnet | 7331     | 10s        | 10M             | 2 MB           |
| Testnet | 17331    | 5s         | 20M             | 4 MB           |
| Devnet  | 73310    | 2s         | 50M             | 8 MB           |

---

## 4. Quantix Virtual Machine (QVM)

### 4.1 Architecture

The QVM is a **stack-based virtual machine** designed for post-quantum smart contract execution.

**Design Goals:**

- Native SPHINCS+ signature verification opcodes
- Efficient gas metering for large signatures
- Bitcoin Script compatibility for simple transactions
- Ethereum-style opcodes for complex contracts

#### Memory Model

| Component | Size       | Description               |
| --------- | ---------- | ------------------------- |
| Stack     | 1024 items | 64-bit unsigned integers  |
| Memory    | 1 MB       | Linear byte-addressed     |
| Storage   | Unlimited  | Persistent contract state |
| Code      | 24 KB max  | Immutable bytecode        |

### 4.2 Opcode Categories

#### Cryptographic Operations

| Opcode                  | Gas           | Description               |
| ----------------------- | ------------- | ------------------------- |
| `OP_CHECK_SPHINCS`      | 50,000        | Verify SPHINCS+ signature |
| `OP_VERIFY_SPHINCS`     | 50,000        | Verify or fail            |
| `SHA3_256`              | 30 + 6/word   | SHA3-256 hash             |
| `QUANTIXHASH`           | 100 + 12/word | QtxHash (memory-hard)     |
| `OP_VERIFY_MERKLE_ROOT` | 1,000         | Verify Merkle proof       |

#### Replay Protection

| Opcode               | Gas    | Description                     |
| -------------------- | ------ | ------------------------------- |
| `OP_CHECK_TIMESTAMP` | 50     | Verify freshness (5 min window) |
| `OP_CHECK_NONCE`     | 100    | Check nonce uniqueness          |
| `OP_STORE_NONCE`     | 20,000 | Store nonce (prevents replay)   |

#### Data Embedding

| Opcode      | Gas    | Description                         |
| ----------- | ------ | ----------------------------------- |
| `OP_RETURN` | 1/byte | Embed arbitrary data (max 80 bytes) |

### 4.3 Gas Model

Gas costs reflect computational reality:

```
Transaction Fee = Base Fee + (Gas Used × Gas Price)
```

**Notable Costs:**

- SPHINCS+ verification: **50,000 gas** (reflects ~10ms CPU time)
- Storage write (32 bytes): **20,000 gas**
- Storage read (32 bytes): **200 gas**
- Simple arithmetic: **3-8 gas**

### 4.4 Contract Storage

Contracts maintain persistent state in a key-value store:

- **Key:** 32-byte slot identifier
- **Value:** 32-byte data
- **Root:** Merkle Patricia Trie for state commitments

Storage supports:

- Dirty tracking for gas refunds
- Atomic commits/reverts
- Cross-contract reads

---

## 5. Tokenomics

### 5.1 QTX Token

**QTX** is the native token of the Quantix Protocol.

| Property       | Value                  |
| -------------- | ---------------------- |
| Name           | Quantix                |
| Symbol         | QTX                    |
| Max Supply     | 5,000,000,000 QTX      |
| Decimals       | 18 (1 QTX = 10¹⁸ nQTX) |
| Address Prefix | `qtx1`                 |

### 5.2 Denomination Units

| Unit | Value     | Description          |
| ---- | --------- | -------------------- |
| nQTX | 1         | Base unit (nano-QTX) |
| gQTX | 10⁹ nQTX  | Giga-QTX             |
| QTX  | 10¹⁸ nQTX | Standard unit        |

### 5.3 Supply Distribution

The total hard-capped maximum supply of the network is **5,000,000,000 QTX**. At Genesis, **4,211,081,600 QTX** is minted, leaving **788,918,400 QTX** strictly reserved for 50 years of block rewards.

| Category                 | Amount            | Vesting                  |
| ------------------------ | ----------------- | ------------------------ |
| **Public Distribution**  | 3,461,081,600 QTX | Immediate                |
| **Ecosystem Fund**       | 500,000,000 QTX   | 4-year linear            |
| **Team & Advisors**      | 250,000,000 QTX   | 4-year with 1-year cliff |
| **Future Block Rewards** | 788,918,400 QTX   | Emitted over 50 years    |

_(Total = 5,000,000,000 QTX)_

### 5.4 Emission & Block Rewards

Instead of decaying inflation, Quantix tokenomics utilizes a flat emission schedule against a hard-capped max supply.

| Parameter         | Value           |
| ----------------- | --------------- |
| Block Reward      | 5 QTX           |
| Target Block Time | 10 seconds      |
| Blocks per Year   | ~3,153,600      |
| Annual Emission   | ~15,768,000 QTX |
| Emission Duration | 50 Years        |

**Emission Schedule:**
Block rewards will mint linearly at 5 QTX per block for exactly 50 years (approx. 157.78 million blocks). After 50 years, the remaining unminted supply of 788,918,400 QTX will be completely exhausted, and validators will be compensated entirely by transaction fees.

### 5.5 Fee Distribution

Transaction fees are distributed:

| Recipient  | Share | Purpose                    |
| ---------- | ----- | -------------------------- |
| Validators | 60%   | Block production incentive |
| Stakers    | 25%   | Delegation rewards         |
| Treasury   | 10%   | Protocol development       |
| Burned     | 5%    | Deflationary pressure      |

### 5.6 Staking Economics

| Parameter          | Value                 |
| ------------------ | --------------------- |
| Minimum Stake      | 32 QTX                |
| Target Stake Ratio | 70%                   |
| Base APY           | ~8% (at target ratio) |
| Unbonding Period   | 14 days               |

APY adjusts dynamically based on total stake ratio to incentivize target participation.

---

## 6. Network Architecture

### 6.1 P2P Layer

Quantix uses **Kademlia DHT** for peer discovery with encrypted handshakes.

**Features:**

- Structured overlay network with O(log N) routing
- Encrypted peer connections (post-quantum TLS planned)
- Gossip protocol for block/transaction propagation
- NAT traversal support

### 6.2 RPC Interface

**JSON-RPC 2.0** over HTTP and WebSocket:

```
POST /rpc
{
  "jsonrpc": "2.0",
  "method": "qtx_getBalance",
  "params": ["qtx1abc..."],
  "id": 1
}
```

**Key Endpoints:**

- `qtx_getBalance` — Account balance
- `qtx_sendTransaction` — Submit transaction
- `qtx_getBlock` — Block by hash/number
- `qtx_call` — Execute contract view function
- `qtx_subscribe` — WebSocket subscriptions

### 6.3 Network Environments

| Environment | Port  | Status   | Purpose                |
| ----------- | ----- | -------- | ---------------------- |
| **Mainnet** | 7331  | Draft    | Production network     |
| **Testnet** | 17331 | Draft    | Staging for developers |
| **Devnet**  | 73310 | **Live** | Local development      |

---

## 7. Roadmap

### Phase 1: Core Protocol (Complete)

- [x] SPHINCS+ signature implementation
- [x] QtxHash function
- [x] PBFT consensus
- [x] RANDAO + VDF leader election
- [x] QVM with 60+ opcodes
- [x] Gas metering system
- [x] Genesis block generation

### Phase 2: Multi-Node Testnet (In Progress)

- [x] Devnet deployment
- [ ] Public testnet with faucet
- [ ] Block explorer
- [ ] Wallet (CLI + Web)
- [ ] Documentation portal

### Phase 3: Security & Audit

- [ ] Cryptography audit
- [ ] Consensus audit
- [ ] Smart contract VM audit
- [ ] Bug bounty program

### Phase 4: Ecosystem

- [ ] JavaScript/TypeScript SDK
- [ ] Python SDK
- [ ] Hardware wallet support
- [ ] DEX integration

### Phase 5: Mainnet Launch

- [ ] Genesis ceremony
- [ ] Validator onboarding
- [ ] Exchange listings
- [ ] Governance activation

---

## 8. Conclusion

Quantix represents a fundamental rethinking of blockchain security for the post-quantum era. By building on NIST-standardized cryptographic primitives, transparent proof systems, and rigorous consensus mechanisms, Quantix provides the security guarantees that long-lived digital assets require.

As quantum computing advances and AI agents become economic actors, the need for trustless, quantum-secure infrastructure will only grow. Quantix is designed to meet that need—not as a retrofit, but as a foundation built for the challenges ahead.

The future is quantum. The blockchain should be too.

---

## References

1. NIST. _Post-Quantum Cryptography Standardization._ 2024.
2. Bernstein, D.J. et al. _SPHINCS+: Submission to the NIST Post-Quantum Project._ 2020.
3. Ben-Sasson, E. et al. _Scalable, transparent, and post-quantum secure computational integrity._ 2018.
4. Castro, M. and Liskov, B. _Practical Byzantine Fault Tolerance._ OSDI 1999.
5. Wesolowski, B. _Efficient verifiable delay functions._ 2019.
6. Biryukov, A. et al. _Argon2: the memory-hard function for password hashing._ 2016.

---

## Contact

- **Website:** https://qpqb.org
- **GitHub:** https://github.com/quantix-org/quantix-org
- **Email:** developer@qpqb.org

---

_© 2026 Quantix Developer Team. All rights reserved._

_This whitepaper is for informational purposes only and does not constitute financial advice or an offer to sell securities._

# Quantix Mainnet Launch Roadmap

**Goal:** Take Quantix from experimental → live public blockchain

---

## Phase 1: Core Completion (Est. 2-3 months)

### 🔧 Technical Debt
- [x] Clean up test data fixtures in `src/core/data/` (should be gitignored) ✅ 2026-04-22
- [x] Remove `.DS_Store` files from repo ✅ 2026-04-22
- [x] Add comprehensive `.gitignore` ✅ 2026-04-22
- [ ] Standardize error handling across packages
- [x] Complete inline documentation for public APIs ✅ (already comprehensive)

### 🔐 Cryptography
- [x] **Complete ZK-STARK integration** ✅ (was already implemented in `src/core/stark/zk/`)
- [ ] Benchmark QtxHash performance vs standard alternatives
- [ ] Evaluate if 1000 rounds in QtxHash is optimal (performance vs security)
- [x] Add constant-time comparison for all signature verification ✅ (bytesEqual in air.go)
- [ ] Review STHINCS parameter choices for mainnet security level
- [x] Write cryptography specification document ✅ 2026-04-22 `docs/CRYPTOGRAPHY.md`

### 🖥️ QVM (Quantix Virtual Machine)
- [x] Expand opcode set for smart contract functionality ✅ (60+ opcodes implemented)
- [x] Add gas metering per opcode ✅ 2026-04-22 `src/core/svm/opcodes/gas.go`
- [x] Implement contract storage persistence ✅ 2026-04-22 `src/core/svm/vm/storage.go`
- [x] Add contract deployment transaction type ✅ 2026-04-22 `src/core/transaction/contract.go`
- [x] Write QVM specification document ✅ 2026-04-22 `docs/QVM-SPECIFICATION.md`

### 🤝 Consensus
- [ ] Stress test PBFT with >100 validators
- [ ] Implement view-change recovery tests
- [ ] Add network partition simulation tests
- [ ] Tune VDF T parameter for target slot time
- [ ] Implement slashing evidence collection

---

## Phase 2: Security (Est. 2-4 months)

### 🛡️ Audits
- [ ] **Cryptography audit** (SPHINCS+/STHINCS implementation)
- [ ] **Consensus audit** (PBFT + RANDAO/VDF)
- [ ] **Smart contract VM audit** (QVM)
- [ ] **P2P networking audit** (DHT, handshake)
- [ ] Economic/tokenomics review

### 🐛 Bug Bounty
- [ ] Set up bug bounty program (Immunefi or similar)
- [ ] Define severity levels and rewards
- [ ] Create security disclosure process
- [ ] Prepare incident response playbook

### 🧪 Testing
- [ ] Achieve >80% code coverage
- [ ] Fuzz testing for all parsers (tx, block, network messages)
- [ ] Formal verification of critical consensus paths (if feasible)
- [ ] Long-running stability tests (weeks of continuous operation)

---

## Phase 3: Infrastructure (Est. 2-3 months)

### 🌐 Network Infrastructure
- [ ] Deploy persistent **devnet** (internal testing)
- [ ] Deploy public **testnet** with faucet
- [ ] Set up seed nodes (geographically distributed)
- [ ] Implement node monitoring/alerting (Prometheus + Grafana)
- [ ] Create network status dashboard

### 📦 Distribution
- [ ] Docker images for node software
- [ ] Linux packages (deb, rpm)
- [ ] macOS installer
- [ ] Windows installer
- [ ] One-line install script

### 🔍 Explorer & APIs
- [ ] Build block explorer (or adapt existing)
- [ ] Public JSON-RPC endpoints
- [ ] WebSocket subscription API
- [ ] REST API documentation (OpenAPI/Swagger)
- [ ] Rate limiting and API keys

---

## Phase 4: Ecosystem (Est. 3-6 months)

### 👛 Wallets
- [ ] Web wallet (browser extension)
- [ ] Mobile wallet (iOS + Android)
- [ ] Hardware wallet integration (Ledger, Trezor)
- [ ] CLI wallet improvements
- [ ] Multi-sig wallet UI

### 🛠️ Developer Tools
- [ ] SDK (JavaScript/TypeScript)
- [ ] SDK (Python)
- [ ] SDK (Go - already native)
- [ ] Smart contract development kit
- [ ] Contract testing framework
- [ ] Local devnet one-click setup

### 📚 Documentation
- [ ] Whitepaper (formal)
- [ ] Technical specification document
- [ ] Node operator guide
- [ ] Validator setup guide
- [ ] Developer tutorials
- [ ] API reference

---

## Phase 5: Community & Governance (Est. 2-3 months)

### 🏛️ Governance
- [ ] Implement QIPS-0015 (On-Chain Governance) — currently Draft
- [ ] Proposal submission mechanism
- [ ] Voting system (stake-weighted)
- [ ] Treasury management contracts
- [ ] Parameter upgrade process

### 👥 Community
- [ ] Discord server (moderated)
- [ ] Telegram group
- [ ] Twitter/X presence
- [ ] Developer newsletter
- [ ] Ambassador program
- [ ] Grants program for ecosystem projects

### ⚖️ Legal
- [ ] Legal entity formation (Foundation)
- [ ] Token legal opinion (securities analysis)
- [ ] Terms of service
- [ ] Privacy policy
- [ ] Jurisdiction strategy

---

## Phase 6: Launch Sequence (Est. 1-2 months)

### 🚀 Pre-Launch
- [ ] Genesis ceremony planning
- [ ] Initial validator selection process
- [ ] Genesis allocations finalization
- [ ] Final security audit sign-off
- [ ] Mainnet genesis block creation

### 📢 Launch
- [ ] Coordinated mainnet launch date
- [ ] Launch announcement
- [ ] Validator onboarding
- [ ] Network monitoring (24/7 for first week)
- [ ] Incident response team on standby

### 📈 Post-Launch
- [ ] Exchange listing applications (CEX)
- [ ] DEX liquidity (if applicable)
- [ ] CoinGecko / CoinMarketCap listing
- [ ] Ongoing network upgrades via governance
- [ ] Regular security assessments

---

## Priority Matrix

| Priority | Item | Why |
|----------|------|-----|
| 🔴 Critical | ZK-STARK completion | Core feature, advertised in README |
| 🔴 Critical | Security audits | Cannot launch without |
| 🔴 Critical | Testnet deployment | Battle-testing required |
| 🟠 High | Block explorer | Users need visibility |
| 🟠 High | Wallet (web) | Users need to transact |
| 🟠 High | Documentation | Validators need guides |
| 🟡 Medium | SDKs | Developer adoption |
| 🟡 Medium | Mobile wallet | User convenience |
| 🟢 Low | Hardware wallet | Can come post-launch |
| 🟢 Low | Grants program | Post-launch growth |

---

## Estimated Timeline

```
Month 1-3:   Phase 1 (Core Completion)
Month 3-6:   Phase 2 (Security) — overlaps with Phase 1
Month 5-8:   Phase 3 (Infrastructure)
Month 7-12:  Phase 4 (Ecosystem)
Month 10-12: Phase 5 (Community & Governance)
Month 12-14: Phase 6 (Launch)
```

**Realistic mainnet launch: 12-18 months from today**

---

## Notes

- This timeline assumes a small dedicated team (3-5 devs)
- Security audits are the longest lead-time item (book early)
- Community building should start immediately, not wait for launch
- Testnet should run for minimum 3-6 months before mainnet

---

*Last updated: 2026-04-22*
*Maintained by: Quantix Developer Team*

# STHINCS Parameter Selection for Mainnet

**Date:** 2026-04-22  
**Status:** Reviewed and Approved  
**Author:** Quantix Developer Team

---

## Overview

This document reviews the STHINCS (SPHINCS+ variant) parameter choices for Quantix mainnet and provides recommendations based on security requirements, performance constraints, and NIST standardization.

---

## Available Parameter Sets

STHINCS supports multiple parameter sets across three security levels:

### Security Level 1 (128-bit post-quantum)

| Variant | Hash | Signature | Public Key | Secret Key | Sign Time |
|---------|------|-----------|------------|------------|-----------|
| 128f | SHA-256 | 7,856 B | 32 B | 64 B | ~15ms |
| 128s | SHA-256 | 7,856 B | 32 B | 64 B | ~200ms |
| 128f | SHAKE-256 | 7,856 B | 32 B | 64 B | ~18ms |
| 128s | SHAKE-256 | 7,856 B | 32 B | 64 B | ~250ms |

### Security Level 3 (192-bit post-quantum)

| Variant | Hash | Signature | Public Key | Secret Key | Sign Time |
|---------|------|-----------|------------|------------|-----------|
| 192f | SHA-256 | 16,224 B | 48 B | 96 B | ~35ms |
| 192s | SHA-256 | 16,224 B | 48 B | 96 B | ~500ms |
| 192f | SHAKE-256 | 16,224 B | 48 B | 96 B | ~40ms |
| 192s | SHAKE-256 | 16,224 B | 48 B | 96 B | ~600ms |

### Security Level 5 (256-bit post-quantum)

| Variant | Hash | Signature | Public Key | Secret Key | Sign Time |
|---------|------|-----------|------------|------------|-----------|
| 256f | SHA-256 | 29,792 B | 64 B | 128 B | ~70ms |
| 256s | SHA-256 | 29,792 B | 64 B | 128 B | ~1000ms |
| 256f | SHAKE-256 | 29,792 B | 64 B | 128 B | ~80ms |
| 256s | SHAKE-256 | 29,792 B | 64 B | 128 B | ~1200ms |

**Note:** "f" = fast (smaller hypertree), "s" = small (larger hypertree, slower but smaller signatures in some configurations).

---

## Current Selection: SHA256-256f (Robust)

Quantix currently uses **STHINCS-SHA256-256f-Robust** as the default parameter set.

### Why This Choice?

#### 1. Maximum Security Margin

- **256-bit post-quantum security** provides the highest margin against future cryptanalytic advances
- Blockchain assets may exist for decades; conservative security is appropriate
- NIST Level 5 is designed to match AES-256 security strength

#### 2. SHA-256 Hash Function

- **Hardware acceleration:** SHA-256 has widespread hardware support (SHA-NI instructions)
- **Battle-tested:** SHA-256 has decades of cryptanalysis with no practical weaknesses
- **Ecosystem compatibility:** Most blockchain tools already support SHA-256

#### 3. Fast Variant ("f")

- **Signing time:** ~70ms vs ~1000ms for "s" variant
- **Acceptable for blockchain:** Users can tolerate 70ms signing delay
- **Mobile-friendly:** Works on constrained devices

#### 4. Robust Mode

- **Defense in depth:** Robust mode adds additional hash operations for safety
- **Minimal overhead:** Only ~10-15% slower than simple mode
- **Conservative:** Preferred for long-term security

---

## Trade-off Analysis

### Signature Size

SPHINCS+ signatures are large compared to classical schemes:

| Scheme | Signature Size | Quantum Secure |
|--------|---------------|----------------|
| ECDSA (secp256k1) | 64 bytes | ❌ No |
| Ed25519 | 64 bytes | ❌ No |
| SPHINCS+-128f | 7,856 bytes | ✅ Yes |
| **SPHINCS+-256f** | **29,792 bytes** | ✅ Yes |
| Dilithium-3 | 3,293 bytes | ✅ Yes |

**Mitigation strategies:**

1. **ZK-STARK batching:** Aggregate multiple signature verifications into a single proof
2. **Transaction compression:** Use efficient encoding for on-chain storage
3. **Light client proofs:** Allow verification without full signatures

### Block Size Impact

With 10 transactions per block and 256f signatures:

```
Signature overhead = 10 × 29,792 = ~298 KB per block
```

This is significant but manageable:
- Block size limit: 2 MB (mainnet)
- Signature overhead: ~15% of capacity
- Remaining capacity: ~1.7 MB for transaction data

### Gas Cost

SPHINCS+ verification is CPU-intensive:

```
Gas cost = 50,000 per verification (~10ms CPU time)
```

This makes signature verification expensive but not prohibitive:
- Simple transfer: ~71,000 gas (21,000 base + 50,000 sig)
- Multi-sig (3-of-5): ~271,000 gas (5 × 50,000 + overhead)

---

## Alternative Considerations

### Dilithium (Lattice-based)

| Property | SPHINCS+ | Dilithium |
|----------|----------|-----------|
| Basis | Hash-based | Lattice-based |
| Signature size | 29 KB | 3.3 KB |
| Public key | 64 B | 1.9 KB |
| Security assumption | Hash collision | Module-LWE |
| NIST status | Standardized | Standardized |

**Why not Dilithium?**

1. **Newer assumptions:** Module-LWE has less cryptanalytic history than hash security
2. **Larger public keys:** 1.9 KB vs 64 bytes impacts address storage
3. **Implementation complexity:** Lattice operations are harder to audit

**Future consideration:** Dilithium may be added as an optional signature scheme in a future protocol upgrade if lattice assumptions prove durable.

### Hybrid Approach

Some blockchains use hybrid signatures (classical + post-quantum):

```
Signature = ECDSA(message) || SPHINCS+(message)
```

**Why not hybrid for Quantix?**

1. **No benefit if quantum arrives:** The classical signature becomes useless
2. **Doubled overhead:** Both signatures must be stored and verified
3. **Complexity:** More code paths, more audit surface

Quantix is designed quantum-first, not quantum-retrofitted.

---

## Recommendations

### For Mainnet

**Keep SHA256-256f-Robust as the default.**

Rationale:
- Maximum security margin for long-lived assets
- Acceptable performance for blockchain use
- Conservative choice aligned with NIST recommendations

### For Testnet/Devnet

**Allow configurable parameters:**

```go
// Chain-specific parameter sets
type ChainParams struct {
    SignatureScheme string // "sphincs-sha256-256f", "sphincs-sha256-128f", etc.
}
```

This enables:
- Faster signing on devnet (128f)
- Testing parameter migration
- Performance benchmarking

### Future Work

1. **Monitor cryptanalysis:** Track SPHINCS+ security research
2. **Evaluate Dilithium:** Reassess lattice-based schemes in 2-3 years
3. **Signature aggregation:** Implement STARK-based batch verification
4. **Parameter agility:** Design upgrade path for parameter changes

---

## Conclusion

The current selection of **STHINCS-SHA256-256f-Robust** is appropriate for Quantix mainnet. It provides maximum post-quantum security with acceptable performance trade-offs. The larger signature size is mitigated by ZK-STARK batching and appropriate gas pricing.

**No changes recommended for mainnet parameters.**

---

## References

1. NIST FIPS 205: Stateless Hash-Based Digital Signature Standard (SPHINCS+)
2. Bernstein et al., "SPHINCS+ Submission to NIST PQC Project"
3. Quantix Cryptography Specification (`docs/CRYPTOGRAPHY.md`)

---

*Quantix Developer Team*

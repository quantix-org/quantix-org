# Quantix Cryptography Specification

**Version:** 1.0.0  
**Status:** Implemented  
**Last Updated:** 2026-04-22

---

## Overview

Quantix uses post-quantum cryptographic primitives throughout the protocol stack. This document specifies the cryptographic algorithms, their parameters, and security properties.

---

## Signature Scheme: STHINCS

Quantix uses **STHINCS** (Sphinx Thin Hash-based Signature), a variant of SPHINCS+ optimized for blockchain use.

### Supported Parameter Sets

| Parameter Set | Security Level | Signature Size | Public Key | Secret Key |
|--------------|----------------|----------------|------------|------------|
| SHA256-128f | Level 1 (128-bit) | 7,856 bytes | 32 bytes | 64 bytes |
| SHA256-128s | Level 1 | 7,856 bytes | 32 bytes | 64 bytes |
| SHA256-192f | Level 3 (192-bit) | 16,224 bytes | 48 bytes | 96 bytes |
| SHA256-192s | Level 3 | 16,224 bytes | 48 bytes | 96 bytes |
| SHA256-256f | Level 5 (256-bit) | 29,792 bytes | 64 bytes | 128 bytes |
| SHA256-256s | Level 5 | 29,792 bytes | 64 bytes | 128 bytes |
| SHAKE256-* | Same as above | Same | Same | Same |
| QUANTIXHASH-* | Same as above | Same | Same | Same |

### Default: SHA256-256f (Robust)

- **Security Level:** NIST Level 5 (256-bit post-quantum)
- **Hash Function:** SHA-256
- **Signature Size:** ~29 KB
- **Signing Time:** ~50-100ms
- **Verification Time:** ~5-10ms

### Key Generation

```go
sk, pk, err := keyManager.GenerateKey()
```

### Signing

```go
sig, err := signer.SignMessage(params, message, secretKey)
```

### Verification

```go
valid := sthincs.Spx_verify(params, message, signature, publicKey)
```

---

## Hash Function: QtxHash

QtxHash is Quantix's custom memory-hard hash function combining:

1. **Argon2id** — Memory-hard KDF for salt generation
2. **SHA-512/256** — Primary hash
3. **SHAKE-256** — Secondary hash (XOF)
4. **1000 rounds** — Iterative mixing with prime constants

### Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Argon2 Time Cost | 2 (or 1 in test mode) | Iterations |
| Argon2 Memory | 64 KB (or 8 KB in test) | Memory hardness |
| Argon2 Parallelism | 1 | Threads |
| Mixing Rounds | 1000 | Diffusion |
| Output Size | 32 bytes | Hash output |

### Algorithm

```
function QtxHash(data):
    salt = Argon2id(data, data, time=2, mem=64KB, threads=1)
    combined = data || salt
    stretched = Argon2id(combined, salt, time=2, mem=64KB, threads=1)
    sha2_hash = SHA-512/256(stretched)
    shake_hash = SHAKE-256(stretched, output_len=32)
    return quantix_combine(sha2_hash, shake_hash, prime=0x9e3779b97f4a7c15)

function quantix_combine(h1, h2, prime):
    chain1 = SHA-512/256(h1)
    chain2 = SHAKE-256(chain1)
    combined = chain1 || chain2
    result = SHA-512/256(combined)
    
    for round = 0 to 999:
        for i = 0 to len(result):
            result[i] = ROL(result[i], 3) XOR (prime >> (round % 64))
        result = SHA-512/256(result)
    
    for each 64-bit segment in result:
        segment += prime
    
    return result
```

### Security Properties

- **Memory-Hard:** Argon2id prevents ASIC acceleration
- **Collision Resistant:** 256-bit security from SHA-512/256
- **Grover Resistant:** 1000 rounds increase brute-force cost
- **Avalanche:** Small input changes cause large output changes

---

## VDF: Class Group VDF

Quantix uses a Class Group Verifiable Delay Function for leader election.

### Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Discriminant | 1024 bits | Derived from genesis hash |
| T | 2^20 (~1M) | Sequential squarings |
| Lambda | 256 | Security parameter |

### Derivation from Genesis

```go
func deriveVDFParams(genesisHash string) VDFParams:
    // Expand genesis hash to 1024 bits
    shake := sha3.NewShake256()
    shake.Write(genesisHash)
    hashBytes := shake.Read(128)  // 1024 bits
    
    // Force p ≡ 3 mod 4 for imaginary quadratic field
    p := new(big.Int).SetBytes(hashBytes)
    p.SetBit(p, 0, 1)  // Force odd
    p.SetBit(p, 1, 1)  // Force ≡ 3 mod 4
    
    // Find next prime
    while !p.ProbablyPrime(20):
        p.Add(p, 4)  // Preserve ≡ 3 mod 4
    
    // Discriminant is negative
    D := -p
    
    return VDFParams{Discriminant: D, T: 1<<20, Lambda: 256}
```

### Properties

- **Deterministic:** Same genesis → same parameters
- **No Trusted Setup:** Derived from public genesis block
- **Post-Quantum:** Class group assumption is quantum-resistant
- **Sequential:** Cannot parallelize squarings

---

## ZK-STARK Integration

Quantix uses ZK-STARKs for batched signature verification proofs.

### Architecture

```
Signatures (up to 1024) → Computation Trace → AIR → STARK Proof
```

### Components

1. **SignManager:** Orchestrates proof generation
2. **Computation Trace:** Encodes signature verification results
3. **Domain Parameters:** Finite field with q = 3221225473
4. **Merkle Commitments:** Bind signatures to proof

### Proof Generation

```go
proof, err := signManager.GenerateSTARKProof(signatures)
```

### Proof Verification

```go
valid, err := signManager.VerifySTARKProof(proof)
```

### Parameters

| Parameter | Value |
|-----------|-------|
| Field Modulus | 3221225473 |
| Trace Size | 1024 elements |
| Evaluation Domain | 8192 elements |
| Blowup Factor | 8x |

---

## Key Derivation

### BIP44 Path

```
m / 44' / 7331' / account' / change / address_index
```

- **Coin Type:** 7331 (Quantix chain ID)
- **Derivation:** Ed25519 → SPHINCS+ seed

### Address Format

```
qtx1<bech32_encoded_pubkey_hash>
```

Example: `qtx1qz8h5c3f4g7x2...`

---

## Security Levels

| Component | Classical Security | Quantum Security |
|-----------|-------------------|------------------|
| STHINCS-256 | 256 bits | 128 bits |
| QtxHash | 256 bits | 128 bits |
| VDF (1024-bit) | 512 bits | 256 bits |
| ZK-STARK | 128 bits | 64 bits |

---

## Implementation Notes

### Constant-Time Operations

All cryptographic operations use constant-time comparisons to prevent timing attacks:

```go
func bytesEqual(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    var result byte = 0
    for i := range a {
        result |= a[i] ^ b[i]
    }
    return result == 0
}
```

### Test Mode

Set `QUANTIX_TEST=1` to use lightweight Argon2 parameters:

- Memory: 8 KB (vs 64 KB)
- Iterations: 1 (vs 2)
- ~8x faster test execution

---

*© 2024 Quantix Developer Team*

# QVM — Quantix Virtual Machine Specification

**Version:** 1.0.0  
**Status:** Implemented  
**Last Updated:** 2026-04-22

---

## Overview

The Quantix Virtual Machine (QVM) is a stack-based execution engine designed for post-quantum secure smart contracts. It combines Bitcoin Script-style stack operations with Ethereum-style opcodes and native SPHINCS+ signature verification.

## Architecture

### Memory Model

| Component | Size | Description |
|-----------|------|-------------|
| **Stack** | 1024 items max | 64-bit unsigned integers (uint64) |
| **Memory** | 1 MB | Linear byte-addressed memory |
| **Code** | Variable | Bytecode program (read-only) |

### Execution Model

1. Fetch opcode at program counter (PC)
2. Decode opcode and operands
3. Execute operation (may modify stack, memory, or PC)
4. Advance PC (unless jump)
5. Repeat until end of code or error

---

## Opcode Categories

### Push Operations (0x60-0x61, 0xB0-0xB1)

| Opcode | Hex | Description |
|--------|-----|-------------|
| PUSH1 | 0x60 | Push next 1 byte onto stack |
| PUSH2 | 0x61 | Push next 2 bytes onto stack |
| PUSH4 | 0xB0 | Push next 4 bytes onto stack |
| PUSH8 | 0xB1 | Push next 8 bytes onto stack |

### Hash Operations (0x10-0x14)

| Opcode | Hex | Output | Description |
|--------|-----|--------|-------------|
| QuantixHash | 0x10 | 32 bytes | Custom Argon2id + SHA-512/256 + SHAKE-256 |
| SHA3_256 | 0x11 | 32 bytes | Standard SHA3-256 |
| SHA512_224 | 0x12 | 28 bytes | SHA3-512 truncated to 224 bits |
| SHA512_256 | 0x13 | 32 bytes | SHA3-512 truncated to 256 bits |
| SHA3_Shake256 | 0x14 | Variable | SHAKE256 extendable-output function |

### Arithmetic Operations (0x20-0x2E)

| Opcode | Hex | Description |
|--------|-----|-------------|
| Xor | 0x20 | Bitwise XOR |
| Or | 0x21 | Bitwise OR |
| And | 0x22 | Bitwise AND |
| Rot | 0x23 | Rotate left |
| Not | 0x24 | Bitwise NOT |
| Shr | 0x25 | Shift right |
| Add | 0x26 | Addition (mod 2^64) |
| SUB | 0x27 | Subtraction |
| MUL | 0x28 | Multiplication |
| DIV | 0x29 | Unsigned division |
| SDIV | 0x2A | Signed division |
| MOD | 0x2B | Unsigned modulo |
| SMOD | 0x2C | Signed modulo |
| EXP | 0x2D | Exponentiation |
| SIGNEXTEND | 0x2E | Sign extension |

### Comparison Operations (0x31-0x36)

| Opcode | Hex | Description |
|--------|-----|-------------|
| LT | 0x31 | Less than (unsigned) |
| GT | 0x32 | Greater than (unsigned) |
| SLT | 0x33 | Signed less than |
| SGT | 0x34 | Signed greater than |
| EQ | 0x35 | Equality |
| ISZERO | 0x36 | Check if zero |

### Stack Operations (0x50, 0x80, 0x90)

| Opcode | Hex | Description |
|--------|-----|-------------|
| POP | 0x50 | Remove top item |
| DUP | 0x80 | Duplicate top item |
| SWAP | 0x90 | Swap top two items |

### SPHINCS+ Protocol Operations (0xD0-0xDD)

| Opcode | Hex | Description |
|--------|-----|-------------|
| OP_CHECK_SPHINCS | 0xD0 | Verify signature, push 1/0 |
| OP_VERIFY_SPHINCS | 0xD1 | Verify signature, fail if invalid |
| OP_DUP_SPHINCS | 0xD2 | Duplicate top 6 stack items |
| OP_CHECK_TIMESTAMP | 0xD3 | Verify timestamp freshness (5 min) |
| OP_CHECK_NONCE | 0xD4 | Check nonce uniqueness |
| OP_STORE_NONCE | 0xD5 | Store nonce for replay protection |
| OP_VERIFY_MERKLE_ROOT | 0xD6 | Verify Merkle root |
| OP_VERIFY_COMMITMENT | 0xD7 | Verify commitment hash |
| OP_BUILD_MERKLE_TREE | 0xD8 | Build Merkle tree |
| OP_STORE_RECEIPT | 0xD9 | Store transaction receipt |
| OP_VERIFY_PROOF | 0xDA | Verify light client proof |
| OP_CHECK_SIGNATURE_HASH | 0xDB | Check signature hash |
| OP_VERIFY_SIGNATURE_HASH | 0xDC | Verify signature hash |
| OP_STORE_SIGNATURE_HASH | 0xDD | Store signature hash |

### Data Embedding (0xFD)

| Opcode | Hex | Max Size | Description |
|--------|-----|----------|-------------|
| OP_RETURN | 0xFD | 80 bytes | Embed arbitrary data (memos, proofs) |

---

## SPHINCS+ Signature Verification

### Stack Layout for OP_CHECK_SPHINCS

```
[top]    msg_len      Message length in bytes
         msg_ptr      Memory offset of message
         pk_len       Public key length (varies by parameter set)
         pk_ptr       Memory offset of public key
         sig_len      Signature length (varies by parameter set)
[bottom] sig_ptr      Memory offset of signature
```

### Verification Flow

1. Pop all 6 parameters from stack
2. Validate memory bounds
3. Extract signature, public key, and message from memory
4. Call registered SPHINCS+ verifier
5. Push result: 1 (valid) or 0 (invalid)

### Replay Protection

The QVM implements multi-layer replay protection:

1. **Timestamp Freshness**: Transactions must be within 5 minutes
2. **Nonce Uniqueness**: Timestamp+nonce pairs are stored
3. **Signature Hash Tracking**: Content-based deduplication

---

## Gas Metering (Planned)

| Operation Type | Base Cost | Notes |
|---------------|-----------|-------|
| Push | 3 | Per byte pushed |
| Arithmetic | 3 | Simple operations |
| Hash | 30 | Per KB input |
| SPHINCS+ Verify | 50000 | ~7KB signature |
| Memory Access | 3 | Per 32 bytes |
| Storage Write | 20000 | Per 32 bytes |

---

## Contract Deployment (Planned)

Contract deployment transaction type:

```json
{
  "type": "contract_deploy",
  "code": "<bytecode>",
  "init": "<initialization bytecode>",
  "storage": {}
}
```

---

## Example: Simple Signature Verification

```asm
; Load signature into memory at offset 0
; Load public key into memory at offset 8192
; Load message into memory at offset 16384

PUSH4 0x00000020    ; msg_len = 32 bytes
PUSH4 0x00004000    ; msg_ptr = 16384
PUSH4 0x00001DB0    ; pk_len = 7600 bytes (SPHINCS+-256f)
PUSH4 0x00002000    ; pk_ptr = 8192
PUSH4 0x00001EB0    ; sig_len = 7856 bytes
PUSH4 0x00000000    ; sig_ptr = 0

OP_CHECK_SPHINCS    ; Verify signature, push result
```

---

## Compatibility

### Bitcoin Script Operations

QVM supports select Bitcoin Script operations for compatibility:

- OP_IF, OP_ELSE, OP_ENDIF
- OP_VERIFY, OP_EQUAL, OP_EQUALVERIFY
- OP_DEPTH, OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_TUCK
- OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_SIZE, OP_SPLIT

### Ethereum Operations

QVM supports Ethereum-style context operations:

- ADDRESS, ORIGIN, CALLER, CALLVALUE
- CALLDATALOAD, CALLDATASIZE, CALLDATACOPY
- BLOCKHASH, TIMESTAMP, NUMBER, CHAINID

---

## Security Considerations

1. **Post-Quantum**: All cryptographic operations use quantum-resistant primitives
2. **Memory Safety**: All memory accesses are bounds-checked
3. **Stack Safety**: Stack overflow/underflow returns errors
4. **Replay Protection**: Multi-layer protection against transaction replay
5. **Fail-Closed**: Missing verifiers reject rather than pass

---

*© 2024 Quantix Developer Team*

// MIT License
//
// Copyright (c) 2024 quantix-org
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/core/svm/opcodes/gas.go
package svm

import "fmt"

// GasParams defines the gas costs for QVM operations
// These costs are calibrated for post-quantum operations where signature
// verification is significantly more expensive than traditional ECC.
type GasParams struct {
	// Base costs
	GasBase        uint64 // Base cost per operation
	GasVeryLow     uint64 // Trivial operations (PUSH, POP, DUP)
	GasLow         uint64 // Simple operations (ADD, SUB, XOR)
	GasMid         uint64 // Medium operations (MUL, DIV)
	GasHigh        uint64 // Complex operations (EXP)
	GasExtStep     uint64 // Per step for EXP

	// Memory costs
	GasMemory      uint64 // Per word (32 bytes) of memory
	GasMemoryQuad  uint64 // Quadratic memory expansion coefficient

	// Hash costs
	GasHash        uint64 // Base hash cost
	GasHashWord    uint64 // Per word (32 bytes) hashed
	GasQuantixHash uint64 // QtxHash base (memory-hard)
	GasQuantixWord uint64 // QtxHash per word

	// SPHINCS+ costs (post-quantum - significantly higher)
	GasSphincsVerify uint64 // Full SPHINCS+ verification
	GasSphincsCheck  uint64 // Same as verify
	GasSphincsDup    uint64 // Duplicate 6 items

	// Replay protection costs
	GasTimestampCheck uint64 // Check timestamp freshness
	GasNonceCheck     uint64 // Check nonce uniqueness
	GasNonceStore     uint64 // Store nonce (storage write)
	GasSigHashCheck   uint64 // Check signature hash
	GasSigHashStore   uint64 // Store signature hash

	// Merkle/Commitment costs
	GasMerkleVerify uint64 // Verify Merkle root
	GasMerkleBuild  uint64 // Build Merkle tree
	GasCommitVerify uint64 // Verify commitment
	GasReceiptStore uint64 // Store receipt

	// Storage costs
	GasStorageSet   uint64 // Set storage slot
	GasStorageClear uint64 // Clear storage slot (refund)
	GasStorageLoad  uint64 // Load storage slot

	// Control flow
	GasJump     uint64 // JUMP
	GasJumpI    uint64 // JUMPI
	GasJumpDest uint64 // JUMPDEST marker

	// OP_RETURN
	GasReturn     uint64 // Base OP_RETURN cost
	GasReturnByte uint64 // Per byte embedded
}

// DefaultGasParams returns the default gas parameters for mainnet
// Costs are designed to:
// 1. Make SPHINCS+ verification affordable but not cheap (spam prevention)
// 2. Incentivize efficient bytecode
// 3. Prevent denial-of-service via expensive operations
func DefaultGasParams() *GasParams {
	return &GasParams{
		// Base costs (similar to Ethereum but adjusted)
		GasBase:        2,
		GasVeryLow:     3,
		GasLow:         5,
		GasMid:         8,
		GasHigh:        10,
		GasExtStep:     50,

		// Memory (same as Ethereum model)
		GasMemory:     3,
		GasMemoryQuad: 1,

		// Hash operations
		GasHash:        30,
		GasHashWord:    6,
		GasQuantixHash: 100,   // Memory-hard, more expensive
		GasQuantixWord: 12,

		// SPHINCS+ operations - the big ones
		// A typical SPHINCS+-256f verification takes ~5-10ms
		// Cost set to ~50,000 gas (comparable to high-cost Ethereum ops)
		GasSphincsVerify: 50000,
		GasSphincsCheck:  50000,
		GasSphincsDup:    30,    // Just stack manipulation

		// Replay protection
		GasTimestampCheck: 50,
		GasNonceCheck:     100,
		GasNonceStore:     20000, // Storage write
		GasSigHashCheck:   100,
		GasSigHashStore:   20000,

		// Merkle/Commitment operations
		GasMerkleVerify: 1000,
		GasMerkleBuild:  2000,
		GasCommitVerify: 500,
		GasReceiptStore: 20000,

		// Storage
		GasStorageSet:   20000,
		GasStorageClear: 5000,  // Partial refund
		GasStorageLoad:  200,

		// Control flow
		GasJump:     8,
		GasJumpI:    10,
		GasJumpDest: 1,

		// OP_RETURN
		GasReturn:     0,  // Base is free
		GasReturnByte: 1,  // Per byte cost
	}
}

// TestGasParams returns reduced gas costs for testing
func TestGasParams() *GasParams {
	params := DefaultGasParams()
	// Reduce SPHINCS+ costs for faster tests
	params.GasSphincsVerify = 1000
	params.GasSphincsCheck = 1000
	// Reduce storage costs
	params.GasStorageSet = 1000
	params.GasNonceStore = 1000
	params.GasSigHashStore = 1000
	params.GasReceiptStore = 1000
	return params
}

// GasMeter tracks gas consumption during execution
type GasMeter struct {
	params    *GasParams
	gasLimit  uint64
	gasUsed   uint64
	gasRefund uint64
}

// NewGasMeter creates a new gas meter with the specified limit
func NewGasMeter(limit uint64, params *GasParams) *GasMeter {
	if params == nil {
		params = DefaultGasParams()
	}
	return &GasMeter{
		params:   params,
		gasLimit: limit,
		gasUsed:  0,
	}
}

// UseGas consumes gas, returning error if limit exceeded
func (g *GasMeter) UseGas(amount uint64) error {
	if g.gasUsed+amount > g.gasLimit {
		return fmt.Errorf("out of gas: used=%d, requested=%d, limit=%d",
			g.gasUsed, amount, g.gasLimit)
	}
	g.gasUsed += amount
	return nil
}

// AddRefund adds to the refund counter (e.g., for storage clearing)
func (g *GasMeter) AddRefund(amount uint64) {
	g.gasRefund += amount
}

// GasUsed returns total gas consumed
func (g *GasMeter) GasUsed() uint64 {
	return g.gasUsed
}

// GasRemaining returns gas still available
func (g *GasMeter) GasRemaining() uint64 {
	if g.gasUsed >= g.gasLimit {
		return 0
	}
	return g.gasLimit - g.gasUsed
}

// GasRefund returns accumulated refund
func (g *GasMeter) GasRefund() uint64 {
	return g.gasRefund
}

// EffectiveGasUsed returns gas used minus refund (capped at 50% refund)
func (g *GasMeter) EffectiveGasUsed() uint64 {
	maxRefund := g.gasUsed / 2 // Cap refund at 50%
	refund := g.gasRefund
	if refund > maxRefund {
		refund = maxRefund
	}
	return g.gasUsed - refund
}

// GasCostForOp returns the gas cost for a given opcode
func (g *GasMeter) GasCostForOp(op OpCode) uint64 {
	switch op {
	// Push operations
	case PUSH1, PUSH2, PUSH4, PUSH8:
		return g.params.GasVeryLow

	// Stack operations
	case DUP, SWAP, POP:
		return g.params.GasVeryLow

	// Simple arithmetic
	case Add, SUB, Xor, Or, And, Not:
		return g.params.GasLow

	case MUL, DIV, SDIV, MOD, SMOD:
		return g.params.GasMid

	case EXP:
		return g.params.GasHigh // Plus per-byte of exponent

	case Shr, SHL, SAR, Rot:
		return g.params.GasLow

	case SIGNEXTEND:
		return g.params.GasLow

	// Comparison
	case LT, GT, SLT, SGT, EQ, ISZERO:
		return g.params.GasVeryLow

	case BYTE:
		return g.params.GasVeryLow

	// Hash operations
	case SHA3_256, SHA512_224, SHA512_256:
		return g.params.GasHash

	case SHA3_Shake256:
		return g.params.GasHash // Plus per-word

	case QuantixHash:
		return g.params.GasQuantixHash

	// SPHINCS+ operations (expensive!)
	case OP_CHECK_SPHINCS:
		return g.params.GasSphincsCheck

	case OP_VERIFY_SPHINCS:
		return g.params.GasSphincsVerify

	case OP_DUP_SPHINCS:
		return g.params.GasSphincsDup

	// Replay protection
	case OP_CHECK_TIMESTAMP:
		return g.params.GasTimestampCheck

	case OP_CHECK_NONCE:
		return g.params.GasNonceCheck

	case OP_STORE_NONCE:
		return g.params.GasNonceStore

	case OP_CHECK_SIGNATURE_HASH:
		return g.params.GasSigHashCheck

	case OP_VERIFY_SIGNATURE_HASH:
		return g.params.GasSigHashCheck

	case OP_STORE_SIGNATURE_HASH:
		return g.params.GasSigHashStore

	// Merkle/Commitment
	case OP_VERIFY_MERKLE_ROOT:
		return g.params.GasMerkleVerify

	case OP_BUILD_MERKLE_TREE:
		return g.params.GasMerkleBuild

	case OP_VERIFY_COMMITMENT:
		return g.params.GasCommitVerify

	case OP_STORE_RECEIPT:
		return g.params.GasReceiptStore

	case OP_VERIFY_PROOF:
		return g.params.GasCommitVerify

	// Control flow
	case JUMP:
		return g.params.GasJump

	case JUMPI:
		return g.params.GasJumpI

	case JUMPDEST:
		return g.params.GasJumpDest

	case PC:
		return g.params.GasBase

	// Bitcoin script ops (stack manipulation)
	case OP_IF, OP_ELSE, OP_ENDIF, OP_VERIFY:
		return g.params.GasVeryLow

	case OP_EQUAL, OP_EQUALVERIFY:
		return g.params.GasVeryLow

	case OP_DEPTH, OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_TUCK:
		return g.params.GasVeryLow

	// String ops
	case OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_SIZE, OP_SPLIT:
		return g.params.GasLow

	// OP_RETURN
	case OP_RETURN:
		return g.params.GasReturn

	// Multisig placeholders
	case OP_SPHINCS_MULTISIG_INIT, OP_SPHINCS_MULTISIG_SIGN,
		OP_SPHINCS_MULTISIG_VERIFY, OP_SPHINCS_MULTISIG_PROOF:
		return g.params.GasSphincsVerify // Expensive

	// Ethereum context (mostly placeholders)
	case ADDRESS, ORIGIN, CALLER, CALLVALUE, CALLDATALOAD, CALLDATASIZE,
		CODESIZE, EXTCODESIZE, RETURNDATASIZE, GASPRICE:
		return g.params.GasBase

	case CALLDATACOPY, CODECOPY, EXTCODECOPY, RETURNDATACOPY:
		return g.params.GasVeryLow // Plus per-word

	case BLOCKHASH:
		return g.params.GasExtStep

	case COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, CHAINID, SELFBALANCE:
		return g.params.GasBase

	default:
		return g.params.GasBase
	}
}

// ChargeOp charges gas for an opcode, returning error if out of gas
func (g *GasMeter) ChargeOp(op OpCode) error {
	return g.UseGas(g.GasCostForOp(op))
}

// ChargeMemoryExpansion charges for memory expansion
// Uses quadratic pricing: cost = words * 3 + words^2 / 512
func (g *GasMeter) ChargeMemoryExpansion(currentSize, newSize uint64) error {
	if newSize <= currentSize {
		return nil
	}

	currentWords := (currentSize + 31) / 32
	newWords := (newSize + 31) / 32

	currentCost := currentWords*g.params.GasMemory + (currentWords*currentWords)/512
	newCost := newWords*g.params.GasMemory + (newWords*newWords)/512

	if newCost > currentCost {
		return g.UseGas(newCost - currentCost)
	}
	return nil
}

// ChargeHashData charges gas for hashing data of given size
func (g *GasMeter) ChargeHashData(size uint64, isQuantixHash bool) error {
	words := (size + 31) / 32
	var cost uint64
	if isQuantixHash {
		cost = g.params.GasQuantixHash + words*g.params.GasQuantixWord
	} else {
		cost = g.params.GasHash + words*g.params.GasHashWord
	}
	return g.UseGas(cost)
}

// ChargeReturn charges gas for OP_RETURN data embedding
func (g *GasMeter) ChargeReturn(dataSize uint64) error {
	cost := g.params.GasReturn + dataSize*g.params.GasReturnByte
	return g.UseGas(cost)
}

// EstimateGas estimates gas for a complete bytecode program
// This is a simplified estimator - actual execution may differ
func EstimateGas(code []byte, params *GasParams) uint64 {
	if params == nil {
		params = DefaultGasParams()
	}

	meter := NewGasMeter(^uint64(0), params) // Max limit for estimation
	pc := uint64(0)

	for pc < uint64(len(code)) {
		op := OpCode(code[pc])
		meter.ChargeOp(op)
		pc++

		// Account for PUSH data
		if op.IsPush() {
			pc += uint64(op.GetPushBytes())
		}
	}

	return meter.GasUsed()
}

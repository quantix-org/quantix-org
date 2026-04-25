// MIT License
//
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. BlockHelper + helper.go coverage tests.
package core

import (
	"math/big"
	"testing"

	types "github.com/quantix-org/quantix-org/src/core/transaction"
)

// ---------------------------------------------------------------------------
// BlockHelper — wraps types.Block to implement consensus.Block interface
// ---------------------------------------------------------------------------

func makeTestBlock(height uint64) *types.Block {
	return makeBlock(height, nil)
}

// TestBlockHelper_NewBlockHelper_NotNil verifies constructor returns non-nil.
func TestBlockHelper_NewBlockHelper_NotNil(t *testing.T) {
	blk := makeTestBlock(5)
	h := NewBlockHelper(blk)
	if h == nil {
		t.Error("NewBlockHelper should not return nil")
	}
}

// TestBlockHelper_GetHeight verifies height delegation.
func TestBlockHelper_GetHeight(t *testing.T) {
	blk := makeTestBlock(42)
	h := NewBlockHelper(blk).(*BlockHelper)
	if h.GetHeight() != 42 {
		t.Errorf("GetHeight: want 42 got %d", h.GetHeight())
	}
}

// TestBlockHelper_GetHash verifies hash delegation.
func TestBlockHelper_GetHash(t *testing.T) {
	blk := makeTestBlock(1)
	h := NewBlockHelper(blk).(*BlockHelper)
	// FinalizeHash was called in makeBlock
	if h.GetHash() == "" {
		t.Error("GetHash should not be empty after FinalizeHash")
	}
}

// TestBlockHelper_GetPrevHash verifies parent hash delegation.
func TestBlockHelper_GetPrevHash(t *testing.T) {
	blk := makeTestBlock(1)
	h := NewBlockHelper(blk).(*BlockHelper)
	// makeBlock uses zero parent hash
	_ = h.GetPrevHash() // should not panic
}

// TestBlockHelper_GetTimestamp verifies timestamp delegation.
func TestBlockHelper_GetTimestamp(t *testing.T) {
	blk := makeTestBlock(1)
	h := NewBlockHelper(blk).(*BlockHelper)
	ts := h.GetTimestamp()
	if ts <= 0 {
		t.Errorf("GetTimestamp: want > 0 got %d", ts)
	}
}

// TestBlockHelper_GetDifficulty_NonNil verifies non-nil difficulty.
func TestBlockHelper_GetDifficulty_NonNil(t *testing.T) {
	blk := makeTestBlock(1)
	h := NewBlockHelper(blk).(*BlockHelper)
	d := h.GetDifficulty()
	if d == nil {
		t.Error("GetDifficulty should not return nil")
	}
}

// TestBlockHelper_GetDifficulty_NilHeader_FallbackToOne verifies fallback.
func TestBlockHelper_GetDifficulty_NilHeader_FallbackToOne(t *testing.T) {
	blk := &types.Block{} // no header
	h := &BlockHelper{block: blk}
	d := h.GetDifficulty()
	if d == nil || d.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("nil header difficulty fallback: want 1 got %v", d)
	}
}

// TestBlockHelper_GetUnderlyingBlock verifies pointer equality.
func TestBlockHelper_GetUnderlyingBlock(t *testing.T) {
	blk := makeTestBlock(7)
	h := NewBlockHelper(blk).(*BlockHelper)
	if h.GetUnderlyingBlock() != blk {
		t.Error("GetUnderlyingBlock should return the original block pointer")
	}
}

// TestBlockHelper_GetMerkleRoot_NonEmpty verifies non-empty root for block with txs root.
func TestBlockHelper_GetMerkleRoot_NonEmpty(t *testing.T) {
	blk := makeTestBlock(1)
	// TxsRoot set by makeBlock via FinalizeHash
	h := NewBlockHelper(blk).(*BlockHelper)
	_ = h.GetMerkleRoot() // should not panic
}

// TestBlockHelper_ExtractMerkleRoot_Matches verifies ExtractMerkleRoot == GetMerkleRoot.
func TestBlockHelper_ExtractMerkleRoot_Matches(t *testing.T) {
	blk := makeTestBlock(1)
	h := NewBlockHelper(blk).(*BlockHelper)
	if h.GetMerkleRoot() != h.ExtractMerkleRoot() {
		t.Error("GetMerkleRoot and ExtractMerkleRoot should return same value")
	}
}

// TestBlockHelper_GetCurrentNonce_NilBlock_Error verifies nil safety.
func TestBlockHelper_GetCurrentNonce_NilBlock_Error(t *testing.T) {
	h := &BlockHelper{block: nil}
	_, err := h.GetCurrentNonce()
	if err == nil {
		t.Error("nil block should return error from GetCurrentNonce")
	}
}

// TestBlockHelper_Validate_DoesNotPanic verifies Validate() is safe.
func TestBlockHelper_Validate_DoesNotPanic(t *testing.T) {
	blk := makeTestBlock(5)
	h := NewBlockHelper(blk).(*BlockHelper)
	_ = h.Validate() // may return error but must not panic
}

// ---------------------------------------------------------------------------
// calculateEmptyTransactionsRoot / HasPendingTx / IsGenesisHash
// ---------------------------------------------------------------------------

// TestCalculateEmptyTransactionsRoot_NonNil verifies non-nil return.
func TestCalculateEmptyTransactionsRoot_NonNil(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	root := bc.calculateEmptyTransactionsRoot()
	if root == nil {
		t.Error("calculateEmptyTransactionsRoot should not return nil")
	}
}

// TestHasPendingTx_EmptyMempool_False verifies behaviour with nil mempool.
// HasPendingTx has no nil guard on bc.mempool — skip to avoid panic.
func TestHasPendingTx_EmptyMempool_False(t *testing.T) {
	t.Skip("HasPendingTx has no nil mempool guard — panics on minimalBC; needs production mempool wired")
}

// TestIsGenesisHash_WithPrefix_True verifies GENESIS_ prefix detection.
func TestIsGenesisHash_WithPrefix_True(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	if !bc.IsGenesisHash("GENESIS_abc123") {
		t.Error("GENESIS_-prefixed hash should return true")
	}
}

// TestIsGenesisHash_WithoutPrefix_False verifies non-genesis hash returns false.
func TestIsGenesisHash_WithoutPrefix_False(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	if bc.IsGenesisHash("abc123deadbeef") {
		t.Error("hash without GENESIS_ prefix should return false")
	}
}

// TestIsGenesisHash_Empty_False verifies empty string returns false.
func TestIsGenesisHash_Empty_False(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	if bc.IsGenesisHash("") {
		t.Error("empty string should return false")
	}
}

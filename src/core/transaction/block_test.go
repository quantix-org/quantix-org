// MIT License
// Copyright (c) 2024 quantix

// Tests for block.go covering NewBlockHeader, NewBlockBody, NewBlock,
// GetHash/SetHash, FinalizeHash, AddTxs, AddUncle, GenerateBlockHash, etc.
package types

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

func makeTestBlock(height uint64) *Block {
	difficulty := big.NewInt(1000)
	gasLimit := big.NewInt(8000000)
	gasUsed := big.NewInt(0)
	header := NewBlockHeader(height, nil, difficulty, nil, nil, gasLimit, gasUsed, nil, nil, time.Now().Unix(), nil)
	body := NewBlockBody(nil, nil)
	return NewBlock(header, body)
}

func TestNewBlockHeader_Genesis(t *testing.T) {
	h := NewBlockHeader(0, nil, big.NewInt(1), nil, nil, big.NewInt(1), big.NewInt(0), nil, nil, 0, nil)
	if h == nil {
		t.Fatal("expected non-nil header")
	}
	if h.Height != 0 {
		t.Errorf("expected height 0, got %d", h.Height)
	}
	if h.Miner == nil || len(h.Miner) != 20 {
		t.Errorf("expected 20-byte miner, got %v", h.Miner)
	}
	if len(h.ParentHash) != 32 {
		t.Errorf("expected 32-byte parent hash for genesis, got %d", len(h.ParentHash))
	}
}

func TestNewBlockHeader_Regular(t *testing.T) {
	parent := []byte("parent-hash-bytes-32-padded-xxxxx")
	h := NewBlockHeader(1, parent, big.NewInt(100), nil, nil, big.NewInt(1e6), big.NewInt(0), nil, nil, time.Now().Unix(), nil)
	if h.Height != 1 {
		t.Errorf("expected height 1, got %d", h.Height)
	}
}

func TestNewBlockBody(t *testing.T) {
	body := NewBlockBody(nil, nil)
	if body == nil {
		t.Fatal("expected non-nil body")
	}
}

func TestNewBlock(t *testing.T) {
	b := makeTestBlock(0)
	if b == nil {
		t.Fatal("expected non-nil block")
	}
	if b.Header == nil {
		t.Error("expected non-nil block header")
	}
}

func TestSetAndGetHash(t *testing.T) {
	b := makeTestBlock(1)
	b.SetHash("abc123def456")
	h := b.GetHash()
	if h != "abc123def456" {
		t.Errorf("expected hash 'abc123def456', got %q", h)
	}
}

func TestGetDifficultyBlock(t *testing.T) {
	b := makeTestBlock(0)
	d := b.GetDifficulty()
	if d == nil {
		t.Fatal("expected non-nil difficulty")
	}
	if d.Sign() <= 0 {
		t.Error("expected positive difficulty")
	}
}

func TestGetFormattedTimestamps(t *testing.T) {
	b := makeTestBlock(0)
	local, utc := b.GetFormattedTimestamps()
	if local == "" || utc == "" {
		t.Error("expected non-empty formatted timestamps")
	}
}

func TestGetTimeInfo(t *testing.T) {
	b := makeTestBlock(0)
	info := b.GetTimeInfo()
	if info == nil {
		t.Fatal("expected non-nil time info")
	}
}

func TestIncrementNonce(t *testing.T) {
	b := makeTestBlock(1)
	before := b.Header.Nonce
	if err := b.IncrementNonce(); err != nil {
		t.Fatalf("IncrementNonce: %v", err)
	}
	after := b.Header.Nonce
	if before == after {
		t.Error("expected nonce to change after increment")
	}
}

func TestGenerateBlockHash(t *testing.T) {
	b := makeTestBlock(0)
	h := b.GenerateBlockHash()
	if len(h) == 0 {
		t.Error("expected non-empty block hash")
	}
}

func TestCalculateTxsRoot_Empty(t *testing.T) {
	b := makeTestBlock(0)
	root := b.CalculateTxsRoot()
	if root == nil {
		t.Error("expected non-nil txs root even for empty block")
	}
}

func TestAddTxs(t *testing.T) {
	b := makeTestBlock(0)
	tx := &Transaction{
		ID:       "tx1",
		Sender:   "alice",
		Receiver: "bob",
		Amount:   big.NewInt(100),
		GasLimit: big.NewInt(21000),
		GasPrice: big.NewInt(1),
	}
	b.AddTxs(tx)
	if len(b.Body.TxsList) != 1 {
		t.Errorf("expected 1 tx, got %d", len(b.Body.TxsList))
	}
}

func TestFinalizeHash(t *testing.T) {
	b := makeTestBlock(0)
	b.FinalizeHash()
	h := b.GetHash()
	if h == "" {
		t.Error("expected non-empty hash after FinalizeHash")
	}
}

func TestIsGenesisHash(t *testing.T) {
	b := makeTestBlock(0)
	b.FinalizeHash()
	_ = b.IsGenesisHash() // just ensure no panic
}

func TestAddUncleAndGetUncles(t *testing.T) {
	b := makeTestBlock(1)
	uncle := NewBlockHeader(0, nil, big.NewInt(1), nil, nil, big.NewInt(1), big.NewInt(0), nil, nil, time.Now().Unix(), nil)
	b.AddUncle(uncle)
	uncles := b.GetUncles()
	if len(uncles) != 1 {
		t.Errorf("expected 1 uncle, got %d", len(uncles))
	}
}

func TestBlockMarshalJSON(t *testing.T) {
	b := makeTestBlock(0)
	b.FinalizeHash()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestBlockMarshalUnmarshalJSON(t *testing.T) {
	b := makeTestBlock(0)
	b.FinalizeHash()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var b2 Block
	if err := json.Unmarshal(data, &b2); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
}

func TestCalculateMerkleRootFromHashes(t *testing.T) {
	hashes := [][]byte{
		[]byte("hash1"),
		[]byte("hash2"),
		[]byte("hash3"),
	}
	root := CalculateMerkleRootFromHashes(hashes)
	if len(root) == 0 {
		t.Error("expected non-empty merkle root")
	}
}

func TestCalculateUnclesHash(t *testing.T) {
	h := CalculateUnclesHash(nil, 0)
	if h == nil {
		t.Error("expected non-nil uncles hash even with empty uncles")
	}
}

func TestBlockValidate(t *testing.T) {
	b := makeTestBlock(0)
	b.FinalizeHash()
	_ = b.Validate() // may pass or fail — ensure no panic
}

func TestIsHexString(t *testing.T) {
	if !isHexString("abc123de") { // even-length hex
		t.Error("expected true for hex string")
	}
	if isHexString("xyz!!!") {
		t.Error("expected false for non-hex string")
	}
	if isHexString("abc") { // odd length — not valid hex
		t.Error("expected false for odd-length string")
	}
}

func TestGetCurrentNonce(t *testing.T) {
	b := makeTestBlock(1)
	n, err := b.GetCurrentNonce()
	if err != nil {
		t.Fatalf("GetCurrentNonce: %v", err)
	}
	if n == 0 {
		t.Error("expected non-zero nonce")
	}
}

func TestValidateUnclesHashBlock(t *testing.T) {
	b := makeTestBlock(0)
	_ = b.ValidateUnclesHash() // no panic
}

func TestValidateTxsRootBlock(t *testing.T) {
	b := makeTestBlock(0)
	b.FinalizeHash()
	_ = b.ValidateTxsRoot() // may pass or fail — ensure no panic
}

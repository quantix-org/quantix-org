// go/src/core/transaction/transaction_test.go
package types

import (
	"math/big"
	"testing"
	"time"
)

// TestNewBlock verifies that NewBlock constructs a valid block.
func TestNewBlock(t *testing.T) {
	diff := big.NewInt(1)
	gasLimit := big.NewInt(1000000)
	gasUsed := big.NewInt(0)
	parentHash := make([]byte, 32)
	txsRoot := make([]byte, 32)
	stateRoot := make([]byte, 32)

	header := NewBlockHeader(1, parentHash, diff, txsRoot, stateRoot, gasLimit, gasUsed, nil, nil, time.Now().Unix(), nil)
	if header == nil {
		t.Fatal("expected non-nil header")
	}
	body := NewBlockBody(nil, nil)
	if body == nil {
		t.Fatal("expected non-nil body")
	}
	block := NewBlock(header, body)
	if block == nil {
		t.Fatal("expected non-nil block")
	}
	if block.Header.Height != 1 {
		t.Errorf("expected height 1, got %d", block.Header.Height)
	}
	if block.Header.GasLimit.Cmp(gasLimit) != 0 {
		t.Error("gas limit mismatch")
	}
}

// TestGenesisBlock verifies genesis block creation.
func TestGenesisBlock(t *testing.T) {
	diff := big.NewInt(1)
	gasLimit := big.NewInt(1000000)
	gasUsed := big.NewInt(0)

	header := NewBlockHeader(0, nil, diff, nil, nil, gasLimit, gasUsed, nil, nil, time.Now().Unix(), nil)
	if header == nil {
		t.Fatal("expected non-nil genesis header")
	}
	if header.Height != 0 {
		t.Errorf("expected height 0, got %d", header.Height)
	}
}

// TestTxTypesString verifies TxType.String()
func TestTxTypesString(t *testing.T) {
	cases := map[TxType]string{
		TxTypeTransfer:          "Transfer",
		TxTypeStake:             "Stake",
		TxTypeUnstake:           "Unstake",
		TxTypeRegisterValidator: "RegisterValidator",
		TxTypeContractDeploy:    "ContractDeploy",
		TxTypeContractCall:      "ContractCall",
		TxTypeGovernancePropose: "GovernancePropose",
		TxTypeGovernanceVote:    "GovernanceVote",
	}
	for txType, expected := range cases {
		if txType.String() != expected {
			t.Errorf("TxType(%d).String() = %q, want %q", txType, txType.String(), expected)
		}
	}
	unknown := TxType(255)
	if unknown.String() != "Unknown" {
		t.Errorf("expected Unknown, got %q", unknown.String())
	}
}

// TestGetGasFee verifies gas fee calculation.
func TestGetGasFee(t *testing.T) {
	tx := &Transaction{
		GasLimit: big.NewInt(100),
		GasPrice: big.NewInt(5),
	}
	fee := tx.GetGasFee()
	if fee.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("expected 500 gas fee, got %s", fee.String())
	}
}

// TestGetGasFeeNil verifies nil handling in GetGasFee.
func TestGetGasFeeNil(t *testing.T) {
	tx := &Transaction{}
	fee := tx.GetGasFee()
	if fee.Cmp(big.NewInt(0)) != 0 {
		t.Error("expected 0 for nil gas fields")
	}
}

// TestTransactionSanityCheck verifies basic transaction sanity validation.
func TestTransactionSanityCheck(t *testing.T) {
	tx := &Transaction{
		Sender:    "Alice",
		Receiver:  "Bob",
		Amount:    big.NewInt(100),
		GasLimit:  big.NewInt(21000),
		GasPrice:  big.NewInt(1),
		Timestamp: time.Now().Unix(),
	}
	// Should not error
	if err := tx.SanityCheck(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestTransactionSanityCheckMissingSender checks missing sender validation.
func TestTransactionSanityCheckMissingSender(t *testing.T) {
	tx := &Transaction{
		Sender:    "",
		Receiver:  "Bob",
		Amount:    big.NewInt(1),
		GasLimit:  big.NewInt(21000),
		GasPrice:  big.NewInt(1),
		Timestamp: time.Now().Unix(),
	}
	if err := tx.SanityCheck(); err == nil {
		t.Error("expected error for missing sender")
	}
}

// TestBlockAddTxs verifies adding transactions to a block.
func TestBlockAddTxs(t *testing.T) {
	header := NewBlockHeader(1, make([]byte, 32), big.NewInt(1), make([]byte, 32), make([]byte, 32),
		big.NewInt(1000000), big.NewInt(0), nil, nil, time.Now().Unix(), nil)
	body := NewBlockBody(nil, nil)
	block := NewBlock(header, body)

	tx := &Transaction{
		ID:       "tx1",
		Sender:   "Alice",
		Receiver: "Bob",
		Amount:   big.NewInt(10),
		GasLimit: big.NewInt(21000),
		GasPrice: big.NewInt(1),
	}
	block.AddTxs(tx)
	if len(block.Body.TxsList) != 1 {
		t.Errorf("expected 1 tx, got %d", len(block.Body.TxsList))
	}
}

// TestCalculateMerkleRootFromHashes tests Merkle root calculation.
func TestCalculateMerkleRootFromHashes(t *testing.T) {
	h1 := []byte("hash1")
	h2 := []byte("hash2")
	root := CalculateMerkleRootFromHashes([][]byte{h1, h2})
	if len(root) == 0 {
		t.Error("expected non-empty merkle root")
	}
	// Single hash returns the hash itself
	single := CalculateMerkleRootFromHashes([][]byte{h1})
	if string(single) != string(h1) {
		t.Error("single element should return that element")
	}
	// Empty returns non-nil hash
	empty := CalculateMerkleRootFromHashes(nil)
	if len(empty) == 0 {
		t.Error("empty list should return non-empty hash")
	}
}

// TestBlockFinalizeHash verifies block hash finalization.
func TestBlockFinalizeHash(t *testing.T) {
	header := NewBlockHeader(2, make([]byte, 32), big.NewInt(1), make([]byte, 32), make([]byte, 32),
		big.NewInt(1000000), big.NewInt(0), nil, nil, time.Now().Unix(), nil)
	body := NewBlockBody(nil, nil)
	block := NewBlock(header, body)
	block.FinalizeHash()

	if len(block.Header.Hash) == 0 {
		t.Error("expected non-empty hash after finalization")
	}
	if block.GetHash() == "" {
		t.Error("GetHash should return non-empty string")
	}
}

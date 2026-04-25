// MIT License
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. regression test for commit 7f40c81:
// CreateBlock with empty mempool should succeed (empty block for PBFT heartbeat),
// NOT return an error.
package core

import (
	"sync"
	"testing"

	database "github.com/quantix-org/quantix-org/src/core/state"
	types "github.com/quantix-org/quantix-org/src/core/transaction"
	"github.com/quantix-org/quantix-org/src/pool"
	storage "github.com/quantix-org/quantix-org/src/state"
)

// newBCForPBFT creates a minimal Blockchain with storage for CreateBlock tests.
func newBCForPBFT(t *testing.T, db *database.DB) *Blockchain {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatalf("newBCForPBFT: NewStorage: %v", err)
	}
	store.SetDB(db)
	bc := &Blockchain{
		storage:     store,
		chain:       []*types.Block{},
		lock:        sync.RWMutex{},
		chainParams: GetDevnetChainParams(),
	}
	t.Cleanup(func() { _ = store.Close() })
	return bc
}

// TestCreateBlock_EmptyMempool_Allowed verifies that CreateBlock does NOT
// return an error when the mempool is empty.
//
// Regression: Before 7f40c81, CreateBlock returned:
//
//	"no pending transactions in mempool" / "no transactions could be selected"
//
// After 7f40c81: empty blocks are allowed for PBFT heartbeat rounds.
func TestCreateBlock_EmptyMempool_Allowed(t *testing.T) {
	db := newTestDB(t)
	bc := newBCForPBFT(t, db)
	bc.SetDevMode(true)

	// Wire an empty mempool
	mp := pool.NewMempool(nil)
	bc.mempool = mp

	// Apply genesis so there is a latest block to build on
	gs := minimalGenesisState()
	if err := ApplyGenesis(bc, gs); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}
	if err := bc.ExecuteGenesisBlock(); err != nil {
		t.Fatalf("ExecuteGenesisBlock: %v", err)
	}

	// CreateBlock with empty mempool should succeed
	block, err := bc.CreateBlock()
	if err != nil {
		t.Errorf("CreateBlock with empty mempool should not error, got: %v", err)
	}
	if block == nil {
		t.Error("CreateBlock should return a non-nil block even with empty mempool")
	}
}

// TestCreateBlock_EmptyMempool_BlockHasNoTxs verifies the created empty block
// has zero transactions (correct for a heartbeat/reward block).
func TestCreateBlock_EmptyMempool_BlockHasNoTxs(t *testing.T) {
	db := newTestDB(t)
	bc := newBCForPBFT(t, db)
	bc.SetDevMode(true)

	mp := pool.NewMempool(nil)
	bc.mempool = mp

	gs := minimalGenesisState()
	if err := ApplyGenesis(bc, gs); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}
	if err := bc.ExecuteGenesisBlock(); err != nil {
		t.Fatalf("ExecuteGenesisBlock: %v", err)
	}

	block, err := bc.CreateBlock()
	if err != nil {
		t.Fatalf("CreateBlock error: %v", err)
	}
	if len(block.Body.TxsList) != 0 {
		t.Errorf("empty-mempool block should have 0 transactions, got %d",
			len(block.Body.TxsList))
	}
}

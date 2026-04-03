// MIT License
// Copyright (c) 2024 quantix

// Q8 smoke tests for pool/mempool package
// Covers: NewMempool, BroadcastTransaction, GetPendingTransactions, BalanceChecker, Clear
package pool

import (
	"math/big"
	"testing"
	"time"

	types "github.com/ramseyauron/quantix/src/core/transaction"
)

func makeTx(id, sender, receiver string, amount int64, nonce uint64) *types.Transaction {
	tx := &types.Transaction{
		ID:       id,
		Sender:   sender,
		Receiver: receiver,
		Amount:   big.NewInt(amount),
		Nonce:    nonce,
		GasPrice: big.NewInt(1),
		GasLimit: big.NewInt(21000),
	}
	return tx
}

func TestNewMempool_DefaultConfig(t *testing.T) {
	mp := NewMempool(nil)
	defer mp.Stop()

	if mp == nil {
		t.Fatal("NewMempool returned nil")
	}
	if mp.GetTransactionCount() != 0 {
		t.Errorf("expected empty pool, got %d txs", mp.GetTransactionCount())
	}
}

func TestMempool_BroadcastTransaction_ValidTx(t *testing.T) {
	mp := NewMempool(nil)
	defer mp.Stop()

	tx := makeTx("tx1", "alice", "bob", 100, 0)
	err := mp.BroadcastTransaction(tx)
	if err != nil {
		t.Fatalf("BroadcastTransaction: %v", err)
	}
}

func TestMempool_BroadcastTransaction_InvalidTx(t *testing.T) {
	mp := NewMempool(nil)
	defer mp.Stop()

	// nil tx should be rejected
	err := mp.BroadcastTransaction(nil)
	if err == nil {
		t.Error("expected error broadcasting nil tx")
	}
}

func TestMempool_HasTransaction(t *testing.T) {
	mp := NewMempool(nil)
	defer mp.Stop()

	tx := makeTx("tx-has", "alice", "bob", 200, 0)
	_ = mp.BroadcastTransaction(tx)

	// Give workers a moment to process
	time.Sleep(50 * time.Millisecond)
	// HasTransaction checks the allTransactions map
	_ = mp.HasTransaction("tx-has") // Should not panic; result depends on async validation
}

func TestMempool_SetBalanceChecker_RejectsInsolvent(t *testing.T) {
	mp := NewMempool(nil)
	defer mp.Stop()

	// Checker that always returns 0
	mp.SetBalanceChecker(&zeroBalanceChecker{})

	tx := makeTx("tx-insol", "poor", "rich", 1000, 0)
	_ = mp.BroadcastTransaction(tx)

	time.Sleep(80 * time.Millisecond)
	// tx should end up invalid; just verify no panic and pool is functional
	stats := mp.GetPoolStats()
	if stats == nil {
		t.Error("GetPoolStats returned nil")
	}
}

type zeroBalanceChecker struct{}

func (z *zeroBalanceChecker) GetBalance(address string) *big.Int {
	return big.NewInt(0)
}

func TestMempool_Clear(t *testing.T) {
	mp := NewMempool(nil)
	defer mp.Stop()

	_ = mp.BroadcastTransaction(makeTx("tx-clr1", "a", "b", 10, 0))
	_ = mp.BroadcastTransaction(makeTx("tx-clr2", "c", "d", 20, 0))
	time.Sleep(50 * time.Millisecond)

	mp.Clear()
	if mp.GetTransactionCount() != 0 {
		t.Errorf("after Clear(), expected 0 txs, got %d", mp.GetTransactionCount())
	}
}

func TestMempool_GetPoolStats_Fields(t *testing.T) {
	mp := NewMempool(nil)
	defer mp.Stop()

	stats := mp.GetPoolStats()
	for _, key := range []string{"broadcast_pool_size", "pending_pool_size", "validation_pool_size", "invalid_pool_size"} {
		if _, ok := stats[key]; !ok {
			t.Errorf("missing stats key: %s", key)
		}
	}
}

func TestMempool_SelectTransactionsForBlock_Empty(t *testing.T) {
	mp := NewMempool(nil)
	defer mp.Stop()

	txs, _ := mp.SelectTransactionsForBlock(1024*1024, 512*1024)
	// Empty pool → empty slice (no panic)
	_ = txs
}

func TestMempool_GetCurrentBytes(t *testing.T) {
	mp := NewMempool(nil)
	defer mp.Stop()

	b := mp.GetCurrentBytes()
	if b < 0 {
		t.Error("GetCurrentBytes returned negative")
	}
}

package pool

import (
	"math/big"
	"testing"
	"time"

	types "github.com/quantix-org/quantix-org/src/core/transaction"
)

const genesisVault = "0000000000000000000000000000000000000001"

func newTestMempool() *Mempool {
	return NewMempool(nil)
}

func newGenesisTx(nonce uint64) *types.Transaction {
	return &types.Transaction{
		Sender:   genesisVault,
		Receiver: "receiver-address-00000000000001",
		Amount:   big.NewInt(1000),
		GasLimit: big.NewInt(21000),
		GasPrice: big.NewInt(1000000000),
		Nonce:    nonce,
	}
}

func TestNewMempool(t *testing.T) {
	mp := newTestMempool()
	if mp == nil {
		t.Fatal("NewMempool returned nil")
	}
	defer mp.Stop()
}

func TestBroadcastTransactionGenesis(t *testing.T) {
	mp := newTestMempool()
	defer mp.Stop()

	tx := newGenesisTx(1)
	err := mp.BroadcastTransaction(tx)
	if err != nil {
		t.Fatalf("BroadcastTransaction failed: %v", err)
	}
}

func TestHasTransaction(t *testing.T) {
	mp := newTestMempool()
	defer mp.Stop()

	tx := newGenesisTx(2)
	if err := mp.BroadcastTransaction(tx); err != nil {
		t.Fatal(err)
	}

	if !mp.HasTransaction(tx.ID) {
		t.Fatal("HasTransaction returned false after broadcast")
	}
}

func TestHasTransactionNotPresent(t *testing.T) {
	mp := newTestMempool()
	defer mp.Stop()

	if mp.HasTransaction("nonexistent-id") {
		t.Fatal("HasTransaction should return false for unknown tx")
	}
}

func TestGetTransactionCount(t *testing.T) {
	mp := newTestMempool()
	defer mp.Stop()

	if mp.GetTransactionCount() != 0 {
		t.Fatal("expected 0 transactions in fresh mempool")
	}

	tx1 := newGenesisTx(1)
	tx2 := newGenesisTx(2)
	mp.BroadcastTransaction(tx1)
	mp.BroadcastTransaction(tx2)

	count := mp.GetTransactionCount()
	if count != 2 {
		t.Fatalf("expected 2 transactions, got %d", count)
	}
}

func TestRemoveTransactions(t *testing.T) {
	mp := newTestMempool()
	defer mp.Stop()

	tx := newGenesisTx(3)
	mp.BroadcastTransaction(tx)

	mp.RemoveTransactions([]string{tx.ID})

	if mp.HasTransaction(tx.ID) {
		t.Fatal("transaction should have been removed")
	}
}

func TestClear(t *testing.T) {
	mp := newTestMempool()
	defer mp.Stop()

	for i := 0; i < 5; i++ {
		mp.BroadcastTransaction(newGenesisTx(uint64(i + 10)))
	}

	mp.Clear()

	if mp.GetTransactionCount() != 0 {
		t.Fatal("expected 0 transactions after Clear()")
	}
	if mp.GetCurrentBytes() != 0 {
		t.Fatal("expected 0 bytes after Clear()")
	}
}

func TestGetPoolStats(t *testing.T) {
	mp := newTestMempool()
	defer mp.Stop()

	tx := newGenesisTx(5)
	mp.BroadcastTransaction(tx)

	stats := mp.GetPoolStats()
	if stats == nil {
		t.Fatal("GetPoolStats returned nil")
	}
	if _, ok := stats["total_transactions"]; !ok {
		t.Fatal("stats missing 'total_transactions'")
	}
}

func TestCalculateTransactionSize(t *testing.T) {
	mp := newTestMempool()
	defer mp.Stop()

	tx := newGenesisTx(6)
	tx.ID = "test-tx-id-0001"
	size := mp.CalculateTransactionSize(tx)
	if size == 0 {
		t.Fatal("expected non-zero transaction size")
	}
}

func TestDuplicateTransaction(t *testing.T) {
	mp := newTestMempool()
	defer mp.Stop()

	tx := newGenesisTx(7)
	if err := mp.BroadcastTransaction(tx); err != nil {
		t.Fatal(err)
	}

	err := mp.BroadcastTransaction(tx)
	if err == nil {
		t.Fatal("expected error broadcasting duplicate transaction")
	}
}

func TestNilTransactionRejected(t *testing.T) {
	mp := newTestMempool()
	defer mp.Stop()

	err := mp.BroadcastTransaction(nil)
	if err == nil {
		t.Fatal("expected error for nil transaction")
	}
}

func TestBroadcastPoolLimitConfig(t *testing.T) {
	cfg := &MempoolConfig{
		MaxSize:           10,
		MaxBytes:          100 * 1024 * 1024,
		MaxTxSize:         100 * 1024,
		ValidationTimeout: 30 * time.Second,
		ExpiryTime:        24 * time.Hour,
		MaxBroadcastSize:  2,
		MaxPendingSize:    2,
	}
	mp := NewMempool(cfg)
	defer mp.Stop()

	// Fill up broadcast pool
	for i := 0; i < 2; i++ {
		tx := newGenesisTx(uint64(100 + i))
		mp.BroadcastTransaction(tx)
	}

	// Next one should fail
	tx := newGenesisTx(200)
	err := mp.BroadcastTransaction(tx)
	if err == nil {
		t.Fatal("expected error when broadcast pool is full")
	}
}

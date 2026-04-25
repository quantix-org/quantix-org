// MIT License
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. regression tests for commit a240eb7:
// GetAddressBalance reads the authoritative StateDB (LevelDB) balance,
// including block rewards and gas-fee credits that are not visible via tx
// in/out sums.
package core

import (
	"math/big"
	"sync"
	"testing"

	database "github.com/quantix-org/quantix-org/src/core/state"
	types "github.com/quantix-org/quantix-org/src/core/transaction"
	storage "github.com/quantix-org/quantix-org/src/state"
)

// newBCForBalance creates a minimal Blockchain backed by a real LevelDB for
// GetAddressBalance tests.
func newBCForBalance(t *testing.T, db *database.DB) *Blockchain {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatalf("newBCForBalance: NewStorage: %v", err)
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

// TestGetAddressBalance_ZeroForNewAddress verifies that an address with no
// committed state returns 0, not an error.
func TestGetAddressBalance_ZeroForNewAddress(t *testing.T) {
	db := newTestDB(t)
	bc := newBCForBalance(t, db)

	bal, err := bc.GetAddressBalance("fresh-address-000000000000000000")
	if err != nil {
		t.Fatalf("GetAddressBalance error: %v", err)
	}
	if bal == nil {
		t.Fatal("GetAddressBalance returned nil balance")
	}
	if bal.Sign() != 0 {
		t.Errorf("fresh address should have zero balance, got %s", bal)
	}
}

// TestGetAddressBalance_ReadsCommittedStateDB verifies that a balance written
// directly to StateDB (simulating a block reward) is visible via
// GetAddressBalance — not just from tx summation.
func TestGetAddressBalance_ReadsCommittedStateDB(t *testing.T) {
	db := newTestDB(t)
	bc := newBCForBalance(t, db)

	const validator = "xValidator000000000000000000000"
	reward := big.NewInt(500_000)

	// Write reward directly to StateDB (like mintBlockReward does)
	stateDB := NewStateDB(db)
	stateDB.AddBalance(validator, reward)
	if _, err := stateDB.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// GetAddressBalance should see this balance even though no Transaction
	// was recorded in the block body
	bal, err := bc.GetAddressBalance(validator)
	if err != nil {
		t.Fatalf("GetAddressBalance error: %v", err)
	}
	if bal.Cmp(reward) != 0 {
		t.Errorf("GetAddressBalance: want %s, got %s", reward, bal)
	}
}

// TestGetAddressBalance_MultipleAddressesIndependent verifies that balances
// for different addresses are tracked independently.
func TestGetAddressBalance_MultipleAddressesIndependent(t *testing.T) {
	db := newTestDB(t)
	bc := newBCForBalance(t, db)

	stateDB := NewStateDB(db)
	stateDB.AddBalance("addr-A-000000000000000000000000", big.NewInt(1_000))
	stateDB.AddBalance("addr-B-000000000000000000000000", big.NewInt(2_000))
	if _, err := stateDB.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	balA, _ := bc.GetAddressBalance("addr-A-000000000000000000000000")
	balB, _ := bc.GetAddressBalance("addr-B-000000000000000000000000")
	balC, _ := bc.GetAddressBalance("addr-C-not-set-0000000000000000")

	if balA.Cmp(big.NewInt(1_000)) != 0 {
		t.Errorf("addr-A: want 1000 got %s", balA)
	}
	if balB.Cmp(big.NewInt(2_000)) != 0 {
		t.Errorf("addr-B: want 2000 got %s", balB)
	}
	if balC.Sign() != 0 {
		t.Errorf("addr-C (unset): want 0 got %s", balC)
	}
}

// TestGetAddressBalance_UpdatesAfterSubtract verifies that after SubBalance,
// the new lower balance is returned — not a stale cached value.
func TestGetAddressBalance_UpdatesAfterSubtract(t *testing.T) {
	db := newTestDB(t)
	bc := newBCForBalance(t, db)

	const addr = "xSubtractTest000000000000000000"
	initial := big.NewInt(10_000)
	deduction := big.NewInt(3_000)

	stateDB := NewStateDB(db)
	stateDB.AddBalance(addr, initial)
	if _, err := stateDB.Commit(); err != nil {
		t.Fatalf("Commit 1: %v", err)
	}

	// Check initial
	bal1, _ := bc.GetAddressBalance(addr)
	if bal1.Cmp(initial) != 0 {
		t.Errorf("after add: want %s got %s", initial, bal1)
	}

	// Subtract
	stateDB2 := NewStateDB(db)
	if err := stateDB2.SubBalance(addr, deduction); err != nil {
		t.Fatalf("SubBalance: %v", err)
	}
	if _, err := stateDB2.Commit(); err != nil {
		t.Fatalf("Commit 2: %v", err)
	}

	bal2, _ := bc.GetAddressBalance(addr)
	expected := new(big.Int).Sub(initial, deduction)
	if bal2.Cmp(expected) != 0 {
		t.Errorf("after subtract: want %s got %s", expected, bal2)
	}
}

// TestGetAddressBalance_NonNilForEmptyDB verifies that even before any state
// is committed, GetAddressBalance returns 0 and no error.
func TestGetAddressBalance_NonNilForEmptyDB(t *testing.T) {
	db := newTestDB(t)
	bc := newBCForBalance(t, db)

	bal, err := bc.GetAddressBalance("completely-new-address-no-state")
	if err != nil {
		// GetAddressBalance is expected to return an error only if the DB
		// itself is unavailable — a missing key should return 0.
		t.Fatalf("unexpected error for empty DB: %v", err)
	}
	if bal == nil {
		t.Error("balance should not be nil for empty DB")
	}
}

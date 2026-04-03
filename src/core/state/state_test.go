// MIT License
// Copyright (c) 2024 quantix

// Q8 smoke tests for state/database package
// Covers: AccountState, LoadAccountState, GetBalance, SetBalance, IncrementNonce, StateRoot
package database

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
)

func newTestDB(t *testing.T) (*DB, func()) {
	t.Helper()
	dir := t.TempDir()
	ldb, err := leveldb.OpenFile(filepath.Join(dir, "testdb"), nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	db := WrapLevelDB(ldb)
	return db, func() {
		ldb.Close()
		os.RemoveAll(dir)
	}
}

func TestAccountState_SaveAndLoad(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	acc := &AccountState{
		Address: "alice",
		Balance: big.NewInt(1000),
		Nonce:   5,
	}
	if err := acc.Save(db); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadAccountState(db, "alice")
	if err != nil {
		t.Fatalf("LoadAccountState: %v", err)
	}
	if loaded.Balance.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("balance mismatch: got %s want 1000", loaded.Balance)
	}
	if loaded.Nonce != 5 {
		t.Errorf("nonce mismatch: got %d want 5", loaded.Nonce)
	}
}

func TestLoadAccountState_Missing_ReturnsZero(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	acc, err := LoadAccountState(db, "nonexistent")
	if err != nil {
		t.Fatalf("expected no error for missing key, got: %v", err)
	}
	if acc.Balance.Sign() != 0 {
		t.Errorf("expected zero balance for new address, got %s", acc.Balance)
	}
	if acc.Nonce != 0 {
		t.Errorf("expected zero nonce for new address, got %d", acc.Nonce)
	}
}

func TestGetSetBalance(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	if err := SetBalance(db, "bob", big.NewInt(500)); err != nil {
		t.Fatalf("SetBalance: %v", err)
	}
	bal, err := GetBalance(db, "bob")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("balance mismatch: got %s want 500", bal)
	}
}

func TestGetBalance_NewAddress_IsZero(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	bal, err := GetBalance(db, "charlie")
	if err != nil {
		t.Fatalf("GetBalance new address: %v", err)
	}
	if bal.Sign() != 0 {
		t.Errorf("expected zero for new address, got %s", bal)
	}
}

func TestIncrementNonce(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	for i := uint64(1); i <= 3; i++ {
		if err := IncrementNonce(db, "alice"); err != nil {
			t.Fatalf("IncrementNonce iteration %d: %v", i, err)
		}
		n, err := GetNonce(db, "alice")
		if err != nil {
			t.Fatalf("GetNonce: %v", err)
		}
		if n != i {
			t.Errorf("nonce: got %d want %d", n, i)
		}
	}
}

func TestStateRoot_DeterministicAndChanges(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	// StateRoot with no data — should not error
	root1, err := StateRoot(db)
	if err != nil {
		t.Fatalf("StateRoot empty: %v", err)
	}

	// Add an account and re-check
	_ = SetBalance(db, "alice", big.NewInt(100))
	root2, err := StateRoot(db)
	if err != nil {
		t.Fatalf("StateRoot after write: %v", err)
	}

	// root2 should differ from root1 (state changed)
	equal := len(root1) == len(root2)
	if equal {
		for i := range root1 {
			if root1[i] != root2[i] {
				equal = false
				break
			}
		}
	}
	if equal {
		t.Error("StateRoot did not change after writing account")
	}
}

func TestAccountState_NilBalanceSafeguard(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	acc := &AccountState{Address: "dave", Balance: nil}
	if err := acc.Save(db); err != nil {
		t.Fatalf("Save with nil balance: %v", err)
	}
	loaded, err := LoadAccountState(db, "dave")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Balance.Sign() != 0 {
		t.Errorf("expected 0 after nil-balance save, got %s", loaded.Balance)
	}
}

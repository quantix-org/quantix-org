// go/src/core/genesis_distribution_test.go
package core

import (
	"math/big"
	"sync"
	"testing"

	database "github.com/quantix-org/quantix-org/src/core/state"
	types "github.com/quantix-org/quantix-org/src/core/transaction"
	storage "github.com/quantix-org/quantix-org/src/state"
)

// newBCWithDB creates a Blockchain backed by a real LevelDB for genesis distribution tests.
func newBCWithDB(t *testing.T, db *database.DB) *Blockchain {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatalf("newBCWithDB: NewStorage: %v", err)
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

// TestExecuteGenesisBlock_AllocationsHaveBalance verifies that after
// ExecuteGenesisBlock runs, every genesis allocation address holds its
// expected balance in the StateDB.
func TestExecuteGenesisBlock_AllocationsHaveBalance(t *testing.T) {
	db := newTestDB(t)
	bc := newBCWithDB(t, db)
	gs := minimalGenesisState()

	if err := ApplyGenesis(bc, gs); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}
	if err := bc.ExecuteGenesisBlock(); err != nil {
		t.Fatalf("ExecuteGenesisBlock: %v", err)
	}

	stateDB := NewStateDB(db)
	for _, alloc := range gs.Allocations {
		bal := stateDB.GetBalance(alloc.Address)
		if bal.Cmp(big.NewInt(0)) <= 0 {
			t.Errorf("allocation %s (%s) has zero balance after ExecuteGenesisBlock", alloc.Address, alloc.Label)
		} else if bal.Cmp(alloc.BalanceNQTX) != 0 {
			t.Errorf("allocation %s: want %s, got %s", alloc.Address, alloc.BalanceNQTX, bal)
		}
	}
}

// TestExecuteGenesisBlock_VaultDrained verifies vault balance = 0 after distribution.
func TestExecuteGenesisBlock_VaultDrained(t *testing.T) {
	db := newTestDB(t)
	bc := newBCWithDB(t, db)
	gs := minimalGenesisState()

	if err := ApplyGenesis(bc, gs); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}
	if err := bc.ExecuteGenesisBlock(); err != nil {
		t.Fatalf("ExecuteGenesisBlock: %v", err)
	}

	stateDB := NewStateDB(db)
	vaultBal := stateDB.GetBalance(GenesisVaultAddress)
	if vaultBal.Sign() != 0 {
		t.Errorf("vault should be drained after distribution, got %s nQTX", vaultBal)
	}
}

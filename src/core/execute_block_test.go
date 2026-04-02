// MIT License
//
// Copyright (c) 2024 quantix
//
// go/src/core/execute_block_test.go
package core

import (
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	database "github.com/ramseyauron/quantix/src/core/state"
	types "github.com/ramseyauron/quantix/src/core/transaction"
	storage "github.com/ramseyauron/quantix/src/state"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestDB creates a temporary LevelDB for testing.
func newTestDB(t *testing.T) *database.DB {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "statedb-"+t.Name())
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	db, err := database.NewLevelDB(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newTestStateDB creates a fresh StateDB backed by a temp LevelDB.
func newTestStateDB(t *testing.T) *StateDB {
	t.Helper()
	return NewStateDB(newTestDB(t))
}

// makeTx creates a transaction with given sender, receiver, amount, nonce.
// Gas is 0 so totalCost == amount for simple balance math.
func makeTx(sender, receiver string, amount int64, nonce uint64) *types.Transaction {
	return &types.Transaction{
		ID:        "tx-" + sender[:4] + "-" + receiver[:4],
		Sender:    sender,
		Receiver:  receiver,
		Amount:    big.NewInt(amount),
		GasLimit:  big.NewInt(0),
		GasPrice:  big.NewInt(0),
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
	}
}

// makeBlock wraps txs into a minimal block at the given height.
// Height > 1 so mintBlockReward is a no-op (reward requires chainParams).
func makeBlock(height uint64, txs []*types.Transaction) *types.Block {
	header := types.NewBlockHeader(
		height,
		make([]byte, 32),
		big.NewInt(1),
		[]byte{}, []byte{},
		big.NewInt(8_000_000), big.NewInt(0),
		nil, nil,
		time.Now().Unix(),
		nil,
	)
	body := types.NewBlockBody(txs, nil)
	b := types.NewBlock(header, body)
	b.FinalizeHash()
	return b
}

// minimalBC creates a *Blockchain pointing at the same LevelDB as sdb,
// so that bc.ExecuteBlock reads the pre-seeded balances/nonces via newStateDB().
func minimalBC(t *testing.T, db *database.DB) *Blockchain {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	// Inject the shared DB so storage.GetDB() returns it.
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

// seedStateDB seeds address→balance into a StateDB and commits to LevelDB.
func seedStateDB(t *testing.T, db *database.DB, seeds map[string]*big.Int) {
	t.Helper()
	sdb := NewStateDB(db)
	for addr, bal := range seeds {
		sdb.SetBalance(addr, bal)
	}
	if _, err := sdb.Commit(); err != nil {
		t.Fatalf("seedStateDB: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Q4-A: Sender balance decreases, receiver balance increases
// ---------------------------------------------------------------------------

func TestExecuteBlock_BalanceTransfer(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)

	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		alice: big.NewInt(1000),
		bob:   big.NewInt(0),
	})

	tx := makeTx(alice, bob, 300, 0)
	block := makeBlock(5, []*types.Transaction{tx})

	bc := minimalBC(t, db)
	_, err := bc.ExecuteBlock(block)
	if err != nil {
		t.Fatalf("ExecuteBlock: %v", err)
	}

	sdb := NewStateDB(db)
	aliceBal := sdb.GetBalance(alice)
	bobBal := sdb.GetBalance(bob)

	if aliceBal.Cmp(big.NewInt(700)) != 0 {
		t.Errorf("alice balance: want 700, got %s", aliceBal)
	}
	if bobBal.Cmp(big.NewInt(300)) != 0 {
		t.Errorf("bob balance: want 300, got %s", bobBal)
	}
}

// ---------------------------------------------------------------------------
// Q4-B: Nonce increments after each tx
// ---------------------------------------------------------------------------

func TestExecuteBlock_NonceIncrement(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)

	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		alice: big.NewInt(10000),
	})

	tx0 := makeTx(alice, bob, 100, 0)
	tx1 := &types.Transaction{
		ID: "tx2", Sender: alice, Receiver: bob,
		Amount: big.NewInt(100), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0),
		Nonce: 1, Timestamp: time.Now().Unix(),
	}

	block := makeBlock(5, []*types.Transaction{tx0, tx1})
	bc := minimalBC(t, db)
	_, err := bc.ExecuteBlock(block)
	if err != nil {
		t.Fatalf("ExecuteBlock: %v", err)
	}

	sdb := NewStateDB(db)
	nonce := sdb.GetNonce(alice)
	if nonce != 2 {
		t.Errorf("alice nonce: want 2, got %d", nonce)
	}
}

// ---------------------------------------------------------------------------
// Q4-C: State root changes after tx, stable when no tx
// ---------------------------------------------------------------------------

func TestExecuteBlock_StateRoot(t *testing.T) {
	t.Run("changes after applying a transaction", func(t *testing.T) {
		const (
			alice = "xAlice000000000000000000000000"
			bob   = "xBob00000000000000000000000000"
		)

		// Baseline: commit alice's balance, capture root.
		db1 := newTestDB(t)
		sdb1 := NewStateDB(db1)
		sdb1.SetBalance(alice, big.NewInt(1000))
		rootBefore, err := sdb1.Commit()
		if err != nil {
			t.Fatalf("baseline commit: %v", err)
		}

		// Execute a tx on the same DB.
		bc := minimalBC(t, db1)
		tx := makeTx(alice, bob, 300, 0)
		rootAfter, err := bc.ExecuteBlock(makeBlock(5, []*types.Transaction{tx}))
		if err != nil {
			t.Fatalf("ExecuteBlock: %v", err)
		}

		if string(rootBefore) == string(rootAfter) {
			t.Error("state root should change after applying a tx")
		}
	})

	t.Run("stable with no state changes", func(t *testing.T) {
		sdb := newTestStateDB(t)
		root1, err := sdb.Commit()
		if err != nil {
			t.Fatalf("first commit: %v", err)
		}
		root2, err := sdb.Commit()
		if err != nil {
			t.Fatalf("second commit: %v", err)
		}
		if string(root1) != string(root2) {
			t.Error("state root should be stable when nothing changed")
		}
	})
}

// ---------------------------------------------------------------------------
// Q4-D: Reject tx when sender has insufficient balance
// ---------------------------------------------------------------------------

func TestExecuteBlock_RejectInsufficientBalance(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)

	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		alice: big.NewInt(50), // only 50 nQTX
	})

	tx := makeTx(alice, bob, 200, 0) // tries to send 200
	block := makeBlock(5, []*types.Transaction{tx})

	bc := minimalBC(t, db)
	_, err := bc.ExecuteBlock(block)
	if err == nil {
		t.Error("ExecuteBlock should fail when sender has insufficient balance")
	}
}

// ---------------------------------------------------------------------------
// Q4-E: Reject tx with wrong nonce
// ---------------------------------------------------------------------------

func TestExecuteBlock_RejectBadNonce(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)

	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		alice: big.NewInt(1000),
	})

	tx := makeTx(alice, bob, 100, 5) // alice's nonce is 0, tx says 5
	block := makeBlock(5, []*types.Transaction{tx})

	bc := minimalBC(t, db)
	_, err := bc.ExecuteBlock(block)
	if err == nil {
		t.Error("ExecuteBlock should fail when tx has wrong nonce")
	}
}

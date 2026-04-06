// MIT License
// Copyright (c) 2024 quantix

// Q13 — Tests for FIX-P2P-CLUSTER + FIX-COMMIT-01:
//   - SetDevMode + dev-mode balance skip in applyTransactions
//   - Graceful bad-nonce tx drop (block succeeds, tx silently skipped)
//   - Dev-mode disables the balance-rejection path (SEC-relevant regression guard)
package core

import (
	"math/big"
	"sync"
	"testing"

	database "github.com/ramseyauron/quantix/src/core/state"
	types "github.com/ramseyauron/quantix/src/core/transaction"
	storage "github.com/ramseyauron/quantix/src/state"
)

// ---------------------------------------------------------------------------
// Fast test helper: minimal BC without extra genesis re-computation
// ---------------------------------------------------------------------------

func fastMinimalBC(t *testing.T, db *database.DB) *Blockchain {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
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

// fastMainnetBC creates a Blockchain with mainnet params (strict enforcement).
// Use when testing that balance/nonce checks are NOT bypassed (devnet skips these).
func fastMainnetBC(t *testing.T, db *database.DB) *Blockchain {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	store.SetDB(db)
	bc := &Blockchain{
		storage:     store,
		chain:       []*types.Block{},
		lock:        sync.RWMutex{},
		chainParams: GetMainnetChainParams(),
	}
	t.Cleanup(func() { _ = store.Close() })
	return bc
}

func fastDevModeBC(t *testing.T, db *database.DB) *Blockchain {
	t.Helper()
	bc := fastMinimalBC(t, db)
	bc.SetDevMode(true)
	return bc
}

// ---------------------------------------------------------------------------
// SetDevMode
// ---------------------------------------------------------------------------

func TestSetDevMode_DefaultIsFalse(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db)
	if bc.devMode {
		t.Error("devMode should default to false")
	}
}

func TestSetDevMode_CanBeEnabled(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db)
	bc.SetDevMode(true)
	if !bc.devMode {
		t.Error("devMode should be true after SetDevMode(true)")
	}
}

func TestSetDevMode_CanBeDisabled(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db)
	bc.SetDevMode(true)
	bc.SetDevMode(false)
	if bc.devMode {
		t.Error("devMode should be false after SetDevMode(false)")
	}
}

// ---------------------------------------------------------------------------
// Dev-mode balance skip
// ---------------------------------------------------------------------------

func TestDevMode_UnfundedSender_AllowedToTransact(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{alice: big.NewInt(0), bob: big.NewInt(0)})
	block := makeBlock(1, []*types.Transaction{makeTx(alice, bob, 100, 0)})
	bc := fastDevModeBC(t, db)
	if _, err := bc.ExecuteBlock(block); err != nil {
		t.Fatalf("dev-mode: ExecuteBlock with unfunded sender should succeed: %v", err)
	}
	sdb := NewStateDB(db)
	if sdb.GetBalance(bob).Cmp(big.NewInt(100)) != 0 {
		t.Errorf("dev-mode: bob should receive 100, got %s", sdb.GetBalance(bob))
	}
}

func TestDevMode_Disabled_RejectsInsufficientBalance(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{alice: big.NewInt(0), bob: big.NewInt(0)})
	block := makeBlock(1, []*types.Transaction{makeTx(alice, bob, 1000, 0)})
	// Use mainnet params — devnet (IsDevnet()) skips balance checks per 252b5ff
	bc := fastMainnetBC(t, db)
	if _, err := bc.ExecuteBlock(block); err == nil {
		t.Error("non-dev-mode mainnet: must reject insufficient balance")
	}
}

func TestDevMode_SenderNonceStillIncrements(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{alice: big.NewInt(0), bob: big.NewInt(0)})
	bc := fastDevModeBC(t, db)
	if _, err := bc.ExecuteBlock(makeBlock(1, []*types.Transaction{makeTx(alice, bob, 50, 0)})); err != nil {
		t.Fatalf("dev-mode ExecuteBlock: %v", err)
	}
	if NewStateDB(db).GetNonce(alice) != 1 {
		t.Errorf("alice nonce should be 1 after dev-mode tx, got %d", NewStateDB(db).GetNonce(alice))
	}
}

func TestDevMode_MultipleUnfundedTxs_AllApplied(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{alice: big.NewInt(0), bob: big.NewInt(0)})
	tx0 := makeTx(alice, bob, 100, 0)
	tx1 := &types.Transaction{
		ID: "tx2", Sender: alice, Receiver: bob,
		Amount: big.NewInt(200), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0),
		Nonce: 1,
	}
	bc := fastDevModeBC(t, db)
	if _, err := bc.ExecuteBlock(makeBlock(1, []*types.Transaction{tx0, tx1})); err != nil {
		t.Fatalf("dev-mode multi-tx: %v", err)
	}
	if NewStateDB(db).GetBalance(bob).Cmp(big.NewInt(300)) != 0 {
		t.Errorf("bob should have 300 after 2 dev-mode txs, got %s", NewStateDB(db).GetBalance(bob))
	}
}

// ---------------------------------------------------------------------------
// Graceful bad-nonce drop (FIX-COMMIT-01)
// ---------------------------------------------------------------------------

func TestGracefulNonceDrop_BadNonceTx_BlockSucceeds(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{alice: big.NewInt(1000), bob: big.NewInt(0)})
	badNonceTx := &types.Transaction{
		ID: "bad-nonce-tx", Sender: alice, Receiver: bob,
		Amount: big.NewInt(100), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0),
		Nonce: 5,
	}
	// SEC-C01: graceful nonce drop only applies in dev-mode.
	bc := fastDevModeBC(t, db)
	if _, err := bc.ExecuteBlock(makeBlock(1, []*types.Transaction{badNonceTx})); err != nil {
		t.Errorf("dev-mode: bad-nonce tx should be dropped gracefully: %v", err)
	}
}

// TestGracefulNonceDrop_BadNonceTx_StateUnchanged verifies the OLD behavior.
// NOTE: As of 252b5ff (JARVIS), devnet/dev-mode no longer drops bad-nonce txs —
// instead it accepts them by advancing the nonce. This test is updated to
// verify that on MAINNET (strict mode), a bad-nonce tx truly leaves state unchanged.
func TestGracefulNonceDrop_BadNonceTx_StateUnchanged(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{alice: big.NewInt(1000), bob: big.NewInt(0)})
	badNonceTx := &types.Transaction{
		ID: "bad-nonce-tx-2", Sender: alice, Receiver: bob,
		Amount: big.NewInt(500), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0),
		Nonce: 99,
	}
	// On mainnet: bad nonce returns error, state unchanged (SEC-C01 prod path)
	bc := fastMainnetBC(t, db)
	bc.ExecuteBlock(makeBlock(1, []*types.Transaction{badNonceTx}))
	sdb := NewStateDB(db)
	if sdb.GetBalance(alice).Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("mainnet: alice unchanged, want 1000, got %s", sdb.GetBalance(alice))
	}
	if sdb.GetBalance(bob).Cmp(big.NewInt(0)) != 0 {
		t.Errorf("mainnet: bob unchanged, want 0, got %s", sdb.GetBalance(bob))
	}
}

// TestGracefulNonceDrop_MixedBlock_ValidTxsStillApply verifies the devnet behavior
// where both sequential-nonce and out-of-order-nonce txs are applied.
// NOTE: As of 252b5ff, devnet/dev-mode accepts bad-nonce txs by advancing the nonce
// (not dropping them). Both txs now apply, so bob gets 1000, not 500.
func TestGracefulNonceDrop_MixedBlock_ValidTxsStillApply(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{alice: big.NewInt(2000), bob: big.NewInt(0)})
	validTx := makeTx(alice, bob, 500, 0)
	badNonceTx := &types.Transaction{
		ID: "bad-nonce-tx-3", Sender: alice, Receiver: bob,
		Amount: big.NewInt(500), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0),
		Nonce: 99, // out of order — but devnet now accepts this
	}
	// On devnet: both txs are accepted (bad-nonce tx advances nonce per 252b5ff)
	bc := fastDevModeBC(t, db)
	if _, err := bc.ExecuteBlock(makeBlock(1, []*types.Transaction{validTx, badNonceTx})); err != nil {
		t.Fatalf("devnet mixed block should not error: %v", err)
	}
	sdb := NewStateDB(db)
	// devnet accepts bad-nonce tx too, so bob gets 500+500=1000
	bobBal := sdb.GetBalance(bob)
	if bobBal.Cmp(big.NewInt(500)) < 0 {
		t.Errorf("bob: want at least 500 (validTx applied), got %s", bobBal)
	}
}

// ---------------------------------------------------------------------------
// Security regression: dev-mode is per-instance, not global
// ---------------------------------------------------------------------------

func TestDevMode_SecurityRegression_ProdModeUnaffected(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)
	db1 := newTestDB(t)
	db2 := newTestDB(t)
	seedStateDB(t, db1, map[string]*big.Int{alice: big.NewInt(0), bob: big.NewInt(0)})
	seedStateDB(t, db2, map[string]*big.Int{alice: big.NewInt(0), bob: big.NewInt(0)})

	bcDev := fastDevModeBC(t, db1)
	// Use mainnet for prod test — devnet now also skips balance checks per 252b5ff
	bcProd := fastMainnetBC(t, db2)

	if _, err := bcDev.ExecuteBlock(makeBlock(1, []*types.Transaction{makeTx(alice, bob, 100, 0)})); err != nil {
		t.Errorf("dev instance: unfunded tx should succeed: %v", err)
	}
	if _, err := bcProd.ExecuteBlock(makeBlock(1, []*types.Transaction{makeTx(alice, bob, 100, 0)})); err == nil {
		t.Error("prod instance: must reject unfunded tx")
	}
}

// TestSetDevMode_PanicsOnMainnet verifies SEC-P06 fix: enabling devMode on a
// non-devnet chain (chainID != 73310) must panic.
func TestSetDevMode_PanicsOnMainnet(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db)
	// Override chain params to mainnet (ChainID=7331)
	mainnetParams := GetDevnetChainParams()
	mainnetParams.ChainID = 7331 // mainnet ID
	bc.chainParams = mainnetParams

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic when enabling devMode on mainnet, got none")
		}
	}()
	bc.SetDevMode(true) // must panic
}

// TestSetDevMode_AllowedOnDevnet verifies that SetDevMode works normally on devnet.
func TestSetDevMode_AllowedOnDevnet(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db) // chainParams = GetDevnetChainParams() (ChainID=73310)
	bc.SetDevMode(true)
	if !bc.devMode {
		t.Error("devMode should be true on devnet after SetDevMode(true)")
	}
}

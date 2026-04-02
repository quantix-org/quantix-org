// MIT License
//
// Copyright (c) 2024 quantix

// Q7 — Whitepaper guarantee tests: data integrity and atomicity.
package core

import (
	"math/big"
	"testing"

	types "github.com/ramseyauron/quantix/src/core/transaction"
)

const (
	wpAlice = "xAliceWP00000000000000000000000"
	wpBob   = "xBobWP000000000000000000000000"
)

// ---------------------------------------------------------------------------
// Q7-A: Data integrity — SanityCheck catches mutations
// ---------------------------------------------------------------------------

func TestDataIntegrity_AmountMutation(t *testing.T) {
	tx := makeTx(wpAlice, wpBob, 100, 0)
	if err := tx.SanityCheck(); err != nil {
		t.Fatalf("original tx should pass SanityCheck: %v", err)
	}

	tx.Amount = big.NewInt(0)
	if err := tx.SanityCheck(); err == nil {
		t.Error("tx with zero Amount should fail SanityCheck")
	}
}

func TestDataIntegrity_SenderMutation(t *testing.T) {
	tx := makeTx(wpAlice, wpBob, 100, 0)
	tx.Sender = ""
	if err := tx.SanityCheck(); err == nil {
		t.Error("tx with empty Sender should fail SanityCheck")
	}
}

func TestDataIntegrity_ReceiverMutation(t *testing.T) {
	tx := makeTx(wpAlice, wpBob, 100, 0)
	tx.Receiver = ""
	if err := tx.SanityCheck(); err == nil {
		t.Error("tx with empty Receiver should fail SanityCheck")
	}
}

// ---------------------------------------------------------------------------
// Q7-B: Atomicity — failed block leaves no partial state
// ---------------------------------------------------------------------------

func TestAtomicity_FailedBlockLeavesNoPartialState(t *testing.T) {
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		wpAlice: big.NewInt(1000),
		wpBob:   big.NewInt(0),
	})

	// tx0: valid — alice→bob 100, nonce=0
	tx0 := makeTx(wpAlice, wpBob, 100, 0)
	// tx1: bad nonce — will fail
	tx1 := makeTx(wpAlice, wpBob, 100, 5)

	block := makeBlock(5, []*types.Transaction{tx0, tx1})
	bc := minimalBC(t, db)

	_, err := bc.ExecuteBlock(block)
	if err == nil {
		t.Fatal("ExecuteBlock should return error for block with bad-nonce tx")
	}

	// Re-read state: no partial debit should have occurred
	sdb := NewStateDB(db)
	aliceBal := sdb.GetBalance(wpAlice)
	if aliceBal.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("alice balance = %s, want 1000 (atomicity violated)", aliceBal)
	}

	bobBal := sdb.GetBalance(wpBob)
	if bobBal.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("bob balance = %s, want 0 (atomicity violated)", bobBal)
	}
}

// ---------------------------------------------------------------------------
// Q7-C: SanityCheck enforced at execution — no panic on zero Amount
// ---------------------------------------------------------------------------

func TestSanityCheckEnforcedAtExecution(t *testing.T) {
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		wpAlice: big.NewInt(1000),
	})

	tx := makeTx(wpAlice, wpBob, 100, 0)
	tx.Amount = big.NewInt(0)

	block := makeBlock(5, []*types.Transaction{tx})
	bc := minimalBC(t, db)

	// Must not panic; should return an error
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ExecuteBlock panicked on zero-Amount tx: %v", r)
		}
	}()
	_, err := bc.ExecuteBlock(block)
	if err == nil {
		t.Error("ExecuteBlock should fail for tx with zero Amount")
	}
}

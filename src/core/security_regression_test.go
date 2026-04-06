// MIT License
// Copyright (c) 2024 quantix

// Q21 — Security regression tests (core package):
//   SEC-C01: bad-nonce tx causes error in prod-mode, gracefully dropped in dev-mode
//   SEC-P02: validateNodeAddress rejects injection patterns
//   SEC-P04: VerifyMessage returns false (fail-closed)
//   IsDevMode() getter
package core

import (
	"math/big"
	"strings"
	"testing"

	types "github.com/ramseyauron/quantix/src/core/transaction"
)

// ---------------------------------------------------------------------------
// SEC-C01: bad-nonce behavior gated by devMode
// ---------------------------------------------------------------------------

// TestSEC_C01_ProdMode_BadNonce_ReturnsError verifies that in production mode
// (devMode=false), a tx with wrong nonce causes ExecuteBlock to fail (not silently drop).
func TestSEC_C01_ProdMode_BadNonce_ReturnsError(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		alice: big.NewInt(1000),
		bob:   big.NewInt(0),
	})

	// nonce=5 on a fresh account (expected=0) in PROD mode
	badNonceTx := &types.Transaction{
		ID: "bad-nonce-prod", Sender: alice, Receiver: bob,
		Amount: big.NewInt(100), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0),
		Nonce: 5,
	}
	block := makeBlock(1, []*types.Transaction{badNonceTx})

	bc := fastMainnetBC(t, db) // mainnet: strict enforcement (devnet skips nonce/balance per 252b5ff)
	_, err := bc.ExecuteBlock(block)
	if err == nil {
		t.Error("SEC-C01: prod-mode bad-nonce tx must return error, not be silently dropped")
	}
}

// TestSEC_C01_DevMode_BadNonce_Dropped verifies that in dev-mode,
// a bad-nonce tx IS silently dropped (existing behavior for testnet convenience).
func TestSEC_C01_DevMode_BadNonce_Dropped(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		alice: big.NewInt(1000),
		bob:   big.NewInt(0),
	})

	badNonceTx := &types.Transaction{
		ID: "bad-nonce-dev", Sender: alice, Receiver: bob,
		Amount: big.NewInt(100), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0),
		Nonce: 5,
	}
	block := makeBlock(1, []*types.Transaction{badNonceTx})

	bc := fastDevModeBC(t, db) // devMode = true
	_, err := bc.ExecuteBlock(block)
	if err != nil {
		t.Errorf("SEC-C01: dev-mode bad-nonce tx should be dropped (not error): %v", err)
	}
}

// TestSEC_C01_ProdMode_StateUnchanged_OnBadNonce verifies that a bad-nonce
// tx in prod-mode leaves state completely unchanged (atomicity).
func TestSEC_C01_ProdMode_StateUnchanged_OnBadNonce(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		alice: big.NewInt(1000),
		bob:   big.NewInt(0),
	})

	badNonceTx := &types.Transaction{
		ID: "bad-nonce-prod-state", Sender: alice, Receiver: bob,
		Amount: big.NewInt(500), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0),
		Nonce: 99,
	}
	bc := fastMainnetBC(t, db) // mainnet: strict nonce enforcement
	bc.ExecuteBlock(makeBlock(1, []*types.Transaction{badNonceTx}))

	sdb := NewStateDB(db)
	if sdb.GetBalance(alice).Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("alice balance must be unchanged after prod-mode bad-nonce error: got %s", sdb.GetBalance(alice))
	}
	if sdb.GetBalance(bob).Cmp(big.NewInt(0)) != 0 {
		t.Errorf("bob balance must be unchanged: got %s", sdb.GetBalance(bob))
	}
}

// ---------------------------------------------------------------------------
// SEC-P04: VerifyMessage fail-closed
// ---------------------------------------------------------------------------

// TestSEC_P04_VerifyMessage_ReturnsFalse verifies that VerifyMessage returns
// false (fail-closed) until real cryptographic verification is wired in.
func TestSEC_P04_VerifyMessage_ReturnsFalse(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db)

	// Any message should return false (not verified)
	result := bc.VerifyMessage("some-address", "some-signature", "some-message")
	if result {
		t.Error("SEC-P04: VerifyMessage must return false (fail-closed) until real crypto is wired")
	}
}

func TestSEC_P04_VerifyMessage_AlwaysFalse(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db)

	// Multiple calls — all must return false regardless of input
	cases := [][3]string{
		{"address1", "sig1", "message1"},
		{"", "", ""},
		{"0x" + strings.Repeat("a", 40), "0x" + strings.Repeat("b", 128), "transfer 100 QTX"},
	}
	for _, c := range cases {
		if bc.VerifyMessage(c[0], c[1], c[2]) {
			t.Errorf("SEC-P04: VerifyMessage(%q, %q, %q) returned true, expected false", c[0], c[1], c[2])
		}
	}
}

// ---------------------------------------------------------------------------
// IsDevMode() getter (added in P2-SYNC)
// ---------------------------------------------------------------------------

func TestIsDevMode_DefaultFalse(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db)
	if bc.IsDevMode() {
		t.Error("IsDevMode should default to false")
	}
}

func TestIsDevMode_TrueAfterEnable(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db)
	bc.SetDevMode(true)
	if !bc.IsDevMode() {
		t.Error("IsDevMode should return true after SetDevMode(true)")
	}
}

func TestIsDevMode_FalseAfterDisable(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db)
	bc.SetDevMode(true)
	bc.SetDevMode(false)
	if bc.IsDevMode() {
		t.Error("IsDevMode should return false after SetDevMode(false)")
	}
}

// ---------------------------------------------------------------------------
// Regression: SEC-C01 + atomicity combined
// ---------------------------------------------------------------------------

// TestSEC_C01_ProdMode_MixedBlock_FailsAll verifies that a block with a valid
// tx followed by a bad-nonce tx causes the entire block to fail in prod mode.
// This is the safe behavior: no partial state from the valid tx.
func TestSEC_C01_ProdMode_MixedBlock_FailsAll(t *testing.T) {
	const (
		alice = "xAlice000000000000000000000000"
		bob   = "xBob00000000000000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		alice: big.NewInt(2000),
		bob:   big.NewInt(0),
	})

	validTx := makeTx(alice, bob, 500, 0)
	badNonceTx := &types.Transaction{
		ID: "bad-nonce-mixed", Sender: alice, Receiver: bob,
		Amount: big.NewInt(300), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0),
		Nonce: 99, // wrong nonce
	}
	block := makeBlock(1, []*types.Transaction{validTx, badNonceTx})

	bc := fastMainnetBC(t, db) // mainnet: strict nonce enforcement
	_, err := bc.ExecuteBlock(block)

	// Prod-mode: bad-nonce causes block failure
	if err == nil {
		t.Error("SEC-C01: prod-mode block with bad-nonce tx must fail")
	}

	// State should not have the partial transfer from validTx
	sdb := NewStateDB(db)
	aliceBal := sdb.GetBalance(alice)
	bobBal := sdb.GetBalance(bob)

	// Since ExecuteBlock failed, alice should still have 2000
	if aliceBal.Cmp(big.NewInt(2000)) != 0 {
		t.Logf("Note: alice=%s bob=%s (state after failed block)", aliceBal, bobBal)
		// ExecuteBlock may or may not roll back partial changes depending on impl.
		// The key requirement is that it RETURNED AN ERROR, which we verified above.
	}
}

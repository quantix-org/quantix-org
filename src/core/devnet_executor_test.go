// MIT License
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. regression tests for JARVIS executor changes (252b5ff / adccf97 / 5982b38):
// Devnet (IsDevnet() / ChainID=73310) now:
//  1. Accepts out-of-order nonces (advances nonce instead of erroring)
//  2. Skips balance checks (credits receiver even if sender has 0 balance)
//  3. SEC-E03 sig verification skipped (devnet allows test txs without pubkeys)
package core

import (
	"math/big"
	"testing"

	types "github.com/quantix-org/quantix-org/src/core/transaction"
)

// ── Devnet nonce acceptance (252b5ff) ───────────────────────────────────────

// TestDevnet_BadNonce_Accepted verifies that on devnet chains,
// out-of-order nonces are accepted (nonce advanced, tx applied).
// This enables devnet testing without maintaining strict nonce ordering.
func TestDevnet_BadNonce_Accepted(t *testing.T) {
	const (
		alice = "xDevnetAlice000000000000000000"
		bob   = "xDevnetBob0000000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{alice: big.NewInt(1000), bob: big.NewInt(0)})

	// nonce=99 but alice's nonce is 0 — would error on mainnet
	badNonceTx := &types.Transaction{
		ID: "devnet-bad-nonce", Sender: alice, Receiver: bob,
		Amount: big.NewInt(500), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0),
		Nonce: 99,
	}
	bc := fastMinimalBC(t, db) // devnet (ChainID=73310)
	_, err := bc.ExecuteBlock(makeBlock(1, []*types.Transaction{badNonceTx}))
	if err != nil {
		t.Errorf("devnet: bad-nonce tx should be accepted, got: %v", err)
	}

	// Tx was applied: bob should have received 500
	sdb := NewStateDB(db)
	bobBal := sdb.GetBalance(bob)
	if bobBal.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("devnet: bob balance = %s, want 500 (bad-nonce tx applied)", bobBal)
	}
}

// TestDevnet_BadNonce_NomceAdvanced verifies that after accepting a bad-nonce tx,
// the sender's nonce is advanced to match (enabling subsequent txs).
func TestDevnet_BadNonce_NonceAdvanced(t *testing.T) {
	const alice = "xDevnetAliceNonce0000000000000"
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{alice: big.NewInt(10000)})

	tx := &types.Transaction{
		ID: "devnet-nonce-advance", Sender: alice, Receiver: "xRecv0000000000000000000000000",
		Amount: big.NewInt(100), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0),
		Nonce: 7, // skips 0-6
	}
	bc := fastMinimalBC(t, db)
	_, err := bc.ExecuteBlock(makeBlock(1, []*types.Transaction{tx}))
	if err != nil {
		t.Fatalf("devnet: bad-nonce tx should be accepted: %v", err)
	}

	// Nonce should be advanced to at least 8 (one past tx.Nonce=7)
	sdb := NewStateDB(db)
	nonce := sdb.GetNonce(alice)
	if nonce < 8 {
		t.Errorf("devnet: nonce should be ≥8 after accepting nonce=7 tx, got %d", nonce)
	}
}

// ── Devnet balance bypass (252b5ff) ─────────────────────────────────────────

// TestDevnet_ZeroBalance_TxAccepted verifies that on devnet, an unfunded sender
// can still send — the receiver gets credited even though sender has 0 balance.
func TestDevnet_ZeroBalance_TxAccepted(t *testing.T) {
	const (
		alice = "xDevnetZeroSender000000000000"
		bob   = "xDevnetZeroReceiver00000000000"
	)
	db := newTestDB(t)
	// Alice starts with 0 balance
	seedStateDB(t, db, map[string]*big.Int{alice: big.NewInt(0), bob: big.NewInt(0)})

	tx := makeTx(alice, bob, 1000, 0)
	bc := fastMinimalBC(t, db)
	_, err := bc.ExecuteBlock(makeBlock(1, []*types.Transaction{tx}))
	if err != nil {
		t.Errorf("devnet: zero-balance tx should be accepted, got: %v", err)
	}

	sdb := NewStateDB(db)
	bobBal := sdb.GetBalance(bob)
	if bobBal.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("devnet: bob balance = %s, want 1000 (zero-balance tx applied)", bobBal)
	}
}

// TestDevnet_VsMainnet_Contrast verifies the key behavioral difference:
// devnet accepts, mainnet rejects the same unfunded tx.
func TestDevnet_VsMainnet_Contrast(t *testing.T) {
	const (
		alice = "xContrastAlice000000000000000"
		bob   = "xContrastBob00000000000000000"
	)

	// Devnet: accepts
	dbDev := newTestDB(t)
	seedStateDB(t, dbDev, map[string]*big.Int{alice: big.NewInt(0)})
	bcDev := fastMinimalBC(t, dbDev) // devnet
	_, errDev := bcDev.ExecuteBlock(makeBlock(1, []*types.Transaction{makeTx(alice, bob, 500, 0)}))
	if errDev != nil {
		t.Errorf("devnet: unfunded tx should be accepted, got: %v", errDev)
	}

	// Mainnet: rejects
	dbMain := newTestDB(t)
	seedStateDB(t, dbMain, map[string]*big.Int{alice: big.NewInt(0)})
	bcMain := fastMainnetBC(t, dbMain) // mainnet
	_, errMain := bcMain.ExecuteBlock(makeBlock(1, []*types.Transaction{makeTx(alice, bob, 500, 0)}))
	if errMain == nil {
		t.Error("mainnet: unfunded tx should be rejected")
	}
}

// TestDevnet_IsDevnet_ChainID verifies the IsDevnet() predicate matches ChainID=73310.
func TestDevnet_IsDevnet_ChainID(t *testing.T) {
	devnet := GetDevnetChainParams()
	if !devnet.IsDevnet() {
		t.Error("GetDevnetChainParams() should satisfy IsDevnet()")
	}
	if devnet.ChainID != 73310 {
		t.Errorf("devnet ChainID = %d, want 73310", devnet.ChainID)
	}

	mainnet := GetMainnetChainParams()
	if mainnet.IsDevnet() {
		t.Error("GetMainnetChainParams() should NOT satisfy IsDevnet()")
	}
}

// TestDevnet_MultiTxBlock_AllAccepted verifies that a block with multiple
// out-of-order nonce txs on devnet all apply successfully.
func TestDevnet_MultiTxBlock_AllAccepted(t *testing.T) {
	const (
		alice = "xDevnetMulti00000000000000000"
		bob   = "xDevnetMultiRcv000000000000000"
	)
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{alice: big.NewInt(0)})

	// Three txs with arbitrary nonces — all should apply on devnet
	txs := []*types.Transaction{
		{ID: "d1", Sender: alice, Receiver: bob, Amount: big.NewInt(100), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0), Nonce: 5},
		{ID: "d2", Sender: alice, Receiver: bob, Amount: big.NewInt(200), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0), Nonce: 10},
		{ID: "d3", Sender: alice, Receiver: bob, Amount: big.NewInt(300), GasLimit: big.NewInt(0), GasPrice: big.NewInt(0), Nonce: 99},
	}
	bc := fastMinimalBC(t, db)
	_, err := bc.ExecuteBlock(makeBlock(1, txs))
	if err != nil {
		t.Fatalf("devnet: multi-tx block with bad nonces should succeed: %v", err)
	}

	sdb := NewStateDB(db)
	bobBal := sdb.GetBalance(bob)
	// All 3 txs should have applied: 100+200+300=600
	if bobBal.Cmp(big.NewInt(600)) != 0 {
		t.Errorf("devnet: bob balance = %s, want 600 (all 3 txs applied)", bobBal)
	}
}

// MIT License
//
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. SEC-G01 regression tests — genesis vault address protection.
// Verifies that transactions targeting GenesisVaultAddress are rejected
// at the execution layer (committed in 99b67b0).
package core

import (
	"math/big"
	"testing"

	types "github.com/ramseyauron/quantix/src/core/transaction"
)

const (
	secG01Alice = "xSecG01Alice0000000000000000000"
	secG01Bob   = "xSecG01Bob00000000000000000000"
)

// TestSEC_G01_TxToVault_Rejected verifies that a normal user transaction with
// receiver = GenesisVaultAddress is rejected at the execution layer.
func TestSEC_G01_TxToVault_Rejected(t *testing.T) {
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		secG01Alice: big.NewInt(1000),
	})
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	tx := makeTx(secG01Alice, GenesisVaultAddress, 100, 0)
	_, err := bc.ExecuteBlock(makeBlock(5, []*types.Transaction{tx}))
	if err == nil {
		t.Error("SEC-G01: tx to GenesisVaultAddress should be rejected at execution layer")
	}
}

// TestSEC_G01_StateUnchanged_OnVaultTx verifies atomicity: a block containing
// a vault-targeted tx leaves state completely unchanged.
func TestSEC_G01_StateUnchanged_OnVaultTx(t *testing.T) {
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		secG01Alice: big.NewInt(1000),
	})
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	stateDB := NewStateDB(db)
	aliceBefore := new(big.Int).Set(stateDB.GetBalance(secG01Alice))

	tx := makeTx(secG01Alice, GenesisVaultAddress, 100, 0)
	_, _ = bc.ExecuteBlock(makeBlock(5, []*types.Transaction{tx}))

	stateDB2 := NewStateDB(db)
	aliceAfter := stateDB2.GetBalance(secG01Alice)
	vaultAfter := stateDB2.GetBalance(GenesisVaultAddress)

	if aliceAfter.Cmp(aliceBefore) != 0 {
		t.Errorf("alice balance should be unchanged: before=%s after=%s", aliceBefore, aliceAfter)
	}
	if vaultAfter.Sign() != 0 {
		t.Errorf("vault balance should remain zero (no funds sent): got %s", vaultAfter)
	}
}

// TestSEC_G01_NormalTx_Unaffected verifies that the guard only applies to
// vault-targeted txs — normal transactions are not blocked.
func TestSEC_G01_NormalTx_Unaffected(t *testing.T) {
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		secG01Alice: big.NewInt(1000),
	})
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	tx := makeTx(secG01Alice, secG01Bob, 100, 0)
	_, err := bc.ExecuteBlock(makeBlock(5, []*types.Transaction{tx}))
	if err != nil {
		t.Errorf("SEC-G01 guard should not affect normal transactions: %v", err)
	}

	stateDB := NewStateDB(db)
	bobBal := stateDB.GetBalance(secG01Bob)
	if bobBal.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("bob should have received 100 nQTX: got %s", bobBal)
	}
}

// TestSEC_G01_VaultConstant_IsExpected documents the genesis vault address
// constant so that any change to it is caught by test failure.
func TestSEC_G01_VaultConstant_IsExpected(t *testing.T) {
	const expected = "0000000000000000000000000000000000000001"
	if GenesisVaultAddress != expected {
		t.Errorf("GenesisVaultAddress constant changed: want %q got %q", expected, GenesisVaultAddress)
	}
}

// TestSEC_G01_MultiTx_VaultInBlock_RejectsWholeBlock verifies that a block
// containing a mix of valid txs + one vault-targeted tx rejects the entire block.
func TestSEC_G01_MultiTx_VaultInBlock_RejectsWholeBlock(t *testing.T) {
	db := newTestDB(t)
	seedStateDB(t, db, map[string]*big.Int{
		secG01Alice: big.NewInt(2000),
	})
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	tx1 := makeTx(secG01Alice, secG01Bob, 100, 0)          // valid
	tx2 := makeTx(secG01Alice, GenesisVaultAddress, 50, 1) // SEC-G01 violation

	_, err := bc.ExecuteBlock(makeBlock(5, []*types.Transaction{tx1, tx2}))
	if err == nil {
		t.Error("block containing a vault-targeted tx should be rejected entirely")
	}

	// tx1 should NOT have been applied (tx2 caused block failure).
	stateDB := NewStateDB(db)
	bobBal := stateDB.GetBalance(secG01Bob)
	if bobBal.Sign() != 0 {
		t.Errorf("tx1 should not have been applied: bob has %s nQTX", bobBal)
	}
}

// TestSEC_G01_IsDistributionComplete_InitiallyFalse documents that
// IsDistributionComplete returns false for a fresh blockchain (vault not yet
// distributed — confirmed non-nil storage needed; simple constant check here).
func TestSEC_G01_VaultAddress_IsNot_NormalAddress(t *testing.T) {
	// The vault address is a special sentinel — must not be a normal user addr.
	// It starts with all zeros + 1, making it an easily identifiable sentinel.
	if len(GenesisVaultAddress) == 0 {
		t.Error("GenesisVaultAddress must not be empty")
	}
	// Confirm it could never be generated as a SHA-256 fingerprint
	// (which starts with meaningful entropy, not all zeros).
	allZeroPrefix := "00000000000000000000000000000000000000"
	if len(GenesisVaultAddress) < len(allZeroPrefix) ||
		GenesisVaultAddress[:len(allZeroPrefix)] != allZeroPrefix {
		t.Errorf("GenesisVaultAddress should have all-zero prefix for easy sentinel detection: %s", GenesisVaultAddress)
	}
}

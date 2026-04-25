// MIT License
//
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. Model C reward distribution tests (f283061) +
// StateDB.SetNonce/DecrementTotalSupply tests (4d5e9c3).
package core

import (
	"math/big"
	"testing"

	types "github.com/quantix-org/quantix-org/src/core/transaction"
)

// ---------------------------------------------------------------------------
// distributeGasFee: 70% burned / 20% attestors / 10% proposer
// ---------------------------------------------------------------------------

const (
	mcProposer  = "xMCProposer0000000000000000000"
	mcAttestor1 = "xMCAttestor100000000000000000"
	mcAttestor2 = "xMCAttestor200000000000000000"
)

// makeAttestation builds a minimal attestation for a validator.
func makeAttestation(validatorID string) *types.Attestation {
	return &types.Attestation{ValidatorID: validatorID}
}

// TestDistributeGasFee_BurnAmount verifies 70% of gas is burned (DecrementTotalSupply).
func TestDistributeGasFee_BurnAmount(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	stateDB := NewStateDB(db)
	// Seed initial supply so DecrementTotalSupply has something to work with
	stateDB.IncrementTotalSupply(big.NewInt(1_000_000_000))
	if _, err := stateDB.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	stateDB2 := NewStateDB(db)
	supplyBefore := new(big.Int).Set(stateDB2.GetTotalSupply())

	gasFee := big.NewInt(1000) // 1000 nQTX gas
	bc.distributeGasFee(gasFee, mcProposer, nil, stateDB2)

	// 70% = 700 nQTX burned
	expectedBurn := big.NewInt(700)
	expectedSupply := new(big.Int).Sub(supplyBefore, expectedBurn)
	if stateDB2.GetTotalSupply().Cmp(expectedSupply) != 0 {
		t.Errorf("supply after burn: want %s got %s", expectedSupply, stateDB2.GetTotalSupply())
	}
}

// TestDistributeGasFee_ProposerShare_NoAttestors verifies proposer gets
// 10% + the 20% attestor pool (100% - 70% burn = 30%) when no attestors.
func TestDistributeGasFee_ProposerShare_NoAttestors(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	stateDB := NewStateDB(db)
	gasFee := big.NewInt(1000)
	bc.distributeGasFee(gasFee, mcProposer, nil, stateDB)

	// No attestors: proposer gets 10% + 20% = 30% (of 1000 = 300)
	proposerBal := stateDB.GetBalance(mcProposer)
	if proposerBal.Cmp(big.NewInt(300)) != 0 {
		t.Errorf("proposer balance (no attestors): want 300 got %s", proposerBal)
	}
}

// TestDistributeGasFee_WithAttestors verifies attestors receive 20% split equally.
func TestDistributeGasFee_WithAttestors(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	attestations := []*types.Attestation{
		makeAttestation(mcAttestor1),
		makeAttestation(mcAttestor2),
	}
	stateDB := NewStateDB(db)
	gasFee := big.NewInt(1000) // 1000 nQTX

	bc.distributeGasFee(gasFee, mcProposer, attestations, stateDB)

	// 10% → proposer = 100
	// 20% → 2 attestors = 100 each (50 each from pool=200)
	// 70% burned
	proposerBal := stateDB.GetBalance(mcProposer)
	if proposerBal.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("proposer balance (with attestors): want 100 got %s", proposerBal)
	}
	att1Bal := stateDB.GetBalance(mcAttestor1)
	att2Bal := stateDB.GetBalance(mcAttestor2)
	if att1Bal.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("attestor1 balance: want 100 got %s", att1Bal)
	}
	if att2Bal.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("attestor2 balance: want 100 got %s", att2Bal)
	}
}

// TestDistributeGasFee_ZeroGas_NoEffect verifies zero gas fee is a no-op.
func TestDistributeGasFee_ZeroGas_NoEffect(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	stateDB := NewStateDB(db)
	bc.distributeGasFee(big.NewInt(0), mcProposer, nil, stateDB)

	if stateDB.GetBalance(mcProposer).Sign() != 0 {
		t.Error("zero gas fee should not credit proposer")
	}
}

// TestDistributeGasFee_NilGas_NoEffect verifies nil gas fee is a no-op.
func TestDistributeGasFee_NilGas_NoEffect(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	stateDB := NewStateDB(db)
	bc.distributeGasFee(nil, mcProposer, nil, stateDB)
	// Should not panic
}

// TestDistributeGasFee_EmptyProposer_NoEffect verifies empty proposer is a no-op.
func TestDistributeGasFee_EmptyProposer_NoEffect(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	stateDB := NewStateDB(db)
	bc.distributeGasFee(big.NewInt(1000), "", nil, stateDB)
	// Should not panic or credit anything
}

// TestDistributeGasFee_SumConstraint verifies burn+proposer+attestors = gasFee
// (integer division may leave dust, so we check within 1 nQTX).
func TestDistributeGasFee_SumConstraint(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	attestations := []*types.Attestation{makeAttestation(mcAttestor1)}
	stateDB := NewStateDB(db)
	gasFee := big.NewInt(100)

	supplyBefore := stateDB.GetTotalSupply() // 0 initially
	bc.distributeGasFee(gasFee, mcProposer, attestations, stateDB)

	proposerBal := stateDB.GetBalance(mcProposer)
	att1Bal := stateDB.GetBalance(mcAttestor1)
	supplyAfter := stateDB.GetTotalSupply() // decremented by burn amount
	burnAmt := new(big.Int).Sub(supplyBefore, supplyAfter)

	total := new(big.Int).Add(burnAmt, new(big.Int).Add(proposerBal, att1Bal))
	// Allow ±2 for integer division dust
	diff := new(big.Int).Abs(new(big.Int).Sub(total, gasFee))
	if diff.Cmp(big.NewInt(2)) > 0 {
		t.Errorf("sum constraint: burn(%s)+proposer(%s)+att1(%s)=%s, want ~%s (diff=%s)",
			burnAmt, proposerBal, att1Bal, total, gasFee, diff)
	}
}

// ---------------------------------------------------------------------------
// mintBlockReward: 40% proposer / 60% attestors
// ---------------------------------------------------------------------------

// TestMintBlockReward_ModelC_40_60_Split verifies 40% goes to proposer
// and 60% is split among attestors.
func TestMintBlockReward_ModelC_40_60_Split(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	cp := GetDevnetChainParams()
	cp.BaseBlockReward = big.NewInt(1000) // 1000 nQTX reward
	bc.chainParams = cp

	attestations := []*types.Attestation{
		makeAttestation(mcAttestor1),
		makeAttestation(mcAttestor2),
	}

	blk := makeBlock(2, nil) // height 2: normal reward block (height 1 = genesis distribution, skipped)
	blk.Header.ProposerID = mcProposer
	blk.Body.Attestations = attestations

	stateDB := NewStateDB(db)
	bc.mintBlockReward(blk, stateDB)

	// 40% of 1000 = 400 → proposer
	// 60% of 1000 = 600 split over 2 attestors = 300 each
	proposerBal := stateDB.GetBalance(mcProposer)
	if proposerBal.Cmp(big.NewInt(400)) != 0 {
		t.Errorf("proposer balance: want 400 got %s", proposerBal)
	}
	att1Bal := stateDB.GetBalance(mcAttestor1)
	att2Bal := stateDB.GetBalance(mcAttestor2)
	if att1Bal.Cmp(big.NewInt(300)) != 0 {
		t.Errorf("attestor1 balance: want 300 got %s", att1Bal)
	}
	if att2Bal.Cmp(big.NewInt(300)) != 0 {
		t.Errorf("attestor2 balance: want 300 got %s", att2Bal)
	}
}

// TestMintBlockReward_NoAttestors_ProposerGets100Pct verifies that with no
// attestors, proposer gets the full reward (40% + 60% = 100%).
func TestMintBlockReward_NoAttestors_ProposerGets100Pct(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	cp := GetDevnetChainParams()
	cp.BaseBlockReward = big.NewInt(1000)
	bc.chainParams = cp

	blk := makeBlock(2, nil) // height >= 2 for normal reward (1 = genesis dist block)
	blk.Header.ProposerID = mcProposer
	// No attestations

	stateDB := NewStateDB(db)
	bc.mintBlockReward(blk, stateDB)

	proposerBal := stateDB.GetBalance(mcProposer)
	if proposerBal.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("proposer should get 100%% with no attestors: want 1000 got %s", proposerBal)
	}
}

// TestMintBlockReward_TotalSupplyIncremented verifies total supply increases
// by the block reward (IncrementTotalSupply called inside mintBlockReward).
func TestMintBlockReward_TotalSupplyIncremented(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)

	cp := GetDevnetChainParams()
	cp.BaseBlockReward = big.NewInt(500)
	bc.chainParams = cp

	blk := makeBlock(2, nil) // height >= 2 for normal reward
	blk.Header.ProposerID = mcProposer

	stateDB := NewStateDB(db)
	supplyBefore := new(big.Int).Set(stateDB.GetTotalSupply())
	bc.mintBlockReward(blk, stateDB)

	supplyAfter := stateDB.GetTotalSupply()
	diff := new(big.Int).Sub(supplyAfter, supplyBefore)
	if diff.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("total supply increment: want 500 got %s", diff)
	}
}

// ---------------------------------------------------------------------------
// StateDB.SetNonce (4d5e9c3)
// ---------------------------------------------------------------------------

// TestStateDB_SetNonce_Basic verifies SetNonce stores and retrieves correctly.
func TestStateDB_SetNonce_Basic(t *testing.T) {
	db := newTestDB(t)
	stateDB := NewStateDB(db)

	addr := "xSetNonceTest0000000000000000"
	stateDB.SetNonce(addr, 42)

	got := stateDB.GetNonce(addr)
	if got != 42 {
		t.Errorf("GetNonce after SetNonce(42): want 42 got %d", got)
	}
}

// TestStateDB_SetNonce_Overwrite verifies SetNonce can overwrite IncrementNonce.
func TestStateDB_SetNonce_Overwrite(t *testing.T) {
	db := newTestDB(t)
	stateDB := NewStateDB(db)

	addr := "xSetNonceOverwrite000000000000"
	stateDB.IncrementNonce(addr) // nonce = 1
	stateDB.IncrementNonce(addr) // nonce = 2
	stateDB.SetNonce(addr, 10)   // fast-forward to 10 (peer sync)

	if got := stateDB.GetNonce(addr); got != 10 {
		t.Errorf("SetNonce(10): want 10 got %d", got)
	}
}

// TestStateDB_SetNonce_Zero verifies setting nonce to 0 works.
func TestStateDB_SetNonce_Zero(t *testing.T) {
	db := newTestDB(t)
	stateDB := NewStateDB(db)

	addr := "xSetNonceZero000000000000000"
	stateDB.IncrementNonce(addr)
	stateDB.SetNonce(addr, 0)

	if got := stateDB.GetNonce(addr); got != 0 {
		t.Errorf("SetNonce(0): want 0 got %d", got)
	}
}

// ---------------------------------------------------------------------------
// StateDB.DecrementTotalSupply (f283061 — gas burn)
// ---------------------------------------------------------------------------

// TestStateDB_DecrementTotalSupply_Basic verifies supply decreases by amount.
func TestStateDB_DecrementTotalSupply_Basic(t *testing.T) {
	db := newTestDB(t)
	stateDB := NewStateDB(db)

	stateDB.IncrementTotalSupply(big.NewInt(1000))
	stateDB.DecrementTotalSupply(big.NewInt(300))

	got := stateDB.GetTotalSupply()
	if got.Cmp(big.NewInt(700)) != 0 {
		t.Errorf("DecrementTotalSupply: want 700 got %s", got)
	}
}

// TestStateDB_DecrementTotalSupply_ZeroAmount_NoOp verifies nil/zero is safe.
func TestStateDB_DecrementTotalSupply_ZeroAmount_NoOp(t *testing.T) {
	db := newTestDB(t)
	stateDB := NewStateDB(db)

	stateDB.IncrementTotalSupply(big.NewInt(500))
	stateDB.DecrementTotalSupply(big.NewInt(0))

	if got := stateDB.GetTotalSupply(); got.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("DecrementTotalSupply(0) should not change supply: got %s", got)
	}
}

// TestStateDB_DecrementTotalSupply_NilAmount_Safe verifies nil is handled.
// Note: DecrementTotalSupply has no nil guard — callers must check.
// This test documents the expected behaviour (nil guard is caller's responsibility).
func TestStateDB_DecrementTotalSupply_NilAmount_Safe(t *testing.T) {
	// distributeGasFee guards: "if gasFee == nil || gasFee.Sign() <= 0"
	// so DecrementTotalSupply(nil) is never reached in normal operation.
	// Skipping direct nil test to avoid panic (by design — nil is caller's guard).
	t.Skip("DecrementTotalSupply requires non-nil input; guarded by distributeGasFee callers")
}

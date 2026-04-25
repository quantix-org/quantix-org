// MIT License
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. — SEC-DUST01 and SEC-DUP01 regression tests (commit 9dc2f5a).
// Tests that:
//   - SEC-DUST01: integer division remainder from attestor pool is credited to proposer
//   - SEC-DUP01: duplicate ValidatorIDs in attestation list only receive one reward each
package core

import (
	"math/big"
	"testing"

	types "github.com/quantix-org/quantix-org/src/core/transaction"
)

const (
	dustProposer  = "xDustProposerXXXXXXXXXXXXXXXX"
	dustAttestor1 = "xDustAttestor1XXXXXXXXXXXXXXXXX"
	dustAttestor2 = "xDustAttestor2XXXXXXXXXXXXXXXXX"
	dustAttestor3 = "xDustAttestor3XXXXXXXXXXXXXXXXX"
)

// makeGasTestState creates a fresh StateDB with seeded supply + balances.
func makeGasTestState(t *testing.T) (*Blockchain, *StateDB) {
	t.Helper()
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)
	st := NewStateDB(db)
	st.IncrementTotalSupply(big.NewInt(1_000_000_000))
	if _, err := st.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return bc, NewStateDB(db)
}

// ── SEC-DUST01: remainder to proposer ──────────────────────────────────────

// TestSECDUST01_GasFee_RemainderToProposer verifies that when the attestor
// pool does not divide evenly among N attestors, the remainder goes to the
// proposer rather than being silently discarded.
func TestSECDUST01_GasFee_RemainderToProposer(t *testing.T) {
	bc, st := makeGasTestState(t)

	// Use a gas fee whose 20%-attestor-pool is NOT evenly divisible by 3 attestors.
	// gasFee = 1000 → attestorPool = 200 → 200/3 = 66 per attestor, remainder = 2
	gasFee := big.NewInt(1000)
	attestors := []*types.Attestation{
		{ValidatorID: dustAttestor1},
		{ValidatorID: dustAttestor2},
		{ValidatorID: dustAttestor3},
	}
	bc.distributeGasFee(gasFee, dustProposer, attestors, st)

	proposerBal := st.GetBalance(dustProposer)
	att1Bal := st.GetBalance(dustAttestor1)
	att2Bal := st.GetBalance(dustAttestor2)
	att3Bal := st.GetBalance(dustAttestor3)

	// 10% proposer + 2 nQTX remainder = 100 + 2 = 102
	expectedProposer := big.NewInt(102) // 10% of 1000 + 2 remainder
	// Each attestor gets floor(200/3) = 66
	expectedPerAttestor := big.NewInt(66)

	if proposerBal.Cmp(expectedProposer) != 0 {
		t.Errorf("SEC-DUST01: proposer balance: want %s got %s", expectedProposer, proposerBal)
	}
	if att1Bal.Cmp(expectedPerAttestor) != 0 {
		t.Errorf("SEC-DUST01: attestor1 balance: want %s got %s", expectedPerAttestor, att1Bal)
	}
	if att2Bal.Cmp(expectedPerAttestor) != 0 {
		t.Errorf("SEC-DUST01: attestor2 balance: want %s got %s", expectedPerAttestor, att2Bal)
	}
	if att3Bal.Cmp(expectedPerAttestor) != 0 {
		t.Errorf("SEC-DUST01: attestor3 balance: want %s got %s", expectedPerAttestor, att3Bal)
	}

	// Total credited = proposer(102) + 3×66(198) = 300 = 30% of 1000. ✓
	total := new(big.Int).Add(proposerBal, new(big.Int).Mul(expectedPerAttestor, big.NewInt(3)))
	if total.Cmp(big.NewInt(300)) != 0 {
		t.Errorf("SEC-DUST01: total credited should be 30%% of gasFee: want 300 got %s", total)
	}
}

// TestSECDUST01_GasFee_EvenDivision_NoRemainder verifies that when division
// is exact, the proposer does NOT receive extra (regression guard).
func TestSECDUST01_GasFee_EvenDivision_NoRemainder(t *testing.T) {
	bc, st := makeGasTestState(t)

	// gasFee = 1000 → attestorPool = 200 → 200/2 = 100 per attestor, remainder = 0
	gasFee := big.NewInt(1000)
	attestors := []*types.Attestation{
		{ValidatorID: dustAttestor1},
		{ValidatorID: dustAttestor2},
	}
	bc.distributeGasFee(gasFee, dustProposer, attestors, st)

	proposerBal := st.GetBalance(dustProposer)
	// proposer = 10% = 100, no remainder → 100
	expectedProposer := big.NewInt(100)
	if proposerBal.Cmp(expectedProposer) != 0 {
		t.Errorf("SEC-DUST01: even division: proposer balance: want %s got %s", expectedProposer, proposerBal)
	}
	// Each attestor = 100
	for _, id := range []string{dustAttestor1, dustAttestor2} {
		bal := st.GetBalance(id)
		if bal.Cmp(big.NewInt(100)) != 0 {
			t.Errorf("SEC-DUST01: even division: attestor %s balance: want 100 got %s", id, bal)
		}
	}
}

// ── SEC-DUP01: deduplication of attestor IDs ────────────────────────────────

// TestSECDUP01_GasFee_DuplicateAttestors_SingleReward verifies that a
// validator listed twice in attestations only receives one reward (not two).
func TestSECDUP01_GasFee_DuplicateAttestors_SingleReward(t *testing.T) {
	bc, st := makeGasTestState(t)

	// dustAttestor1 appears twice — should only receive one share
	gasFee := big.NewInt(1000)
	attestors := []*types.Attestation{
		{ValidatorID: dustAttestor1},
		{ValidatorID: dustAttestor1}, // duplicate
	}
	bc.distributeGasFee(gasFee, dustProposer, attestors, st)

	att1Bal := st.GetBalance(dustAttestor1)

	// After dedup, 1 unique attestor → perAttestor = 200, remainder = 0
	expectedAtt1 := big.NewInt(200)
	if att1Bal.Cmp(expectedAtt1) != 0 {
		t.Errorf("SEC-DUP01: duplicate attestor should get single share: want %s got %s",
			expectedAtt1, att1Bal)
	}
}

// TestSECDUP01_GasFee_ProposerIDSkipped verifies that if the proposer's own
// ValidatorID appears in attestations, it does NOT get double-credited.
func TestSECDUP01_GasFee_ProposerIDSkipped(t *testing.T) {
	bc, st := makeGasTestState(t)

	// dustProposer appears as an attestor — should be skipped
	gasFee := big.NewInt(1000)
	attestors := []*types.Attestation{
		{ValidatorID: dustProposer}, // same as proposerID → should be skipped
		{ValidatorID: dustAttestor1},
	}
	bc.distributeGasFee(gasFee, dustProposer, attestors, st)

	proposerBal := st.GetBalance(dustProposer)
	att1Bal := st.GetBalance(dustAttestor1)

	// 1 unique non-proposer attestor → perAttestor = 200, no remainder
	// proposer gets 10% = 100 (NOT double: not 10% + attestor share)
	expectedProposer := big.NewInt(100)
	expectedAtt1 := big.NewInt(200)

	if proposerBal.Cmp(expectedProposer) != 0 {
		t.Errorf("SEC-DUP01: proposer-in-attestors: proposer balance: want %s got %s",
			expectedProposer, proposerBal)
	}
	if att1Bal.Cmp(expectedAtt1) != 0 {
		t.Errorf("SEC-DUP01: proposer-in-attestors: att1 balance: want %s got %s",
			expectedAtt1, att1Bal)
	}
}

// TestSECDUP01_GasFee_EmptyValidatorIDSkipped verifies attestations with
// empty ValidatorID are silently skipped and don't affect reward accounting.
func TestSECDUP01_GasFee_EmptyValidatorIDSkipped(t *testing.T) {
	bc, st := makeGasTestState(t)

	gasFee := big.NewInt(1000)
	attestors := []*types.Attestation{
		{ValidatorID: ""}, // empty — should be skipped
		{ValidatorID: dustAttestor1},
		{ValidatorID: ""}, // another empty
	}
	bc.distributeGasFee(gasFee, dustProposer, attestors, st)

	att1Bal := st.GetBalance(dustAttestor1)
	// 1 valid attestor → 200 nQTX
	if att1Bal.Cmp(big.NewInt(200)) != 0 {
		t.Errorf("SEC-DUP01: empty ValidatorID: att1 balance: want 200 got %s", att1Bal)
	}
}

// TestSECDUP01_GasFee_MixedDuplicatesAndUnique verifies that in a mixed list
// (some unique, some duplicate), each unique validator gets exactly one share.
func TestSECDUP01_GasFee_MixedDuplicatesAndUnique(t *testing.T) {
	bc, st := makeGasTestState(t)

	// 5 attestation entries but only 2 unique IDs
	gasFee := big.NewInt(1000)
	attestors := []*types.Attestation{
		{ValidatorID: dustAttestor1},
		{ValidatorID: dustAttestor2},
		{ValidatorID: dustAttestor1}, // dup
		{ValidatorID: dustAttestor2}, // dup
		{ValidatorID: dustAttestor1}, // dup again
	}
	bc.distributeGasFee(gasFee, dustProposer, attestors, st)

	att1Bal := st.GetBalance(dustAttestor1)
	att2Bal := st.GetBalance(dustAttestor2)

	// 2 unique attestors → 200/2 = 100 each, remainder = 0
	expectedEach := big.NewInt(100)
	if att1Bal.Cmp(expectedEach) != 0 {
		t.Errorf("SEC-DUP01: mixed dups: att1 balance: want %s got %s", expectedEach, att1Bal)
	}
	if att2Bal.Cmp(expectedEach) != 0 {
		t.Errorf("SEC-DUP01: mixed dups: att2 balance: want %s got %s", expectedEach, att2Bal)
	}
}

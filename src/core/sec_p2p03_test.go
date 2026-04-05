// MIT License
//
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. SEC-P2P03 partial mitigation tests (48f19bf).
// Verifies that attestation counts are capped at MaxValidators in both
// distributeGasFee and mintBlockReward to bound fake-validator reward attacks.
package core

import (
	"fmt"
	"math/big"
	"testing"

	types "github.com/ramseyauron/quantix/src/core/transaction"
)

const (
	secP2P03Proposer = "xP2P03Proposer0000000000000000"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeAttestations creates n attestations with distinct ValidatorIDs.
func makeAttestations(n int) []*types.Attestation {
	atts := make([]*types.Attestation, n)
	for i := 0; i < n; i++ {
		atts[i] = &types.Attestation{
			ValidatorID: fmt.Sprintf("xValidator%05d000000000000000", i),
		}
	}
	return atts
}

// bcWithMaxValidators returns a minimalBC with ConsensusConfig.MaxValidators set.
func bcWithMaxValidators(t *testing.T, maxValidators int) *Blockchain {
	t.Helper()
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)
	cp := GetDevnetChainParams()
	cc := GetDefaultConsensusConfig()
	cc.MaxValidators = maxValidators
	cp.ConsensusConfig = cc
	bc.chainParams = cp
	return bc
}

// ---------------------------------------------------------------------------
// distributeGasFee — attestation count cap (SEC-P2P03)
// ---------------------------------------------------------------------------

// TestSECP2P03_GasFee_AttestationCapEnforced verifies that when more attestations
// than MaxValidators are provided, only MaxValidators are processed.
func TestSECP2P03_GasFee_AttestationCapEnforced(t *testing.T) {
	maxV := 5
	bc := bcWithMaxValidators(t, maxV)
	db := newTestDB(t)

	// 10 attestations with MaxValidators=5: only 5 should receive rewards
	attestations := makeAttestations(10)
	stateDB := NewStateDB(db)
	gasFee := big.NewInt(10000)

	bc.distributeGasFee(gasFee, secP2P03Proposer, attestations, stateDB)

	// Validators 0..4 should have balance > 0; validators 5..9 should have 0
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("xValidator%05d000000000000000", i)
		if stateDB.GetBalance(id).Sign() == 0 {
			t.Errorf("validator[%d] should have received gas reward (within cap)", i)
		}
	}
	for i := 5; i < 10; i++ {
		id := fmt.Sprintf("xValidator%05d000000000000000", i)
		if stateDB.GetBalance(id).Sign() > 0 {
			t.Errorf("validator[%d] should NOT receive reward (exceeds cap)", i)
		}
	}
}

// TestSECP2P03_GasFee_ExactlyAtCap verifies attestations == MaxValidators all receive rewards.
func TestSECP2P03_GasFee_ExactlyAtCap(t *testing.T) {
	maxV := 4
	bc := bcWithMaxValidators(t, maxV)
	db := newTestDB(t)

	attestations := makeAttestations(maxV)
	stateDB := NewStateDB(db)
	bc.distributeGasFee(big.NewInt(10000), secP2P03Proposer, attestations, stateDB)

	for i := 0; i < maxV; i++ {
		id := fmt.Sprintf("xValidator%05d000000000000000", i)
		if stateDB.GetBalance(id).Sign() == 0 {
			t.Errorf("validator[%d] should have received reward (at cap)", i)
		}
	}
}

// TestSECP2P03_GasFee_BelowCap verifies normal case (< MaxValidators) is unaffected.
func TestSECP2P03_GasFee_BelowCap(t *testing.T) {
	maxV := 10
	bc := bcWithMaxValidators(t, maxV)
	db := newTestDB(t)

	// 3 attestations with MaxValidators=10: all 3 should get rewards
	attestations := makeAttestations(3)
	stateDB := NewStateDB(db)
	bc.distributeGasFee(big.NewInt(10000), secP2P03Proposer, attestations, stateDB)

	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("xValidator%05d000000000000000", i)
		if stateDB.GetBalance(id).Sign() == 0 {
			t.Errorf("validator[%d] should have received reward (below cap)", i)
		}
	}
}

// TestSECP2P03_GasFee_DefaultCap100 verifies default cap is 100 when ConsensusConfig is nil.
func TestSECP2P03_GasFee_DefaultCap100(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	bc.SetDevMode(true)
	// Leave chainParams as-is (ConsensusConfig from GetDevnetChainParams)
	cp := GetDevnetChainParams()
	cp.ConsensusConfig = nil // no consensus config → fallback to 100
	bc.chainParams = cp

	// 150 attestations with nil ConsensusConfig → default cap 100
	attestations := makeAttestations(150)
	stateDB := NewStateDB(db)
	bc.distributeGasFee(big.NewInt(150000), secP2P03Proposer, attestations, stateDB)

	// Validators 0..99 should have received rewards
	rewarded := 0
	for i := 0; i < 150; i++ {
		id := fmt.Sprintf("xValidator%05d000000000000000", i)
		if stateDB.GetBalance(id).Sign() > 0 {
			rewarded++
		}
	}
	if rewarded > 100 {
		t.Errorf("default cap should be 100, but %d validators got rewards", rewarded)
	}
}

// ---------------------------------------------------------------------------
// mintBlockReward — attestation count cap (SEC-P2P03)
// ---------------------------------------------------------------------------

// TestSECP2P03_MintReward_AttestationCapEnforced verifies that mintBlockReward
// only distributes the 60% attestor pool to at most MaxValidators attestors.
func TestSECP2P03_MintReward_AttestationCapEnforced(t *testing.T) {
	maxV := 3
	bc := bcWithMaxValidators(t, maxV)
	db := newTestDB(t)

	cp := bc.chainParams
	cp.BaseBlockReward = big.NewInt(300) // easy math
	bc.chainParams = cp

	// 6 attestors, cap=3: only first 3 should receive the 60% pool
	attestations := makeAttestations(6)
	blk := makeBlock(2, nil) // height 2 = normal reward
	blk.Header.ProposerID = secP2P03Proposer
	blk.Body.Attestations = attestations

	stateDB := NewStateDB(db)
	bc.mintBlockReward(blk, stateDB)

	// Proposer gets 40% of 300 = 120
	proposerBal := stateDB.GetBalance(secP2P03Proposer)
	if proposerBal.Cmp(big.NewInt(120)) != 0 {
		t.Errorf("proposer balance: want 120 got %s", proposerBal)
	}

	// 60% = 180 split over 3 (not 6): 60 each
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("xValidator%05d000000000000000", i)
		bal := stateDB.GetBalance(id)
		if bal.Cmp(big.NewInt(60)) != 0 {
			t.Errorf("validator[%d] balance: want 60 got %s", i, bal)
		}
	}
	// Validators 3..5 should have 0 (capped out)
	for i := 3; i < 6; i++ {
		id := fmt.Sprintf("xValidator%05d000000000000000", i)
		if stateDB.GetBalance(id).Sign() > 0 {
			t.Errorf("validator[%d] should NOT get reward (over cap)", i)
		}
	}
}

// TestSECP2P03_MaxValidatorsConstant documents the default MaxValidators value.
func TestSECP2P03_MaxValidatorsConstant(t *testing.T) {
	cc := GetDefaultConsensusConfig()
	if cc.MaxValidators != 100 {
		t.Errorf("default MaxValidators: want 100 got %d", cc.MaxValidators)
	}
}

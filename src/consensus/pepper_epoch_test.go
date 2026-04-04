// PEPPER Sprint2 — consensus additional coverage: epoch, staking helpers, BytesToUint256
package consensus

import (
	"math/big"
	"testing"
)

// ── ValidatorSet.ProcessEpochTransition ──────────────────────────────────────

func TestProcessEpochTransition_NoPanic(t *testing.T) {
	vs := makeVSWithValidators(t, 3)
	vs.ProcessEpochTransition(0)
	vs.ProcessEpochTransition(1)
}

// ── ValidatorSet.GetEpochStakeDistribution ───────────────────────────────────

func TestGetEpochStakeDistribution_Empty(t *testing.T) {
	minStake := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e9))
	vs := NewValidatorSet(minStake)
	dist := vs.GetEpochStakeDistribution(0)
	if dist == nil {
		t.Error("GetEpochStakeDistribution should return non-nil map")
	}
	if len(dist) != 0 {
		t.Errorf("empty validator set should have 0 distribution, got %d", len(dist))
	}
}

func TestGetEpochStakeDistribution_WithValidators(t *testing.T) {
	vs := makeVSWithValidators(t, 3)
	dist := vs.GetEpochStakeDistribution(0)
	if dist == nil {
		t.Error("GetEpochStakeDistribution returned nil")
	}
	// With 3 validators, distribution should have entries
	if len(dist) == 0 {
		t.Error("expected non-empty distribution with validators")
	}
}

// ── BytesToUint256 ────────────────────────────────────────────────────────────

func TestBytesToUint256_Basic(t *testing.T) {
	data := []byte{0, 0, 0, 1}
	result := BytesToUint256(data)
	if result == nil {
		t.Fatal("BytesToUint256 returned nil")
	}
	if result.IsZero() {
		t.Error("BytesToUint256([0,0,0,1]) should be non-zero")
	}
}

func TestBytesToUint256_Empty(t *testing.T) {
	result := BytesToUint256([]byte{})
	if result == nil {
		t.Fatal("BytesToUint256(empty) returned nil")
	}
}

func TestBytesToUint256_AllZeros(t *testing.T) {
	result := BytesToUint256(make([]byte, 32))
	if result == nil {
		t.Fatal("BytesToUint256 returned nil")
	}
	if !result.IsZero() {
		t.Error("BytesToUint256(zeros) should be zero")
	}
}

// ── StakedValidator helpers ───────────────────────────────────────────────────

func TestStakedValidator_GetStakeInQTX(t *testing.T) {
	vs := makeVSWithValidators(t, 2)
	active := vs.GetActiveValidators(0)
	if len(active) == 0 {
		t.Skip("no active validators")
	}
	for _, v := range active {
		qtx := v.GetStakeInQTX()
		if qtx <= 0 {
			t.Errorf("validator %s: GetStakeInQTX should be > 0, got %f", v.ID, qtx)
		}
	}
}

// ── QuorumVerifier edge cases ─────────────────────────────────────────────────

func TestQuorumVerifier_LargeNetwork(t *testing.T) {
	qv := NewQuorumVerifier(100, 30, 2.0/3.0)
	if !qv.VerifySafety() {
		t.Error("100 nodes, 30 faulty, 2/3 quorum should be safe")
	}
	sz := qv.CalculateMinQuorumSize()
	if sz < 67 {
		t.Errorf("min quorum for 100 nodes at 2/3 should be ~67, got %d", sz)
	}
}

func TestQuorumVerifier_SingleNode(t *testing.T) {
	qv := NewQuorumVerifier(1, 0, 1.0)
	sz := qv.CalculateMinQuorumSize()
	if sz != 1 {
		t.Errorf("single node quorum: want 1, got %d", sz)
	}
}

// ── VDFCache additional ───────────────────────────────────────────────────────

func TestVDFCache_MultipleEpochs(t *testing.T) {
	vc := NewVDFCache()
	vc.MarkVerified(1, "A")
	vc.MarkVerified(1, "B")
	vc.MarkVerified(2, "A")

	if !vc.IsVerified(1, "A") {
		t.Error("epoch 1, A should be verified")
	}
	if !vc.IsVerified(1, "B") {
		t.Error("epoch 1, B should be verified")
	}
	if !vc.IsVerified(2, "A") {
		t.Error("epoch 2, A should be verified")
	}
	if vc.IsVerified(2, "B") {
		t.Error("epoch 2, B should NOT be verified")
	}
}

func TestVDFCache_PruneAll(t *testing.T) {
	vc := NewVDFCache()
	vc.MarkVerified(1, "A")
	vc.MarkVerified(2, "B")
	vc.Prune(10) // prune everything before epoch 10
	if vc.IsVerified(1, "A") || vc.IsVerified(2, "B") {
		t.Error("all epochs before 10 should be pruned")
	}
}

// ── SelectCommittee determinism ───────────────────────────────────────────────

func TestStakeWeightedSelector_DeterministicSelection(t *testing.T) {
	vs := makeVSWithValidators(t, 4)
	sel := NewStakeWeightedSelector(vs)
	var seed [32]byte
	copy(seed[:], "fixed_deterministic_seed_bytes!!")

	p1 := sel.SelectProposer(1, seed)
	p2 := sel.SelectProposer(1, seed)
	if p1 == nil || p2 == nil {
		t.Skip("SelectProposer returned nil")
	}
	if p1.ID != p2.ID {
		t.Error("SelectProposer should be deterministic for same epoch/seed")
	}
}

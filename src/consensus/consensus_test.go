// MIT License
// Copyright (c) 2024 quantix-org

package consensus

import (
	"math/big"
	"testing"

	denom "github.com/quantix-org/quantix-org/src/params/denom"
)

// ============================================================
// QUORUM TESTS
// ============================================================

// TestQuorumBFTSafety verifies VerifySafety() with correct float comparison.
func TestQuorumBFTSafety(t *testing.T) {
	cases := []struct {
		total    int
		faulty   int
		fraction float64
		safe     bool
	}{
		{total: 4, faulty: 1, fraction: 0.67, safe: true},  // 1*3 < 4 ✓
		{total: 7, faulty: 2, fraction: 0.67, safe: true},  // 2*3 < 7 ✓
		{total: 21, faulty: 6, fraction: 0.67, safe: true}, // 6*3 < 21 ✓
		{total: 21, faulty: 7, fraction: 0.67, safe: false}, // 7*3 = 21, not < 21
		{total: 3, faulty: 1, fraction: 0.67, safe: false},  // 1*3 = 3, not < 3
		{total: 1, faulty: 0, fraction: 0.67, safe: true},  // 0*3 < 1 ✓
	}

	for _, c := range cases {
		qv := NewQuorumVerifier(c.total, c.faulty, c.fraction)
		got := qv.VerifySafety()
		if got != c.safe {
			t.Errorf("VerifySafety(total=%d, faulty=%d) = %v, want %v",
				c.total, c.faulty, got, c.safe)
		}
	}
}

// TestQuorumMinSize verifies quorum size calculation is correct
func TestQuorumMinSize(t *testing.T) {
	cases := []struct {
		total    int
		fraction float64
		minSize  int
	}{
		{total: 4, fraction: 0.67, minSize: 3},
		{total: 7, fraction: 0.67, minSize: 5},
		{total: 21, fraction: 0.67, minSize: 15},
		{total: 1, fraction: 0.67, minSize: 1},
		{total: 100, fraction: 0.67, minSize: 67},
	}

	for _, c := range cases {
		qv := NewQuorumVerifier(c.total, 0, c.fraction)
		got := qv.CalculateMinQuorumSize()
		if got != c.minSize {
			t.Errorf("CalculateMinQuorumSize(total=%d, fraction=%.2f) = %d, want %d",
				c.total, c.fraction, got, c.minSize)
		}
	}
}

// TestQuorumIntersection verifies that two quorums always share at least one honest node
func TestQuorumIntersection(t *testing.T) {
	cases := []struct {
		total      int
		faulty     int
		fraction   float64
		intersects bool
	}{
		{total: 4, faulty: 1, fraction: 0.67, intersects: true},
		{total: 21, faulty: 6, fraction: 0.67, intersects: true},
		{total: 3, faulty: 1, fraction: 0.50, intersects: false}, // 50% quorum insufficient
	}

	for _, c := range cases {
		qv := NewQuorumVerifier(c.total, c.faulty, c.fraction)
		got := qv.VerifyQuorumIntersection()
		if got != c.intersects {
			t.Errorf("VerifyQuorumIntersection(total=%d, faulty=%d, q=%.2f) = %v, want %v",
				c.total, c.faulty, c.fraction, got, c.intersects)
		}
	}
}

// TestOptimalQuorumFraction verifies optimal fraction is never below 2/3
func TestOptimalQuorumFraction(t *testing.T) {
	cases := []struct {
		faulty int
		total  int
		minVal float64
	}{
		{faulty: 0, total: 0, minVal: 2.0 / 3.0}, // edge: zero nodes
		{faulty: 1, total: 4, minVal: 2.0 / 3.0},
		{faulty: 6, total: 21, minVal: 2.0 / 3.0},
		{faulty: 10, total: 21, minVal: 2.0 / 3.0}, // high fault → fraction > 2/3
	}

	for _, c := range cases {
		got := CalculateOptimalQuorumFraction(c.faulty, c.total)
		if got < c.minVal-1e-9 {
			t.Errorf("CalculateOptimalQuorumFraction(%d, %d) = %.4f, want >= %.4f",
				c.faulty, c.total, got, c.minVal)
		}
	}
}

// TestQuorumCalculatorMaxFaulty verifies max faulty node calculation
func TestQuorumCalculatorMaxFaulty(t *testing.T) {
	cases := []struct {
		total     int
		fraction  float64
		maxFaulty int
	}{
		{total: 4, fraction: 0.67, maxFaulty: 1},
		{total: 21, fraction: 0.67, maxFaulty: 6},
		{total: 0, fraction: 0.67, maxFaulty: 0},
	}

	for _, c := range cases {
		qc := NewQuorumCalculator(c.fraction)
		got := qc.CalculateMaxFaulty(c.total)
		if got != c.maxFaulty {
			t.Errorf("CalculateMaxFaulty(total=%d, fraction=%.2f) = %d, want %d",
				c.total, c.fraction, got, c.maxFaulty)
		}
	}
}

// ============================================================
// VALIDATOR SET TESTS
// ============================================================

func minStake() *big.Int {
	// 32 QTX in nQTX (base units)
	return new(big.Int).Mul(big.NewInt(32), big.NewInt(denom.QTX))
}

// TestValidatorSetAddAndRetrieve verifies adding a validator and retrieving it
func TestValidatorSetAddAndRetrieve(t *testing.T) {
	vs := NewValidatorSet(minStake())

	if err := vs.AddValidator("node-1", 100); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	active := vs.GetActiveValidators(0)
	if len(active) != 1 {
		t.Fatalf("expected 1 active validator, got %d", len(active))
	}
	if active[0].ID != "node-1" {
		t.Errorf("expected node-1, got %s", active[0].ID)
	}
}

// TestValidatorSetBelowMinStakeRejected verifies minimum stake enforcement
func TestValidatorSetBelowMinStakeRejected(t *testing.T) {
	vs := NewValidatorSet(minStake())

	// 1 QTX — below 32 QTX minimum
	err := vs.AddValidator("node-low", 1)
	if err == nil {
		t.Error("expected error for stake below minimum, got nil")
	}
}

// TestValidatorSetTotalStake verifies total stake accounting
func TestValidatorSetTotalStake(t *testing.T) {
	vs := NewValidatorSet(minStake())

	_ = vs.AddValidator("node-1", 100)
	_ = vs.AddValidator("node-2", 200)

	total := vs.GetTotalStake()
	expected := new(big.Int).Mul(big.NewInt(300), big.NewInt(denom.QTX))

	if total.Cmp(expected) != 0 {
		t.Errorf("total stake = %s nQTX, want %s nQTX", total, expected)
	}
}

// TestValidatorSetUpdateStake verifies stake can be updated
func TestValidatorSetUpdateStake(t *testing.T) {
	vs := NewValidatorSet(minStake())
	_ = vs.AddValidator("node-1", 100)

	if err := vs.UpdateStake("node-1", 500); err != nil {
		t.Fatalf("UpdateStake failed: %v", err)
	}

	active := vs.GetActiveValidators(0)
	if active[0].GetStakeInSPX() != 500 {
		t.Errorf("expected stake 500 QTX, got %.2f", active[0].GetStakeInSPX())
	}
}

// TestValidatorSetUpdateStakeUnknown verifies updating unknown validator fails
func TestValidatorSetUpdateStakeUnknown(t *testing.T) {
	vs := NewValidatorSet(minStake())
	err := vs.UpdateStake("ghost", 100)
	if err == nil {
		t.Error("expected error updating unknown validator, got nil")
	}
}

// TestValidatorSetSlash verifies slashing reduces stake and marks validator ejected
func TestValidatorSetSlash(t *testing.T) {
	vs := NewValidatorSet(minStake())
	_ = vs.AddValidator("node-bad", 32) // exactly minimum

	// Slash 50% (5000 bps) — drops below minimum → ejected
	vs.SlashValidator("node-bad", "double-sign", 5000)

	active := vs.GetActiveValidators(0)
	for _, v := range active {
		if v.ID == "node-bad" && !v.IsSlashed {
			t.Error("expected node-bad to be marked slashed after penalty below minimum")
		}
	}
}

// TestValidatorSetSlashUnknown verifies slashing unknown validator is a no-op (no panic)
func TestValidatorSetSlashUnknown(t *testing.T) {
	vs := NewValidatorSet(minStake())
	// Should not panic
	vs.SlashValidator("nobody", "test", 1000)
}

// TestValidatorSetDeterministicOrder verifies GetActiveValidators is deterministic
func TestValidatorSetDeterministicOrder(t *testing.T) {
	vs := NewValidatorSet(minStake())
	ids := []string{"charlie", "alice", "bob", "dave"}
	for _, id := range ids {
		_ = vs.AddValidator(id, 100)
	}

	first := vs.GetActiveValidators(0)
	second := vs.GetActiveValidators(0)

	for i := range first {
		if first[i].ID != second[i].ID {
			t.Errorf("non-deterministic order at index %d: %s vs %s",
				i, first[i].ID, second[i].ID)
		}
	}

	// First element should be "alice" (lexicographic)
	if first[0].ID != "alice" {
		t.Errorf("expected first validator to be 'alice', got '%s'", first[0].ID)
	}
}

// TestValidatorSetIsValidStakeAmount verifies stake amount validation
func TestValidatorSetIsValidStakeAmount(t *testing.T) {
	vs := NewValidatorSet(minStake())

	below := new(big.Int).Mul(big.NewInt(1), big.NewInt(denom.QTX))
	above := new(big.Int).Mul(big.NewInt(100), big.NewInt(denom.QTX))

	if vs.IsValidStakeAmount(nil) {
		t.Error("nil stake should be invalid")
	}
	if vs.IsValidStakeAmount(below) {
		t.Error("1 QTX stake should be invalid (below 32 QTX minimum)")
	}
	if !vs.IsValidStakeAmount(above) {
		t.Error("100 QTX stake should be valid")
	}
}

// TestValidatorSetActiveValidatorIDs verifies IDs helper returns same order
func TestValidatorSetActiveValidatorIDs(t *testing.T) {
	vs := NewValidatorSet(minStake())
	_ = vs.AddValidator("zorro", 50)
	_ = vs.AddValidator("alpha", 50)
	_ = vs.AddValidator("mike", 50)

	ids := vs.ActiveValidatorIDs(0)
	if len(ids) != 3 {
		t.Fatalf("expected 3 IDs, got %d", len(ids))
	}
	// Should be sorted: alpha, mike, zorro
	expected := []string{"alpha", "mike", "zorro"}
	for i, id := range ids {
		if id != expected[i] {
			t.Errorf("ids[%d] = %s, want %s", i, id, expected[i])
		}
	}
}

// ============================================================
// STAKE-WEIGHTED SELECTOR TESTS
// ============================================================

// TestStakeWeightedSelectorDeterministic verifies same seed → same proposer
func TestStakeWeightedSelectorDeterministic(t *testing.T) {
	vs := NewValidatorSet(minStake())
	_ = vs.AddValidator("node-A", 100)
	_ = vs.AddValidator("node-B", 100)
	_ = vs.AddValidator("node-C", 100)

	selector := NewStakeWeightedSelector(vs)
	seed := [32]byte{0x01, 0x02, 0x03}

	first := selector.SelectProposer(0, seed)
	second := selector.SelectProposer(0, seed)

	if first == nil || second == nil {
		t.Fatal("SelectProposer returned nil")
	}
	if first.ID != second.ID {
		t.Errorf("non-deterministic selection: %s vs %s", first.ID, second.ID)
	}
}

// TestStakeWeightedSelectorDifferentSeeds verifies different seeds can yield different proposers
func TestStakeWeightedSelectorDifferentSeeds(t *testing.T) {
	vs := NewValidatorSet(minStake())
	_ = vs.AddValidator("node-A", 100)
	_ = vs.AddValidator("node-B", 100)
	_ = vs.AddValidator("node-C", 100)

	selector := NewStakeWeightedSelector(vs)

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		seed := [32]byte{byte(i), byte(i >> 8)}
		p := selector.SelectProposer(0, seed)
		if p != nil {
			seen[p.ID] = true
		}
	}

	// With 3 validators and 50 different seeds, should see more than 1 unique proposer
	if len(seen) < 2 {
		t.Errorf("expected at least 2 unique proposers over 50 seeds, got %d: %v", len(seen), seen)
	}
}

// TestStakeWeightedSelectorEmptySet verifies empty set returns nil
func TestStakeWeightedSelectorEmptySet(t *testing.T) {
	vs := NewValidatorSet(minStake())
	selector := NewStakeWeightedSelector(vs)
	seed := [32]byte{}

	result := selector.SelectProposer(0, seed)
	if result != nil {
		t.Errorf("expected nil for empty validator set, got %s", result.ID)
	}
}

// TestStakeWeightedSelectorHigherStakeFavored verifies stake weighting
func TestStakeWeightedSelectorHigherStakeFavored(t *testing.T) {
	vs := NewValidatorSet(minStake())
	_ = vs.AddValidator("whale", 10000) // 10000 QTX
	_ = vs.AddValidator("minnow", 32)   // 32 QTX minimum

	selector := NewStakeWeightedSelector(vs)

	whaleCount := 0
	for i := 0; i < 100; i++ {
		seed := [32]byte{byte(i), byte(i * 7), byte(i * 13)}
		p := selector.SelectProposer(0, seed)
		if p != nil && p.ID == "whale" {
			whaleCount++
		}
	}

	// Whale has ~99.7% of stake, should be selected in vast majority of cases
	if whaleCount < 80 {
		t.Errorf("expected whale to be selected most often (~99%%), got %d/100", whaleCount)
	}
}

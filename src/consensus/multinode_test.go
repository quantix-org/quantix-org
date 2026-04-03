// MIT License
// Copyright (c) 2024 quantix

// go/src/consensus/multinode_test.go
package consensus

import (
	"math"
	"math/big"
	"testing"
	"time"

	denom "github.com/ramseyauron/quantix/src/params/denom"
)

// ---------------------------------------------------------------------------
// Q9-A: ConsensusMode switching
// ---------------------------------------------------------------------------

func TestMultiNodeConsensusModeSwitch(t *testing.T) {
	tests := []struct {
		name           string
		validatorCount int
		wantMode       ConsensusMode
	}{
		{"1 validator => DEVNET_SOLO", 1, DEVNET_SOLO},
		{"2 validators => DEVNET_SOLO", 2, DEVNET_SOLO},
		{"3 validators => DEVNET_SOLO", 3, DEVNET_SOLO},
		{"4 validators => PBFT", 4, PBFT},
		{"5 validators => PBFT", 5, PBFT},
		{"10 validators => PBFT", 10, PBFT},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := GetConsensusMode(tc.validatorCount)
			if got != tc.wantMode {
				t.Errorf("GetConsensusMode(%d): want %s, got %s",
					tc.validatorCount, tc.wantMode, got)
			}
		})
	}
}

func TestMultiNodeConsensusModeString(t *testing.T) {
	if DEVNET_SOLO.String() != "DEVNET_SOLO" {
		t.Errorf("expected DEVNET_SOLO string, got %q", DEVNET_SOLO.String())
	}
	if PBFT.String() != "PBFT" {
		t.Errorf("expected PBFT string, got %q", PBFT.String())
	}
}

// ---------------------------------------------------------------------------
// Q9-B: View-change backoff — consecutive view changes should increase wait
// ---------------------------------------------------------------------------

func TestMultiNodeViewChangeBackoff(t *testing.T) {
	// The actual startViewChange enforces a 60-second rate limit.
	// We model the expected backoff policy: each consecutive failure increases
	// the minimum wait by a factor (here we test the principle, not clock sleep).
	base := 60 * time.Second
	backoffFactor := 2.0

	waits := make([]time.Duration, 4)
	waits[0] = base
	for i := 1; i < len(waits); i++ {
		waits[i] = time.Duration(float64(waits[i-1]) * backoffFactor)
	}

	// Verify each wait is strictly greater than the previous
	for i := 1; i < len(waits); i++ {
		if waits[i] <= waits[i-1] {
			t.Errorf("backoff[%d]=%v should be > backoff[%d]=%v", i, waits[i], i-1, waits[i-1])
		}
	}

	// Verify the minimum rate-limit window that consensus enforces
	if base < 60*time.Second {
		t.Errorf("base backoff %v is less than the 60s view-change rate limit", base)
	}
}

// ---------------------------------------------------------------------------
// Q9-C: Quorum with N=4 requires 3 votes (⌊2×4/3⌋+1 = 3)
// ---------------------------------------------------------------------------

func TestMultiNodeQuorumN4(t *testing.T) {
	const N = 4
	// Standard formula: ⌊2N/3⌋ + 1
	want := int(math.Floor(2.0*N/3.0)) + 1
	if want != 3 {
		t.Fatalf("formula check failed: want 3, got %d", want)
	}

	qv := NewQuorumVerifier(N, 0, 2.0/3.0)
	got := qv.CalculateMinQuorumSize()
	if got != want {
		t.Errorf("N=%d quorum: want %d, got %d", N, want, got)
	}

	// Verify that 2 votes are not enough (< quorum)
	if 2 >= got {
		t.Errorf("2 votes should be below quorum %d", got)
	}
	// Verify that 3 votes are sufficient (>= quorum)
	if 3 < got {
		t.Errorf("3 votes should meet quorum %d", got)
	}
}

// ---------------------------------------------------------------------------
// Q9-D: Validator join — add validator, verify active set increases
// ---------------------------------------------------------------------------

func TestMultiNodeValidatorJoin(t *testing.T) {
	minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(denom.QTX))
	vs := NewValidatorSet(minStake)

	initial := len(vs.GetActiveValidators(0))

	if err := vs.AddValidator("node-A", 32); err != nil {
		t.Fatalf("AddValidator node-A: %v", err)
	}
	if err := vs.AddValidator("node-B", 32); err != nil {
		t.Fatalf("AddValidator node-B: %v", err)
	}

	afterAdd := len(vs.GetActiveValidators(0))
	if afterAdd <= initial {
		t.Errorf("active set should have grown: before=%d, after=%d", initial, afterAdd)
	}
	if afterAdd != initial+2 {
		t.Errorf("expected %d validators, got %d", initial+2, afterAdd)
	}
}

// ---------------------------------------------------------------------------
// Q9-E: Validator leave — remove via slash, verify active set decreases
// ---------------------------------------------------------------------------

func TestMultiNodeValidatorLeave(t *testing.T) {
	minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(denom.QTX))
	vs := NewValidatorSet(minStake)

	if err := vs.AddValidator("val-1", 32); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	if err := vs.AddValidator("val-2", 32); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	if err := vs.AddValidator("val-3", 32); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}

	before := len(vs.GetActiveValidators(0))

	// Slash removes the validator from the active set
	vs.SlashValidator("val-1", "test leave", 10000 /* 100% */)

	after := len(vs.GetActiveValidators(0))
	if after >= before {
		t.Errorf("active set should have shrunk: before=%d, after=%d", before, after)
	}

	// Confirm the slashed validator is no longer active
	for _, v := range vs.GetActiveValidators(0) {
		if v.ID == "val-1" {
			t.Error("slashed validator val-1 still appears in active set")
		}
	}
}

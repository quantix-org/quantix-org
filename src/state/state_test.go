// go/src/state/state_test.go
package state

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// TestNewStorage verifies that NewStorage creates directories and returns non-nil.
func TestNewStorage(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "quantix_test_storage")
	defer os.RemoveAll(dir)

	s, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil storage")
	}
}

// TestStorageGetTotalBlocks verifies totalBlocks starts at 0.
func TestStorageGetTotalBlocks(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "quantix_test_total")
	defer os.RemoveAll(dir)

	s, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}
	if s.GetTotalBlocks() != 0 {
		t.Errorf("expected 0 total blocks, got %d", s.GetTotalBlocks())
	}
}

// TestStorageGetTPSMetrics verifies TPS metrics are returned correctly.
func TestStorageGetTPSMetrics(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "quantix_test_tps")
	defer os.RemoveAll(dir)

	s, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}
	metrics := s.GetTPSMetrics()
	if metrics == nil {
		t.Fatal("expected non-nil TPS metrics")
	}
}

// TestCalculateQuorumSize verifies quorum size for Byzantine fault tolerance.
func TestCalculateQuorumSize(t *testing.T) {
	cases := []struct {
		n        int
		expected int
	}{
		{0, 1},
		{1, 1},
		{3, 3},
		{4, 3},
		{7, 5},
	}
	for _, tc := range cases {
		got := calculateQuorumSize(tc.n)
		if got != tc.expected {
			t.Errorf("calculateQuorumSize(%d) = %d, want %d", tc.n, got, tc.expected)
		}
	}
}

// TestNewStateMachine verifies that a state machine can be created.
func TestNewStateMachine(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "quantix_test_sm")
	defer os.RemoveAll(dir)

	s, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}

	validators := []string{"node1", "node2", "node3"}
	sm := NewStateMachine(s, "node1", validators)
	if sm == nil {
		t.Fatal("expected non-nil state machine")
	}
}

// TestStateMachineInitialState verifies the initial state is set correctly.
func TestStateMachineInitialState(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "quantix_test_sm_state")
	defer os.RemoveAll(dir)

	s, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}

	sm := NewStateMachine(s, "node1", []string{"node1"})
	current := sm.GetCurrentState()
	if current == nil {
		t.Fatal("expected non-nil current state")
	}
}

// TestStateMachineGetFinalStates verifies that final states are returned.
func TestStateMachineGetFinalStates(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "quantix_test_sm_final")
	defer os.RemoveAll(dir)

	s, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}
	sm := NewStateMachine(s, "node1", []string{"node1"})
	// Initial final states should be empty slice, not nil-panicking
	states := sm.GetFinalStates()
	_ = states
}

// TestStateTransitionValidation verifies that state transitions are validated.
func TestStateTransitionValidation(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "quantix_test_sm_transition")
	defer os.RemoveAll(dir)

	s, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}
	sm := NewStateMachine(s, "node1", []string{"node1"})

	// Missing validator ID should fail
	err = sm.validateStateTransition(&StateTransition{TransitionType: "validator_add"})
	if err == nil {
		t.Error("expected error for missing validator ID")
	}

	// Valid transition
	err = sm.validateStateTransition(&StateTransition{
		TransitionType: "validator_add",
		ValidatorID:    "node2",
		StakeAmount:    big.NewInt(1000),
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Unknown transition type
	err = sm.validateStateTransition(&StateTransition{TransitionType: "unknown_type"})
	if err == nil {
		t.Error("expected error for unknown transition type")
	}
}

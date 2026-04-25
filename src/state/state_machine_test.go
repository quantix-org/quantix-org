// MIT License
// Copyright (c) 2024 quantix
package state_test

import (
	"testing"

	"github.com/quantix-org/quantix-org/src/state"
)

// newTestSM creates a StateMachine with a temp-dir storage for unit tests.
func newTestSM(t *testing.T, nodeID string, validators []string) *state.StateMachine {
	t.Helper()
	dir := t.TempDir()
	storage, err := state.NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	return state.NewStateMachine(storage, nodeID, validators)
}

// ── NewStateMachine ─────────────────────────────────────────────────────────

func TestNewStateMachine_NotNil(t *testing.T) {
	sm := newTestSM(t, "node-0", nil)
	if sm == nil {
		t.Error("expected non-nil StateMachine")
	}
}

func TestNewStateMachine_EmptyValidators(t *testing.T) {
	sm := newTestSM(t, "node-0", []string{})
	if sm == nil {
		t.Error("expected non-nil StateMachine with empty validators")
	}
}

func TestNewStateMachine_WithValidators(t *testing.T) {
	sm := newTestSM(t, "node-0", []string{"v1", "v2", "v3", "v4"})
	if sm == nil {
		t.Error("expected non-nil StateMachine with validators")
	}
}

// ── GetFinalStates ──────────────────────────────────────────────────────────

func TestGetFinalStates_InitiallyEmpty(t *testing.T) {
	sm := newTestSM(t, "node-0", nil)
	states := sm.GetFinalStates()
	if states == nil {
		t.Error("GetFinalStates should return non-nil slice")
	}
	if len(states) != 0 {
		t.Errorf("initial final states: want 0, got %d", len(states))
	}
}

// ── Stop ────────────────────────────────────────────────────────────────────

func TestStop_NoError(t *testing.T) {
	sm := newTestSM(t, "node-0", nil)
	if err := sm.Stop(); err != nil {
		t.Errorf("Stop() error: %v", err)
	}
}

// ── PopulatedFinalStates ────────────────────────────────────────────────────

func TestPopulatedFinalStates_NilInput_ReturnsNil(t *testing.T) {
	sm := newTestSM(t, "node-0", nil)
	result := sm.PopulatedFinalStates(nil)
	if result != nil {
		t.Error("PopulatedFinalStates(nil) should return nil")
	}
}

func TestPopulatedFinalStates_EmptyInput(t *testing.T) {
	sm := newTestSM(t, "node-0", nil)
	result := sm.PopulatedFinalStates([]*state.FinalStateInfo{})
	if len(result) != 0 {
		t.Errorf("PopulatedFinalStates([]) should return empty, got %d", len(result))
	}
}

func TestPopulatedFinalStates_ValidEntry(t *testing.T) {
	sm := newTestSM(t, "node-0", nil)
	entry := &state.FinalStateInfo{
		BlockHash:   "0000000000000000000000000000000000000000000000000000000000000001",
		BlockHeight: 1,
		MessageType: "commit",
		Valid:       true,
	}
	result := sm.PopulatedFinalStates([]*state.FinalStateInfo{entry})
	if len(result) == 0 {
		t.Error("PopulatedFinalStates should return at least one result for valid entry")
	}
}

// ── SyncFinalStatesNow ──────────────────────────────────────────────────────

func TestSyncFinalStatesNow_NilConsensus_NoPanel(t *testing.T) {
	// SyncFinalStatesNow with nil consensus should not panic
	sm := newTestSM(t, "node-0", nil)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SyncFinalStatesNow panicked: %v", r)
		}
	}()
	sm.SyncFinalStatesNow()
}

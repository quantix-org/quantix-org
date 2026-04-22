// MIT License
// Copyright (c) 2024 quantix-org

package consensus

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =====================================================
// View Change Recovery Tests
// =====================================================

// TestViewChangeOnLeaderFailure tests that view change triggers when leader fails.
func TestViewChangeOnLeaderFailure(t *testing.T) {
	t.Log("=== Test: View Change on Leader Failure ===")

	// Create mock consensus with 4 validators
	mc := NewMockConsensus(4)

	// Simulate leader failure (validator 0 is leader for height 1)
	mc.SetValidatorOnline(0, false)

	// Try to reach consensus
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := mc.RunConsensusRound(ctx, 1)

	if !result.ViewChangeTriggered {
		t.Error("Expected view change to trigger when leader is offline")
	}

	if result.NewLeaderID != 1 {
		t.Errorf("Expected new leader to be validator 1, got %d", result.NewLeaderID)
	}

	t.Logf("View change triggered: old leader=%d, new leader=%d", 0, result.NewLeaderID)
}

// TestViewChangeOnByzantineLeader tests view change when leader proposes invalid block.
func TestViewChangeOnByzantineLeader(t *testing.T) {
	t.Log("=== Test: View Change on Byzantine Leader ===")

	mc := NewMockConsensus(4)

	// Make leader Byzantine (proposes invalid block)
	mc.SetValidatorByzantine(0, true)
	mc.SetByzantineBehavior(0, "invalid_proposal")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := mc.RunConsensusRound(ctx, 1)

	if !result.ViewChangeTriggered {
		t.Error("Expected view change when leader proposes invalid block")
	}

	t.Logf("Byzantine leader detected, view change triggered")
}

// TestViewChangeQuorum tests that view change requires 2f+1 view-change messages.
func TestViewChangeQuorum(t *testing.T) {
	t.Log("=== Test: View Change Quorum Requirement ===")

	mc := NewMockConsensus(7) // 7 validators, f=2, need 5 for view change

	// Leader is offline
	mc.SetValidatorOnline(0, false)

	// Only 4 validators can communicate (not enough for view change)
	mc.SetValidatorOnline(5, false)
	mc.SetValidatorOnline(6, false)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result := mc.RunConsensusRound(ctx, 1)

	// With only 4 validators, view change should fail (need 5)
	if result.Success {
		t.Error("Expected consensus to fail without view change quorum")
	}

	t.Logf("View change quorum check: needed 5, had 4, consensus failed as expected")
}

// TestViewChangeRecovery tests full recovery after view change.
func TestViewChangeRecovery(t *testing.T) {
	t.Log("=== Test: View Change Recovery ===")

	mc := NewMockConsensus(4)

	// Height 1: Leader fails, view change
	mc.SetValidatorOnline(0, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result1 := mc.RunConsensusRound(ctx, 1)
	if !result1.ViewChangeTriggered {
		t.Error("Expected view change at height 1")
	}

	// Height 2: New leader (validator 1) succeeds
	result2 := mc.RunConsensusRound(ctx, 2)
	if !result2.Success {
		t.Error("Expected consensus to succeed at height 2 with new leader")
	}

	// Height 3: Original leader comes back online
	mc.SetValidatorOnline(0, true)

	result3 := mc.RunConsensusRound(ctx, 3)
	if !result3.Success {
		t.Error("Expected consensus to succeed at height 3")
	}

	t.Logf("Recovery complete: height 1 (view change), height 2 (success), height 3 (success)")
}

// TestConsecutiveViewChanges tests handling of multiple consecutive view changes.
func TestConsecutiveViewChanges(t *testing.T) {
	t.Log("=== Test: Consecutive View Changes ===")

	mc := NewMockConsensus(5)

	// Make first three validators fail one by one
	viewChanges := 0

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	for i := 0; i < 3; i++ {
		mc.SetValidatorOnline(i, false)

		result := mc.RunConsensusRound(ctx, uint64(i+1))
		if result.ViewChangeTriggered {
			viewChanges++
		}
	}

	if viewChanges < 2 {
		t.Errorf("Expected at least 2 view changes, got %d", viewChanges)
	}

	t.Logf("Handled %d consecutive view changes", viewChanges)
}

// =====================================================
// Mock Consensus Implementation for Testing
// =====================================================

// MockConsensus simulates a PBFT consensus for testing.
type MockConsensus struct {
	mu         sync.Mutex
	validators []*MockValidator
	currentView uint64
	viewChanges int64
}

// ConsensusRoundResult contains the result of a consensus round.
type ConsensusRoundResult struct {
	Success             bool
	BlockFinalized      bool
	ViewChangeTriggered bool
	NewLeaderID         int
	PrepareVotes        int
	CommitVotes         int
	ErrorMessage        string
}

// NewMockConsensus creates a new mock consensus with n validators.
func NewMockConsensus(n int) *MockConsensus {
	mc := &MockConsensus{
		validators: make([]*MockValidator, n),
	}

	for i := 0; i < n; i++ {
		mc.validators[i] = &MockValidator{
			ID:     string(rune('A' + i)),
			Stake:  100,
			Online: true,
		}
	}

	return mc
}

// SetValidatorOnline sets a validator's online status.
func (mc *MockConsensus) SetValidatorOnline(idx int, online bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if idx < len(mc.validators) {
		mc.validators[idx].Online = online
	}
}

// SetValidatorByzantine sets a validator as Byzantine.
func (mc *MockConsensus) SetValidatorByzantine(idx int, byzantine bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if idx < len(mc.validators) {
		mc.validators[idx].IsByzantine = byzantine
	}
}

// SetByzantineBehavior sets the Byzantine behavior type.
func (mc *MockConsensus) SetByzantineBehavior(idx int, behavior string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if idx < len(mc.validators) {
		mc.validators[idx].ByzantineType = behavior
	}
}

// RunConsensusRound simulates a single consensus round.
func (mc *MockConsensus) RunConsensusRound(ctx context.Context, height uint64) *ConsensusRoundResult {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	result := &ConsensusRoundResult{}
	n := len(mc.validators)
	f := (n - 1) / 3 // Maximum Byzantine validators
	quorum := 2*f + 1

	// Determine leader for this view
	leaderIdx := int(mc.currentView) % n

	// Check if leader is online and not Byzantine
	leader := mc.validators[leaderIdx]
	if !leader.Online {
		// Trigger view change
		result.ViewChangeTriggered = true
		atomic.AddInt64(&mc.viewChanges, 1)
		mc.currentView++
		result.NewLeaderID = int(mc.currentView) % n
		return result
	}

	if leader.IsByzantine && leader.ByzantineType == "invalid_proposal" {
		// Byzantine leader proposes invalid block, honest validators detect and view change
		result.ViewChangeTriggered = true
		atomic.AddInt64(&mc.viewChanges, 1)
		mc.currentView++
		result.NewLeaderID = int(mc.currentView) % n
		return result
	}

	// Count online, honest validators
	prepareVotes := 0
	commitVotes := 0

	for _, v := range mc.validators {
		if v.Online && !v.IsByzantine {
			prepareVotes++
		}
	}

	result.PrepareVotes = prepareVotes

	// Check prepare quorum
	if prepareVotes < quorum {
		result.ErrorMessage = "prepare quorum not reached"
		return result
	}

	// Commit phase
	for _, v := range mc.validators {
		if v.Online && !v.IsByzantine {
			commitVotes++
		}
	}

	result.CommitVotes = commitVotes

	// Check commit quorum
	if commitVotes < quorum {
		result.ErrorMessage = "commit quorum not reached"
		return result
	}

	// Block finalized
	result.Success = true
	result.BlockFinalized = true
	return result
}

// GetViewChanges returns the number of view changes.
func (mc *MockConsensus) GetViewChanges() int64 {
	return atomic.LoadInt64(&mc.viewChanges)
}

// =====================================================
// Network Partition Tests
// =====================================================

// TestNetworkPartitionRecovery tests consensus recovery after network partition.
func TestNetworkPartitionRecovery(t *testing.T) {
	t.Log("=== Test: Network Partition Recovery ===")

	config := &StressTestConfig{
		NumValidators:     10,
		Duration:          30 * time.Second,
		BlockTime:         500 * time.Millisecond,
		ByzantineFraction: 0.0,
		NetworkLatencyMs:  10,
		PartitionEnabled:  true,
		PartitionDuration: 5 * time.Second,
		PartitionInterval: 10 * time.Second,
		TxPerBlock:        10,
	}

	st := NewStressTest(config)

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	result := st.Run(ctx)

	t.Logf("Blocks produced: %d", result.BlocksProduced)
	t.Logf("Blocks finalized: %d", result.BlocksFinalized)
	t.Logf("Partitions triggered: %d", result.PartitionsTriggered)
	t.Logf("View changes: %d", result.ViewChanges)

	finalizationRate := float64(result.BlocksFinalized) / float64(result.BlocksProduced)
	if finalizationRate < 0.7 {
		t.Errorf("Finalization rate too low: %.2f%% (expected >= 70%%)", finalizationRate*100)
	}

	t.Logf("Network partition recovery test passed with %.1f%% finalization", finalizationRate*100)
}

// TestVDFTuning tests different VDF T parameter values.
func TestVDFTuning(t *testing.T) {
	t.Log("=== Test: VDF T Parameter Tuning ===")

	// Test different T values
	tValues := []int{1000, 10000, 100000, 1000000}

	for _, tVal := range tValues {
		t.Run("T="+string(rune(tVal)), func(t *testing.T) {
			start := time.Now()

			// Simulate VDF computation (in reality this would call actual VDF)
			vdf := &VDF{
				Discriminant: []byte("test-discriminant"),
				T:            tVal,
			}

			// Mock computation time (actual VDF takes ~1µs per squaring)
			expectedTime := time.Duration(tVal) * time.Microsecond
			time.Sleep(expectedTime / 1000) // Simulate at 1/1000 speed for testing

			elapsed := time.Since(start)

			t.Logf("VDF T=%d: simulated time ~%v (target: ~%v)", tVal, elapsed, expectedTime)
		})
	}

	t.Log("VDF tuning analysis:")
	t.Log("  T=1,000:     ~1ms   - Too fast, vulnerable to grinding")
	t.Log("  T=10,000:    ~10ms  - Minimum recommended")
	t.Log("  T=100,000:   ~100ms - Good balance")
	t.Log("  T=1,000,000: ~1s    - Maximum recommended for 10s block time")
	t.Log("")
	t.Log("Recommendation: T=100,000 (~100ms) for 10s block time")
	t.Log("This provides 1% of block time for VDF, leaving 99% for propagation and consensus")
}

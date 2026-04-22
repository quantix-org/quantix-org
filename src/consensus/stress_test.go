// MIT License
// Copyright (c) 2024 quantix-org

package consensus

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// =====================================================
// Consensus Stress Test Framework
// =====================================================

// StressTestConfig configures a consensus stress test run.
type StressTestConfig struct {
	// Number of validators to simulate
	NumValidators int

	// Duration of the stress test
	Duration time.Duration

	// Target block time
	BlockTime time.Duration

	// Byzantine fault injection
	ByzantineFraction float64 // Fraction of validators that behave maliciously
	ByzantineBehavior string  // "silent", "equivocate", "random"

	// Network simulation
	NetworkLatencyMs   int     // Base network latency
	NetworkJitterMs    int     // Random jitter added to latency
	PacketLossPercent  float64 // Percentage of messages that get dropped

	// Partition simulation
	PartitionEnabled   bool          // Enable network partitions
	PartitionDuration  time.Duration // How long partitions last
	PartitionInterval  time.Duration // Time between partitions

	// Load parameters
	TxPerBlock int // Transactions per block
}

// DefaultStressTestConfig returns a default stress test configuration.
func DefaultStressTestConfig() *StressTestConfig {
	return &StressTestConfig{
		NumValidators:      100,
		Duration:           5 * time.Minute,
		BlockTime:          2 * time.Second,
		ByzantineFraction:  0.1, // 10% Byzantine
		ByzantineBehavior:  "random",
		NetworkLatencyMs:   50,
		NetworkJitterMs:    20,
		PacketLossPercent:  1.0,
		PartitionEnabled:   false,
		PartitionDuration:  30 * time.Second,
		PartitionInterval:  2 * time.Minute,
		TxPerBlock:         100,
	}
}

// StressTestResult contains the results of a stress test run.
type StressTestResult struct {
	// Basic metrics
	BlocksProduced      int64
	BlocksFinalized     int64
	TransactionsTotal   int64
	TransactionsPerSec  float64
	AverageBlockTime    time.Duration
	AverageFinalityTime time.Duration

	// Consensus metrics
	ViewChanges         int64
	SuccessfulVotes     int64
	FailedVotes         int64
	QuorumFailures      int64

	// Byzantine detection
	DoubleSignsDetected int64
	SlashingsExecuted   int64
	FalsePositives      int64

	// Network metrics
	MessagesTotal       int64
	MessagesDropped     int64
	AverageLatencyMs    float64

	// Partition metrics
	PartitionsTriggered int64
	RecoveryTime        time.Duration

	// Errors
	Errors []string

	// Overall
	Success bool
	Summary string
}

// StressTest runs a consensus stress test.
type StressTest struct {
	config  *StressTestConfig
	result  *StressTestResult
	running atomic.Bool

	// Simulated validators
	validators []*MockValidator

	// Metrics
	mu                sync.Mutex
	blocksProduced    int64
	blocksFinalized   int64
	viewChanges       int64
	doubleSignsFound  int64
	messagesTotal     int64
	messagesDropped   int64
	totalLatencyNs    int64
}

// MockValidator simulates a validator for stress testing.
type MockValidator struct {
	ID           string
	Stake        uint64
	IsByzantine  bool
	ByzantineType string
	Online       bool
	Partition    int // 0 = no partition, 1+ = partition group

	// State
	CurrentView    uint64
	LastVotedBlock string
	DoubleVotes    int
}

// NewStressTest creates a new stress test instance.
func NewStressTest(config *StressTestConfig) *StressTest {
	if config == nil {
		config = DefaultStressTestConfig()
	}

	st := &StressTest{
		config: config,
		result: &StressTestResult{},
	}

	// Create validators
	st.validators = make([]*MockValidator, config.NumValidators)
	byzantineCount := int(float64(config.NumValidators) * config.ByzantineFraction)

	for i := 0; i < config.NumValidators; i++ {
		st.validators[i] = &MockValidator{
			ID:            fmt.Sprintf("validator-%d", i),
			Stake:         uint64(100 + rand.Intn(900)), // 100-1000 stake
			IsByzantine:   i < byzantineCount,
			ByzantineType: config.ByzantineBehavior,
			Online:        true,
			Partition:     0,
		}
	}

	return st
}

// Run executes the stress test.
func (st *StressTest) Run(ctx context.Context) *StressTestResult {
	if !st.running.CompareAndSwap(false, true) {
		st.result.Errors = append(st.result.Errors, "stress test already running")
		return st.result
	}
	defer st.running.Store(false)

	startTime := time.Now()
	endTime := startTime.Add(st.config.Duration)

	// Start partition simulator if enabled
	var partitionCancel context.CancelFunc
	if st.config.PartitionEnabled {
		var partitionCtx context.Context
		partitionCtx, partitionCancel = context.WithCancel(ctx)
		go st.runPartitionSimulator(partitionCtx)
	}

	// Run consensus rounds
	blockNum := uint64(0)
	for time.Now().Before(endTime) {
		select {
		case <-ctx.Done():
			st.result.Errors = append(st.result.Errors, "context cancelled")
			goto done
		default:
		}

		// Simulate one consensus round
		success := st.simulateConsensusRound(blockNum)
		if success {
			atomic.AddInt64(&st.blocksFinalized, 1)
		}
		atomic.AddInt64(&st.blocksProduced, 1)
		blockNum++

		// Sleep for block time
		time.Sleep(st.config.BlockTime)
	}

done:
	if partitionCancel != nil {
		partitionCancel()
	}

	// Calculate results
	duration := time.Since(startTime)
	st.result.BlocksProduced = atomic.LoadInt64(&st.blocksProduced)
	st.result.BlocksFinalized = atomic.LoadInt64(&st.blocksFinalized)
	st.result.TransactionsTotal = st.result.BlocksFinalized * int64(st.config.TxPerBlock)
	st.result.TransactionsPerSec = float64(st.result.TransactionsTotal) / duration.Seconds()
	st.result.ViewChanges = atomic.LoadInt64(&st.viewChanges)
	st.result.DoubleSignsDetected = atomic.LoadInt64(&st.doubleSignsFound)
	st.result.MessagesTotal = atomic.LoadInt64(&st.messagesTotal)
	st.result.MessagesDropped = atomic.LoadInt64(&st.messagesDropped)

	if st.result.BlocksProduced > 0 {
		st.result.AverageBlockTime = duration / time.Duration(st.result.BlocksProduced)
	}

	if st.messagesTotal > 0 {
		st.result.AverageLatencyMs = float64(atomic.LoadInt64(&st.totalLatencyNs)) / float64(st.messagesTotal) / 1e6
	}

	// Determine success
	finalizationRate := float64(st.result.BlocksFinalized) / float64(st.result.BlocksProduced)
	st.result.Success = finalizationRate >= 0.95 && len(st.result.Errors) == 0

	st.result.Summary = fmt.Sprintf(
		"Stress test complete: %d/%d blocks finalized (%.1f%%), %.1f TPS, %d view changes, %d double-signs detected",
		st.result.BlocksFinalized, st.result.BlocksProduced, finalizationRate*100,
		st.result.TransactionsPerSec, st.result.ViewChanges, st.result.DoubleSignsDetected,
	)

	return st.result
}

// simulateConsensusRound simulates a single PBFT consensus round.
func (st *StressTest) simulateConsensusRound(blockNum uint64) bool {
	blockHash := fmt.Sprintf("block-%d-%d", blockNum, rand.Int63())

	// Phase 1: Propose
	leader := st.selectLeader(blockNum)
	if !leader.Online || (leader.IsByzantine && rand.Float64() < 0.3) {
		// Leader is offline or Byzantine leader fails to propose
		atomic.AddInt64(&st.viewChanges, 1)
		return false
	}

	// Phase 2: Prepare
	prepareVotes := 0
	for _, v := range st.validators {
		if !st.canCommunicate(leader, v) {
			continue
		}

		st.simulateMessage()

		if v.IsByzantine {
			// Byzantine behavior
			switch v.ByzantineType {
			case "silent":
				continue // Don't vote
			case "equivocate":
				// Double vote (detectable)
				if v.LastVotedBlock != "" && v.LastVotedBlock != blockHash {
					v.DoubleVotes++
					atomic.AddInt64(&st.doubleSignsFound, 1)
				}
			case "random":
				if rand.Float64() < 0.5 {
					continue
				}
			}
		}

		if v.Online {
			prepareVotes++
			v.LastVotedBlock = blockHash
		}
	}

	// Check quorum (2/3 + 1)
	quorum := (2 * st.config.NumValidators / 3) + 1
	if prepareVotes < quorum {
		atomic.AddInt64(&st.viewChanges, 1)
		return false
	}

	// Phase 3: Commit
	commitVotes := 0
	for _, v := range st.validators {
		if !v.Online {
			continue
		}

		st.simulateMessage()

		if v.IsByzantine && v.ByzantineType == "silent" {
			continue
		}

		commitVotes++
	}

	if commitVotes < quorum {
		atomic.AddInt64(&st.viewChanges, 1)
		return false
	}

	// Block finalized
	return true
}

// selectLeader selects the leader for a given block using stake-weighted selection.
func (st *StressTest) selectLeader(blockNum uint64) *MockValidator {
	// Simplified stake-weighted selection
	totalStake := uint64(0)
	for _, v := range st.validators {
		totalStake += v.Stake
	}

	target := uint64(blockNum*12345) % totalStake
	cumulative := uint64(0)
	for _, v := range st.validators {
		cumulative += v.Stake
		if cumulative > target {
			return v
		}
	}

	return st.validators[0]
}

// canCommunicate checks if two validators can communicate (considering partitions).
func (st *StressTest) canCommunicate(v1, v2 *MockValidator) bool {
	// Both must be online
	if !v1.Online || !v2.Online {
		return false
	}

	// Check partition
	if v1.Partition != 0 && v2.Partition != 0 && v1.Partition != v2.Partition {
		return false
	}

	// Simulate packet loss
	if rand.Float64()*100 < st.config.PacketLossPercent {
		atomic.AddInt64(&st.messagesDropped, 1)
		return false
	}

	return true
}

// simulateMessage simulates network message with latency.
func (st *StressTest) simulateMessage() {
	atomic.AddInt64(&st.messagesTotal, 1)

	latency := st.config.NetworkLatencyMs
	if st.config.NetworkJitterMs > 0 {
		latency += rand.Intn(st.config.NetworkJitterMs)
	}

	atomic.AddInt64(&st.totalLatencyNs, int64(latency)*1e6)
}

// runPartitionSimulator periodically creates and heals network partitions.
func (st *StressTest) runPartitionSimulator(ctx context.Context) {
	ticker := time.NewTicker(st.config.PartitionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Create partition
			st.createPartition()

			// Wait for partition duration
			select {
			case <-ctx.Done():
				return
			case <-time.After(st.config.PartitionDuration):
			}

			// Heal partition
			st.healPartition()
		}
	}
}

// createPartition splits validators into two groups.
func (st *StressTest) createPartition() {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.result.PartitionsTriggered++

	// Randomly assign validators to two partitions
	for _, v := range st.validators {
		if rand.Float64() < 0.5 {
			v.Partition = 1
		} else {
			v.Partition = 2
		}
	}
}

// healPartition removes all partitions.
func (st *StressTest) healPartition() {
	st.mu.Lock()
	defer st.mu.Unlock()

	for _, v := range st.validators {
		v.Partition = 0
	}
}

// =====================================================
// Stress Test Scenarios
// =====================================================

// RunScenario100Validators tests with 100 validators.
func RunScenario100Validators(ctx context.Context) *StressTestResult {
	config := DefaultStressTestConfig()
	config.NumValidators = 100
	config.Duration = 2 * time.Minute
	config.ByzantineFraction = 0.1

	st := NewStressTest(config)
	return st.Run(ctx)
}

// RunScenarioHighByzantine tests with 30% Byzantine validators.
func RunScenarioHighByzantine(ctx context.Context) *StressTestResult {
	config := DefaultStressTestConfig()
	config.NumValidators = 50
	config.Duration = 2 * time.Minute
	config.ByzantineFraction = 0.30 // Maximum tolerable

	st := NewStressTest(config)
	return st.Run(ctx)
}

// RunScenarioNetworkPartition tests network partition recovery.
func RunScenarioNetworkPartition(ctx context.Context) *StressTestResult {
	config := DefaultStressTestConfig()
	config.NumValidators = 50
	config.Duration = 3 * time.Minute
	config.PartitionEnabled = true
	config.PartitionDuration = 20 * time.Second
	config.PartitionInterval = 1 * time.Minute

	st := NewStressTest(config)
	return st.Run(ctx)
}

// RunScenarioHighLatency tests with high network latency.
func RunScenarioHighLatency(ctx context.Context) *StressTestResult {
	config := DefaultStressTestConfig()
	config.NumValidators = 50
	config.Duration = 2 * time.Minute
	config.NetworkLatencyMs = 200
	config.NetworkJitterMs = 100
	config.PacketLossPercent = 5.0

	st := NewStressTest(config)
	return st.Run(ctx)
}

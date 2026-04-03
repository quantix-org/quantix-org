// MIT License
// Copyright (c) 2024 quantix

// go/src/consensus/mode.go
package consensus

import logger "github.com/ramseyauron/quantix/src/log"

// ConsensusMode represents the active consensus strategy.
type ConsensusMode int

const (
	// DEVNET_SOLO is used when the validator count is below the quorum threshold.
	// In this mode the single leader mines blocks without waiting for peer votes.
	DEVNET_SOLO ConsensusMode = iota

	// PBFT is the normal multi-node Byzantine Fault Tolerant consensus.
	// Requires at least MinPBFTValidators validators.
	PBFT
)

// MinPBFTValidators is the minimum number of validators required for real PBFT.
const MinPBFTValidators = 4

// GetConsensusMode returns the appropriate ConsensusMode for the given validator count.
func GetConsensusMode(validatorCount int) ConsensusMode {
	if validatorCount >= MinPBFTValidators {
		return PBFT
	}
	return DEVNET_SOLO
}

// String returns a human-readable name for the mode.
func (m ConsensusMode) String() string {
	switch m {
	case DEVNET_SOLO:
		return "DEVNET_SOLO"
	case PBFT:
		return "PBFT"
	default:
		return "UNKNOWN"
	}
}

// ActiveConsensusMode returns the current consensus mode for this node based on
// how many validators are visible (self + peers).
func (c *Consensus) ActiveConsensusMode() ConsensusMode {
	c.mu.RLock()
	n := c.getTotalNodes()
	c.mu.RUnlock()
	return GetConsensusMode(n)
}

// logModeTransition emits a notice when the consensus mode would change.
func (c *Consensus) logModeTransition(prev, next ConsensusMode) {
	if prev != next {
		logger.Info("🔀 Consensus mode transition: %s → %s (validators: %d, threshold: %d)",
			prev, next, c.getTotalNodes(), MinPBFTValidators)
	}
}

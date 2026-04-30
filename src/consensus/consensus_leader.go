// MIT License
//
// Copyright (c) 2024 quantix
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


// consensus/consensus_leader.go — leader election (RANDAO + round-robin), epoch transitions, leader validation
package consensus

import (
	"sort"
	"time"

	logger "github.com/quantix-org/quantix-org/src/log"
)

func (c *Consensus) UpdateLeaderStatus() {
	c.updateLeaderStatus() // Call private implementation
}

func (c *Consensus) updateLeaderStatus() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Fall back to round-robin if stake-weighted selection is disabled
	if !c.useStakeWeighted {
		c.updateLeaderStatusRoundRobin()
		return
	}

	// Get current slot and epoch from time converter
	currentSlot := c.timeConverter.CurrentSlot()
	currentEpoch := currentSlot / SlotsPerEpoch

	// Handle epoch transition if we've moved to a new epoch
	if currentEpoch > c.currentEpoch {
		c.onEpochTransition(currentEpoch)
	}

	// Get RANDAO seed for current slot and select proposer
	seed := c.randao.GetSeed(currentSlot)
	selected := c.selector.SelectProposer(currentEpoch, seed)

	// Handle case where no validator was selected
	if selected == nil {
		c.isLeader = false
		c.electedLeaderID = ""
		c.electedSlot = 0
		logger.Warn("No validator selected for slot %d", currentSlot)
		return
	}

	// Store the elected leader information
	c.electedLeaderID = selected.ID
	c.electedSlot = currentSlot // Store the slot used for election
	c.isLeader = (selected.ID == c.nodeID)

	// Log selection status with appropriate formatting
	if c.isLeader {
		logger.Info("✅ Node %s selected as proposer for slot %d with stake %.2f QTX",
			c.nodeID, currentSlot, selected.GetStakeInQTX())
	} else {
		logger.Info("   Node %s NOT selected for slot %d (selected: %s with %.2f QTX)",
			c.nodeID, currentSlot, selected.ID, selected.GetStakeInQTX())
	}
}

func (c *Consensus) shouldPreventViewChange() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	// Block view change if we're in prepare phases — but not if we've been stuck for > 30s.
	// A long stall means the phase will never complete; force a view change to recover.
	stuckTooLong := time.Since(c.lastProposalTime) > 30*time.Second
	if stuckTooLong {
		return false // Allow view change to break the deadlock
	}
	if c.phase == PhasePrePrepared || c.phase == PhasePrepared {
		return true
	}
	// Block view change if we have pending votes
	if len(c.receivedVotes) > 0 || len(c.prepareVotes) > 0 {
		return true
	}
	return false
}

func (c *Consensus) onEpochTransition(newEpoch uint64) {
	// NOTE: c.mu is already held by the caller — do NOT lock here.
	logger.Info("🔄 Entering epoch %d", newEpoch)
	// Process attestations from the previous epoch
	if newEpoch > 0 {
		c.processEpochAttestations(newEpoch - 1)
	}
	c.currentEpoch = newEpoch // Update current epoch
}

func (c *Consensus) updateLeaderStatusRoundRobin() {
	// Use the staking registry — same on every node, not dependent on peer state.
	validators := c.validatorSet.ActiveValidatorIDs(c.currentEpoch)
	if len(validators) == 0 {
		// Fallback: live peers (first startup before staking is populated)
		validators = c.getValidators()
	}
	if len(validators) == 0 {
		c.isLeader = false
		c.electedLeaderID = ""
		return
	}
	// Sort for deterministic ordering (ActiveValidatorIDs already sorts, but be explicit)
	sort.Strings(validators)
	// Select leader based on current view
	leaderIndex := int(c.currentView) % len(validators)
	expectedLeader := validators[leaderIndex]
	c.electedLeaderID = expectedLeader
	c.isLeader = (expectedLeader == c.nodeID)
}

func (c *Consensus) updateLeaderStatusWithValidators(validators []string) {
	if len(validators) == 0 {
		c.isLeader = false
		c.electedLeaderID = ""
		return
	}

	// Sort for deterministic selection
	sort.Strings(validators)
	// Select leader based on current view
	leaderIndex := int(c.currentView) % len(validators)
	expectedLeader := validators[leaderIndex]

	// Store elected leader
	c.electedLeaderID = expectedLeader
	c.isLeader = (expectedLeader == c.nodeID)

	// Log election result
	if c.isLeader {
		logger.Info("✅ Node %s elected as leader for view %d (index %d/%d)",
			c.nodeID, c.currentView, leaderIndex, len(validators))
	} else {
		logger.Debug("Node %s is NOT leader for view %d (leader: %s)",
			c.nodeID, c.currentView, expectedLeader)
	}
}

func (c *Consensus) isValidLeader(nodeID string, view uint64) bool {
	// Use elected leader if available
	if c.electedLeaderID != "" {
		isValid := c.electedLeaderID == nodeID
		if isValid {
			logger.Info("✅ Valid leader (RANDAO/elected): %s for view %d", nodeID, view)
		} else {
			logger.Info("❌ Invalid leader: expected elected=%s for view %d, got=%s",
				c.electedLeaderID, view, nodeID)
		}
		return isValid
	}

	// Fallback: electedLeaderID not set (should not happen in normal operation)
	validators := c.getValidators()
	if len(validators) == 0 {
		return false
	}
	// Round-robin selection fallback
	sort.Strings(validators)
	leaderIndex := int(view) % len(validators)
	expectedLeader := validators[leaderIndex]
	isValid := expectedLeader == nodeID
	if isValid {
		logger.Info("✅ Valid leader (round-robin fallback): %s for view %d", nodeID, view)
	} else {
		logger.Info("❌ Invalid leader (round-robin fallback): expected %s for view %d, got %s",
			expectedLeader, view, nodeID)
	}
	return isValid
}

func (c *Consensus) getValidators() []string {
	peers := c.nodeManager.GetPeers()
	validatorSet := make(map[string]bool)
	validators := []string{}

	// Add self if validator
	if c.isValidator() {
		validatorSet[c.nodeID] = true
		validators = append(validators, c.nodeID)
	}

	// Add validator peers
	for _, peer := range peers {
		node := peer.GetNode()
		if node != nil && node.GetRole() == RoleValidator && node.GetStatus() == NodeStatusActive {
			nodeID := node.GetID()
			// Avoid duplicates
			if !validatorSet[nodeID] && nodeID != "" {
				validatorSet[nodeID] = true
				validators = append(validators, nodeID)
			}
		}
	}

	// Sort for deterministic ordering
	sort.Strings(validators)

	// Ensure we always have at least this node
	if len(validators) == 0 {
		logger.Error("CRITICAL: No validators found for consensus!")
		return []string{c.nodeID}
	}

	return validators
}

func (c *Consensus) isValidator() bool {
	self := c.nodeManager.GetNode(c.nodeID)
	return self != nil && self.GetRole() == RoleValidator
}


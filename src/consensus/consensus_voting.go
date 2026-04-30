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


// consensus/consensus_voting.go — prepare votes, commit votes, quorum checks
package consensus

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/quantix-org/quantix-org/src/common"
	types "github.com/quantix-org/quantix-org/src/core/transaction"
	logger "github.com/quantix-org/quantix-org/src/log"
	denom "github.com/quantix-org/quantix-org/src/params/denom"
)

func (c *Consensus) HandleVote(vote *Vote) error {
	select {
	case c.voteCh <- vote:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	default:
		return fmt.Errorf("vote channel full, dropping vote from %s", vote.VoterID)
	}
}

func (c *Consensus) HandlePrepareVote(vote *Vote) error {
	select {
	case c.prepareCh <- vote:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	default:
		return fmt.Errorf("prepare channel full, dropping prepare from %s", vote.VoterID)
	}
}

func (c *Consensus) processPrepareVote(vote *Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify vote signature if signing service available (skip in dev-mode)
	if c.signingService != nil && len(vote.Signature) > 0 && !c.devMode {
		valid, err := c.signingService.VerifyVote(vote)
		if err != nil || !valid {
			logger.Warn("Invalid prepare vote signature from %s", vote.VoterID)
			return
		}
	}

	// Initialize vote tracking maps for this block if needed
	if c.prepareVotes[vote.BlockHash] == nil {
		c.prepareVotes[vote.BlockHash] = make(map[string]*Vote)
		c.weightedPrepareVotes[vote.BlockHash] = big.NewInt(0)
	}

	// Ignore duplicate votes
	if _, exists := c.prepareVotes[vote.BlockHash][vote.VoterID]; exists {
		return
	}

	// Store the vote
	c.prepareVotes[vote.BlockHash][vote.VoterID] = vote

	// Add voter's stake to weighted vote total
	stake := c.getValidatorStake(vote.VoterID)
	c.weightedPrepareVotes[vote.BlockHash].Add(c.weightedPrepareVotes[vote.BlockHash], stake)

	// Log vote receipt with stake amount in QTX
	stakeSPX := new(big.Float).Quo(new(big.Float).SetInt(stake), new(big.Float).SetFloat64(denom.QTX))
	logger.Info("📊 Prepare vote: %s, block=%s, stake=%.2f QTX", vote.VoterID, vote.BlockHash, stakeSPX)

	// Calculate current vote count and quorum requirements
	totalVotes := len(c.prepareVotes[vote.BlockHash])
	quorumSize := c.calculateQuorumSize(c.getTotalNodes())

	logger.Info("📊 Prepare vote received: node=%s, from=%s, block=%s, votes=%d/%d, phase=%v, prepared=%v",
		c.nodeID, vote.VoterID, vote.BlockHash, totalVotes, quorumSize, c.phase, c.preparedBlock != nil)

	// Check if we've achieved quorum for this block
	if c.hasPrepareQuorum(vote.BlockHash) {
		logger.Info("🎉 PREPARE QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)

		// FIX-VIEWCHANGE-STORM: a view change may have cleared preparedBlock via
		// resetConsensusState.  Restore it from the proposedBlocks cache so that
		// the prepare quorum can still advance the protocol.
		if c.preparedBlock == nil || c.preparedBlock.GetHash() != vote.BlockHash {
			if cached, ok := c.proposedBlocks[vote.BlockHash]; ok && cached != nil {
				logger.Info("📦 Restoring preparedBlock from cache after view change, hash=%s", vote.BlockHash)
				c.preparedBlock = cached
			}
		}

		// Verify we have a prepared block for this hash
		if c.preparedBlock == nil || c.preparedBlock.GetHash() != vote.BlockHash {
			logger.Warn("❌ No prepared block found for hash %s (have: %v)", vote.BlockHash, c.preparedBlock != nil)
			if c.preparedBlock != nil {
				logger.Warn("   Current prepared block hash: %s", c.preparedBlock.GetHash())
			}
			return
		}

		// Add this vote to consensus signatures
		signatureHex := hex.EncodeToString(vote.Signature)
		consensusSig := &ConsensusSignature{
			BlockHash:    vote.BlockHash,
			BlockHeight:  c.currentHeight,
			SignerNodeID: vote.VoterID,
			Signature:    signatureHex,
			MessageType:  "prepare",
			View:         vote.View,
			Timestamp:    common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
			Valid:        true,
			MerkleRoot:   "pending_calculation",
			Status:       "prepared",
		}
		c.addConsensusSig(consensusSig)

		// Sticky proposal: save prepared block for re-use after view change
		c.lastPreparedBlock = c.preparedBlock
		c.lastPreparedHeight = c.currentHeight
		logger.Info("📌 Saved lastPreparedBlock hash=%s at height=%d", c.preparedBlock.GetHash(), c.currentHeight)

		// Transition to prepared phase if we're in pre-prepared
		if c.phase == PhasePrePrepared {
			c.phase = PhasePrepared
			c.lockedBlock = c.preparedBlock
			// Update block metadata
			if direct, ok := c.preparedBlock.(*types.Block); ok {
				direct.Header.CommitStatus = "prepared"
			} else if helper, ok := c.preparedBlock.(interface{ GetUnderlyingBlock() *types.Block }); ok {
				if ub := helper.GetUnderlyingBlock(); ub != nil {
					ub.Header.CommitStatus = "prepared"
				}
			}
			// Send commit vote for this block
			c.voteForBlock(vote.BlockHash, vote.View)
		} else {
			logger.Info("⚠️ Already in phase %v, skipping phase transition", c.phase)
		}
	}
}

func (c *Consensus) processVote(vote *Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify vote signature if signing service available (skip in dev-mode)
	if c.signingService != nil && len(vote.Signature) > 0 && !c.devMode {
		valid, err := c.signingService.VerifyVote(vote)
		if err != nil || !valid {
			logger.Warn("Invalid vote signature from %s", vote.VoterID)
			return
		}
	}

	// Initialize vote tracking for this block if needed
	if c.receivedVotes[vote.BlockHash] == nil {
		c.receivedVotes[vote.BlockHash] = make(map[string]*Vote)
		c.weightedCommitVotes[vote.BlockHash] = big.NewInt(0)
	}

	// Ignore duplicate votes
	if _, exists := c.receivedVotes[vote.BlockHash][vote.VoterID]; exists {
		return
	}

	// Store the vote
	c.receivedVotes[vote.BlockHash][vote.VoterID] = vote

	// Get voter's stake
	stake := c.getValidatorStake(vote.VoterID)
	// Handle zero stake case
	if stake.Cmp(big.NewInt(0)) == 0 {
		if vote.VoterID == c.nodeID {
			// Self stake fallback
			stake = new(big.Int).Mul(big.NewInt(32), big.NewInt(denom.QTX))
			logger.Info("⚠️ Self stake was zero, using default: 32 QTX")
		} else {
			logger.Warn("⚠️ Vote from %s has zero stake", vote.VoterID)
		}
	}

	// Add stake to weighted vote total
	c.weightedCommitVotes[vote.BlockHash].Add(c.weightedCommitVotes[vote.BlockHash], stake)

	// Log vote receipt with stake amount
	stakeSPX := new(big.Float).Quo(new(big.Float).SetInt(stake), new(big.Float).SetFloat64(denom.QTX))
	logger.Info("📊 Commit vote: %s, block=%s, stake=%.2f QTX", vote.VoterID, vote.BlockHash, stakeSPX)

	// Calculate current vote count and quorum requirements
	totalVotes := len(c.receivedVotes[vote.BlockHash])
	quorumSize := c.calculateQuorumSize(c.getTotalNodes())
	logger.Info("📊 Commit vote received: node=%s, from=%s, block=%s, votes=%d/%d, phase=%v",
		c.nodeID, vote.VoterID, vote.BlockHash, totalVotes, quorumSize, c.phase)
	// FIX-COMMIT-SHORTCUT: if we receive a commit vote from another validator
	// and haven't sent our own yet, the sender already achieved prepare quorum.
	// Join the commit round now — required for liveness when prepare votes are
	// dropped in a star topology and a node never reaches local prepare quorum.
	if !c.sentVotes[vote.BlockHash] {
		var blockForCommit Block
		if c.preparedBlock != nil && c.preparedBlock.GetHash() == vote.BlockHash {
			blockForCommit = c.preparedBlock
		} else if c.lockedBlock != nil && c.lockedBlock.GetHash() == vote.BlockHash {
			blockForCommit = c.lockedBlock
		} else if cached, ok := c.proposedBlocks[vote.BlockHash]; ok && cached != nil {
			blockForCommit = cached
		}
		if blockForCommit != nil {
			prevPhase := c.phase
			if c.phase == PhasePrePrepared || c.phase == PhaseIdle {
				c.phase = PhasePrepared
			}
			c.preparedBlock = blockForCommit
			c.lockedBlock = blockForCommit
			logger.Info("📦 Commit shortcut: joining commit round for block %s"+
				" (received commit from %s, local phase was %v)",
				vote.BlockHash, vote.VoterID, prevPhase)
			c.voteForBlock(vote.BlockHash, vote.View)
		}
	}

	// Check if we've achieved quorum for this block
	if c.hasQuorum(vote.BlockHash) {
		logger.Info("🎉 COMMIT QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)

		// Determine which block to commit
		var blockToCommit Block
		// FIX-VIEWCHANGE-STORM: restore preparedBlock/lockedBlock from cache if
		// a view change cleared them before commit quorum was reached.
		if (c.lockedBlock == nil || c.lockedBlock.GetHash() != vote.BlockHash) &&
			(c.preparedBlock == nil || c.preparedBlock.GetHash() != vote.BlockHash) {
			if cached, ok := c.proposedBlocks[vote.BlockHash]; ok && cached != nil {
				logger.Info("📦 Restoring preparedBlock from cache (commit path) for hash=%s", vote.BlockHash)
				c.preparedBlock = cached
			}
		}
		if c.lockedBlock != nil && c.lockedBlock.GetHash() == vote.BlockHash {
			blockToCommit = c.lockedBlock
		} else if c.preparedBlock != nil && c.preparedBlock.GetHash() == vote.BlockHash {
			blockToCommit = c.preparedBlock
		} else {
			logger.Warn("❌ No block found to commit for hash %s", vote.BlockHash)
			return
		}

		// Move to committed phase if not already there
		if c.phase != PhaseCommitted {
			c.phase = PhaseCommitted
			logger.Info("🚀 Moving to COMMITTED phase for block %s", vote.BlockHash)
		}

		// Add this vote to consensus signatures
		signatureHex := hex.EncodeToString(vote.Signature)
		consensusSig := &ConsensusSignature{
			BlockHash:    vote.BlockHash,
			BlockHeight:  c.currentHeight,
			SignerNodeID: vote.VoterID,
			Signature:    signatureHex,
			MessageType:  "commit",
			View:         vote.View,
			Timestamp:    common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
			Valid:        true,
			MerkleRoot:   "pending_calculation",
			Status:       "committed",
		}
		c.addConsensusSig(consensusSig)

		// Commit the block
		c.commitBlock(blockToCommit)
	}
}

func (c *Consensus) sendPrepareVote(blockHash string, view uint64) {
	// Check if already sent prepare vote for this block
	if c.sentPrepareVotes[blockHash] {
		return
	}

	// Create prepare vote message
	prepareVote := &Vote{
		BlockHash: blockHash,
		View:      view,
		VoterID:   c.nodeID,
		Signature: []byte{},
	}

	// Sign the vote if signing service available and not in dev-mode
	if c.signingService != nil && !c.devMode {
		if err := c.signingService.SignVote(prepareVote); err != nil {
			logger.Warn("Failed to sign prepare vote: %v", err)
			return
		}
	}

	// Mark as sent and broadcast
	c.sentPrepareVotes[blockHash] = true
	c.broadcastPrepareVote(prepareVote)
	// FIX-PBFT-DEADLOCK: self-deliver prepare vote so this node counts its own vote
	// towards quorum (needed for followers — without self-delivery they never reach
	// prepare quorum and never send commit votes).
	go func() { _ = c.HandlePrepareVote(prepareVote) }()
	logger.Info("Node %s sent prepare vote for block %s at view %d", c.nodeID, blockHash, view)
}

func (c *Consensus) voteForBlock(blockHash string, view uint64) {
	// Check if already sent commit vote for this block
	if c.sentVotes[blockHash] {
		return
	}

	// Find the block to vote for
	var blockToVote Block
	if c.lockedBlock != nil && c.lockedBlock.GetHash() == blockHash {
		blockToVote = c.lockedBlock
	} else if c.preparedBlock != nil && c.preparedBlock.GetHash() == blockHash {
		blockToVote = c.preparedBlock
	} else if cached, ok := c.proposedBlocks[blockHash]; ok && cached != nil {
		// FIX-VIEWCHANGE-STORM: fall back to proposedBlocks cache when a view
		// change cleared lockedBlock/preparedBlock before voteForBlock was called.
		logger.Info("📦 Using cached proposedBlock for commit vote, hash=%s", blockHash)
		blockToVote = cached
	} else {
		logger.Warn("❌ No block found to vote for hash %s", blockHash)
		return
	}

	// Create commit vote message
	vote := &Vote{
		BlockHash: blockHash,
		View:      view,
		VoterID:   c.nodeID,
		Signature: []byte{},
	}

	// Sign the vote if signing service available and not in dev-mode
	if c.signingService != nil && !c.devMode {
		if err := c.signingService.SignVote(vote); err != nil {
			logger.Warn("Failed to sign commit vote: %v", err)
			return
		}
	}

	// Mark as sent and broadcast
	c.sentVotes[blockHash] = true
	c.broadcastVote(vote)
	// FIX-PBFT-DEADLOCK: self-deliver commit vote so this node counts its own
	// vote towards commit quorum (needed for all nodes including the proposer).
	go func() { _ = c.HandleVote(vote) }()
	logger.Info("🗳️ Node %s sent COMMIT vote for block %s (height %d) at view %d",
		c.nodeID, blockHash, blockToVote.GetHeight(), view)
}

func (c *Consensus) hasQuorum(blockHash string) bool {
	// Get votes for this block
	votes := c.receivedVotes[blockHash]
	if votes == nil {
		return false
	}

	// Calculate total stake that has voted
	totalStakeVoted := big.NewInt(0)
	for voterID := range votes {
		if stake := c.getValidatorStake(voterID); stake != nil {
			totalStakeVoted.Add(totalStakeVoted, stake)
		}
	}

	// Store weighted vote total
	c.weightedCommitVotes[blockHash] = totalStakeVoted

	// FIX-QUORUM-RACE: use the snapshotted total stake for this round so that
	// a validator re-registering mid-round cannot raise the quorum bar.
	totalStake := c.roundTotalStake
	if totalStake == nil {
		totalStake = c.validatorSet.GetTotalStake()
	}

	// Cannot achieve quorum if total stake is zero
	if totalStake == nil || totalStake.Cmp(big.NewInt(0)) == 0 {
		logger.Warn("Total stake is zero, cannot achieve quorum")
		return false
	}

	// F-02 fix: floor(2*totalStake/3) allows exactly 66.6% to pass due to integer
	// truncation. BFT safety requires strictly more than 2/3, so we add +1.
	requiredStake := new(big.Int).Mul(totalStake, big.NewInt(2))
	requiredStake.Div(requiredStake, big.NewInt(3))
	requiredStake.Add(requiredStake, big.NewInt(1)) // +1 enforces strict BFT majority

	// Check if quorum achieved
	hasQuorum := totalStakeVoted.Cmp(requiredStake) >= 0

	// Log quorum details if achieved
	if hasQuorum && totalStakeVoted.Cmp(big.NewInt(0)) > 0 {
		votedSPX := new(big.Float).Quo(new(big.Float).SetInt(totalStakeVoted), new(big.Float).SetFloat64(denom.QTX))
		totalQTX := new(big.Float).Quo(new(big.Float).SetInt(totalStake), new(big.Float).SetFloat64(denom.QTX))
		if totalQTX.Cmp(big.NewFloat(0)) != 0 {
			pct := new(big.Float).Quo(votedSPX, totalQTX)
			pct.Mul(pct, big.NewFloat(100))
			logger.Info("🎯 Quorum achieved: %.2f / %.2f QTX voted (%.1f%%)", votedSPX, totalQTX, pct)
		}
	}
	return hasQuorum
}

func (c *Consensus) hasPrepareQuorum(blockHash string) bool {
	// Get prepare votes for this block
	votes := c.prepareVotes[blockHash]
	if votes == nil {
		return false
	}

	// Calculate total stake that has voted
	totalStakeVoted := big.NewInt(0)
	for voterID := range votes {
		if stake := c.getValidatorStake(voterID); stake != nil {
			totalStakeVoted.Add(totalStakeVoted, stake)
		}
	}

	// Store weighted vote total
	c.weightedPrepareVotes[blockHash] = totalStakeVoted

	// Get total stake from validator set
	// FIX-QUORUM-RACE: use the snapshotted total stake for this round so that
	// a validator re-registering mid-round cannot raise the quorum bar.
	totalStake := c.roundTotalStake
	if totalStake == nil {
		totalStake = c.validatorSet.GetTotalStake()
	}

	// Cannot achieve quorum if total stake is zero
	if totalStake == nil || totalStake.Cmp(big.NewInt(0)) == 0 {
		return false
	}

	// F-02 fix: same off-by-one correction as hasQuorum — enforce strict BFT majority.
	requiredStake := new(big.Int).Mul(totalStake, big.NewInt(2))
	requiredStake.Div(requiredStake, big.NewInt(3))
	requiredStake.Add(requiredStake, big.NewInt(1)) // +1 enforces strict BFT majority

	return totalStakeVoted.Cmp(requiredStake) >= 0
}

func (c *Consensus) getValidatorStake(validatorID string) *big.Int {
	c.validatorSet.mu.RLock()
	defer c.validatorSet.mu.RUnlock()
	if val, exists := c.validatorSet.validators[validatorID]; exists {
		return val.StakeAmount
	}
	return big.NewInt(0)
}

func (c *Consensus) calculateQuorumSize(totalNodes int) int {
	if totalNodes < 1 {
		return 1
	}
	// floor(2N/3) + 1 mirrors the stake-weighted threshold
	quorumSize := (2*totalNodes)/3 + 1
	if quorumSize < 1 {
		return 1 // Minimum quorum size is 1
	}
	return quorumSize
}

func (c *Consensus) getTotalNodes() int {
	// Primary: count from validatorSet (authoritative once PBFT is active)
	if c.validatorSet != nil {
		c.validatorSet.mu.RLock()
		vsCount := len(c.validatorSet.validators)
		c.validatorSet.mu.RUnlock()
		if vsCount >= MinPBFTValidators {
			return vsCount
		}
	}

	// Fallback: count from P2P peer list
	peers := c.nodeManager.GetPeers()
	validatorCount := 0
	// Count validator peers
	for _, peer := range peers {
		node := peer.GetNode()
		if node.GetRole() == RoleValidator && node.GetStatus() == NodeStatusActive {
			validatorCount++
		}
	}
	// Count self if validator
	if c.isValidator() {
		validatorCount++
	}
	return validatorCount
}

func (c *Consensus) broadcastVote(vote *Vote) error {
	logger.Info("Broadcasting commit vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("vote", vote)
}

func (c *Consensus) broadcastPrepareVote(vote *Vote) error {
	logger.Info("Broadcasting prepare vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("prepare", vote)
}

func (c *Consensus) broadcastTimeout(timeout *TimeoutMsg) error {
	logger.Info("Broadcasting timeout for view %d", timeout.View)
	return c.nodeManager.BroadcastMessage("timeout", timeout)
}


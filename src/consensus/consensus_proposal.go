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


// consensus/consensus_proposal.go — block proposal creation, validation, and broadcasting
package consensus

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/quantix-org/quantix-org/src/common"
	types "github.com/quantix-org/quantix-org/src/core/transaction"
	logger "github.com/quantix-org/quantix-org/src/log"
)

func (c *Consensus) ProposeBlock(block Block) error {
	// Verify leader status and build proposal under lock; release before network I/O.
	c.mu.Lock()

	// Verify this node is actually the leader
	if !c.isLeader {
		c.mu.Unlock()
		return fmt.Errorf("node %s is not the leader", c.nodeID)
	}

	// Sign the block header if signing service is available and not in dev-mode
	if c.signingService != nil && !c.devMode {
		c.mu.Unlock()
		if err := c.signingService.SignBlock(block); err != nil {
			logger.Warn("⚠️ SignBlock failed (non-fatal, continuing proposal): %v", err)
		}
		c.mu.Lock()
	}

	// Update block metadata for tracking
	// BUG 3 FIX: In devMode, block signing is skipped but we still mark SigValid=true
	// to avoid false "signature_valid:false" in logs. Signature verification is skipped
	// in dev/test mode by design.
	sigValid := c.devMode // devMode: no signing, mark valid; production: sign first, then mark below
	if direct, ok := block.(*types.Block); ok {
		direct.Header.CommitStatus = "proposed"
		direct.Header.SigValid = sigValid
	} else if helper, ok := block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		if ub := helper.GetUnderlyingBlock(); ub != nil {
			ub.Header.CommitStatus = "proposed"
			ub.Header.SigValid = sigValid
		}
	}

	// Use the slot from election time, NOT current slot.
	// By the time ProposeBlock is called, the slot may have advanced,
	// causing followers to re-derive a different winner from the new slot.
	// Use the slot from election time, NOT current slot.
	proposalSlot := c.electedSlot
	if proposalSlot == 0 {
		proposalSlot = c.timeConverter.CurrentSlot()
		logger.Warn("⚠️ electedSlot was 0, using current slot %d", proposalSlot)
	}

	// Create the proposal message
	proposal := &Proposal{
		Block:           block,
		View:            c.currentView,
		ProposerID:      c.nodeID,
		Signature:       []byte{},
		ElectedLeaderID: c.electedLeaderID,
		SlotNumber:      proposalSlot, // CRITICAL: Must be set for signature verification
	}

	// Log the proposal details before signing
	logger.Info("📝 Creating proposal: slot=%d, view=%d, leader=%s, block=%s",
		proposalSlot, c.currentView, c.nodeID, block.GetHash())

	// Sign the proposal (skip in dev-mode to avoid slow SPHINCS+ operations)
	if c.signingService != nil && !c.devMode {
		if err := c.signingService.SignProposal(proposal); err != nil {
			logger.Warn("⚠️ SignProposal failed (non-fatal, continuing proposal): %v", err)
		}
	}

	// In DEVNET_SOLO mode we self-commit without waiting for peer votes.
	// This avoids a deadlock where the single node waits for a quorum that
	// can never be reached.
	// FIX-PBFT-DEADLOCK: c.mu is already held here — call getTotalNodes() directly
	// instead of ActiveConsensusMode() which would re-acquire c.mu.RLock() causing
	// a self-deadlock on the same goroutine (sync.RWMutex is not reentrant).
	devnetSolo := GetConsensusMode(c.getTotalNodes()) == DEVNET_SOLO
	c.mu.Unlock()

	if devnetSolo {
		logger.Info("⛏️  DEVNET_SOLO: self-committing block %s (no peers)", proposal.Block.GetHash())
		c.mu.Lock()
		c.preparedBlock = proposal.Block
		c.lockedBlock = proposal.Block
		c.phase = PhaseCommitted
		c.mu.Unlock()
		c.commitBlock(proposal.Block)
		return nil
	}

	// Broadcast the proposal (lock already released)
	// FIX-PBFT-DEADLOCK: also self-deliver the proposal so the proposer node
	// participates in the prepare phase (sets preparedBlock, sends PrepareVote).
	// Without self-delivery, the proposer never sets c.preparedBlock and cannot
	// reach prepare quorum even when f+1 followers send PrepareVotes.
	if err := c.broadcastProposal(proposal); err != nil {
		return err
	}
	return c.HandleProposal(proposal)
}

func (c *Consensus) HandleProposal(proposal *Proposal) error {
	select {
	case c.proposalCh <- proposal:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	default:
		return fmt.Errorf("proposal channel full, dropping proposal for block %s", proposal.Block.GetHash())
	}
}

func (c *Consensus) processProposal(proposal *Proposal) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get block nonce for logging
	nonce, err := proposal.Block.GetCurrentNonce()
	nonceStr := "unknown"
	if err != nil {
		logger.Warn("Failed to get block nonce: %v", err)
	} else {
		nonceStr = fmt.Sprintf("%d", nonce)
	}

	// Log proposal receipt
	logger.Info("🔍 Processing proposal for block %s at view %d from %s, nonce: %s",
		proposal.Block.GetHash(), proposal.View, proposal.ProposerID, nonceStr)

	// Validate the block itself
	if err := c.blockChain.ValidateBlock(proposal.Block); err != nil {
		logger.Warn("❌ Block validation failed: %v", err)
		return
	}

	// Check for duplicate proposal.
	// Duplicates arrive when the star-topology relay bounces our own broadcast
	// back to us (validator-0 relays to all peers including the original sender).
	// The sender never marks outgoing messages in seenConsensusMsgs, so the
	// bounced copy passes the P2P dedup and reaches processProposal a second time.
	// Triggering a view-change here would be wrong: it would kill a live round
	// milliseconds after it started, causing an infinite rotate-proposer loop.
	// Just silently discard — the relay-loopback prevention in BroadcastMessage
	// (MarkConsensusMsgSeen) ensures this race shrinks to zero over time.
	if c.preparedBlock != nil && c.preparedBlock.GetHash() == proposal.Block.GetHash() {
		logger.Warn("⚠️ Duplicate proposal for block %s at height %d (relay bounce) — ignoring",
			proposal.Block.GetHash(), proposal.Block.GetHeight())
		return
	}

	// Verify proposal signature if signing service available.
	// F-12: Reject proposals with missing signatures when signing service is configured.
	if c.signingService != nil && !c.devMode {
		if len(proposal.Signature) == 0 {
			logger.Warn("❌ Rejecting unsigned proposal from %s (signing service active)", proposal.ProposerID)
			return
		}
		valid, err := c.signingService.VerifyProposal(proposal)
		if err != nil {
			logger.Warn("❌ Error verifying proposal signature from %s: %v", proposal.ProposerID, err)
			return
		}
		if !valid {
			logger.Warn("❌ Invalid proposal signature from %s", proposal.ProposerID)
			return
		}
		logger.Info("✅ Valid signature for proposal from %s", proposal.ProposerID)
	} else if c.signingService == nil {
		logger.Warn("⚠️ No signing service, skipping proposal signature verification")
	} else {
		logger.Info("⚠️ Dev-mode: skipping proposal signature verification from %s", proposal.ProposerID)
	}

	// Verify block header signature
	if c.signingService != nil && !c.devMode {
		valid, err := c.signingService.VerifyBlockSignature(proposal.Block)
		if err != nil || !valid {
			logger.Warn("❌ Invalid block header signature from proposer %s: %v", proposal.ProposerID, err)
			return
		}
		logger.Info("✅ Block header signature verified for block %s", proposal.Block.GetHash())
	}

	// Update block metadata for tracking
	if direct, ok := proposal.Block.(*types.Block); ok {
		direct.Header.SigValid = true
		direct.Header.CommitStatus = "proposed"
	} else if helper, ok := proposal.Block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		if ub := helper.GetUnderlyingBlock(); ub != nil {
			ub.Header.SigValid = true
			ub.Header.CommitStatus = "proposed"
		}
	}

	// Add proposal signature to consensus signatures
	signatureHex := hex.EncodeToString(proposal.Signature)
	consensusSig := &ConsensusSignature{
		BlockHash:    proposal.Block.GetHash(),
		BlockHeight:  proposal.Block.GetHeight(),
		SignerNodeID: proposal.ProposerID,
		Signature:    signatureHex,
		MessageType:  "proposal",
		View:         proposal.View,
		Timestamp:    common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
		Valid:        true,
		MerkleRoot:   "pending_calculation",
		Status:       "proposed",
	}
	// Check for stale proposal
	if proposal.View < c.currentView {
		logger.Warn("❌ Stale proposal for view %d, current view %d", proposal.View, c.currentView)
		return
	}

	// Handle view advancement if proposal is for a newer view
	if proposal.View > c.currentView {
		logger.Info("🔄 Advancing view from %d to %d", c.currentView, proposal.View)
		c.currentView = proposal.View
		c.resetConsensusState()
		// Re-run so electedLeaderID is refreshed for the new view
		c.updateLeaderStatus()
	}

	// Verify block height matches expected next height
	currentHeight := c.blockChain.GetLatestBlock().GetHeight()
	if proposal.Block.GetHeight() != currentHeight+1 {
		logger.Warn("❌ Invalid block height: expected %d, got %d",
			currentHeight+1, proposal.Block.GetHeight())
		return
	}

	// PBFT LOCK: once we've accepted a proposal for this height at the current view,
	// reject any competing proposal with a different block hash.
	// Multiple validators may each believe they are the RANDAO-elected leader; without
	// this lock every arriving proposal overwrites c.preparedBlock, orphaning the
	// prepare/commit votes for the previous hash → split voting → permanent stall.
	// A proposal with a HIGHER view number is handled by the view-advance branch above
	// (calls resetConsensusState which clears preparedBlock) so it is not affected.
	if c.preparedBlock != nil {
		logger.Warn("⚠️ PBFT lock: already accepted block %s for height %d view %d — rejecting competing proposal %s from %s",
			c.preparedBlock.GetHash(), proposal.Block.GetHeight(), c.currentView,
			proposal.Block.GetHash(), proposal.ProposerID)
		return
	}

	// Determine the expected leader for this proposal.
	// At view 0 the leader is RANDAO-elected (slot-based).
	// At view > 0 a view-change fired — leader is round-robin (currentView % numValidators),
	// same formula used by startViewChange/updateLeaderStatusRoundRobin.
	// Using RANDAO at view > 0 would disagree with the proposer and reject every view-change proposal.
	if proposal.View > 0 {
		// View-change: sync electedLeaderID via round-robin before validation.
		c.updateLeaderStatusRoundRobin()
		logger.Info("\U0001f504 Follower using round-robin leader=%s for view %d", c.electedLeaderID, proposal.View)
	} else if proposal.SlotNumber > 0 {
		slotEpoch := proposal.SlotNumber / SlotsPerEpoch
		seed := c.randao.GetSeed(proposal.SlotNumber)
		selected := c.selector.SelectProposer(slotEpoch, seed)
		if selected != nil {
			c.electedLeaderID = selected.ID
			logger.Info("\U0001f504 Follower re-derived electedLeaderID=%s for slot %d (epoch %d)",
				c.electedLeaderID, proposal.SlotNumber, slotEpoch)
		} else {
			logger.Warn("\u26a0\ufe0f SelectProposer returned nil for slot %d, trusting signed proposal", proposal.SlotNumber)
			c.electedLeaderID = proposal.ProposerID
		}
	} else if proposal.ElectedLeaderID != "" {
		logger.Warn("\u26a0\ufe0f Proposal has no SlotNumber, using embedded ElectedLeaderID=%s", proposal.ElectedLeaderID)
		c.electedLeaderID = proposal.ElectedLeaderID
	} else {
		c.updateLeaderStatus()
	}
	// ────────────────────────────────────────────────────────────────────────

	// Validate that the proposer is the legitimate leader
	if !c.isValidLeader(proposal.ProposerID, proposal.View) {
		logger.Warn("❌ Invalid leader %s for view %d (electedLeaderID=%s)",
			proposal.ProposerID, proposal.View, c.electedLeaderID)
		return
	}

	// Record signature only for proposals that pass all validation checks
	c.addConsensusSig(consensusSig)
	logger.Info("✅ Added proposal signature for block %s", proposal.Block.GetHash())

	// Accept the proposal
	logger.Info("✅ Node %s accepting proposal for block %s at view %d (height %d, nonce: %s)",
		c.nodeID, proposal.Block.GetHash(), proposal.View, proposal.Block.GetHeight(), nonceStr)

	// P2-5: record proposal arrival time for partition detection
	c.lastProposalTime = common.GetTimeService().Now()

	// Store prepared block and move to pre-prepared phase
	c.preparedBlock = proposal.Block
	c.preparedView = proposal.View
	c.phase = PhasePrePrepared

	// FIX-VIEWCHANGE-STORM: cache accepted proposal so processPrepareVote/processVote
	// can still find the block after a view change clears preparedBlock/lockedBlock.
	if c.proposedBlocks == nil {
		c.proposedBlocks = make(map[string]Block)
	}
	c.proposedBlocks[proposal.Block.GetHash()] = proposal.Block

	// FIX-QUORUM-RACE: snapshot the validator set total stake at proposal-accept
	// time.  This prevents a validator re-registering between prepare and commit
	// phases from silently raising the quorum bar and preventing commit quorum.
	if c.roundTotalStake == nil {
		c.roundTotalStake = c.validatorSet.GetTotalStake()
		stakeStr := new(big.Float).Quo(new(big.Float).SetInt(c.roundTotalStake),
			new(big.Float).SetFloat64(1e6)).Text('f', 2)
		logger.Info("📸 Snapshotted round total stake: %s QTX (height %d)",
			stakeStr, proposal.Block.GetHeight())
	}

	// Send prepare vote for this block
	c.sendPrepareVote(proposal.Block.GetHash(), proposal.View)
}

func (c *Consensus) CacheMerkleRoot(blockHash, merkleRoot string) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()
	// Initialize cache if needed
	if c.merkleRootCache == nil {
		c.merkleRootCache = make(map[string]string)
	}
	c.merkleRootCache[blockHash] = merkleRoot
	logger.Info("Cached merkle root for block %s: %s", blockHash, merkleRoot)
}

func (c *Consensus) GetCachedMerkleRoot(blockHash string) string {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()
	if c.merkleRootCache != nil {
		if root, exists := c.merkleRootCache[blockHash]; exists {
			return root
		}
	}
	return ""
}

func (c *Consensus) StatusFromMsgType(messageType string) string {
	switch messageType {
	case "proposal":
		return "proposed"
	case "prepare":
		return "prepared"
	case "commit":
		return "committed"
	case "timeout":
		return "view_change"
	default:
		return "processed"
	}
}

func (c *Consensus) broadcastProposal(proposal *Proposal) error {
	logger.Info("Broadcasting proposal for block %s at view %d", proposal.Block.GetHash(), proposal.View)
	return c.nodeManager.BroadcastMessage("proposal", proposal)
}


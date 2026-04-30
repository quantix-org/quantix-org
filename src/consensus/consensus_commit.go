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


// consensus/consensus_commit.go — block commitment and external commit notification
package consensus

import (

	"github.com/quantix-org/quantix-org/src/common"
	types "github.com/quantix-org/quantix-org/src/core/transaction"
	logger "github.com/quantix-org/quantix-org/src/log"
)

func (c *Consensus) commitBlock(block Block) {
	logger.Info("🚀 Node %s attempting to commit block %s at height %d",
		c.nodeID, block.GetHash(), block.GetHeight())

	// Verify block height
	currentHeight := c.blockChain.GetLatestBlock().GetHeight()
	if block.GetHeight() != currentHeight+1 {
		logger.Warn("❌ Block height mismatch: expected %d, got %d", currentHeight+1, block.GetHeight())
		return
	}

	// Extract underlying block if needed
	var tb *types.Block
	if direct, ok := block.(*types.Block); ok {
		tb = direct
	} else if helper, ok := block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		tb = helper.GetUnderlyingBlock()
	}

	// Update block metadata if extraction succeeded
	if tb == nil {
		logger.Error("❌ commitBlock: cannot extract *types.Block from %T", block)
	} else {
		tb.Header.CommitStatus = "committed"
		if len(tb.Header.ProposerSignature) > 0 {
			tb.Header.SigValid = true
		}

		// Attach attestations from votes to the block
		votesSnapshot := make(map[string]*Vote)
		if votes, exists := c.receivedVotes[block.GetHash()]; exists {
			for k, v := range votes {
				votesSnapshot[k] = v
			}
		}

		if len(votesSnapshot) > 0 {
			tb.Body.Attestations = make([]*types.Attestation, 0, len(votesSnapshot))
			for voterID, vote := range votesSnapshot {
				tb.Body.Attestations = append(tb.Body.Attestations, &types.Attestation{
					ValidatorID: voterID,
					BlockHash:   block.GetHash(),
					View:        vote.View,
					Signature:   vote.Signature,
				})
			}
			logger.Info("✅ Attached %d attestations to block %s", len(tb.Body.Attestations), block.GetHash())
		} else {
			logger.Warn("⚠️ No votes in snapshot for block %s — attestations will be empty", block.GetHash())
		}
	}

	// Commit block to blockchain
	if err := c.blockChain.CommitBlock(block); err != nil {
		logger.Error("❌ Error committing block: %v", err)
		return
	}

	// Execute commit callback if provided
	if c.onCommit != nil {
		if err := c.onCommit(block); err != nil {
			logger.Warn("⚠️ Error in commit callback: %v", err)
		}
	}

	// Update consensus state
	c.currentHeight = block.GetHeight()
	c.lastBlockTime = common.GetTimeService().Now()
	c.lastProposalTime = common.GetTimeService().Now() // reset so shouldPreventViewChange doesn't immediately expire
	// Clear sticky-proposal for the committed height
	if c.lastPreparedHeight <= block.GetHeight() {
		c.lastPreparedBlock = nil
		c.lastPreparedHeight = 0
	}
	// Clear height-specific vote maps before resetting view state.
	c.receivedVotes = make(map[string]map[string]*Vote)
	c.prepareVotes = make(map[string]map[string]*Vote)
	// FIX-VIEWCHANGE-STORM: clear per-height block cache on height advance.
	c.proposedBlocks = make(map[string]Block)
	// FIX-QUORUM-RACE: clear the snapshotted stake so the next round captures a fresh value.
	c.roundTotalStake = nil
	c.resetConsensusState()
	c.currentView = 0 // Reset view counter for new height (PBFT: views are per-height)

	logger.Info("🎉 Node %s successfully committed block %s at height %d",
		c.nodeID, block.GetHash(), c.currentHeight)
}

func (c *Consensus) OnExternalBlockCommit(height uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.currentHeight >= height {
		// Already at or past this height via normal consensus — nothing to do.
		return
	}
	logger.Info("🔄 Gossip-sync: block height=%d committed externally, advancing consensus state", height)
	c.currentHeight = height
	c.lastBlockTime = common.GetTimeService().Now()
	c.lastProposalTime = common.GetTimeService().Now() // prevent immediate view-change timer
	if c.lastPreparedHeight <= height {
		c.lastPreparedBlock = nil
		c.lastPreparedHeight = 0
	}
	// Clear height-specific vote maps before resetting view state.
	c.receivedVotes = make(map[string]map[string]*Vote)
	c.prepareVotes = make(map[string]map[string]*Vote)
	// FIX-QUORUM-RACE: clear the snapshotted stake on external height advance too.
	c.roundTotalStake = nil
	c.resetConsensusState()
	c.currentView = 0 // Reset view per-height so stale view numbers don't block next proposals
}


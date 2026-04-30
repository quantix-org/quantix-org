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


// consensus/consensus_viewchange.go — view change, timeout processing, consensus state reset
package consensus

import (
	"fmt"
	"time"

	"github.com/quantix-org/quantix-org/src/common"
	logger "github.com/quantix-org/quantix-org/src/log"
)

func (c *Consensus) HandleTimeout(timeout *TimeoutMsg) error {
	select {
	case c.timeoutCh <- timeout:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	default:
		return fmt.Errorf("timeout channel full, dropping timeout from %s", timeout.VoterID)
	}
}

func (c *Consensus) processTimeout(timeout *TimeoutMsg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify timeout signature if signing service available (skip in dev-mode)
	if c.signingService != nil && len(timeout.Signature) > 0 && !c.devMode {
		valid, err := c.signingService.VerifyTimeout(timeout)
		if err != nil || !valid {
			logger.Warn("Invalid timeout signature from %s: %v", timeout.VoterID, err)
			return
		}
	} else if c.signingService == nil {
		logger.Warn("WARNING: No signing service, accepting unsigned timeout from %s", timeout.VoterID)
	}

	// F-13: Collect timeout messages per view and only advance when a strict
	// majority of validators agree (prevents a single node from unilaterally
	// advancing the view and wiping ongoing prepare rounds).
	if timeout.View > c.currentView {
		if c.timeoutVotes[timeout.View] == nil {
			c.timeoutVotes[timeout.View] = make(map[string]*TimeoutMsg)
		}
		c.timeoutVotes[timeout.View][timeout.VoterID] = timeout

		validators := c.getValidators()
		n := len(validators)
		// FIX-VIEWCHANGE-STORM: use strict majority (ceil(n/2)) instead of f+1.
		// With n=3, f=0, the old formula f+1=1 let a *single* node advance the
		// view, wiping all in-progress prepare rounds.  Requiring 2-of-3 forces
		// genuine agreement before a view change is committed.
		required := (n + 1) / 2
		if required < 1 {
			required = 1
		}
		votes := len(c.timeoutVotes[timeout.View])
		logger.Info("View change votes for view %d: %d/%d (need %d)", timeout.View, votes, n, required)
		if votes >= required {
			logger.Info("View change quorum reached for view %d by %s", timeout.View, timeout.VoterID)
			// Clean up old timeout votes
			for v := range c.timeoutVotes {
				if v <= c.currentView {
					delete(c.timeoutVotes, v)
				}
			}
			c.currentView = timeout.View
			c.lastViewChange = common.GetTimeService().Now()
			c.resetConsensusState()
			c.updateLeaderStatusWithValidators(validators)
			logger.Info("View change completed: node=%s, new_view=%d, leader=%v", c.nodeID, c.currentView, c.isLeader)
		}
	}
}

func (c *Consensus) startViewChange() {
	// Try to acquire view change lock
	if !c.tryViewChangeLock() {
		return
	}
	defer c.viewChangeMutex.Unlock()

	var newView uint64
	{
		// Scope the mu lock to state mutation only; release before network I/O.
		c.mu.Lock()
		if c.phase != PhaseIdle {
			stuckTooLong := time.Since(c.lastProposalTime) > 30*time.Second
			if !stuckTooLong {
				c.mu.Unlock()
				return
			}
			// Force-reset stuck phase to allow recovery view change
			c.resetConsensusState()
		}
		if common.GetTimeService().Now().Sub(c.lastViewChange) < 30*time.Second {
			c.mu.Unlock()
			return // Rate limit view changes
		}
		if c.currentHeight > 0 && common.GetTimeService().Now().Sub(c.lastBlockTime) < 30*time.Second {
			c.mu.Unlock()
			return // Recent block committed, don't change view
		}

		// Get current validators
		validators := c.getValidators()
		if len(validators) == 0 {
			logger.Warn("Skipping view change - no validators available")
			c.mu.Unlock()
			return
		}

		// Calculate new view number
		newView = c.currentView + 1
		logger.Info("🔄 Node %s initiating view change to view %d", c.nodeID, newView)

		// Update consensus state
		c.currentView = newView
		c.lastViewChange = common.GetTimeService().Now()
		c.resetConsensusState()
		c.updateLeaderStatusWithValidators(validators)

		c.mu.Unlock() // Release before network I/O below
	}

	// Create and broadcast timeout message
	timeoutMsg := &TimeoutMsg{
		View:      newView,
		VoterID:   c.nodeID,
		Signature: []byte{},
		Timestamp: common.GetCurrentTimestamp(),
	}

	// Sign timeout if signing service available
	if c.signingService != nil {
		if err := c.signingService.SignTimeout(timeoutMsg); err != nil {
			logger.Warn("Failed to sign timeout message: %v", err)
			return
		}
	}

	// Broadcast timeout
	if err := c.broadcastTimeout(timeoutMsg); err != nil {
		logger.Warn("Failed to broadcast timeout message: %v", err)
	}
}

func (c *Consensus) tryViewChangeLock() bool {
	acquired := make(chan bool, 1)
	// Try to acquire lock in goroutine
	go func() {
		c.viewChangeMutex.Lock()
		acquired <- true
	}()
	// Wait for acquisition or timeout
	select {
	case <-acquired:
		return true
	case <-time.After(100 * time.Millisecond):
		return false
	case <-c.ctx.Done():
		return false
	}
}

func (c *Consensus) resetConsensusState() {
	c.phase = PhaseIdle
	c.lockedBlock = nil
	c.preparedBlock = nil
	c.preparedView = 0
	c.sentVotes = make(map[string]bool)
	c.sentPrepareVotes = make(map[string]bool)
	// Note: do NOT clear electedLeaderID or electedSlot here —
	// they are still needed by ProposeBlock and isValidLeader after a reset.
}


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


// consensus/consensus_getters.go — public getters and simple setters
package consensus

import (
	"fmt"
	"time"

	"github.com/quantix-org/quantix-org/src/common"
)

func (c *Consensus) GetElectedLeaderID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.electedLeaderID
}

func (c *Consensus) GetCurrentView() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentView
}

func (c *Consensus) IsLeader() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isLeader
}

func (c *Consensus) GetLastPreparedBlock() (Block, uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastPreparedBlock, c.lastPreparedHeight
}

func (c *Consensus) GetPhase() ConsensusPhase {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.phase
}

func (c *Consensus) GetCurrentHeight() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentHeight
}

func (c *Consensus) SetLastBlockTime(blockTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastBlockTime = blockTime
}

func (c *Consensus) GetConsensusState() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Get block hashes for display
	preparedHash := ""
	if c.preparedBlock != nil {
		preparedHash = c.preparedBlock.GetHash()
	}
	lockedHash := ""
	if c.lockedBlock != nil {
		lockedHash = c.lockedBlock.GetHash()
	}

	currentTime := common.GetTimeService().Now()
	// Format state information
	return fmt.Sprintf(
		"Node=%s, View=%d, Phase=%v, Leader=%v, ElectedLeader=%s, Height=%d, "+
			"PreparedBlock=%s, LockedBlock=%s, PreparedView=%d, "+
			"LastViewChange=%v, LastBlockTime=%v, PrepareVotes=%d, CommitVotes=%d",
		c.nodeID, c.currentView, c.phase, c.isLeader, c.electedLeaderID, c.currentHeight,
		preparedHash, lockedHash, c.preparedView,
		currentTime.Sub(c.lastViewChange), currentTime.Sub(c.lastBlockTime),
		len(c.prepareVotes), len(c.receivedVotes),
	)
}


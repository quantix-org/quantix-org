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


// consensus/consensus.go — struct definition, constructor, lifecycle, main event loop
package consensus

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/quantix-org/quantix-org/src/common"
	logger "github.com/quantix-org/quantix-org/src/log"
)

// Workflow: ProposeBlock → processProposal → processPrepareVote → processVote → commitBlock

func NewConsensus(
	nodeID string,
	nodeManager NodeManager,
	blockchain BlockChain,
	signingService *SigningService,
	onCommit func(Block) error,
	minStakeAmount *big.Int,
) *Consensus {

	// Create a cancellable context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize VDF parameters for class group VDF (post-quantum)
	// Parameters are loaded from the canonical genesis constants — fixed at
	// trusted setup time and identical on every node in the network.
	// In production, these should come from genesis/trusted setup
	vdfParams, err := LoadCanonicalVDFParams()
	if err != nil {
		// A mismatched or missing discriminant means this node will elect
		// different leaders than its peers and can never reach consensus.
		// This is a fatal startup error — do not continue with a placeholder.
		logger.Error("❌ FATAL: Could not load canonical VDF parameters: %v", err)
		logger.Error("   Ensure the genesis VDF parameters are correctly embedded.")
		cancel()
		return nil
	}
	logger.Info("✅ Loaded canonical VDF parameters: D=%d bits, T=%d",
		vdfParams.Discriminant.BitLen(), vdfParams.T)

	// Initialize RANDAO with genesis seed and VDF parameters
	genesisSeed := [32]byte{0x53, 0x50, 0x48, 0x58} // "SPHX"
	// In NewConsensus, when creating RANDAO:
	randao := NewRANDAO(genesisSeed, vdfParams, nodeID)

	// Create validator set with minimum stake requirement
	validatorSet := NewValidatorSet(minStakeAmount)

	// Create stake-weighted selector for leader election
	selector := NewStakeWeightedSelector(validatorSet)

	// Use the blockchain's genesis time so every node starts slot counting
	// from the same anchor, producing identical slot numbers and seeds.
	var genesisTime time.Time
	if blockchain != nil {
		genesisTime = blockchain.GetGenesisTime()
	}
	if genesisTime.IsZero() {
		// Fallback: hardcoded genesis timestamp if blockchain doesn't provide one
		genesisTime = time.Unix(1732070400, 0)
	}
	// Create time converter for slot calculations
	timeConverter := NewTimeConverter(genesisTime)

	// Add this node as a validator if it has sufficient stake
	// if blockchain != nil {
	// 	// Get this node's stake from the blockchain
	// 	stake := blockchain.GetValidatorStake(nodeID)
	// 	if stake != nil {
	// 		minStake := validatorSet.GetMinStakeAmount()
	// 		// Check if node meets minimum stake requirement
	// 		if stake.Cmp(minStake) >= 0 {
	// 			// Convert to QTX units (div by denomination)
	// 			stakeSPX := new(big.Int).Div(stake, big.NewInt(denom.QTX))
	// 			validatorSet.AddValidator(nodeID, uint64(stakeSPX.Int64()))
	// 		}
	// 	}
	// 	// If node not in validator set, add with minimum stake
	// 	if validatorSet.validators[nodeID] == nil {
	// 		minStakeSPX := validatorSet.GetMinStakeSPX()
	// 		logger.Info("Adding self %s with minimum stake %d QTX", nodeID, minStakeSPX)
	// 		validatorSet.AddValidator(nodeID, minStakeSPX)
	// 	}
	// }

	// NEW: Register self public key with signing service
	if signingService != nil {
		// Register self public key so the node can verify its own signatures
		if selfPK := signingService.GetPublicKeyObject(); selfPK != nil {
			signingService.RegisterPublicKey(nodeID, selfPK)
			logger.Info("✅ Registered self public key for %s", nodeID)
		} else {
			logger.Warn("⚠️ Could not get self public key for %s", nodeID)
		}
	}

	// Create consensus instance
	cons := &Consensus{
		nodeID:               nodeID,                                  // Unique identifier for this node
		nodeManager:          nodeManager,                             // Manages peer connections
		blockChain:           blockchain,                              // Reference to blockchain storage
		signingService:       signingService,                          // Handles cryptographic signatures
		currentView:          0,                                       // Current consensus view (round)
		currentHeight:        0,                                       // Current blockchain height
		phase:                PhaseIdle,                               // Current consensus phase
		quorumFraction:       0.67,                                    // 2/3 majority requirement
		timeout:              300 * time.Second,                       // View change timeout
		receivedVotes:        make(map[string]map[string]*Vote),       // Commit votes by block hash
		prepareVotes:         make(map[string]map[string]*Vote),       // Prepare votes by block hash
		sentVotes:            make(map[string]bool),                   // Track sent commit votes
		sentPrepareVotes:     make(map[string]bool),                   // Track sent prepare votes
		proposalCh:           make(chan *Proposal, 500),               // Proposal channel buffer
		voteCh:               make(chan *Vote, 1000),                  // Vote channel buffer
		timeoutCh:            make(chan *TimeoutMsg, 100),             // Timeout channel buffer
		prepareCh:            make(chan *Vote, 1000),                  // Prepare vote channel buffer
		onCommit:             onCommit,                                // Callback for block commit
		ctx:                  ctx,                                     // Context for cancellation
		cancel:               cancel,                                  // Cancel function
		lastViewChange:       common.GetTimeService().Now(),           // Last view change timestamp
		viewChangeMutex:      sync.Mutex{},                            // Mutex for view change
		lastBlockTime:        common.GetTimeService().Now(),           // Last block commit timestamp
		validatorSet:         validatorSet,                            // Set of active validators
		randao:               randao,                                  // VDF-based RANDAO instance
		selector:             selector,                                // Leader selector
		timeConverter:        timeConverter,                           // Slot time converter
		useStakeWeighted:     true,                                    // Use stake-weighted leader election
		weightedPrepareVotes: make(map[string]*big.Int),               // Weighted prepare votes by stake
		weightedCommitVotes:  make(map[string]*big.Int),               // Weighted commit votes by stake
		attestations:         make(map[uint64][]*Attestation),         // Attestations by epoch
		electedLeaderID:      "",                                      // Set by UpdateLeaderStatus
		timeoutVotes:         make(map[uint64]map[string]*TimeoutMsg), // For view change quorum
		viewChangeBackoff:    2 * time.Second,                         // P2-4: initial backoff
		lastProposalTime:     common.GetTimeService().Now(),           // P2-5: partition detection
		proposedBlocks:       make(map[string]Block),                  // FIX-VIEWCHANGE-STORM: cache proposals by hash
	}

	// Initialize and validate VDF parameters (run once at startup)
	if err := cons.initializeVDF(); err != nil {
		logger.Error("VDF initialization failed: %v", err)
		// Don't fail consensus startup, but log the error
	}

	return cons
}

func (c *Consensus) Start() error {
	logger.Info("Consensus started for node %s", c.nodeID)

	// Start goroutines for handling different message types
	go c.handleProposals()
	go c.handleVotes()
	go c.handlePrepareVotes()
	go c.handleTimeouts()
	go c.consensusLoop()

	// Start periodic VDF state validation
	go c.periodicVDFValidation()

	// Start periodic RANDAO state sync
	go c.periodicStateSync()

	return nil
}

func (c *Consensus) GetNodeID() string {
	c.mu.RLock() // Read lock for thread safety
	defer c.mu.RUnlock()
	return c.nodeID
}

func (c *Consensus) SetTimeout(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = d
}

func (c *Consensus) Stop() error {
	logger.Info("Consensus stopped for node %s", c.nodeID)
	c.cancel() // Cancel context to stop all goroutines
	return nil
}

func (c *Consensus) initializeVDF() error {
	if c.randao == nil {
		logger.Warn("RANDAO not initialized, cannot validate VDF parameters")
		return nil
	}

	// Single authoritative source for VDF parameters — never deviate from this.
	canonicalParams, err := LoadCanonicalVDFParams()
	if err != nil {
		return fmt.Errorf("failed to load canonical VDF params: %w", err)
	}

	// Validate that the RANDAO instance was created with the same parameters.
	if err := c.randao.ValidateVDFParams(canonicalParams); err != nil {
		// Parameters differ: the RANDAO instance was created with different values
		// (e.g. passed incorrect params at construction).  Force-sync to canonical.
		logger.Error("VDF parameter mismatch detected at startup: %v", err)
		logger.Error("Forcing sync to canonical parameters (T=%d, D=%d bits)",
			canonicalParams.T, canonicalParams.Discriminant.BitLen())

		if syncErr := c.randao.forceSyncParams(canonicalParams); syncErr != nil {
			return fmt.Errorf("failed to sync VDF params to canonical: %w", syncErr)
		}
		logger.Info("VDF parameters force-synced to canonical values")
		c.randao.Recovery()
		return nil
	}

	logger.Info("VDF parameters validated: T=%d, D=%d bits — OK",
		canonicalParams.T, canonicalParams.Discriminant.BitLen())

	// Also validate in-memory state consistency.
	if err := c.randao.ValidateState(); err != nil {
		logger.Warn("VDF state inconsistency at startup: %v — running recovery", err)
		c.randao.Recovery()
	}

	return nil
}

func (c *Consensus) consensusLoop() {
	// Create timer for view change timeout
	viewTimer := time.NewTimer(c.timeout)
	defer viewTimer.Stop() // Ensure timer is stopped on exit

	// P2-5: partition detection ticker (check every 10s)
	partitionTicker := time.NewTicker(10 * time.Second)
	defer partitionTicker.Stop()

	prevMode := DEVNET_SOLO

	for {
		select {
		case <-partitionTicker.C:
			// P2-5: if in PBFT mode and no proposal for 2× block time (20s), trigger view change
			n := c.getTotalNodes()
			if GetConsensusMode(n) == PBFT {
				c.mu.RLock()
				lastProp := c.lastProposalTime
				c.mu.RUnlock()
				if time.Since(lastProp) > 20*time.Second {
					// FIX-VIEWCHANGE-STORM: honour shouldPreventViewChange even from the
					// partition ticker — if we're actively in a prepare round (phase
					// PrePrepared/Prepared) there's no partition; the round just needs
					// more time.  Only fire the view change when we're genuinely idle.
					if !c.shouldPreventViewChange() {
						logger.Warn("⚠️ Network partition suspected, initiating view change (no proposal for %v)",
							time.Since(lastProp).Truncate(time.Second))
						c.startViewChange()
					}
				}
			}

		case <-viewTimer.C:
			// Check current consensus mode
			n := c.getTotalNodes()
			mode := GetConsensusMode(n)
			c.logModeTransition(prevMode, mode)
			prevMode = mode

			// In DEVNET_SOLO mode with only 1 validator, do NOT trigger view
			// changes — doing so would loop endlessly since there are no peers
			// to collect timeout quorum from.  The solo leader mines via the
			// DevnetMineBlock path; real PBFT only activates at >= 4 validators.
			if mode == DEVNET_SOLO {
				logger.Info("⛏️  DEVNET_SOLO mode (%d validators < %d): skipping view change",
					n, MinPBFTValidators)
				viewTimer.Reset(c.timeout)
				continue
			}

			if c.shouldPreventViewChange() {
				viewTimer.Reset(10 * time.Second)
				continue
			}

			c.mu.RLock()
			currentHeight := c.currentHeight
			c.mu.RUnlock()

			if currentHeight == 0 {
				viewTimer.Reset(30 * time.Second)
				continue
			}

			// Skip view change if the chain has already advanced past current height
			// (meaning consensus already succeeded for this round)
			if c.blockChain != nil {
				chainHeight := c.blockChain.GetLatestBlock()
				if chainHeight != nil && chainHeight.GetHeight() > currentHeight {
					// Chain advanced — suppress view change, just update our height
					c.mu.Lock()
					c.currentHeight = chainHeight.GetHeight()
					c.mu.Unlock()
					viewTimer.Reset(c.timeout)
					continue
				}
			}

			c.startViewChange()

			// P2-4: exponential backoff for view change timer (2s → 30s cap)
			c.mu.Lock()
			backoff := c.viewChangeBackoff
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			c.viewChangeBackoff = backoff
			c.mu.Unlock()

			// NOTE: DEVNET_SOLO fallback removed — it causes chain forks when multiple
			// nodes simultaneously think they're the leader after rapid view changes.
			// The leader loop's view-change detection now handles recovery correctly.

			viewTimer.Reset(backoff)

		case <-c.ctx.Done(): // Consensus stopping
			logger.Info("Consensus loop stopped for node %s", c.nodeID)
			return
		}
	}
}

func (c *Consensus) handleProposals() {
	for {
		select {
		case proposal, ok := <-c.proposalCh:
			if !ok { // Channel closed
				return
			}
			c.processProposal(proposal) // Process the proposal
		case <-c.ctx.Done(): // Consensus stopping
			logger.Info("Proposal handler stopped for node %s", c.nodeID)
			return
		}
	}
}

func (c *Consensus) handleVotes() {
	for {
		select {
		case vote, ok := <-c.voteCh:
			if !ok { // Channel closed
				return
			}
			c.processVote(vote) // Process the vote
		case <-c.ctx.Done(): // Consensus stopping
			logger.Info("Vote handler stopped for node %s", c.nodeID)
			return
		}
	}
}

func (c *Consensus) handlePrepareVotes() {
	for {
		select {
		case vote, ok := <-c.prepareCh:
			if !ok { // Channel closed
				return
			}
			c.processPrepareVote(vote) // Process the prepare vote
		case <-c.ctx.Done(): // Consensus stopping
			logger.Info("Prepare vote handler stopped for node %s", c.nodeID)
			return
		}
	}
}

func (c *Consensus) handleTimeouts() {
	for {
		select {
		case timeout, ok := <-c.timeoutCh:
			if !ok { // Channel closed
				return
			}
			c.processTimeout(timeout) // Process the timeout
		case <-c.ctx.Done(): // Consensus stopping
			logger.Info("Timeout handler stopped for node %s", c.nodeID)
			return
		}
	}
}

func (c *Consensus) SetLeader(isLeader bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isLeader = isLeader
	logger.Info("Node %s leader status set to %t", c.nodeID, isLeader)
}

func (c *Consensus) SetDevMode(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.devMode = enabled
	if enabled {
		logger.Info("⚠️  Consensus dev-mode enabled for %s: sig verification skipped on votes", c.nodeID)
	}
}


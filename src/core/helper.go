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

// go/src/core/helper.go
package core

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ramseyauron/quantix/src/common"
	"github.com/ramseyauron/quantix/src/consensus"
	database "github.com/ramseyauron/quantix/src/core/state"
	types "github.com/ramseyauron/quantix/src/core/transaction"
	logger "github.com/ramseyauron/quantix/src/log"
	"github.com/ramseyauron/quantix/src/policy"
	"github.com/ramseyauron/quantix/src/pool"
	storage "github.com/ramseyauron/quantix/src/state"
)

// NewBlockHelper creates a new adapter for types.Block
func NewBlockHelper(block *types.Block) consensus.Block {
	return &BlockHelper{block: block}
}

// GetHeight returns the block height
func (a *BlockHelper) GetHeight() uint64 {
	return a.block.GetHeight()
}

// GetHash returns the block hash
func (a *BlockHelper) GetHash() string {
	return a.block.GetHash()
}

// GetPrevHash returns the previous block hash
func (a *BlockHelper) GetPrevHash() string {
	return a.block.GetPrevHash()
}

// GetTimestamp returns the block timestamp
func (a *BlockHelper) GetTimestamp() int64 {
	return a.block.GetTimestamp()
}

// Validate validates the block
func (a *BlockHelper) Validate() error {
	return a.block.Validate()
}

// GetDifficulty returns the block difficulty
func (a *BlockHelper) GetDifficulty() *big.Int {
	if a.block.Header != nil {
		return a.block.Header.Difficulty
	}
	return big.NewInt(1)
}

// GetCurrentNonce returns the current nonce value - ADD THIS METHOD
func (a *BlockHelper) GetCurrentNonce() (uint64, error) {
	if a.block == nil {
		return 0, fmt.Errorf("block is nil")
	}
	return a.block.GetCurrentNonce()
}

// GetUnderlyingBlock returns the underlying types.Block
func (a *BlockHelper) GetUnderlyingBlock() *types.Block {
	return a.block
}

// GetMerkleRoot returns the merkle root as a string
func (b *BlockHelper) GetMerkleRoot() string {
	if b.block != nil && b.block.Header != nil {
		return fmt.Sprintf("%x", b.block.Header.TxsRoot)
	}
	return ""
}

// ExtractMerkleRoot returns the merkle root as a string
func (b *BlockHelper) ExtractMerkleRoot() string {
	if b.block != nil && b.block.Header != nil {
		return fmt.Sprintf("%x", b.block.Header.TxsRoot)
	}
	return ""
}

// GetStateMachine returns the state machine instance
func (bc *Blockchain) GetStateMachine() *storage.StateMachine {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.stateMachine
}

// SetConsensus sets the consensus module for the state machine
func (bc *Blockchain) SetConsensus(consensus *consensus.Consensus) {
	bc.stateMachine.SetConsensus(consensus)
}

// IsGenesisHash checks if a hash is a valid genesis hash (starts with GENESIS_)
func (bc *Blockchain) IsGenesisHash(hash string) bool {
	return strings.HasPrefix(hash, "GENESIS_")
}

// calculateEmptyTransactionsRoot returns a standard Merkle root for empty transactions
func (bc *Blockchain) calculateEmptyTransactionsRoot() []byte {
	// Standard empty Merkle root (hash of empty string)
	emptyHash := common.SpxHash([]byte{})
	return emptyHash
}

// IsValidChain checks the integrity of the full chain
func (bc *Blockchain) IsValidChain() error {
	return bc.storage.ValidateChain()
}

// Start TPS auto-save in blockchain initialization
func (bc *Blockchain) StartTPSAutoSave(ctx context.Context) {
	bc.storage.StartTPSAutoSave(ctx)
}

// VerifyMessage verifies a signed message (placeholder)
func (bc *Blockchain) VerifyMessage(address, signature, message string) bool {
	logger.Info("Message verification requested - address: %s, message: %s", address, message)
	return true
}

// HasPendingTx checks if a transaction is in the mempool
func (bc *Blockchain) HasPendingTx(hash string) bool {
	return bc.mempool.HasTransaction(hash)
}

// SetGossipBroadcaster wires the P2P gossip broadcaster so that CommitBlock
// and AddTransaction can push data to connected peers immediately.
// FIX-P2P-05
// SetDevMode enables or disables dev-mode. In dev-mode, balance checks are
// skipped in applyTransactions, allowing unfunded test addresses to transact.
//
// SEC-P06: guard — dev-mode may only be enabled on devnet chains (ChainID=73310).
// Attempting to enable it on mainnet/testnet panics to prevent silent bypass
// of balance checks in production.
func (bc *Blockchain) SetDevMode(enabled bool) {
	if enabled && bc.chainParams != nil && !bc.chainParams.IsDevnet() {
		panic("SetDevMode: cannot enable dev-mode on non-devnet chain (chainID=" +
			fmt.Sprintf("%d", bc.chainParams.ChainID) + ")")
	}
	bc.devMode = enabled
}

func (bc *Blockchain) SetGossipBroadcaster(b GossipBroadcaster) {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	bc.gossipBroadcaster = b
}

// AddBlockFromPeer validates and commits a block received from the gossip
// network.  It is separate from CommitBlock to avoid re-broadcasting the
// block to the network (which would create an infinite loop).
// FIX-P2P-05
func (bc *Blockchain) AddBlockFromPeer(block *types.Block) error {
	if block == nil {
		return fmt.Errorf("AddBlockFromPeer: nil block")
	}
	// Check height – skip if we already have this block.
	latest := bc.GetLatestBlock()
	if latest != nil && block.GetHeight() <= latest.GetHeight() {
		return nil // already have it
	}
	// Full commit path (validates, executes state, stores).
	helper := NewBlockHelper(block)
	if err := bc.CommitBlock(helper); err != nil {
		return fmt.Errorf("AddBlockFromPeer: %w", err)
	}
	return nil
}

// SetConsensusEngine sets the consensus engine
func (bc *Blockchain) SetConsensusEngine(engine *consensus.Consensus) {
	bc.consensusEngine = engine
}

// GetStorage returns the storage instance for external access
func (bc *Blockchain) GetStorage() *storage.Storage {
	return bc.storage
}

// GetMempool returns the mempool instance
func (bc *Blockchain) GetMempool() *pool.Mempool {
	return bc.mempool
}

// GetChainParams returns the Quantix blockchain parameters for external recognition
func (bc *Blockchain) GetChainParams() *QuantixChainParameters {
	return bc.chainParams
}

// SaveBasicChainState saves a basic chain state
// Simplified version of chain state saving without node information
func (bc *Blockchain) SaveBasicChainState() error {
	return bc.StoreChainState(nil) // Only one parameter now
}

// SetStorageDB injects a shared *database.DB into the blockchain's storage
// layer, enabling StateDB-backed block execution (ExecuteBlock / CommitBlock).
// Call this once after NewBlockchain and before any CommitBlock invocation.
func (bc *Blockchain) SetStorageDB(db *database.DB) {
	bc.storage.SetDB(db)
}

// SetStateDB injects a shared *database.DB into the blockchain's storage
// for consensus state management.
func (bc *Blockchain) SetStateDB(db *database.DB) {
	bc.storage.SetStateDB(db)
}

// Helper function to check if string is hex
func isHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// RequiresDistributionBeforePromotion returns true for devnet — the network
// must drain the genesis vault before it can be promoted to testnet/mainnet.
func (p *QuantixChainParameters) RequiresDistributionBeforePromotion() bool {
	return p.IsDevnet()
}

// GetGovernancePolicy returns the governance policy parameters
func (p *QuantixChainParameters) GetGovernancePolicy() *policy.PolicyParameters {
	return policy.GetDefaultPolicyParams()
}

// CalculateTransactionFee calculates fee for a transaction based on governance policy
func (p *QuantixChainParameters) CalculateTransactionFee(bytes uint64, ops uint64, hashes uint64) *policy.FeeComponents {
	govPolicy := p.GetGovernancePolicy()
	return govPolicy.CalculateFees(bytes, ops, hashes)
}

// GetInflationRate returns the current inflation rate based on stake ratio
func (p *QuantixChainParameters) GetInflationRate(currentStakeRatio float64) float64 {
	govPolicy := p.GetGovernancePolicy()
	return govPolicy.CalculateAnnualInflation(uint64(currentStakeRatio * 10000))
}

// GetStorageCost calculates storage cost based on governance policy
func (p *QuantixChainParameters) GetStorageCost(bytes uint64, months float64) *policy.StoragePricing {
	govPolicy := p.GetGovernancePolicy()
	return govPolicy.CalculateStorageCost(bytes, months)
}

// GetMaxBlockSize returns the maximum block size in bytes
// Getter for maximum block size
func (p *QuantixChainParameters) GetMaxBlockSize() uint64 {
	return p.MaxBlockSize
}

// GetTargetBlockSize returns the target block size in bytes
// Getter for target block size (optimization target)
func (p *QuantixChainParameters) GetTargetBlockSize() uint64 {
	return p.TargetBlockSize
}

// GetMaxTransactionSize returns the maximum transaction size in bytes
// Getter for maximum transaction size
func (p *QuantixChainParameters) GetMaxTransactionSize() uint64 {
	return p.MaxTransactionSize
}

// IsBlockSizeValid checks if a block size is within acceptable limits
// Validates block size against chain parameters
func (p *QuantixChainParameters) IsBlockSizeValid(blockSize uint64) bool {
	// Block must not exceed maximum and must be positive
	return blockSize <= p.MaxBlockSize && blockSize > 0
}

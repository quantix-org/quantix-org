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


// consensus/consensus_signatures.go — SMR consensus signatures, merkle root cache
package consensus

import (
	"fmt"
	"reflect"

	types "github.com/quantix-org/quantix-org/src/core/transaction"
	logger "github.com/quantix-org/quantix-org/src/log"
)

func (c *Consensus) addConsensusSig(sig *ConsensusSignature) {
	c.signatureMutex.Lock()
	defer c.signatureMutex.Unlock()

	logger.Info("🔄 Adding consensus signature for block %s (type: %s)", sig.BlockHash, sig.MessageType)

	// Try to get merkle root from cache first
	if sig.MerkleRoot == "" {
		if cachedRoot := c.GetCachedMerkleRoot(sig.BlockHash); cachedRoot != "" {
			sig.MerkleRoot = cachedRoot
		}
	}

	// If merkle root still missing, try to extract from block
	if sig.MerkleRoot == "" || sig.MerkleRoot == "pending_calculation" {
		block := c.blockChain.GetBlockByHash(sig.BlockHash)
		if block != nil {
			sig.MerkleRoot = c.extractMerkleRootFromBlock(block)
			if sig.MerkleRoot != "" && sig.MerkleRoot != "pending_calculation" {
				c.CacheMerkleRoot(sig.BlockHash, sig.MerkleRoot)
			}
		} else {
			sig.MerkleRoot = fmt.Sprintf("not_in_storage_%s", sig.BlockHash[:8])
			logger.Warn("⚠️ Block not found in storage yet: %s", sig.BlockHash)
		}
	}

	// Emergency fallback if merkle root still empty
	if sig.MerkleRoot == "" {
		sig.MerkleRoot = fmt.Sprintf("emergency_fallback_%s", sig.BlockHash[:8])
		logger.Error("🚨 CRITICAL: Used emergency fallback for merkle root!")
	}

	// Set status if not already set
	if sig.Status == "" {
		sig.Status = c.StatusFromMsgType(sig.MessageType)
	}

	// Append to signatures collection
	c.consensusSignatures = append(c.consensusSignatures, sig)
	logger.Info("🎯 Added signature: block=%s, merkle_root=%s, status=%s", sig.BlockHash, sig.MerkleRoot, sig.Status)
}

func (c *Consensus) extractMerkleRootFromBlock(block Block) string {
	// Try to get underlying block and extract from header
	if blockHelper, ok := block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		if ub := blockHelper.GetUnderlyingBlock(); ub != nil {
			if ub.Header != nil && len(ub.Header.TxsRoot) > 0 {
				return fmt.Sprintf("%x", ub.Header.TxsRoot)
			}
		}
	}

	// Try reflection to find TxsRoot field
	val := reflect.ValueOf(block)
	if val.Kind() == reflect.Ptr {
		elem := val.Elem()
		if elem.Type().Name() == "Block" {
			headerField := elem.FieldByName("Header")
			if headerField.IsValid() {
				txsRootField := headerField.FieldByName("TxsRoot")
				if txsRootField.IsValid() && !txsRootField.IsZero() {
					return fmt.Sprintf("%x", txsRootField.Interface())
				}
			}
		}
	}

	// Try to get from transaction count as fallback
	if txGetter, ok := block.(interface{ GetTransactions() []interface{} }); ok {
		if txs := txGetter.GetTransactions(); len(txs) > 0 {
			return fmt.Sprintf("calculated_from_%d_txs", len(txs))
		}
	}

	// Last resort fallback
	return fmt.Sprintf("no_merkle_info_%s", block.GetHash()[:8])
}

func (c *Consensus) DebugConsensusSignaturesDeep() {
	c.signatureMutex.RLock()
	defer c.signatureMutex.RUnlock()

	logger.Info("🔍 DEEP DEBUG: Current consensus signatures (%d total):", len(c.consensusSignatures))
	for i, sig := range c.consensusSignatures {
		logger.Info("  Signature %d: block=%s, type=%s, merkle=%s, status=%s, valid=%t",
			i, sig.BlockHash, sig.MessageType, sig.MerkleRoot, sig.Status, sig.Valid)
	}
}

func (c *Consensus) ForcePopulateAllSignatures() {
	c.signatureMutex.Lock()
	defer c.signatureMutex.Unlock()

	logger.Info("🔄 Force populating all consensus signatures")

	// Process each signature
	for i, sig := range c.consensusSignatures {
		originalMerkleRoot := sig.MerkleRoot
		originalStatus := sig.Status

		// Get block from blockchain
		block := c.blockChain.GetBlockByHash(sig.BlockHash)
		if block != nil {
			var merkleRoot string
			// Extract merkle root based on block type
			switch b := block.(type) {
			case *types.Block:
				if b.Header != nil && len(b.Header.TxsRoot) > 0 {
					merkleRoot = fmt.Sprintf("%x", b.Header.TxsRoot)
				}
			case Block:
				if g, ok := b.(interface{ GetMerkleRoot() string }); ok {
					merkleRoot = g.GetMerkleRoot()
				}
			}
			if merkleRoot != "" {
				sig.MerkleRoot = merkleRoot
			} else {
				sig.MerkleRoot = fmt.Sprintf("no_merkle_info_%s", sig.BlockHash[:8])
			}
		} else {
			sig.MerkleRoot = fmt.Sprintf("block_not_found_%s", sig.BlockHash[:8])
			logger.Warn("⚠️ Block not found for hash %s", sig.BlockHash)
		}

		// Set status based on message type if missing
		if sig.Status == "" {
			switch sig.MessageType {
			case "proposal":
				sig.Status = "proposed"
			case "prepare":
				sig.Status = "prepared"
			case "commit":
				sig.Status = "committed"
			case "timeout":
				sig.Status = "view_change"
			default:
				sig.Status = "unknown"
			}
		}

		logger.Info("🔄 Signature %d: block=%s, merkle=%s->%s, status=%s->%s",
			i, sig.BlockHash, originalMerkleRoot, sig.MerkleRoot, originalStatus, sig.Status)
	}

	logger.Info("✅ Force population completed for %d signatures", len(c.consensusSignatures))
}

func (c *Consensus) GetConsensusSignatures() []*ConsensusSignature {
	c.signatureMutex.RLock()
	defer c.signatureMutex.RUnlock()
	// Create a copy to avoid external modification
	signatures := make([]*ConsensusSignature, len(c.consensusSignatures))
	copy(signatures, c.consensusSignatures)
	return signatures
}


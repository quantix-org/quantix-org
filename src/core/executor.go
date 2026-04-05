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

// go/src/core/executor.go
package core

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	types "github.com/ramseyauron/quantix/src/core/transaction"
	logger "github.com/ramseyauron/quantix/src/log"
)

// sha256Bytes returns the SHA-256 digest of b as a byte slice.
func sha256Bytes(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// maxSupplyNSPX is the hard cap: 5 billion QTX expressed in nQTX.
var maxSupplyNSPX = new(big.Int).Mul(
	big.NewInt(5_000_000_000),
	big.NewInt(1e18),
)

// newStateDB opens the StateDB for this blockchain node.
// It calls bc.storage.GetDB() which opens (or returns a cached) *database.DB
// against the node's LevelDB directory.
func (bc *Blockchain) newStateDB() (*StateDB, error) {
	db, err := bc.storage.GetDB()
	if err != nil {
		return nil, fmt.Errorf("newStateDB: %w", err)
	}
	return NewStateDB(db), nil
}

// IsDistributionComplete returns true when the genesis vault has been fully
// drained — i.e. every allocation has been transferred out of GenesisVaultAddress.
// This is the signal that devnet's bootstrap phase is finished and the chain
// is ready to be promoted to testnet or mainnet.
func (bc *Blockchain) IsDistributionComplete() bool {
	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Warn("IsDistributionComplete: cannot open stateDB: %v", err)
		return false
	}
	bal := stateDB.GetBalance(GenesisVaultAddress)
	complete := bal.Sign() == 0
	if complete {
		logger.Info("✅ IsDistributionComplete: vault %s balance = 0, distribution done", GenesisVaultAddress)
	}
	return complete
}

// TotalAllocatedNSPX returns the sum of all genesis allocations in nQTX.
// Used to calculate how many more blocks need to run before distribution is done.
func TotalAllocatedNSPX() *big.Int {
	allocs := DefaultGenesisAllocations()
	total := new(big.Int)
	for _, a := range allocs {
		if a.BalanceNQTX != nil {
			total.Add(total, a.BalanceNQTX)
		}
	}
	return total
}

// applyTransactions applies every transaction in block to stateDB,
// enforcing nonce ordering, balance sufficiency, and gas fee collection.
// Genesis funding transactions (sender == "genesis") are skipped because
// ApplyGenesisState has already credited them.
// applyTransactions — genesis sender check no longer needed,
// block 0 body is empty. Keep for safety but it will never fire.
func (bc *Blockchain) applyTransactions(block *types.Block, stateDB *StateDB) error {
	proposerID := block.Header.ProposerID

	for i, tx := range block.Body.TxsList {
		if tx.Sender == "genesis" {
			// Should not occur — genesis block body is now empty.
			// Kept as a safety guard.
			continue
		}

		// SEC-E01: Sanity-check every transaction before touching state.
		// Catches nil Amount, empty sender/receiver, non-positive amount,
		// and nil gas fields — any of which would panic or silently corrupt state.
		if err := tx.SanityCheck(); err != nil {
			return fmt.Errorf("tx[%d] %s: sanity check failed: %w", i, tx.ID, err)
		}

		// SEC-G01: Block any transaction targeting the GenesisVaultAddress.
		// The genesis vault (0000...0001) is a protocol-internal address whose
		// balance is only drained during ExecuteGenesisBlock.  Any user transaction
		// sending funds there would permanently lock them — no withdrawal path exists.
		// This also prevents an attacker from inflating the vault balance to disrupt
		// supply accounting or confuse IsDistributionComplete logic.
		if tx.Receiver == GenesisVaultAddress {
			return fmt.Errorf("tx[%d] %s: SEC-G01: transactions to genesis vault address are forbidden", i, tx.ID)
		}

		// SEC-E03: Execution-layer signature verification.
		// Blocks received via direct peer broadcast or archive sync bypass the
		// mempool, so we must re-verify here.  Verification requires:
		//   1. bc.sigVerifier — a TxSigVerifier injected via SetSigVerifier
		//   2. tx.SenderPublicKey — the raw SPHINCS+ public key bytes
		//   3. tx.Signature, SigTimestamp, SigNonce — from SignMessage
		//
		// If the sender's public key is not yet on-chain, we register it on
		// first use (validated against the Fingerprint / SHA-256(pubkey) binding).
		// If sigVerifier is nil OR devMode is enabled, verification is skipped (devnet backwards compat).
		if bc.sigVerifier != nil && len(tx.Signature) > 0 && !bc.devMode {
			pubKey := tx.SenderPublicKey
			if len(pubKey) == 0 {
				// Attempt to load a previously registered public key from StateDB.
				pubKey = stateDB.GetPublicKey(tx.Sender)
			}
			if len(pubKey) == 0 {
				return fmt.Errorf("tx[%d] %s: SEC-E03: sender public key not available for signature verification", i, tx.ID)
			}
			// Build canonical message: SHA-256("sender:receiver:amount:nonce")
			canonicalPreimage := tx.Sender + ":" + tx.Receiver + ":" + tx.Amount.String() + ":" + fmt.Sprintf("%d", tx.Nonce)
			canonicalMsg := sha256Bytes([]byte(canonicalPreimage))
			if !bc.sigVerifier.VerifyTxSignature(canonicalMsg, tx.SigTimestamp, tx.SigNonce, tx.Signature, pubKey) {
				return fmt.Errorf("tx[%d] %s: SEC-E03: invalid SPHINCS+ signature", i, tx.ID)
			}
			// Register the public key on first appearance (fingerprint-bound).
			if len(tx.SenderPublicKey) > 0 {
				stateDB.RegisterPublicKey(tx.Sender, tx.SenderPublicKey)
			}
		}

		expected := stateDB.GetNonce(tx.Sender)
		if tx.Nonce != expected {
			// SEC-C01: In dev-mode, gracefully drop txs with bad nonces so
			// devnet test transactions with non-sequential nonces don't abort
			// the whole block. In production (non-devMode), return an error to
			// prevent silent nonce skipping which could reorder/replay txs.
			if bc.devMode {
				logger.Warn("executor: dev-mode: dropping tx[%d] %s: bad nonce: got %d want %d",
					i, tx.ID, tx.Nonce, expected)
				continue
			}
			return fmt.Errorf("tx[%d] %s: bad nonce: got %d want %d", i, tx.ID, tx.Nonce, expected)
		}

		gasFee := tx.GetGasFee()
		totalCost := new(big.Int).Add(tx.Amount, gasFee)

		bal := stateDB.GetBalance(tx.Sender)
		if bal.Cmp(totalCost) < 0 {
			if bc.devMode {
				// Dev-mode: skip balance check, allow unfunded test addresses.
				logger.Warn("executor: dev-mode: skipping balance check for tx[%d] %s (bal=%s needs=%s)",
					i, tx.ID, bal.String(), totalCost.String())
				stateDB.AddBalance(tx.Receiver, tx.Amount)
				bc.distributeGasFee(gasFee, proposerID, block.Body.Attestations, stateDB)
				stateDB.IncrementNonce(tx.Sender)
				logger.Info("executor: tx[%d] %s → %s %s nQTX (gas %s nQTX) ✓ [dev-mode]",
					i, tx.Sender, tx.Receiver, tx.Amount.String(), gasFee.String())
				continue
			}
			return fmt.Errorf("tx[%d] %s: %s has %s nQTX, needs %s nQTX",
				i, tx.ID, tx.Sender, bal.String(), totalCost.String())
		}

		if err := stateDB.SubBalance(tx.Sender, totalCost); err != nil {
			return fmt.Errorf("tx[%d] SubBalance: %w", i, err)
		}
		stateDB.AddBalance(tx.Receiver, tx.Amount)
		bc.distributeGasFee(gasFee, proposerID, block.Body.Attestations, stateDB)

		stateDB.IncrementNonce(tx.Sender)
		logger.Info("executor: tx[%d] %s → %s %s nQTX (gas %s nQTX) ✓",
			i, tx.Sender, tx.Receiver, tx.Amount.String(), gasFee.String())
	}
	return nil
}

// distributeGasFee splits a gas fee: 70% burned, 20% to attestors, 10% to proposer.
// If no attestors are present, all non-burned amount goes to proposer.
func (bc *Blockchain) distributeGasFee(gasFee *big.Int, proposerID string, attestations []*types.Attestation, stateDB *StateDB) {
	if gasFee == nil || gasFee.Sign() <= 0 || proposerID == "" {
		return
	}

	// 70% burned (already deducted from sender — just don't credit it)
	burnAmt := new(big.Int).Mul(gasFee, big.NewInt(70))
	burnAmt.Div(burnAmt, big.NewInt(100))

	// 10% → proposer
	proposerAmt := new(big.Int).Mul(gasFee, big.NewInt(10))
	proposerAmt.Div(proposerAmt, big.NewInt(100))

	// 20% → attestors (remainder after burn + proposer)
	attestorPool := new(big.Int).Sub(gasFee, new(big.Int).Add(burnAmt, proposerAmt))

	stateDB.DecrementTotalSupply(burnAmt)
	stateDB.AddBalance(proposerID, proposerAmt)

	if len(attestations) > 0 && attestorPool.Sign() > 0 {
		perAttestor := new(big.Int).Div(attestorPool, big.NewInt(int64(len(attestations))))
		if perAttestor.Sign() > 0 {
			for _, att := range attestations {
				if att.ValidatorID != "" {
					stateDB.AddBalance(att.ValidatorID, perAttestor)
				}
			}
		}
	} else if proposerID != "" {
		// No attestors: give attestor pool to proposer
		stateDB.AddBalance(proposerID, attestorPool)
	}

	logger.Info("gasFee distribution: burned=%s nQTX (70%%), proposer=%s nQTX (10%%), attestors=%d x each from pool=%s nQTX (20%%)",
		burnAmt.String(), proposerAmt.String(), len(attestations), attestorPool.String())
}

// mintBlockReward issues BaseBlockReward to the block proposer, respecting
// the hard 5 billion QTX supply cap.
func (bc *Blockchain) mintBlockReward(block *types.Block, stateDB *StateDB) {
	if bc.chainParams == nil {
		return
	}

	proposerID := block.Header.ProposerID
	if proposerID == "" {
		logger.Warn("mintBlockReward: no proposer_id on block %d", block.GetHeight())
		return
	}

	if block.GetHeight() == 0 {
		// Block 0: mint entire genesis supply to the vault.
		allocs := DefaultGenesisAllocations()
		reward := new(big.Int)
		for _, a := range allocs {
			if a.BalanceNQTX != nil {
				reward.Add(reward, a.BalanceNQTX)
			}
		}
		stateDB.AddBalance(proposerID, reward)
		stateDB.IncrementTotalSupply(reward)
		logger.Info("mintBlockReward: genesis mint %s nQTX → vault %s",
			reward.String(), proposerID)
		return
	}

	// Block 1 is always the genesis distribution block on every environment.
	// Transactions move coins from the vault to allocation addresses.
	// No new coins should be minted here.
	if block.GetHeight() == 1 {
		logger.Info("mintBlockReward: skipping reward for distribution block 1")
		return
	}

	// Normal block reward.
	// SEC-E04: Guard against nil BaseBlockReward before dereferencing.
	if bc.chainParams.BaseBlockReward == nil {
		logger.Warn("mintBlockReward: BaseBlockReward is nil on block %d, skipping", block.GetHeight())
		return
	}
	reward := new(big.Int).Set(bc.chainParams.BaseBlockReward)
	if reward.Sign() <= 0 {
		return
	}

	current := stateDB.GetTotalSupply()
	if new(big.Int).Add(current, reward).Cmp(maxSupplyNSPX) > 0 {
		remaining := new(big.Int).Sub(maxSupplyNSPX, current)
		if remaining.Sign() <= 0 {
			logger.Info("mintBlockReward: supply cap reached, block %d", block.GetHeight())
			return
		}
		reward = remaining
	}

	// Model C: 40% → proposer, 60% → attestors equally
	attestations := block.Body.Attestations
	proposerShare := new(big.Int).Mul(reward, big.NewInt(40))
	proposerShare.Div(proposerShare, big.NewInt(100))
	attestorPool := new(big.Int).Sub(reward, proposerShare)

	stateDB.AddBalance(proposerID, proposerShare)
	stateDB.IncrementTotalSupply(reward)

	attestorIDs := make([]string, 0, len(attestations))
	if len(attestations) > 0 {
		perAttestor := new(big.Int).Div(attestorPool, big.NewInt(int64(len(attestations))))
		if perAttestor.Sign() > 0 {
			for _, att := range attestations {
				if att.ValidatorID != "" {
					stateDB.AddBalance(att.ValidatorID, perAttestor)
					attestorIDs = append(attestorIDs, att.ValidatorID)
				}
			}
		}
	} else {
		// No attestors (genesis, devmode early blocks): 100% to proposer
		stateDB.AddBalance(proposerID, attestorPool)
	}

	proposerSPX := new(big.Float).Quo(new(big.Float).SetInt(proposerShare), new(big.Float).SetInt(big.NewInt(1e18)))
	attestorSPX := new(big.Float)
	if len(attestations) > 0 {
		attestorSPX.Quo(
			new(big.Float).SetInt(new(big.Int).Div(attestorPool, big.NewInt(int64(len(attestations))))),
			new(big.Float).SetInt(big.NewInt(1e18)),
		)
	}
	logger.Info("✅ distributedReward: proposer %s got %.6f QTX (40%%), attestors %v got %.6f QTX each (60%%) (block %d)",
		proposerID, proposerSPX, attestorIDs, attestorSPX, block.GetHeight())
}

// ExecuteBlock is called from CommitBlock.  It applies transactions, mints the
// block reward, and returns the new StateRoot to stamp into the block header.
func (bc *Blockchain) ExecuteBlock(block *types.Block) ([]byte, error) {
	stateDB, err := bc.newStateDB()
	if err != nil {
		return nil, fmt.Errorf("ExecuteBlock: %w", err)
	}

	if err := bc.applyTransactions(block, stateDB); err != nil {
		return nil, fmt.Errorf("ExecuteBlock: applyTransactions: %w", err)
	}

	bc.mintBlockReward(block, stateDB)

	stateRoot, err := stateDB.Commit()
	if err != nil {
		return nil, fmt.Errorf("ExecuteBlock: commit: %w", err)
	}
	return stateRoot, nil
}

// ExecuteGenesisBlock runs ExecuteBlock on block 0 so mintBlockReward fires
// and credits GenesisVaultAddress with the full allocation supply, then
// distributes from the vault to each genesis allocation address.
// Must be called AFTER SetStorageDB — it needs a live DB handle.
// It is idempotent: if the first allocation already has a non-zero balance it returns nil.
func (bc *Blockchain) ExecuteGenesisBlock() error {
	bc.lock.RLock()
	if len(bc.chain) == 0 || bc.chain[0] == nil {
		bc.lock.RUnlock()
		return fmt.Errorf("ExecuteGenesisBlock: genesis block not in memory")
	}
	genesisBlock := bc.chain[0]
	bc.lock.RUnlock()

	// Idempotency: skip if allocations were already distributed.
	allocs := DefaultGenesisAllocations()
	stateDB, err := bc.newStateDB()
	if err != nil {
		return fmt.Errorf("ExecuteGenesisBlock: %w", err)
	}
	if len(allocs) > 0 && stateDB.GetBalance(allocs[0].Address).Sign() > 0 {
		logger.Info("ExecuteGenesisBlock: allocations already distributed, skipping")
		return nil
	}

	// Step 1: Execute block 0 — mints entire genesis supply to GenesisVaultAddress.
	if _, err := bc.ExecuteBlock(genesisBlock); err != nil {
		return fmt.Errorf("ExecuteGenesisBlock: %w", err)
	}
	logger.Info("✅ ExecuteGenesisBlock: vault %s funded", GenesisVaultAddress)

	// Step 2: Distribute from vault to each allocation address.
	// The genesis block body contains funding txs with sender="genesis" which
	// applyTransactions skips (no real signing key). We apply them here by
	// debiting the vault and crediting each allocation address directly.
	stateDB2, err := bc.newStateDB()
	if err != nil {
		return fmt.Errorf("ExecuteGenesisBlock: open stateDB for distribution: %w", err)
	}

	for _, alloc := range allocs {
		if alloc.BalanceNQTX == nil || alloc.BalanceNQTX.Sign() <= 0 {
			continue
		}
		if err := stateDB2.SubBalance(GenesisVaultAddress, alloc.BalanceNQTX); err != nil {
			return fmt.Errorf("ExecuteGenesisBlock: SubBalance vault for %s: %w", alloc.Address, err)
		}
		stateDB2.AddBalance(alloc.Address, alloc.BalanceNQTX)
		logger.Info("ExecuteGenesisBlock: distribute %s nQTX → %s (%s)",
			alloc.BalanceNQTX.String(), alloc.Address, alloc.Label)
	}

	stateRoot, err := stateDB2.Commit()
	if err != nil {
		return fmt.Errorf("ExecuteGenesisBlock: commit distribution: %w", err)
	}

	// Patch the genesis block header with the real state root.
	bc.lock.Lock()
	if len(bc.chain) > 0 && bc.chain[0] != nil {
		bc.chain[0].Header.StateRoot = stateRoot
		bc.chain[0].FinalizeHash()
		if storeErr := bc.storage.StoreBlock(bc.chain[0]); storeErr != nil {
			logger.Warn("ExecuteGenesisBlock: re-store genesis block: %v", storeErr)
		}
	}
	bc.lock.Unlock()

	logger.Info("✅ ExecuteGenesisBlock: %d allocations distributed, state_root=%x",
		len(allocs), stateRoot)
	return nil
}

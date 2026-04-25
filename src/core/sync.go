// MIT License
// Copyright (c) 2024 quantix

// go/src/core/sync.go
//
// P2-2: Node sync protocol.
// New nodes joining testnet fetch blocks from seed peers via HTTP.
// State machine: NEW_NODE → SYNCING → SYNCED
package core

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	types "github.com/quantix-org/quantix-org/src/core/transaction"
	logger "github.com/quantix-org/quantix-org/src/log"
)

// SetSeedPeers configures seed peer HTTP addresses for initial block sync.
// Must be called before SyncFromSeeds.
func (bc *Blockchain) SetSeedPeers(peers []string) {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	bc.seedPeers = peers
}

// GetNodeSyncState returns the current sync state.
func (bc *Blockchain) GetNodeSyncState() NodeSyncState {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.nodeSyncState
}

// SyncFromSeeds tries to sync the local chain from the configured seed peers.
// Should be called once at startup when the local chain is empty.
func (bc *Blockchain) SyncFromSeeds() error {
	bc.lock.RLock()
	chainLen := len(bc.chain)
	peers := make([]string, len(bc.seedPeers))
	copy(peers, bc.seedPeers)
	bc.lock.RUnlock()

	// Only sync if chain has no real blocks beyond genesis
	if chainLen > 1 || len(peers) == 0 {
		return nil
	}

	bc.lock.Lock()
	bc.nodeSyncState = SyncStateSyncing
	bc.lock.Unlock()

	logger.Info("🔄 Node sync: entering SYNCING state, seeds=%v", peers)

	for _, peer := range peers {
		if err := bc.syncFromPeer(peer); err != nil {
			logger.Warn("Sync from peer %s failed: %v", peer, err)
			continue
		}
		// Successfully synced
		bc.lock.Lock()
		bc.nodeSyncState = SyncStateSynced
		bc.lock.Unlock()
		logger.Info("✅ Node sync: SYNCED from peer %s", peer)
		return nil
	}

	// Failed to sync from any peer — fall back to DEVNET_SOLO operation
	bc.lock.Lock()
	bc.nodeSyncState = SyncStateSynced // Consider ourselves synced (genesis-only)
	bc.lock.Unlock()
	logger.Warn("⚠️ Node sync: no reachable seed peers, operating as genesis node")
	return nil
}

// syncFromPeer fetches all blocks from a single seed peer using paginated GET /blocks.
// Loops until local block count equals seed block count (P2-SYNC spec).
func (bc *Blockchain) syncFromPeer(peerBase string) error {
	const pageSize = 100
	client := &http.Client{Timeout: 30 * time.Second}

	// getSeedCount queries the seed's block count.
	getSeedCount := func() (uint64, error) {
		resp, err := client.Get(fmt.Sprintf("%s/blockcount", peerBase))
		if err != nil {
			return 0, fmt.Errorf("GET /blockcount: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var countResp struct {
			Count uint64 `json:"count"`
		}
		if err := json.Unmarshal(body, &countResp); err != nil {
			return 0, fmt.Errorf("parse /blockcount: %w", err)
		}
		return countResp.Count, nil
	}

	seedCount, err := getSeedCount()
	if err != nil {
		return err
	}

	// GENESIS SYNC: fetch seed's genesis block and compare with ours.
	// When genesis timestamps differ (each process uses time.Now()), peer nodes
	// must adopt the seed's genesis so all blocks chain correctly.
	{
		url := fmt.Sprintf("%s/blocks?from=0&limit=1", peerBase)
		resp, err := client.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var seedBlocks []*types.Block
			if json.Unmarshal(body, &seedBlocks) == nil && len(seedBlocks) > 0 {
				seedGenesis := seedBlocks[0]
				// SEC-SYNC01: Verify genesis block content integrity before replacing.
				// All height≥1 blocks pass SEC-P01 hash verification; genesis must too.
				// A MITM or malicious peer could otherwise inject a crafted genesis with
				// altered initial state or token distribution.
				computedGenesisHash := string(seedGenesis.GenerateBlockHash())
				if computedGenesisHash != seedGenesis.GetHash() {
					logger.Warn("[SYNC] Genesis block hash mismatch from peer: claimed=%s computed=%s — rejecting poisoned genesis",
						seedGenesis.GetHash(), computedGenesisHash)
					// Skip genesis replacement but continue syncing height 1+ blocks.
				} else {
					localGenesis := bc.GetBlockByNumber(0)
					if localGenesis == nil || localGenesis.GetHash() != seedGenesis.GetHash() {
						log.Printf("[SYNC] Genesis mismatch — replacing local genesis (hash=%s) with seed genesis (hash=%s ts=%d)",
							func() string {
								if localGenesis != nil {
									return localGenesis.GetHash()
								}
								return "nil"
							}(), seedGenesis.GetHash(), seedGenesis.GetTimestamp())
						// Replace genesis in storage and in-memory chain
						if err := bc.storage.ReplaceGenesisBlock(seedGenesis); err != nil {
							logger.Warn("[SYNC] Failed to replace genesis block: %v — continuing", err)
						} else {
							bc.lock.Lock()
							bc.chain = []*types.Block{seedGenesis}
							bc.lock.Unlock()
							// Reset the cached genesis so future code uses the seed's genesis.
							resetCachedGenesis(seedGenesis)
							log.Printf("[SYNC] Genesis replaced: hash=%s ts=%d", seedGenesis.GetHash(), seedGenesis.GetTimestamp())
						}
					}
				} // end SEC-SYNC01 hash-verified else
			}
		}
	}

	// Sync blocks from height 1 onwards.
	for {
		localCount := bc.GetBlockCount()
		if localCount >= seedCount {
			break
		}

		from := localCount // localCount = latestHeight+1 = next needed height
		url := fmt.Sprintf("%s/blocks?from=%d&limit=%d", peerBase, from, pageSize)
		resp, err := client.Get(url)
		if err != nil {
			return fmt.Errorf("GET %s: %w", url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var blocks []*types.Block
		if err := json.Unmarshal(body, &blocks); err != nil {
			return fmt.Errorf("parse /blocks: %w", err)
		}
		if len(blocks) == 0 {
			break
		}

		for _, blk := range blocks {
			if blk.GetHash() == "" {
				logger.Warn("⚠️ Received block with empty hash at height %d, skipping", blk.Header.Height)
				continue
			}

			// SEC-P01: verify block hash against block content before importing.
			computedHashBytes := blk.GenerateBlockHash()
			computedHash := string(computedHashBytes)
			claimedHash := blk.GetHash()
			if computedHash != claimedHash {
				logger.Warn("⚠️ Block %d hash mismatch: claimed=%s computed=%s — skipping",
					blk.Header.Height, claimedHash, computedHash)
				continue
			}

			localNow := bc.GetBlockCount()
			log.Printf("[SYNC] Catching up: block %d/%d from seed", blk.Header.Height, seedCount)

			if err := bc.AddBlockFromPeer(blk); err != nil {
				// Fall back to ImportBlock for resilience (also with peerSync flag set).
				bc.peerSyncMu.Lock()
				bc.peerSyncInProgress = true
				bc.peerSyncMu.Unlock()
				result := bc.ImportBlock(blk)
				bc.peerSyncMu.Lock()
				bc.peerSyncInProgress = false
				bc.peerSyncMu.Unlock()
				if result != ImportedBest && result != ImportedExisting && result != ImportedSide {
					logger.Warn("Failed to import block %d from peer: result=%v", blk.Header.Height, result)
				}
			}
			_ = localNow
		}

		// Refresh seed count in case it grew
		if newCount, err := getSeedCount(); err == nil {
			seedCount = newCount
		}
	}

	log.Printf("[SYNC] Caught up with seed %s at block %d", peerBase, bc.GetBlockCount())
	return nil
}

// SyncFromPeerHTTP is a public wrapper around syncFromPeer for use by external callers
// (e.g., the sync heartbeat goroutine in bind/nodes.go).
func (bc *Blockchain) SyncFromPeerHTTP(peerBaseURL string) error {
	return bc.syncFromPeer(peerBaseURL)
}

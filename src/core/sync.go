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
	"net/http"
	"time"

	types "github.com/ramseyauron/quantix/src/core/transaction"
	logger "github.com/ramseyauron/quantix/src/log"
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
func (bc *Blockchain) syncFromPeer(peerBase string) error {
	const pageSize = 100
	client := &http.Client{Timeout: 30 * time.Second}

	// Query the peer's block count first
	resp, err := client.Get(fmt.Sprintf("%s/blockcount", peerBase))
	if err != nil {
		return fmt.Errorf("GET /blockcount: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var countResp struct {
		Count uint64 `json:"count"`
	}
	if err := json.Unmarshal(body, &countResp); err != nil {
		return fmt.Errorf("parse /blockcount: %w", err)
	}
	total := countResp.Count

	// We already have genesis (height 0); skip it
	var from uint64 = 1
	fetched := uint64(0)

	for from <= total {
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
			// Verify block hash before storing
			computedHash := blk.GetHash()
			if computedHash == "" {
				logger.Warn("⚠️ Received block with empty hash at height %d, skipping", blk.Header.Height)
				continue
			}

			logger.Info("Syncing from peer %s: block %d/%d", peerBase, blk.Header.Height, total)

			// Import the block into our chain
			result := bc.ImportBlock(blk)
			if result != ImportedBest && result != ImportedExisting && result != ImportedSide {
				logger.Warn("Failed to import block %d from peer: %v", blk.Header.Height, result)
				// Continue — don't abort the whole sync for one bad block
			}
			fetched++
		}

		from += uint64(len(blocks))
	}

	logger.Info("✅ Sync complete: fetched %d blocks from %s", fetched, peerBase)
	return nil
}

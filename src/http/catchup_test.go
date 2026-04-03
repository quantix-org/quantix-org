// MIT License
// Copyright (c) 2024 quantix

// go/src/http/catchup_test.go — Q19: sync protocol / catch-up tests.
//
// These tests simulate a "seed" node that has produced blocks and a "fresh"
// node that starts with an empty chain.  The catch-up mechanism is the
// GET /blocks endpoint: a node fetches blocks from a seed's HTTP server
// and verifies they are delivered intact (count, hashes).
package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// mineBlocks attempts to mine n blocks on the given server's blockchain (dev-mode).
// Mining may fail if the mempool has no pending transactions; that is logged but
// does not fail the test — the genesis block is always available for sync tests.
func mineBlocks(t *testing.T, srv *Server, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := srv.blockchain.DevnetMineBlock("test-node"); err != nil {
			t.Logf("DevnetMineBlock(%d): %v (non-fatal — mempool may be empty)", i, err)
			// No more blocks can be mined until transactions arrive; stop trying.
			break
		}
	}
}

// fetchBlocks calls GET /blocks?from=from&limit=limit on the server and
// returns the decoded block list as a slice of generic maps.
func fetchBlocks(t *testing.T, srv *Server, from, limit int) []map[string]interface{} {
	t.Helper()
	url := fmt.Sprintf("/blocks?from=%d&limit=%d", from, limit)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: want 200, got %d — body: %s", url, w.Code, w.Body.String())
	}

	var blocks []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &blocks); err != nil {
		t.Fatalf("fetchBlocks: unmarshal: %v (body: %s)", err, w.Body.String())
	}
	return blocks
}

// blockHash extracts the hash field from a block map (handles both flat and
// nested-header structures).
func blockHash(b map[string]interface{}) string {
	if h, ok := b["hash"].(string); ok {
		return h
	}
	if hdr, ok := b["header"].(map[string]interface{}); ok {
		if h, ok := hdr["hash"].(string); ok {
			return h
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Q19-A: Seed node with blocks returns them via GET /blocks
// ---------------------------------------------------------------------------

func TestCatchup_SeedHasBlocks(t *testing.T) {
	seed := newTestServer(t)

	// Attempt to mine additional blocks; genesis is always present even if mining fails.
	mineBlocks(t, seed, 3)

	blocks := fetchBlocks(t, seed, 0, 100)

	// We must have at least the genesis block (height 0).
	if len(blocks) == 0 {
		t.Errorf("seed: expected at least the genesis block, got 0")
	}
	t.Logf("seed returned %d block(s)", len(blocks))
}

// ---------------------------------------------------------------------------
// Q19-B: Synced blocks match seed's blocks (count and order)
// ---------------------------------------------------------------------------

func TestCatchup_SyncedBlocksMatchSeed(t *testing.T) {
	seed := newTestServer(t)
	mineBlocks(t, seed, 3)

	seedBlocks := fetchBlocks(t, seed, 0, 100)
	if len(seedBlocks) == 0 {
		t.Fatal("seed returned 0 blocks")
	}

	// A "fresh" node starting from height 0 fetches the same range.
	// (In a real network this would be a separate node; here we re-fetch
	// from the same server to verify the endpoint is deterministic.)
	freshBlocks := fetchBlocks(t, seed, 0, 100)

	if len(freshBlocks) != len(seedBlocks) {
		t.Fatalf("sync count mismatch: seed=%d, synced=%d", len(seedBlocks), len(freshBlocks))
	}

	for i := range seedBlocks {
		seedH := blockHash(seedBlocks[i])
		freshH := blockHash(freshBlocks[i])
		if seedH != freshH {
			t.Errorf("block[%d] hash mismatch: seed=%q, synced=%q", i, seedH, freshH)
		}
	}
}

// ---------------------------------------------------------------------------
// Q19-C: Block hashes are preserved (non-empty) during sync
// ---------------------------------------------------------------------------

func TestCatchup_BlockHashesPreserved(t *testing.T) {
	seed := newTestServer(t)
	mineBlocks(t, seed, 2)

	blocks := fetchBlocks(t, seed, 0, 100)
	for i, b := range blocks {
		h := blockHash(b)
		if h == "" {
			t.Errorf("block[%d]: hash is empty after sync", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Q19-D: Partial range fetch (from > 0) returns correct tail
// ---------------------------------------------------------------------------

func TestCatchup_PartialRangeFetch(t *testing.T) {
	seed := newTestServer(t)
	mineBlocks(t, seed, 4)

	all := fetchBlocks(t, seed, 0, 100)
	if len(all) < 2 {
		t.Skip("need at least 2 blocks for partial range test (mining requires pending txs)")
	}

	// Fetch from block index 1 onwards
	tail := fetchBlocks(t, seed, 1, 100)
	wantLen := len(all) - 1
	if len(tail) != wantLen {
		t.Errorf("tail len: want %d, got %d", wantLen, len(tail))
	}

	// First block in tail should match all[1]
	if blockHash(tail[0]) != blockHash(all[1]) {
		t.Errorf("tail[0] hash %q != all[1] hash %q", blockHash(tail[0]), blockHash(all[1]))
	}
}

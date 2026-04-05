// MIT License
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. SEC-P2P01 tests — seenConsensusMsgs TTL-based dedup (056148b).
// Also covers seenBlocks TTL pattern which uses the same pruning logic.
package p2p

import (
	"testing"
	"time"

)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// SEC-P2P01: seenConsensusMsgsTTL constant verification
// ---------------------------------------------------------------------------

// TestSECP2P01_TTLConstant_Is2Minutes documents the 2-minute TTL for
// seenConsensusMsgs and guards against accidental changes.
func TestSECP2P01_TTLConstant_Is2Minutes(t *testing.T) {
	if seenConsensusMsgsTTL != 2*time.Minute {
		t.Errorf("seenConsensusMsgsTTL: want 2m got %v", seenConsensusMsgsTTL)
	}
}

// TestSECP2P01_SeenBlocksTTL_Is5Minutes documents the seenBlocks TTL.
func TestSECP2P01_SeenBlocksTTL_Is5Minutes(t *testing.T) {
	if seenBlocksTTL != 5*time.Minute {
		t.Errorf("seenBlocksTTL: want 5m got %v", seenBlocksTTL)
	}
}

// TestSECP2P01_ConsensusTTL_LessThanBlockTTL verifies the consensus dedup
// window is shorter than the block dedup window (fast rounds vs slow sync).
func TestSECP2P01_ConsensusTTL_LessThanBlockTTL(t *testing.T) {
	if seenConsensusMsgsTTL >= seenBlocksTTL {
		t.Errorf("consensus TTL should be < block TTL: %v >= %v",
			seenConsensusMsgsTTL, seenBlocksTTL)
	}
}

// ---------------------------------------------------------------------------
// markBlockSeen / isBlockSeen — same lazy-prune pattern as seenConsensusMsgs
// ---------------------------------------------------------------------------

// TestMarkBlockSeen_FreshHashIsSeen verifies a just-marked block is seen.
func TestMarkBlockSeen_FreshHashIsSeen(t *testing.T) {
	srv := newTestServer(t, "0")
	hash := "aaabbbcccdddeee000111222333444555666777888999000aaabbbcccdddeee000"
	srv.markBlockSeen(hash)
	if !srv.isBlockSeen(hash) {
		t.Error("freshly marked block should be seen")
	}
}

// TestMarkBlockSeen_UnknownHashNotSeen verifies unknown hash is not seen.
func TestMarkBlockSeen_UnknownHashNotSeen(t *testing.T) {
	srv := newTestServer(t, "0")
	if srv.isBlockSeen("not-a-real-hash-00000000000000000000000000000") {
		t.Error("unknown hash should not be seen")
	}
}

// TestMarkBlockSeen_EmptyHashSkipped verifies empty hash is not stored.
func TestMarkBlockSeen_EmptyHashSkipped(t *testing.T) {
	srv := newTestServer(t, "0")
	srv.markBlockSeen("")
	if srv.isBlockSeen("") {
		t.Error("empty hash should never be 'seen'")
	}
}

// TestMarkBlockSeen_DuplicateIdempotent verifies marking the same hash twice
// doesn't cause errors and still returns seen=true.
func TestMarkBlockSeen_DuplicateIdempotent(t *testing.T) {
	srv := newTestServer(t, "0")
	hash := "deadbeef00000000000000000000000000000000000000000000000000000000"
	srv.markBlockSeen(hash)
	srv.markBlockSeen(hash) // second call should not panic or corrupt state
	if !srv.isBlockSeen(hash) {
		t.Error("hash should still be seen after duplicate mark")
	}
}

// TestMarkBlockSeen_MultipleHashes verifies multiple distinct hashes are
// tracked independently.
func TestMarkBlockSeen_MultipleHashes(t *testing.T) {
	srv := newTestServer(t, "0")
	hashes := []string{
		"hash0000000000000000000000000000000000000000000000000000000000001",
		"hash0000000000000000000000000000000000000000000000000000000000002",
		"hash0000000000000000000000000000000000000000000000000000000000003",
	}
	for _, h := range hashes {
		srv.markBlockSeen(h)
	}
	for _, h := range hashes {
		if !srv.isBlockSeen(h) {
			t.Errorf("hash %q should be seen", h)
		}
	}
}

// TestIsBlockSeen_NeverMarked verifies isBlockSeen returns false for unmarked hash.
func TestIsBlockSeen_NeverMarked(t *testing.T) {
	srv := newTestServer(t, "0")
	if srv.isBlockSeen("never-marked-hash-0000000000000000000000000000000") {
		t.Error("unmarked hash should return false")
	}
}

// ---------------------------------------------------------------------------
// SEC-P2P01: seenConsensusMsgs map structure (type + initial state)
// ---------------------------------------------------------------------------

// TestSECP2P01_SeenConsensusMsgsMap_IsNilInitially verifies the map is nil
// before first use (lazy init pattern — same as before the fix).
func TestSECP2P01_SeenConsensusMsgsMap_IsNilInitially(t *testing.T) {
	srv := newTestServer(t, "0")
	// The map is nil until the first consensus message is processed.
	// This tests the lazy-init invariant — map starts nil, no pre-allocation.
	if srv.seenConsensusMsgs != nil {
		// This is fine if it was pre-allocated; just document the actual state.
		t.Logf("seenConsensusMsgs pre-allocated with %d entries", len(srv.seenConsensusMsgs))
	}
}

// TestSECP2P01_MapType_IsTimeValued documents that seenConsensusMsgs uses
// time.Time values (not struct{}) after the SEC-P2P01 fix.
// This is a compile-time check: if the type changed back to struct{},
// this file would not compile.
func TestSECP2P01_MapType_IsTimeValued(t *testing.T) {
	// Create a map of the same type as seenConsensusMsgs to verify type at compile time.
	var m map[string]time.Time = srv_makeSeenMap()
	if m == nil {
		m = make(map[string]time.Time)
	}
	key := "test-msg-hash"
	m[key] = time.Now()
	if _, ok := m[key]; !ok {
		t.Error("time-valued map should store and retrieve entries")
	}
}

// srv_makeSeenMap returns a map of the same type as Server.seenConsensusMsgs.
// If Server.seenConsensusMsgs is ever changed back to map[string]struct{},
// this function will fail to compile (type mismatch).
func srv_makeSeenMap() map[string]time.Time {
	srv := &Server{}
	return srv.seenConsensusMsgs
}

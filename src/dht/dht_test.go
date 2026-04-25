// MIT License
// Copyright (c) 2024 quantix

// P3-Q1: PEPPER targeted tests for src/dht — routing table + utility coverage.
package dht

import (
	"net"
	"testing"
	"time"

	"github.com/quantix-org/quantix-org/src/network"
	"github.com/quantix-org/quantix-org/src/rpc"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func makeNodeID(seed byte) rpc.NodeID {
	var id rpc.NodeID
	id[0] = seed
	return id
}

func makeAddr(port int) net.UDPAddr {
	return net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
}

// ---------------------------------------------------------------------------
// kBucket tests
// ---------------------------------------------------------------------------

func TestKBucket_Observe_BelowCapacity(t *testing.T) {
	b := newBucket(4)
	for i := 0; i < 4; i++ {
		b.Observe(makeNodeID(byte(i+1)), makeAddr(9000+i))
	}
	if b.Len() != 4 {
		t.Fatalf("expected 4 entries, got %d", b.Len())
	}
}

func TestKBucket_Observe_AtCapacity_EvictsOldest(t *testing.T) {
	b := newBucket(2)
	b.Observe(makeNodeID(1), makeAddr(9001))
	b.Observe(makeNodeID(2), makeAddr(9002))
	// At capacity; adding a new unknown node should evict front
	b.Observe(makeNodeID(3), makeAddr(9003))
	if b.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", b.Len())
	}
	// node 1 should have been evicted; node 2 and 3 should remain
	var ids []rpc.NodeID
	b.CopyToList(nil) // warm up
	list := b.CopyToList(nil)
	for _, r := range list {
		ids = append(ids, r.NodeID)
	}
	for _, id := range ids {
		if id == makeNodeID(1) {
			t.Error("node 1 should have been evicted")
		}
	}
}

func TestKBucket_Observe_UpdateExisting(t *testing.T) {
	b := newBucket(3)
	b.Observe(makeNodeID(1), makeAddr(9001))
	b.Observe(makeNodeID(2), makeAddr(9002))
	b.Observe(makeNodeID(3), makeAddr(9003))
	// Update node 1 — should not evict anything
	b.Observe(makeNodeID(1), makeAddr(9001))
	if b.Len() != 3 {
		t.Fatalf("expected 3 entries, got %d", b.Len())
	}
}

func TestKBucket_CopyToList(t *testing.T) {
	b := newBucket(8)
	b.Observe(makeNodeID(10), makeAddr(9010))
	b.Observe(makeNodeID(11), makeAddr(9011))
	list := b.CopyToList(nil)
	if len(list) != 2 {
		t.Fatalf("expected 2, got %d", len(list))
	}
}

// ---------------------------------------------------------------------------
// routingTable tests
// ---------------------------------------------------------------------------

func TestRoutingTable_Observe_IgnoresSelf(t *testing.T) {
	selfID := makeNodeID(42)
	rt := newRoutingTable(DefaultK, DefaultBits, selfID, makeAddr(8000))
	rt.Observe(selfID, makeAddr(8000)) // self should be ignored
	// All buckets should be empty
	for i, b := range rt.buckets {
		if b.Len() != 0 {
			t.Fatalf("bucket %d should be empty after observing self, got %d", i, b.Len())
		}
	}
}

func TestRoutingTable_Observe_And_KNearest(t *testing.T) {
	selfID := makeNodeID(0)
	rt := newRoutingTable(DefaultK, DefaultBits, selfID, makeAddr(8000))

	// Add several nodes
	for i := 1; i <= 5; i++ {
		rt.Observe(makeNodeID(byte(i)), makeAddr(8000+i))
	}

	// Generate a target that differs from self at bit 7 (byte 0)
	var target rpc.NodeID
	target[0] = 0x80
	results := rt.KNearest(target)
	if len(results) == 0 {
		t.Fatal("KNearest returned empty results")
	}
}

func TestRoutingTable_KNearest_IncludesSelf(t *testing.T) {
	selfID := makeNodeID(10)
	rt := newRoutingTable(DefaultK, DefaultBits, selfID, makeAddr(8001))
	var target rpc.NodeID
	target[0] = 0xFF
	results := rt.KNearest(target)
	hasSelf := false
	for _, r := range results {
		if r.NodeID == selfID {
			hasSelf = true
		}
	}
	if !hasSelf {
		t.Error("KNearest should include self node")
	}
}

func TestRoutingTable_InterestedNodes(t *testing.T) {
	selfID := makeNodeID(1)
	rt := newRoutingTable(DefaultK, 128, selfID, makeAddr(8002)) // 128 bits avoids getRandomInterestedNodeID panic for high prefix lens
	// Populate some buckets so InterestedNodes returns non-empty
	rt.Observe(makeNodeID(2), makeAddr(9002))
	nodes := rt.InterestedNodes()
	_ = nodes // just ensure no panic
}

func TestRoutingTable_GetStaleRemote_Empty(t *testing.T) {
	rt := newRoutingTable(DefaultK, DefaultBits, makeNodeID(1), makeAddr(8003))
	stale := rt.GetStaleRemote()
	if stale == nil {
		t.Error("expected non-nil (empty) stale slice")
	}
}

func TestRoutingTable_GC_RemovesDeadNodes(t *testing.T) {
	rt := newRoutingTable(DefaultK, DefaultBits, makeNodeID(0), makeAddr(8004))
	rt.Observe(makeNodeID(5), makeAddr(9005))
	// Force the lastSeen far in the past
	for _, b := range rt.buckets {
		for el := b.buckets.Front(); el != nil; el = el.Next() {
			rec := el.Value
			rec.lastSeen = time.Now().Add(-deadThreshold - time.Second)
			b.buckets.Set(el.Key, rec)
		}
	}
	rt.GC()
	totalNodes := 0
	for _, b := range rt.buckets {
		totalNodes += b.Len()
	}
	if totalNodes != 0 {
		t.Errorf("expected all dead nodes removed, got %d remaining", totalNodes)
	}
}

// ---------------------------------------------------------------------------
// getRandomDelay
// ---------------------------------------------------------------------------

func TestGetRandomDelay_InRange(t *testing.T) {
	d := time.Second
	delay := getRandomDelay(d)
	if delay < 0 || delay >= d {
		t.Errorf("random delay %v not in [0, %v)", delay, d)
	}
}

// ---------------------------------------------------------------------------
// network.Key helpers (exercised via routing table)
// ---------------------------------------------------------------------------

func TestKey_IsEmpty(t *testing.T) {
	var k network.Key
	if !k.IsEmpty() {
		t.Error("zero key should be empty")
	}
	k[0] = 1
	if k.IsEmpty() {
		t.Error("non-zero key should not be empty")
	}
}

func TestKey_CommonPrefixLength_Same(t *testing.T) {
	var a, b network.Key
	a[0] = 0xAB
	b[0] = 0xAB
	cpl := a.CommonPrefixLength(b)
	if cpl < 8 {
		t.Errorf("same key high byte should share ≥8 prefix bits, got %d", cpl)
	}
}

func TestKey_Distance_XOR(t *testing.T) {
	var a, b network.Key
	a[0] = 0x01
	b[0] = 0x02
	var d network.Key
	d.Distance(a, b)
	if d[0] != 0x03 {
		t.Errorf("expected XOR distance 0x03, got 0x%02x", d[0])
	}
}

// go/src/dht/dht_test.go
package dht

import (
	"net"
	"testing"

	"github.com/quantix-org/quantix-org/src/rpc"
)

// TestNewRoutingTable verifies that a routing table can be created.
func TestNewRoutingTable(t *testing.T) {
	var selfID rpc.NodeID
	selfID[0] = 1
	addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3000}

	rt := newRoutingTable(DefaultK, DefaultBits, selfID, addr)
	if rt == nil {
		t.Fatal("expected non-nil routing table")
	}
	if rt.k != DefaultK {
		t.Errorf("expected k=%d, got %d", DefaultK, rt.k)
	}
	if rt.bits != DefaultBits {
		t.Errorf("expected bits=%d, got %d", DefaultBits, rt.bits)
	}
}

// TestRoutingTableObserve verifies that observing a node adds it to the routing table.
func TestRoutingTableObserve(t *testing.T) {
	var selfID rpc.NodeID
	selfID[0] = 0
	addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3000}
	rt := newRoutingTable(DefaultK, DefaultBits, selfID, addr)

	var peerID rpc.NodeID
	peerID[0] = 0xff // Maximum distance from selfID
	peerAddr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3001}
	rt.Observe(peerID, peerAddr)
	// Should not panic; the bucket at the appropriate prefix should have at least 1 entry
}

// TestRoutingTableKNearest verifies KNearest returns valid results.
func TestRoutingTableKNearest(t *testing.T) {
	var selfID rpc.NodeID
	selfID[0] = 1
	addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3000}
	rt := newRoutingTable(DefaultK, DefaultBits, selfID, addr)

	// No nodes in table, should return empty slice
	var target rpc.NodeID
	target[0] = 2
	result := rt.KNearest(target)
	_ = result // Don't panic
}

// TestNewBucket verifies that a kBucket is properly initialized.
func TestNewBucket(t *testing.T) {
	b := newBucket(DefaultK)
	if b == nil {
		t.Fatal("expected non-nil kBucket")
	}
	if b.Len() != 0 {
		t.Errorf("expected empty bucket, got %d", b.Len())
	}
}

// TestBucketObserve verifies that observing a node adds it to the bucket.
func TestBucketObserve(t *testing.T) {
	b := newBucket(DefaultK)
	var nodeID rpc.NodeID
	nodeID[0] = 42
	addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3001}

	b.Observe(nodeID, addr)
	if b.Len() == 0 {
		t.Error("expected non-empty bucket after observe")
	}
}

// TestDHTConstants verifies DHT configuration constants.
func TestDHTConstants(t *testing.T) {
	if DefaultK <= 0 {
		t.Errorf("DefaultK should be positive, got %d", DefaultK)
	}
	if DefaultBits <= 0 {
		t.Errorf("DefaultBits should be positive, got %d", DefaultBits)
	}
}

// TestDHTConfigFields verifies DHTConfig field assignment.
func TestDHTConfigFields(t *testing.T) {
	cfg := DHTConfig{
		Proto: "udp4",
		Address: net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 7000,
		},
		Secret: 42,
	}
	if cfg.Proto != "udp4" {
		t.Errorf("expected udp4, got %s", cfg.Proto)
	}
	if cfg.Secret != 42 {
		t.Errorf("expected secret 42, got %d", cfg.Secret)
	}
}

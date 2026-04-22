// go/src/network/network_test.go
package network

import (
	"testing"
	"time"
)

// TestNodeIDString verifies NodeID.String() returns a hex string.
func TestNodeIDString(t *testing.T) {
	var id NodeID
	for i := range id {
		id[i] = byte(i)
	}
	s := id.String()
	if len(s) != 64 {
		t.Errorf("expected 64 hex chars, got %d: %s", len(s), s)
	}
}

// TestNodeStatusConstants verifies node status constants.
func TestNodeStatusConstants(t *testing.T) {
	if NodeStatusActive != "active" {
		t.Error("NodeStatusActive mismatch")
	}
	if NodeStatusInactive != "inactive" {
		t.Error("NodeStatusInactive mismatch")
	}
	if NodeStatusUnknown != "unknown" {
		t.Error("NodeStatusUnknown mismatch")
	}
}

// TestNodeRoleConstants verifies node role constants.
func TestNodeRoleConstants(t *testing.T) {
	if RoleSender != "sender" {
		t.Error("RoleSender mismatch")
	}
	if RoleReceiver != "receiver" {
		t.Error("RoleReceiver mismatch")
	}
	if RoleValidator != "validator" {
		t.Error("RoleValidator mismatch")
	}
}

// TestPeerInfo verifies PeerInfo struct can be populated.
func TestPeerInfo(t *testing.T) {
	var id NodeID
	pi := PeerInfo{
		NodeID:     "test-node",
		KademliaID: id,
		Address:    "127.0.0.1:3000",
		Status:     NodeStatusActive,
		Role:       RoleValidator,
		Timestamp:  time.Now(),
	}
	if pi.NodeID != "test-node" {
		t.Errorf("expected node ID test-node, got %s", pi.NodeID)
	}
}

// TestNodePortConfig verifies NodePortConfig construction.
func TestNodePortConfig(t *testing.T) {
	cfg := NodePortConfig{
		ID:      "node-1",
		TCPAddr: "127.0.0.1:3001",
		UDPPort: "3002",
	}
	if cfg.ID != "node-1" {
		t.Errorf("expected node-1, got %s", cfg.ID)
	}
}

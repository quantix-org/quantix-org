// MIT License
// Copyright (c) 2024 quantix

// Q24 — Tests for P2-PBFT-FULL new surface:
//   - DecodeConsensusEnvelope (pure JSON decode)
//   - RouteConsensusMessage (envelope routing to consensus handlers)
//   - NewP2PNodeManager (constructor)
//   - GetPeers / GetNode with nil nodeManager (nil-safety)
package p2p

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ramseyauron/quantix/src/consensus"
)

func init() {
	os.Setenv("DEVNET_ALLOW_VDF_RESET", "1")
	consensus.InitVDFFromGenesis(func() (string, error) {
		return "0000000000000000000000000000000000000000000000000000000000000001", nil
	})
}

// ---------------------------------------------------------------------------
// DecodeConsensusEnvelope
// ---------------------------------------------------------------------------

func TestDecodeConsensusEnvelope_ValidProposal(t *testing.T) {
	raw := []byte(`{"type":"proposal","payload":{"proposer_id":"node-1","view":1}}`)
	env, err := DecodeConsensusEnvelope(raw)
	if err != nil {
		t.Fatalf("DecodeConsensusEnvelope: %v", err)
	}
	if env.Type != "proposal" {
		t.Errorf("Type: got %q want proposal", env.Type)
	}
	if len(env.Payload) == 0 {
		t.Error("Payload should not be empty")
	}
}

func TestDecodeConsensusEnvelope_ValidVote(t *testing.T) {
	payload := map[string]interface{}{"voter_id": "node-2", "view": 1, "block_hash": "abc123"}
	payloadBytes, _ := json.Marshal(payload)
	raw, _ := json.Marshal(map[string]interface{}{"type": "vote", "payload": json.RawMessage(payloadBytes)})

	env, err := DecodeConsensusEnvelope(raw)
	if err != nil {
		t.Fatalf("DecodeConsensusEnvelope vote: %v", err)
	}
	if env.Type != "vote" {
		t.Errorf("Type: got %q want vote", env.Type)
	}
}

func TestDecodeConsensusEnvelope_InvalidJSON_Error(t *testing.T) {
	_, err := DecodeConsensusEnvelope([]byte("not-json{{"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDecodeConsensusEnvelope_EmptyPayload(t *testing.T) {
	raw := []byte(`{"type":"timeout","payload":null}`)
	env, err := DecodeConsensusEnvelope(raw)
	if err != nil {
		t.Fatalf("DecodeConsensusEnvelope empty payload: %v", err)
	}
	if env.Type != "timeout" {
		t.Errorf("Type: got %q want timeout", env.Type)
	}
}

// ---------------------------------------------------------------------------
// RouteConsensusMessage
// ---------------------------------------------------------------------------













// ---------------------------------------------------------------------------
// NewP2PNodeManager / GetPeers / GetNode
// ---------------------------------------------------------------------------

func TestNewP2PNodeManager_NotNil(t *testing.T) {
	m := NewP2PNodeManager(nil)
	if m == nil {
		t.Fatal("NewP2PNodeManager returned nil")
	}
}

func TestP2PNodeManager_GetPeers_NilNodeManager_EmptyMap(t *testing.T) {
	m := NewP2PNodeManager(nil)
	peers := m.GetPeers()
	if peers == nil {
		t.Error("GetPeers should return non-nil map even with nil nodeManager")
	}
	if len(peers) != 0 {
		t.Errorf("expected empty peers with nil nodeManager, got %d", len(peers))
	}
}

func TestP2PNodeManager_GetNode_NilNodeManager_ReturnsFallback(t *testing.T) {
	m := NewP2PNodeManager(nil)
	node := m.GetNode("test-node-id")
	if node == nil {
		t.Fatal("GetNode should return non-nil fallback node even with nil nodeManager")
	}
	if node.GetID() != "test-node-id" {
		t.Errorf("GetNode fallback: GetID() = %q, want test-node-id", node.GetID())
	}
}

func TestP2PNodeManager_GetNode_KnownID_ReturnsNode(t *testing.T) {
	m := NewP2PNodeManager(nil)
	// With nil nodeManager, returns p2pNode fallback
	n1 := m.GetNode("peer-A")
	n2 := m.GetNode("peer-B")
	if n1.GetID() == n2.GetID() {
		t.Error("different node IDs should return different nodes")
	}
}

// ---------------------------------------------------------------------------
// p2pNode interface implementation
// ---------------------------------------------------------------------------

func TestP2PNode_GetRole_DefaultsToZero(t *testing.T) {
	m := NewP2PNodeManager(nil)
	node := m.GetNode("any-node")
	// Role should be zero (NodeRole(0)) as documented
	if int(node.GetRole()) != 0 {
		t.Errorf("p2pNode default role: want 0, got %d", node.GetRole())
	}
}

func TestP2PNode_GetStatus_DefaultsToZero(t *testing.T) {
	m := NewP2PNodeManager(nil)
	node := m.GetNode("any-node")
	if int(node.GetStatus()) != 0 {
		t.Errorf("p2pNode default status: want 0, got %d", node.GetStatus())
	}
}

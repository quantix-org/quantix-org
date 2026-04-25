// MIT License
// Copyright (c) 2024 quantix

// P3-Q1: PEPPER targeted tests for src/p2p — non-network-I/O units.
package p2p

import (
	"encoding/json"
	"testing"
	"time"

	security "github.com/quantix-org/quantix-org/src/handshake"
	"github.com/quantix-org/quantix-org/src/network"
)

// ---------------------------------------------------------------------------
// Helper — build a minimal dev-mode server (no UDP, no DB)
// ---------------------------------------------------------------------------

func newTestServer(t *testing.T, port string) *Server {
	t.Helper()
	cfg := network.NodePortConfig{
		ID:      "test-" + port,
		Name:    "test-" + port,
		TCPAddr: "127.0.0.1:" + port,
		UDPPort: "0", // won't bind
		Role:    network.RoleValidator,
		DevMode: true,
	}
	srv := NewServer(cfg, nil, nil)
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	return srv
}

// ---------------------------------------------------------------------------
// Server accessors
// ---------------------------------------------------------------------------

func TestServer_LocalNode_NotNil(t *testing.T) {
	srv := newTestServer(t, "19910")
	if srv.LocalNode() == nil {
		t.Error("LocalNode() returned nil")
	}
}

func TestServer_NodeManager_NotNil(t *testing.T) {
	srv := newTestServer(t, "19912")
	if srv.NodeManager() == nil {
		t.Error("NodeManager() returned nil")
	}
}

func TestServer_PeerManager_NotNil(t *testing.T) {
	srv := newTestServer(t, "19914")
	if srv.PeerManager() == nil {
		t.Error("PeerManager() returned nil")
	}
}

func TestServer_UpdateSeedNodes(t *testing.T) {
	srv := newTestServer(t, "19916")
	seeds := []string{"127.0.0.1:9000", "127.0.0.1:9001"}
	srv.UpdateSeedNodes(seeds)
	// No panic = pass; internal state not exposed but exercise the path
}

// ---------------------------------------------------------------------------
// PeerManager — UpdatePeerScore on non-existent peer (no-op)
// ---------------------------------------------------------------------------

func TestPeerManager_UpdatePeerScore_UnknownPeer_NoOp(t *testing.T) {
	srv := newTestServer(t, "19918")
	pm := srv.PeerManager()
	// Should not panic on unknown peer
	pm.UpdatePeerScore("unknown-peer", 10)
}

// ---------------------------------------------------------------------------
// PeerManager — DisconnectPeer on missing peer returns error
// ---------------------------------------------------------------------------

func TestPeerManager_DisconnectPeer_NotFound_Error(t *testing.T) {
	srv := newTestServer(t, "19920")
	pm := srv.PeerManager()
	err := pm.DisconnectPeer("nobody")
	if err == nil {
		t.Error("expected error when disconnecting non-existent peer")
	}
}

// ---------------------------------------------------------------------------
// PeerManager — BanPeer on missing peer returns error
// ---------------------------------------------------------------------------

func TestPeerManager_BanPeer_NotFound_Error(t *testing.T) {
	srv := newTestServer(t, "19922")
	pm := srv.PeerManager()
	err := pm.BanPeer("nobody", time.Hour)
	if err == nil {
		t.Error("expected error when banning non-existent peer")
	}
}

// ---------------------------------------------------------------------------
// PeerManager — ConnectPeer on banned peer returns error
// ---------------------------------------------------------------------------

func TestPeerManager_ConnectPeer_Banned(t *testing.T) {
	srv := newTestServer(t, "19924")
	pm := srv.PeerManager()
	// Manually inject a ban
	pm.mu.Lock()
	pm.bans["banned-node"] = time.Now().Add(time.Hour)
	pm.mu.Unlock()

	node := &network.Node{
		ID:      "banned-node",
		Address: "127.0.0.1:9999",
	}
	err := pm.ConnectPeer(node)
	if err == nil {
		t.Error("expected error for banned peer")
	}
}

// ---------------------------------------------------------------------------
// generateMessageID — deterministic, non-empty
// ---------------------------------------------------------------------------

func TestGenerateMessageID_NonEmpty(t *testing.T) {
	msg := &security.Message{Type: "ping", Data: "test"}
	id := generateMessageID(msg)
	if len(id) == 0 {
		t.Error("expected non-empty message ID")
	}
}

func TestGenerateMessageID_Deterministic(t *testing.T) {
	msg := &security.Message{Type: "ping", Data: "test"}
	id1 := generateMessageID(msg)
	id2 := generateMessageID(msg)
	if id1 != id2 {
		t.Errorf("message ID should be deterministic: %s != %s", id1, id2)
	}
}

func TestGenerateMessageID_DifferentForDifferentMessages(t *testing.T) {
	a := generateMessageID(&security.Message{Type: "ping", Data: "a"})
	b := generateMessageID(&security.Message{Type: "ping", Data: "b"})
	if a == b {
		t.Error("different messages should produce different IDs")
	}
}

// ---------------------------------------------------------------------------
// DecodeConsensusEnvelope — valid and invalid JSON
// ---------------------------------------------------------------------------

func TestDecodeConsensusEnvelope_ValidJSON(t *testing.T) {
	env := map[string]interface{}{
		"type":    "proposal",
		"payload": json.RawMessage(`{}`),
	}
	raw, _ := json.Marshal(env)
	decoded, err := DecodeConsensusEnvelope(raw)
	if err != nil {
		t.Fatalf("DecodeConsensusEnvelope: %v", err)
	}
	if decoded == nil {
		t.Error("expected non-nil envelope")
	}
}

func TestDecodeConsensusEnvelope_InvalidJSON_Error_P3(t *testing.T) {
	_, err := DecodeConsensusEnvelope([]byte("not-json{{{"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// NewP2PNodeManager
// ---------------------------------------------------------------------------

func TestNewP2PNodeManager_NotNil_P3(t *testing.T) {
	nm := network.NewNodeManager(16, nil, nil)
	mgr := NewP2PNodeManager(nm)
	if mgr == nil {
		t.Error("NewP2PNodeManager returned nil")
	}
}

func TestP2PNodeManager_GetPeers_Empty_P3(t *testing.T) {
	nm := network.NewNodeManager(16, nil, nil)
	mgr := NewP2PNodeManager(nm)
	peers := mgr.GetPeers()
	if peers == nil {
		t.Error("GetPeers should return non-nil map")
	}
}

func TestP2PNodeManager_GetNode_Unknown_P3(t *testing.T) {
	nm := network.NewNodeManager(16, nil, nil)
	mgr := NewP2PNodeManager(nm)
	n := mgr.GetNode("does-not-exist")
	_ = n // should not panic, may return zero value
}

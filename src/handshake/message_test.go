// MIT License
// Copyright (c) 2024 quantix

// Q16 — Tests for src/handshake/message.go (previously 0% coverage)
// Covers: ValidateMessage, Encode, DecodeMessage for all message types
package security

import (
	"encoding/json"
	"math/big"
	"testing"

	types "github.com/ramseyauron/quantix/src/core/transaction"
)

// ---------------------------------------------------------------------------
// ValidateMessage — empty type
// ---------------------------------------------------------------------------

func TestValidateMessage_EmptyType_Error(t *testing.T) {
	m := &Message{Type: "", Data: nil}
	if err := m.ValidateMessage(); err == nil {
		t.Error("expected error for empty message type")
	}
}

// ---------------------------------------------------------------------------
// ValidateMessage — ping/pong
// ---------------------------------------------------------------------------

func TestValidateMessage_Ping_StringData_OK(t *testing.T) {
	m := &Message{Type: "ping", Data: "node-id-123"}
	if err := m.ValidateMessage(); err != nil {
		t.Errorf("ping with string data: %v", err)
	}
}

func TestValidateMessage_Ping_NonStringData_Error(t *testing.T) {
	m := &Message{Type: "ping", Data: 42}
	if err := m.ValidateMessage(); err == nil {
		t.Error("expected error for ping with non-string data")
	}
}

func TestValidateMessage_Pong_StringData_OK(t *testing.T) {
	m := &Message{Type: "pong", Data: "node-id-456"}
	if err := m.ValidateMessage(); err != nil {
		t.Errorf("pong with string data: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValidateMessage — verack
// ---------------------------------------------------------------------------

func TestValidateMessage_Verack_StringData_OK(t *testing.T) {
	m := &Message{Type: "verack", Data: "node-id-abc"}
	if err := m.ValidateMessage(); err != nil {
		t.Errorf("verack with string data: %v", err)
	}
}

func TestValidateMessage_Verack_NonStringData_Error(t *testing.T) {
	m := &Message{Type: "verack", Data: map[string]interface{}{}}
	if err := m.ValidateMessage(); err == nil {
		t.Error("expected error for verack with non-string data")
	}
}

// ---------------------------------------------------------------------------
// ValidateMessage — jsonrpc
// ---------------------------------------------------------------------------

func TestValidateMessage_JSONRPC_ValidData_OK(t *testing.T) {
	m := &Message{
		Type: "jsonrpc",
		Data: map[string]interface{}{"jsonrpc": "2.0", "method": "eth_blockNumber"},
	}
	if err := m.ValidateMessage(); err != nil {
		t.Errorf("jsonrpc valid data: %v", err)
	}
}

func TestValidateMessage_JSONRPC_WrongVersion_Error(t *testing.T) {
	m := &Message{
		Type: "jsonrpc",
		Data: map[string]interface{}{"jsonrpc": "1.0"},
	}
	if err := m.ValidateMessage(); err == nil {
		t.Error("expected error for jsonrpc with wrong version")
	}
}

func TestValidateMessage_JSONRPC_NonMap_Error(t *testing.T) {
	m := &Message{Type: "jsonrpc", Data: "raw string"}
	if err := m.ValidateMessage(); err == nil {
		t.Error("expected error for jsonrpc with non-map data")
	}
}

// ---------------------------------------------------------------------------
// ValidateMessage — version
// ---------------------------------------------------------------------------

func TestValidateMessage_Version_AllFields_OK(t *testing.T) {
	m := &Message{
		Type: "version",
		Data: map[string]interface{}{
			"version":      "1.0.0",
			"node_id":      "node-abc",
			"chain_id":     "7331",
			"block_height": float64(42),
			"nonce":        "0000000000000001",
		},
	}
	if err := m.ValidateMessage(); err != nil {
		t.Errorf("version with all fields: %v", err)
	}
}

func TestValidateMessage_Version_MissingField_Error(t *testing.T) {
	m := &Message{
		Type: "version",
		Data: map[string]interface{}{
			"version": "1.0.0",
			// missing node_id, chain_id, block_height, nonce
		},
	}
	if err := m.ValidateMessage(); err == nil {
		t.Error("expected error for version with missing fields")
	}
}

func TestValidateMessage_Version_NonMap_Error(t *testing.T) {
	m := &Message{Type: "version", Data: "not-a-map"}
	if err := m.ValidateMessage(); err == nil {
		t.Error("expected error for version with non-map data")
	}
}

// ---------------------------------------------------------------------------
// ValidateMessage — transaction
// ---------------------------------------------------------------------------

func TestValidateMessage_Transaction_TypedPtr_OK(t *testing.T) {
	tx := &types.Transaction{
		Sender:   "xAlice000000000000000000000000",
		Receiver: "xBob00000000000000000000000000",
		Amount:   big.NewInt(100),
	}
	m := &Message{Type: "transaction", Data: tx}
	if err := m.ValidateMessage(); err != nil {
		t.Errorf("transaction with typed ptr: %v", err)
	}
}

func TestValidateMessage_Transaction_MapData_OK(t *testing.T) {
	// After JSON round-trip, Data becomes map[string]interface{}
	m := &Message{
		Type: "transaction",
		Data: map[string]interface{}{"sender": "alice", "amount": "100"},
	}
	if err := m.ValidateMessage(); err != nil {
		t.Errorf("transaction with map data: %v", err)
	}
}

func TestValidateMessage_Transaction_WrongType_Error(t *testing.T) {
	m := &Message{Type: "transaction", Data: 12345}
	if err := m.ValidateMessage(); err == nil {
		t.Error("expected error for transaction with integer data")
	}
}

// ---------------------------------------------------------------------------
// ValidateMessage — block
// ---------------------------------------------------------------------------

func TestValidateMessage_Block_MapData_OK(t *testing.T) {
	m := &Message{
		Type: "block",
		Data: map[string]interface{}{"height": float64(1), "hash": "abc123"},
	}
	if err := m.ValidateMessage(); err != nil {
		t.Errorf("block with map data: %v", err)
	}
}

func TestValidateMessage_Block_TypedPtr_OK(t *testing.T) {
	block := &types.Block{}
	m := &Message{Type: "block", Data: block}
	if err := m.ValidateMessage(); err != nil {
		t.Errorf("block with typed ptr: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValidateMessage — unknown type (passes through, FIX-P2P-GOSSIP2)
// ---------------------------------------------------------------------------

func TestValidateMessage_UnknownType_Passthrough(t *testing.T) {
	m := &Message{Type: "gossip_block", Data: map[string]interface{}{}}
	if err := m.ValidateMessage(); err != nil {
		t.Errorf("unknown type should pass through (FIX-P2P-GOSSIP2): %v", err)
	}
}

func TestValidateMessage_GossipTx_Passthrough(t *testing.T) {
	m := &Message{Type: "gossip_tx", Data: "anything"}
	if err := m.ValidateMessage(); err != nil {
		t.Errorf("gossip_tx type should pass through: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Encode / DecodeMessage
// ---------------------------------------------------------------------------

func TestEncode_ProducesJSON(t *testing.T) {
	m := &Message{Type: "ping", Data: "node-x"}
	b, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(b) == 0 {
		t.Error("Encode should produce non-empty bytes")
	}
	// Should be valid JSON
	var check map[string]interface{}
	if err := json.Unmarshal(b, &check); err != nil {
		t.Errorf("Encode produced invalid JSON: %v", err)
	}
}

func TestEncode_Decode_Roundtrip_Ping(t *testing.T) {
	m := &Message{Type: "ping", Data: "my-node-id"}
	b, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	m2, err := DecodeMessage(b)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if m2.Type != "ping" {
		t.Errorf("Type: got %q want ping", m2.Type)
	}
}

func TestEncode_Decode_Roundtrip_JSONRPC(t *testing.T) {
	m := &Message{
		Type: "jsonrpc",
		Data: map[string]interface{}{"jsonrpc": "2.0", "id": float64(1)},
	}
	b, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	m2, err := DecodeMessage(b)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if m2.Type != "jsonrpc" {
		t.Errorf("Type: got %q want jsonrpc", m2.Type)
	}
}

func TestDecodeMessage_InvalidJSON_Error(t *testing.T) {
	_, err := DecodeMessage([]byte("not-json{{{"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDecodeMessage_EmptyType_Error(t *testing.T) {
	// JSON with empty type should fail ValidateMessage
	data := []byte(`{"type":"","data":"something"}`)
	_, err := DecodeMessage(data)
	if err == nil {
		t.Error("expected error for message with empty type")
	}
}

func TestDecodeMessage_Version_Roundtrip(t *testing.T) {
	m := &Message{
		Type: "version",
		Data: map[string]interface{}{
			"version":      "1.0.0",
			"node_id":      "peer-xyz",
			"chain_id":     "7331",
			"block_height": float64(100),
			"nonce":        "000000000000abcd",
		},
	}
	b, _ := m.Encode()
	decoded, err := DecodeMessage(b)
	if err != nil {
		t.Fatalf("DecodeMessage version roundtrip: %v", err)
	}
	if decoded.Type != "version" {
		t.Errorf("Type: got %q want version", decoded.Type)
	}
}

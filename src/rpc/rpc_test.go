// go/src/rpc/rpc_test.go
package rpc

import (
	"testing"
)

// TestGetRPCID verifies that GetRPCID returns a non-zero value.
func TestGetRPCID(t *testing.T) {
	id := GetRPCID()
	if id == 0 {
		t.Error("expected non-zero RPCID")
	}
}

// TestNodeIDString verifies NodeID.String() returns 64-char hex.
func TestNodeIDString(t *testing.T) {
	var id NodeID
	for i := range id {
		id[i] = byte(i)
	}
	s := id.String()
	if len(s) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(s))
	}
}

// TestCodecPutGetUint64 verifies uint64 encode/decode round-trip.
func TestCodecPutGetUint64(t *testing.T) {
	c := &Codec{}
	buf := make([]byte, 8)
	c.PutUint64(buf, 42)
	v := c.Uint64(buf)
	if v != 42 {
		t.Errorf("expected 42, got %d", v)
	}
}

// TestCodecPutGetUint32 verifies uint32 encode/decode round-trip.
func TestCodecPutGetUint32(t *testing.T) {
	c := &Codec{}
	buf := make([]byte, 4)
	c.PutUint32(buf, 1234)
	v := c.Uint32(buf)
	if v != 1234 {
		t.Errorf("expected 1234, got %d", v)
	}
}

// TestCodecPutGetUint16 verifies uint16 encode/decode round-trip.
func TestCodecPutGetUint16(t *testing.T) {
	c := &Codec{}
	buf := make([]byte, 2)
	c.PutUint16(buf, 999)
	v := c.Uint16(buf)
	if v != 999 {
		t.Errorf("expected 999, got %d", v)
	}
}

// TestNewKVStore verifies that NewKVStore returns a non-nil store.
func TestNewKVStore(t *testing.T) {
	s := NewKVStore()
	if s == nil {
		t.Fatal("expected non-nil KVStore")
	}
}

// TestKVStorePutGet verifies basic put/get in the KV store.
func TestKVStorePutGet(t *testing.T) {
	s := NewKVStore()
	var k Key
	k[0] = 1
	s.Put(k, []byte("value1"), 60)
	values, ok := s.Get(k)
	if !ok {
		t.Error("expected key to exist")
	}
	if len(values) == 0 {
		t.Error("expected at least one value")
	}
	if string(values[0]) != "value1" {
		t.Errorf("expected value1, got %s", values[0])
	}
}

// TestKVStoreGetMissing verifies get on missing key returns false.
func TestKVStoreGetMissing(t *testing.T) {
	s := NewKVStore()
	var k Key
	k[0] = 99
	_, ok := s.Get(k)
	if ok {
		t.Error("expected key to not exist")
	}
}

// TestRemoteMarshalUnmarshal verifies Remote marshal/unmarshal round-trip.
func TestRemoteMarshalUnmarshal(t *testing.T) {
	var r Remote
	r.NodeID[0] = 42
	r.Address.Port = 3000

	size := r.MarshalSize()
	buf := make([]byte, size)
	out, err := r.Marshal(buf)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var r2 Remote
	if err := r2.Unmarshal(out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if r2.NodeID[0] != 42 {
		t.Errorf("expected NodeID[0] = 42, got %d", r2.NodeID[0])
	}
}

// TestJSONRPCRequestFields verifies JSONRPCRequest struct fields.
func TestJSONRPCRequestFields(t *testing.T) {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "getBlock",
		Params:  nil,
		ID:      1,
	}
	if req.Method != "getBlock" {
		t.Errorf("expected getBlock, got %s", req.Method)
	}
}

// TestJSONRPCResponseFields verifies JSONRPCResponse struct fields.
func TestJSONRPCResponseFields(t *testing.T) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  "ok",
		ID:      1,
	}
	if resp.Result != "ok" {
		t.Errorf("expected ok, got %v", resp.Result)
	}
}

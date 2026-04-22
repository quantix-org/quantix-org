// go/src/server/server_test.go
package server

import (
	"testing"
)

// TestServerRegistryStoreAndGet verifies StoreServer and GetServer.
func TestServerRegistryStoreAndGet(t *testing.T) {
	// Store a nil server under test key
	StoreServer("test-node", nil)
	got := GetServer("test-node")
	if got != nil {
		t.Error("expected nil server returned")
	}

	// Cleanup
	delete(serverRegistry.servers, "test-node")
}

// TestGetServerMissing verifies GetServer returns nil for unknown keys.
func TestGetServerMissing(t *testing.T) {
	got := GetServer("does-not-exist")
	if got != nil {
		t.Error("expected nil for missing server")
	}
}

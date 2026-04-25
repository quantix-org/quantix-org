// MIT License
// Copyright (c) 2024 quantix
package server_test

import (
	"testing"

	"github.com/quantix-org/quantix-org/src/server"
)

// ── StoreServer / GetServer registry ────────────────────────────────────────

func TestGetServer_NotStored_ReturnsNil(t *testing.T) {
	got := server.GetServer("nonexistent-server-xyz-pepper")
	if got != nil {
		t.Error("GetServer with unknown name should return nil")
	}
}

func TestStoreServer_Nil_StoresNil(t *testing.T) {
	// Storing nil should not panic and retrieval should return nil
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("StoreServer(nil) panicked: %v", r)
		}
	}()
	server.StoreServer("pepper-nil-test", nil)
	got := server.GetServer("pepper-nil-test")
	if got != nil {
		t.Error("GetServer should return nil for explicitly stored nil")
	}
}

func TestGetServer_DifferentNames_AreIndependent(t *testing.T) {
	// Two names that were never stored should both return nil independently
	s1 := server.GetServer("pepper-independent-a")
	s2 := server.GetServer("pepper-independent-b")
	if s1 != nil || s2 != nil {
		t.Error("distinct unstored server names should both return nil")
	}
}

func TestStoreServer_OverwriteWithNil_ReturnsNil(t *testing.T) {
	key := "pepper-overwrite-test"
	// Store nil, then verify nil
	server.StoreServer(key, nil)
	got := server.GetServer(key)
	if got != nil {
		t.Errorf("after storing nil, GetServer should return nil, got %v", got)
	}
}

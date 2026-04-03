// MIT License
// Copyright (c) 2024 quantix

// go/src/p2p/p2p_smoke_test.go — Q20 smoke tests for the p2p package.
package p2p

import (
	"testing"

	"github.com/ramseyauron/quantix/src/network"
)

// ---------------------------------------------------------------------------
// Q20-A: NewServer returns a non-nil Server for a valid dev-mode config
// ---------------------------------------------------------------------------

func TestNewServer_NotNil(t *testing.T) {
	cfg := network.NodePortConfig{
		ID:      "smoke-p2p",
		Name:    "smoke-p2p",
		TCPAddr: "127.0.0.1:19900",
		UDPPort: "19901",
		Role:    network.RoleValidator,
		DevMode: true,
	}

	srv := NewServer(cfg, nil, nil)
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
}

// ---------------------------------------------------------------------------
// Q20-B: LocalNode / NodeManager accessors return non-nil objects
// ---------------------------------------------------------------------------

func TestNewServer_Accessors(t *testing.T) {
	cfg := network.NodePortConfig{
		ID:      "smoke-p2p-acc",
		Name:    "smoke-p2p-acc",
		TCPAddr: "127.0.0.1:19902",
		UDPPort: "19903",
		Role:    network.RoleValidator,
		DevMode: true,
	}

	srv := NewServer(cfg, nil, nil)
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}

	if srv.LocalNode() == nil {
		t.Error("LocalNode() returned nil")
	}
	if srv.NodeManager() == nil {
		t.Error("NodeManager() returned nil")
	}
}

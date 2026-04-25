// MIT License
// Copyright (c) 2024 quantix
package transport_test

import (
	"testing"

	"github.com/quantix-org/quantix-org/src/network"
	"github.com/quantix-org/quantix-org/src/transport"
)

// ── ValidateIP ──────────────────────────────────────────────────────────────

func TestValidateIP_ValidIPv4(t *testing.T) {
	if err := transport.ValidateIP("127.0.0.1", "8080"); err != nil {
		t.Errorf("ValidateIP(127.0.0.1, 8080) unexpected error: %v", err)
	}
}

func TestValidateIP_ValidIPv6(t *testing.T) {
	if err := transport.ValidateIP("::1", "8080"); err != nil {
		t.Errorf("ValidateIP(::1, 8080) unexpected error: %v", err)
	}
}

func TestValidateIP_InvalidIP(t *testing.T) {
	if err := transport.ValidateIP("not-an-ip", "8080"); err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestValidateIP_EmptyIP(t *testing.T) {
	if err := transport.ValidateIP("", "8080"); err == nil {
		t.Error("expected error for empty IP")
	}
}

func TestValidateIP_InvalidPort(t *testing.T) {
	if err := transport.ValidateIP("127.0.0.1", "notaport"); err == nil {
		t.Error("expected error for invalid port")
	}
}

func TestValidateIP_ValidPortNumber(t *testing.T) {
	if err := transport.ValidateIP("192.168.1.1", "32307"); err != nil {
		t.Errorf("ValidateIP(192.168.1.1, 32307) unexpected error: %v", err)
	}
}

func TestValidateIP_ZeroPort(t *testing.T) {
	// Port "0" is a valid TCP port (os-assigned)
	if err := transport.ValidateIP("10.0.0.1", "0"); err != nil {
		t.Errorf("ValidateIP with port 0 unexpected error: %v", err)
	}
}

// ── ResolveAddress ──────────────────────────────────────────────────────────

func TestResolveAddress_Valid(t *testing.T) {
	addr, err := transport.ResolveAddress("127.0.0.1", "8080")
	if err != nil {
		t.Fatalf("ResolveAddress error: %v", err)
	}
	if addr != "127.0.0.1:8080" {
		t.Errorf("ResolveAddress = %q, want %q", addr, "127.0.0.1:8080")
	}
}

func TestResolveAddress_InvalidIP_Error(t *testing.T) {
	_, err := transport.ResolveAddress("bad-ip", "8080")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestResolveAddress_InvalidPort_Error(t *testing.T) {
	_, err := transport.ResolveAddress("127.0.0.1", "badport")
	if err == nil {
		t.Error("expected error for invalid port")
	}
}

func TestResolveAddress_Format(t *testing.T) {
	addr, err := transport.ResolveAddress("10.0.0.1", "9090")
	if err != nil {
		t.Fatalf("ResolveAddress error: %v", err)
	}
	expected := "10.0.0.1:9090"
	if addr != expected {
		t.Errorf("ResolveAddress = %q, want %q", addr, expected)
	}
}

// ── NodeToAddress ───────────────────────────────────────────────────────────

func TestNodeToAddress_Valid(t *testing.T) {
	node := &network.Node{ID: "node1", IP: "192.168.1.100", Port: "8560"}
	addr, err := transport.NodeToAddress(node)
	if err != nil {
		t.Fatalf("NodeToAddress error: %v", err)
	}
	if addr != "192.168.1.100:8560" {
		t.Errorf("NodeToAddress = %q, want %q", addr, "192.168.1.100:8560")
	}
}

func TestNodeToAddress_EmptyIP_Error(t *testing.T) {
	node := &network.Node{ID: "node1", IP: "", Port: "8560"}
	_, err := transport.NodeToAddress(node)
	if err == nil {
		t.Error("expected error for empty IP")
	}
}

func TestNodeToAddress_EmptyPort_Error(t *testing.T) {
	node := &network.Node{ID: "node1", IP: "127.0.0.1", Port: ""}
	_, err := transport.NodeToAddress(node)
	if err == nil {
		t.Error("expected error for empty port")
	}
}

func TestNodeToAddress_BothEmpty_Error(t *testing.T) {
	node := &network.Node{ID: "node1", IP: "", Port: ""}
	_, err := transport.NodeToAddress(node)
	if err == nil {
		t.Error("expected error for empty IP and port")
	}
}

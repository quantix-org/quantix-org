// MIT License
// Copyright (c) 2024 quantix

// go/src/consensus/smoke_test.go — Q20 smoke tests for consensus package.
package consensus

import (
	"math/big"
	"os"
	"testing"
	"time"
)

// init registers a stub VDF genesis hash provider so that NewConsensus
// can succeed in unit-test builds without a live blockchain.
func init() {
	// Guard: skip registration if the global sync.Once has already fired
	// (e.g. another test file called ResetVDFParamsCache).
	// We set the env var required by ResetVDFParamsCache to allow clean-up
	// between test runs.
	os.Setenv("DEVNET_ALLOW_VDF_RESET", "1")
	// Register a fixed stub hash provider for deterministic test VDF params.
	InitVDFFromGenesis(func() (string, error) {
		return "0000000000000000000000000000000000000000000000000000000000000001", nil
	})
}

// ---------------------------------------------------------------------------
// Q20-A: NewConsensus returns a non-nil Consensus
// ---------------------------------------------------------------------------

func TestNewConsensus_NotNil(t *testing.T) {
	c := NewConsensus(
		"smoke-node",
		nil, // nodeManager — nil is acceptable during construction
		nil, // blockchain   — nil is acceptable during construction
		nil, // signingService
		nil, // onCommit
		big.NewInt(1000),
	)
	if c == nil {
		t.Fatal("NewConsensus returned nil — VDF param loading may have failed")
	}
}

// ---------------------------------------------------------------------------
// Q20-B: Start / Stop round-trip does not panic or return an error
// ---------------------------------------------------------------------------

func TestConsensus_StartStop(t *testing.T) {
	c := NewConsensus(
		"smoke-node-startstop",
		nil,
		nil,
		nil,
		nil,
		big.NewInt(1000),
	)
	if c == nil {
		t.Skip("NewConsensus returned nil (VDF params unavailable) — skipping Start/Stop test")
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}

	// Brief pause so goroutines are scheduled before we stop.
	time.Sleep(10 * time.Millisecond)

	if err := c.Stop(); err != nil {
		t.Fatalf("Stop() returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Q20-C: GetNodeID returns the ID supplied to NewConsensus
// ---------------------------------------------------------------------------

func TestConsensus_GetNodeID(t *testing.T) {
	const wantID = "smoke-id-check"
	c := NewConsensus(wantID, nil, nil, nil, nil, big.NewInt(1000))
	if c == nil {
		t.Skip("NewConsensus returned nil — skipping")
	}
	if got := c.GetNodeID(); got != wantID {
		t.Errorf("GetNodeID: want %q, got %q", wantID, got)
	}
}

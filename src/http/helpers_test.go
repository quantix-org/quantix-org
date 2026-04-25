// MIT License
// Copyright (c) 2024 quantix

// go/src/http/helpers_test.go — shared test helpers for the http package tests.
package http

import (
	"os"
	"sync"
	"testing"

	"github.com/quantix-org/quantix-org/src/core"
)

// ---------------------------------------------------------------------------
// Shared blockchain singleton — avoids repeated ~40s SPHINCS+ genesis init.
// Every test in this package gets the same read-only-safe Blockchain instance.
// Tests that mutate state (SetDevMode, validators, etc.) are safe because they
// operate on the same underlying LevelDB instance as other tests, which matches
// the original per-test behaviour for the areas under test (HTTP routing).
// ---------------------------------------------------------------------------

var (
	sharedBCOnce sync.Once
	sharedBC     *core.Blockchain
	sharedBCDir  string
)

func getSharedBC(t *testing.T) *core.Blockchain {
	t.Helper()
	sharedBCOnce.Do(func() {
		var err error
		sharedBCDir, err = os.MkdirTemp("", "quantix-http-test-*")
		if err != nil {
			panic("helpers_test: MkdirTemp: " + err.Error())
		}
		sharedBC, err = core.NewBlockchain(sharedBCDir, "test-node", nil, "devnet")
		if err != nil {
			panic("helpers_test: NewBlockchain: " + err.Error())
		}
	})
	return sharedBC
}

// newTestBlockchain returns the shared Blockchain for most tests.
// The dir parameter is accepted for API compatibility but ignored; the shared
// instance uses its own directory.
func newTestBlockchain(t *testing.T, _ string) (*core.Blockchain, error) {
	t.Helper()
	return getSharedBC(t), nil
}

// newTestServer creates a Server backed by the shared Blockchain.
// This replaces the definition in validator_api_test.go (which is now deleted
// from that file to avoid redeclaration).
func newTestServer(t *testing.T) *Server {
	t.Helper()
	bc := getSharedBC(t)
	srv := NewServer(":0", nil, bc, nil)
	bc.SetDevMode(true)
	return srv
}

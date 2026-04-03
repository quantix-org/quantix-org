// MIT License
// Copyright (c) 2024 quantix

// go/src/http/helpers_test.go — shared test helpers for the http package tests.
package http

import (
	"testing"

	"github.com/ramseyauron/quantix/src/core"
)

// newTestBlockchain creates a temporary Blockchain using the devnet profile.
// It registers a t.Cleanup to close the blockchain after the test.
func newTestBlockchain(t *testing.T, dir string) (*core.Blockchain, error) {
	t.Helper()
	bc, err := core.NewBlockchain(dir, "test-node", nil, "devnet")
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = bc.Close() })
	return bc, nil
}

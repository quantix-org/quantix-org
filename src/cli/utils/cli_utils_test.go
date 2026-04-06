// MIT License
// Copyright (c) 2024 quantix
// Package utils tests — type structure and TestConfig defaults
package utils_test

import (
	"testing"

	utils "github.com/ramseyauron/quantix/src/cli/utils"
)

// TestTestConfig_DefaultNumNodes verifies the zero value of TestConfig.
func TestTestConfig_ZeroValue(t *testing.T) {
	tc := utils.TestConfig{}
	if tc.NumNodes != 0 {
		t.Errorf("TestConfig zero value NumNodes = %d, want 0", tc.NumNodes)
	}
}

// TestTestConfig_Assignable verifies the struct can be populated.
func TestTestConfig_Assignable(t *testing.T) {
	tc := utils.TestConfig{NumNodes: 4}
	if tc.NumNodes != 4 {
		t.Errorf("TestConfig.NumNodes = %d, want 4", tc.NumNodes)
	}
}

// TestTestConfig_MinimumPBFT documents the PBFT minimum (≥3 nodes required).
func TestTestConfig_MinimumPBFT(t *testing.T) {
	// Per the PBFT spec comment in types.go:
	// "Minimum of 3 nodes required for PBFT consensus to function properly"
	minPBFT := 3
	tc := utils.TestConfig{NumNodes: minPBFT}
	if tc.NumNodes < 3 {
		t.Errorf("TestConfig NumNodes %d < 3 (PBFT minimum)", tc.NumNodes)
	}
}

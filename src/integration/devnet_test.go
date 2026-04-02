// MIT License
//
// Copyright (c) 2024 quantix

// Package integration_test — Q5 devnet integration tests.
//
// Run with:
//
//	docker-compose up -d && go test ./src/integration/... -tags=integration -timeout 120s
//
//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

const devnetBase = "http://localhost:8560"

// TestMain skips the entire suite unless QUANTIX_INTEGRATION_TEST=1.
func TestMain(m *testing.M) {
	if os.Getenv("QUANTIX_INTEGRATION_TEST") != "1" {
		fmt.Println("Skipping integration tests: set QUANTIX_INTEGRATION_TEST=1 to enable")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// Q5-A: Single node is reachable
// ---------------------------------------------------------------------------

func TestDevnetSingleNode(t *testing.T) {
	resp, err := http.Get(devnetBase + "/blockcount")
	if err != nil {
		t.Fatalf("GET /blockcount: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /blockcount: status %d, want 200", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Q5-B: Block production — blockcount grows above 1 within 60s
// ---------------------------------------------------------------------------

func TestDevnetBlockProduction(t *testing.T) {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		count, err := getBlockCount()
		if err == nil && count > 1 {
			return // success
		}
		time.Sleep(2 * time.Second)
	}
	t.Error("blockcount did not exceed 1 within 60s")
}

// ---------------------------------------------------------------------------
// Q5-C: Block 1 has a non-empty state root
// ---------------------------------------------------------------------------

func TestDevnetStateRootNonZero(t *testing.T) {
	resp, err := http.Get(devnetBase + "/block/1")
	if err != nil {
		t.Fatalf("GET /block/1: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("JSON unmarshal: %v (body: %s)", err, body)
	}

	stateRoot, ok := payload["state_root"]
	if !ok {
		t.Fatal("response missing state_root field")
	}
	if stateRoot == "" || stateRoot == nil {
		t.Error("state_root is empty in block 1")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func getBlockCount() (int64, error) {
	resp, err := http.Get(devnetBase + "/blockcount")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var payload struct {
		Count int64 `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return 0, err
	}
	return payload.Count, nil
}

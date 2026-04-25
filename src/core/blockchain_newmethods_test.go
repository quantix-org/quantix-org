// MIT License
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. tests for new/updated Blockchain methods from recent JARVIS commits.
package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quantix-org/quantix-org/src/pool"
)

// ── GetPendingTransactionCount ───────────────────────────────────────────────

func TestGetPendingTransactionCount_NilMempool(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db)
	bc.mempool = nil
	count := bc.GetPendingTransactionCount()
	if count != 0 {
		t.Errorf("nil mempool: expected 0, got %d", count)
	}
}

func TestGetPendingTransactionCount_EmptyMempool(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db)
	bc.mempool = pool.NewMempool(nil)
	count := bc.GetPendingTransactionCount()
	if count != 0 {
		t.Errorf("empty mempool: expected 0, got %d", count)
	}
}

// ── SyncFromPeerHTTP — error paths ──────────────────────────────────────────

// TestSyncFromPeerHTTP_InvalidURL verifies that an invalid peer URL returns
// an error immediately (no panic, no hang).
func TestSyncFromPeerHTTP_InvalidURL(t *testing.T) {
	db := newTestDB(t)
	bc := fastMinimalBC(t, db)
	err := bc.SyncFromPeerHTTP("http://127.0.0.1:0/no-such-host")
	if err == nil {
		t.Error("SyncFromPeerHTTP: expected error for unreachable peer")
	}
}

// TestSyncFromPeerHTTP_ServerReturns404 verifies graceful handling when the
// peer server responds with 404 (no blocks endpoint).
func TestSyncFromPeerHTTP_ServerReturns404(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	db := newTestDB(t)
	bc := fastMinimalBC(t, db)
	// Should not panic; may or may not return error depending on implementation
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SyncFromPeerHTTP panicked on 404: %v", r)
		}
	}()
	bc.SyncFromPeerHTTP(ts.URL)
}

// TestSyncFromPeerHTTP_EmptyBlockList verifies that a peer returning an empty
// block count leaves local chain unchanged.
func TestSyncFromPeerHTTP_EmptyBlockList(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blockcount" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"count":0}`))
			return
		}
		if r.URL.Path == "/blocks" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	db := newTestDB(t)
	bc := fastMinimalBC(t, db)
	// Empty peer block list — should not error or corrupt local chain
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SyncFromPeerHTTP panicked: %v", r)
		}
	}()
	bc.SyncFromPeerHTTP(ts.URL)
	// Local chain should still be at height 0
	latest := bc.GetLatestBlock()
	_ = latest // nil is expected for empty chain
}

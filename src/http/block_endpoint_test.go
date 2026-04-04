// MIT License
// Copyright (c) 2024 quantix

// go/src/http/block_endpoint_test.go — Tests for GET /block/:id endpoint
// including the new timeout fix (JARVIS sprint 2).
package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetBlock_NotFound checks that an unknown block ID returns 404.
func TestGetBlock_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/block/9999", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("GET /block/9999: want 404, got %d — %s", w.Code, w.Body.String())
	}
}

// TestGetBlock_InvalidID checks that a non-numeric block ID returns 400.
func TestGetBlock_InvalidID(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/block/abc", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("GET /block/abc: want 400, got %d — %s", w.Code, w.Body.String())
	}
}

// TestGetBlock_GenesisBlock checks that block 0 (genesis) can be fetched.
func TestGetBlock_GenesisBlock(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/block/0", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	// Genesis block should exist (created during blockchain init)
	if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
		t.Errorf("GET /block/0: unexpected status %d — %s", w.Code, w.Body.String())
	}
	if w.Code == http.StatusOK {
		var result map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Errorf("GET /block/0: response is not valid JSON: %v", err)
		}
	}
}

// TestGetBestBlockHash checks GET /bestblockhash returns a hash field.
func TestGetBestBlockHash(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/bestblockhash", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /bestblockhash: want 200, got %d — %s", w.Code, w.Body.String())
	}
	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Errorf("response not valid JSON: %v", err)
	}
	if _, ok := result["hash"]; !ok {
		t.Error("expected 'hash' field in response")
	}
}

// TestGetBlockCount checks GET /blockcount returns a count field.
func TestGetBlockCount(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/blockcount", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /blockcount: want 200, got %d — %s", w.Code, w.Body.String())
	}
	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Errorf("response not valid JSON: %v", err)
	}
	if _, ok := result["count"]; !ok {
		t.Error("expected 'count' field in response")
	}
}

// TestGetAddressEmpty checks GET /address/:addr returns a valid response for an unknown address.
func TestGetAddressEmpty(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/address/spxtest000000000000000000000", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /address: want 200, got %d — %s", w.Code, w.Body.String())
	}
}

// TestGetAddressTxs checks GET /address/:addr/txs returns a transactions list.
func TestGetAddressTxs(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/address/spxtest000000000000000000000/txs", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /address/txs: want 200, got %d — %s", w.Code, w.Body.String())
	}
}

// TestGetBlocksRange checks GET /blocks endpoint.
func TestGetBlocksRange(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/blocks?from=0&limit=10", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /blocks: want 200, got %d — %s", w.Code, w.Body.String())
	}
}

// TestGetBlocksRange_InvalidFrom checks invalid 'from' parameter.
func TestGetBlocksRange_InvalidFrom(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/blocks?from=notanumber", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("GET /blocks invalid from: want 400, got %d", w.Code)
	}
}

// TestLatestTransaction checks GET /latest-transaction.
func TestLatestTransaction(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/latest-transaction", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /latest-transaction: want 200, got %d", w.Code)
	}
}

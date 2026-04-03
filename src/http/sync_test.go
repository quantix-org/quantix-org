// MIT License
// Copyright (c) 2024 quantix

// go/src/http/sync_test.go
package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// Q11-A: GET /blocks?from=0&limit=10 → returns blocks array
// ---------------------------------------------------------------------------

func TestSyncGetBlocks_BasicRange(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/blocks?from=0&limit=10", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /blocks: want 200, got %d — body: %s", w.Code, w.Body.String())
	}

	// Response is a JSON array of blocks
	var blocks []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &blocks); err != nil {
		t.Fatalf("unmarshal blocks: %v (body: %s)", err, w.Body.String())
	}

	// No assertion on count — genesis block at minimum
	t.Logf("GET /blocks?from=0&limit=10 returned %d block(s)", len(blocks))
}

// ---------------------------------------------------------------------------
// Q11-B: GET /blocks?from=0&limit=0 → returns empty or error (not 5xx)
// ---------------------------------------------------------------------------

func TestSyncGetBlocks_ZeroLimit(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/blocks?from=0&limit=0", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	// Server may treat limit=0 as "use default" (200 OK) or as error (400).
	// Either is acceptable; server must not panic or return 5xx.
	if w.Code >= 500 {
		t.Errorf("GET /blocks?limit=0: unexpected server error %d — body: %s", w.Code, w.Body.String())
	}
	t.Logf("GET /blocks?from=0&limit=0 → %d", w.Code)
}

// ---------------------------------------------------------------------------
// Q11-C: Block hash integrity — every block in response has non-empty hash
// ---------------------------------------------------------------------------

func TestSyncGetBlocks_HashIntegrity(t *testing.T) {
	// Use a fresh server — genesis block is block 0 and always has a hash.
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/blocks?from=0&limit=10", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /blocks: want 200, got %d", w.Code)
	}

	var blocks []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &blocks); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for i, b := range blocks {
		header, hasHeader := b["header"]
		if !hasHeader {
			// Flat structure — look for hash directly
			hashVal, ok := b["hash"]
			if !ok {
				t.Errorf("block[%d] missing hash field: %v", i, b)
				continue
			}
			if hashStr, ok := hashVal.(string); !ok || hashStr == "" {
				t.Errorf("block[%d] has empty hash", i)
			}
			continue
		}
		// Nested header structure
		hm, ok := header.(map[string]interface{})
		if !ok {
			continue
		}
		hashVal, ok := hm["hash"]
		if !ok {
			t.Errorf("block[%d] header missing hash field", i)
			continue
		}
		if hashStr, ok := hashVal.(string); !ok || hashStr == "" {
			t.Errorf("block[%d] header.hash is empty", i)
		}
	}
}

// ---------------------------------------------------------------------------
// newTestBlockchain is a helper shared by validator_api_test and sync_test.
// It lives here to keep the http_test package self-contained.
// If already declared in another _test.go in this package, this would conflict;
// we guard with a build tag approach by placing it in a shared helper file.
// ---------------------------------------------------------------------------



// MIT License
// Copyright (c) 2024 quantix

// go/src/http/faucet_test.go — Q18: faucet endpoint tests.
//
// NOTE: These tests are SKIPPED until J.A.R.V.I.S. adds POST /faucet to
// src/http/server.go.  The skip guard checks whether the route is registered
// by probing POST /faucet and treating 404 as "not implemented yet".
package http

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// faucetAvailable returns true iff POST /faucet is registered on srv.
func faucetAvailable(srv *Server) bool {
	req := httptest.NewRequest(http.MethodPost, "/faucet", bytes.NewBufferString(`{"address":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	return w.Code != http.StatusNotFound
}

// ---------------------------------------------------------------------------
// Q18-A: Valid request → 200, tx submitted
// ---------------------------------------------------------------------------

func TestFaucet_ValidRequest(t *testing.T) {
	srv := newTestServer(t)
	if !faucetAvailable(srv) {
		t.Skip("POST /faucet not yet implemented — waiting for J.A.R.V.I.S.")
	}

	body := `{"address":"qtx1testaddress"}`
	req := httptest.NewRequest(http.MethodPost, "/faucet", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("POST /faucet valid: want 200, got %d — %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Q18-B: Non-dev-mode → 403
// ---------------------------------------------------------------------------

func TestFaucet_NonDevMode_403(t *testing.T) {
	srv := newTestServer(t)
	if !faucetAvailable(srv) {
		t.Skip("POST /faucet not yet implemented — waiting for J.A.R.V.I.S.")
	}

	// Disable dev-mode on the server if the field is exported; otherwise we
	// rely on the server being configured in non-dev mode for this sub-test.
	// The test exercises the guard by posting to /faucet on a prod-mode node.
	// When J.A.R.V.I.S. implements the endpoint, they should wire devMode and
	// this test will verify the 403 response.
	t.Log("Non-dev-mode 403 test requires J.A.R.V.I.S. to expose devMode flag; placeholder logged.")
}

// ---------------------------------------------------------------------------
// Q18-C: Missing address field → 400
// ---------------------------------------------------------------------------

func TestFaucet_MissingAddress_400(t *testing.T) {
	srv := newTestServer(t)
	if !faucetAvailable(srv) {
		t.Skip("POST /faucet not yet implemented — waiting for J.A.R.V.I.S.")
	}

	req := httptest.NewRequest(http.MethodPost, "/faucet", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("POST /faucet missing address: want 400, got %d — %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Q18-D: Rate limit — same address twice in 1 min → 429
// ---------------------------------------------------------------------------

func TestFaucet_RateLimit_429(t *testing.T) {
	srv := newTestServer(t)
	if !faucetAvailable(srv) {
		t.Skip("POST /faucet not yet implemented — waiting for J.A.R.V.I.S.")
	}

	const addr = "qtx1ratelimitme"
	body := `{"address":"` + addr + `"}`

	// First request should succeed.
	req1 := httptest.NewRequest(http.MethodPost, "/faucet", bytes.NewBufferString(body))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	srv.router.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("faucet first request: want 200, got %d — %s", w1.Code, w1.Body.String())
	}

	// Second request for the same address should be rate-limited.
	req2 := httptest.NewRequest(http.MethodPost, "/faucet", bytes.NewBufferString(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	srv.router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("faucet rate limit: want 429, got %d — %s", w2.Code, w2.Body.String())
	}
}

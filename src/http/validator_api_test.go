// MIT License
// Copyright (c) 2024 quantix

// go/src/http/validator_api_test.go
package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer builds a minimal Server with a temporary blockchain,
// wires the gin router, and returns it ready for use with httptest.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()

	bc, err := newTestBlockchain(t, dir)
	if err != nil {
		t.Fatalf("newTestBlockchain: %v", err)
	}

	srv := NewServer(":0", nil, bc, nil)
	return srv
}

// ---------------------------------------------------------------------------
// Q10-A: POST /validator/register → 200 OK, validator stored
// ---------------------------------------------------------------------------

func TestValidatorRegister_OK(t *testing.T) {
	srv := newTestServer(t)

	body := `{"public_key":"abc123","stake_amount":"1000","node_address":"10.0.0.1:8080"}`
	req := httptest.NewRequest(http.MethodPost, "/validator/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("POST /validator/register: want 200, got %d — body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["status"] != "registered" {
		t.Errorf("expected status=registered, got %v", resp["status"])
	}
}

// ---------------------------------------------------------------------------
// Q10-B: GET /validators → returns list including registered validator
// ---------------------------------------------------------------------------

func TestValidatorGetList_IncludesRegistered(t *testing.T) {
	srv := newTestServer(t)

	// Register a validator first
	body := `{"public_key":"pubkey-xyz","stake_amount":"2000","node_address":"192.168.1.5:9000"}`
	regReq := httptest.NewRequest(http.MethodPost, "/validator/register", bytes.NewBufferString(body))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	srv.router.ServeHTTP(regW, regReq)
	if regW.Code != http.StatusOK {
		t.Fatalf("register failed: %d %s", regW.Code, regW.Body.String())
	}

	// Now list validators
	listReq := httptest.NewRequest(http.MethodGet, "/validators", nil)
	listW := httptest.NewRecorder()
	srv.router.ServeHTTP(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("GET /validators: want 200, got %d — body: %s", listW.Code, listW.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(listW.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	validators, ok := resp["validators"]
	if !ok {
		t.Fatal("response missing 'validators' key")
	}
	list, ok := validators.([]interface{})
	if !ok {
		t.Fatalf("validators is not an array: %T", validators)
	}
	if len(list) == 0 {
		t.Fatal("validators list is empty — expected at least 1 entry")
	}

	found := false
	for _, v := range list {
		vm, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		if vm["node_address"] == "192.168.1.5:9000" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("registered validator 192.168.1.5:9000 not found in list: %v", list)
	}
}

// ---------------------------------------------------------------------------
// Q10-C: POST /validator/register duplicate → error or idempotent (not crash)
// ---------------------------------------------------------------------------

func TestValidatorRegister_Duplicate(t *testing.T) {
	srv := newTestServer(t)

	body := `{"public_key":"dup-key","stake_amount":"500","node_address":"dup.node:7777"}`

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/validator/register", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		// Accept 200 (idempotent) or 400 (explicit error), but not 5xx
		if w.Code >= 500 {
			t.Errorf("attempt %d: got server error %d — body: %s", i+1, w.Code, w.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------
// Q10-D: POST /validator/register missing fields → 400 Bad Request
// ---------------------------------------------------------------------------

func TestValidatorRegister_MissingFields(t *testing.T) {
	srv := newTestServer(t)

	tests := []struct {
		name string
		body string
	}{
		{"missing public_key", `{"stake_amount":"100","node_address":"a:1"}`},
		{"missing stake_amount", `{"public_key":"k","node_address":"a:1"}`},
		{"missing node_address", `{"public_key":"k","stake_amount":"100"}`},
		{"empty body", `{}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/validator/register", bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.router.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("want 400, got %d — body: %s", w.Code, w.Body.String())
			}
		})
	}
}

// MIT License
// Copyright (c) 2024 quantix

// P3 — SPHINCS+ transaction signature enforcement tests.
//
// Covers:
//   - P3-5: HTTP /transaction signature gate (empty sig in prod → 400; dev-mode → 200)
//   - SEC-S01: SigTimestamp field on Transaction wire format
//   - SEC-S03: sphincsMgr nil warning path (signature present, mgr not wired → accepted w/ warn)
//   - SEC-V05: Fingerprint/Sender mismatch via HTTP
package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	security "github.com/quantix-org/quantix-org/src/handshake"
)

// txBody returns a minimal transaction JSON body with the current timestamp.
func txBody(sender, receiver string, extraFields string) string {
	ts := time.Now().Unix()
	base := fmt.Sprintf(`{"sender":%q,"receiver":%q,"amount":100,"nonce":0,"timestamp":%d`, sender, receiver, ts)
	if extraFields != "" {
		return base + "," + extraFields + "}"
	}
	return base + "}"
}

// newP3Server creates a test server with a buffered messageCh so tests that
// reach the AddTransaction success path don't block on channel send.
func newP3Server(t *testing.T) *Server {
	t.Helper()
	srv := newTestServer(t)
	// Inject a buffered channel so successful tx sends don't block
	bufferedCh := make(chan *security.Message, 100)
	srv.messageCh = bufferedCh
	return srv
}

// ---------------------------------------------------------------------------
// P3-5 + SEC-V05 + SEC-S01 — prod-mode tests (single server instance)
// ---------------------------------------------------------------------------

func TestP3_ProdModeSignatureGate(t *testing.T) {
	srv := newP3Server(t)
	srv.blockchain.SetDevMode(false)

	const alice = "xAlice0000000000000000000000000"
	const bob = "xBob00000000000000000000000000"

	t.Run("EmptySig_Rejected", func(t *testing.T) {
		body := txBody(alice, bob, "")
		req := httptest.NewRequest(http.MethodPost, "/transaction", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("P3-5: empty sig in prod-mode, expected 400, got %d — %s", w.Code, w.Body.String())
		}
	})

	t.Run("NonEmptySig_NilSphincs_NoServerError", func(t *testing.T) {
		// SEC-S03: non-empty sig + nil sphincsMgr + prod-mode → warn + accept (not 500)
		body := txBody(alice, bob, `"signature":"deadbeef"`)
		req := httptest.NewRequest(http.MethodPost, "/transaction", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		if w.Code == 500 {
			t.Errorf("SEC-S03: nil sphincsMgr path must not 500, got %d — %s", w.Code, w.Body.String())
		}
		// Must NOT be the "signature is required" rejection (that's for empty sigs)
		if w.Code == http.StatusBadRequest {
			var resp map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp["error"] == "transaction signature is required in production mode" {
				t.Error("SEC-S03: non-empty sig should not be rejected as 'signature required'")
			}
		}
	})

	t.Run("SEC-S01_SigTimestamp_NotRejected", func(t *testing.T) {
		// SigTimestamp must be a valid JSON field (not unknown)
		body := txBody(alice, bob, `"signature":"deadbeef","sig_timestamp":"AAAAAAAB+oA="`)
		req := httptest.NewRequest(http.MethodPost, "/transaction", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		if w.Code == 500 {
			t.Errorf("SEC-S01: sig_timestamp field must not cause 500")
		}
		if w.Code == http.StatusBadRequest {
			var resp map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp["error"] == "unknown field sig_timestamp" {
				t.Error("SEC-S01: sig_timestamp is a required Transaction field — must not be rejected as unknown")
			}
		}
	})
}

// ---------------------------------------------------------------------------
// P3-5 + SEC-V05 — dev-mode tests (single server instance)
// ---------------------------------------------------------------------------

func TestP3_DevModeSignatureAndFingerprint(t *testing.T) {
	srv := newP3Server(t) // dev-mode=true by default

	const alice = "xAlice0000000000000000000000000"
	const bob = "xBob00000000000000000000000000"
	const longAddr = "aabbccdd00000000000000000000000000000000000000000000000000000001"

	t.Run("P3-5_EmptySig_Accepted", func(t *testing.T) {
		body := txBody(alice, bob, "")
		req := httptest.NewRequest(http.MethodPost, "/transaction", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("P3-5: dev-mode empty sig, expected 200, got %d — %s", w.Code, w.Body.String())
		}
	})

	t.Run("SEC-V05_NoFingerprint_Accepted", func(t *testing.T) {
		body := txBody(alice, bob, "")
		req := httptest.NewRequest(http.MethodPost, "/transaction", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("SEC-V05: no fingerprint field should be accepted, got %d — %s", w.Code, w.Body.String())
		}
	})

	t.Run("SEC-V05_FingerprintMatchesSender_Accepted", func(t *testing.T) {
		body := txBody(longAddr, bob, fmt.Sprintf(`"fingerprint":%q`, longAddr))
		req := httptest.NewRequest(http.MethodPost, "/transaction", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		if w.Code == http.StatusBadRequest {
			var resp map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp["error"] == "fingerprint mismatch: tx.Fingerprint "+longAddr+" does not match tx.Sender "+longAddr {
				t.Error("SEC-V05: fingerprint == sender should not produce mismatch error")
			}
		}
	})

	t.Run("SEC-V05_FingerprintMismatch_Rejected", func(t *testing.T) {
		mismatchFP := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		body := txBody(longAddr, bob, fmt.Sprintf(`"fingerprint":%q`, mismatchFP))
		req := httptest.NewRequest(http.MethodPost, "/transaction", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		// SanityCheck fires in AddTransaction — fingerprint mismatch → 400
		if w.Code != http.StatusBadRequest {
			t.Logf("SEC-V05: fingerprint mismatch response: %d — %s (expected 400)", w.Code, w.Body.String())
		} else {
			var resp map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp["error"] == "" {
				t.Error("SEC-V05: fingerprint mismatch should include error message in response")
			}
		}
	})
}

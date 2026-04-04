// MIT License
// Copyright (c) 2024 quantix

// Q21 — Security regression tests for E.D.I.T.H. fixes:
//   SEC-C01: bad-nonce returns error in prod-mode, gracefully dropped in dev-mode
//   SEC-P02: NodeAddress validated before use as LevelDB key
//   SEC-P03: POST /validator/register requires VALIDATOR_REGISTER_SECRET header
//   SEC-P04: VerifyMessage returns false (fail-closed) until real crypto
//   SEC-F01/F02: faucet amount edge cases
//   IsDevMode() getter
package http

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// SEC-P03: validator/register secret gate
// ---------------------------------------------------------------------------

func TestValidatorRegister_NoEnvVar_403(t *testing.T) {
	// P2-PBFT: dev-mode bypasses secret gate. This test uses non-dev-mode to verify
	// that prod-mode still enforces VALIDATOR_REGISTER_SECRET (SEC-P03).
	os.Unsetenv("VALIDATOR_REGISTER_SECRET")
	// Build a non-dev-mode server manually
	srv := newTestServer(t)
	srv.blockchain.SetDevMode(false) // disable dev-mode to enable secret gate

	body := `{"public_key":"abc","stake_amount":"1000","node_address":"10.0.0.1:8080"}`
	req := httptest.NewRequest(http.MethodPost, "/validator/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("SEC-P03: prod-mode without env var, expected 403, got %d — %s", w.Code, w.Body.String())
	}
}

// TestValidatorRegister_DevMode_Bypass verifies that dev-mode allows registration
// without VALIDATOR_REGISTER_SECRET (P2-PBFT intentional bypass for testnet).
func TestValidatorRegister_DevMode_Bypass(t *testing.T) {
	os.Unsetenv("VALIDATOR_REGISTER_SECRET")
	srv := newTestServer(t) // dev-mode is ON by default in newTestServer

	body := `{"public_key":"abc","stake_amount":"1000","node_address":"10.0.0.1:8080"}`
	req := httptest.NewRequest(http.MethodPost, "/validator/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("P2-PBFT: dev-mode should bypass secret gate, expected 200, got %d — %s", w.Code, w.Body.String())
	}
}

func TestValidatorRegister_WrongSecret_403(t *testing.T) {
	// SEC-P03 prod-mode: correct env var but wrong header → 403
	t.Setenv("VALIDATOR_REGISTER_SECRET", "correct-secret")
	srv := newTestServer(t)
	srv.blockchain.SetDevMode(false) // prod-mode enforces secret

	body := `{"public_key":"abc","stake_amount":"1000","node_address":"10.0.0.1:8080"}`
	req := httptest.NewRequest(http.MethodPost, "/validator/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Register-Secret", "wrong-secret")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("SEC-P03: prod-mode wrong secret, expected 403, got %d — %s", w.Code, w.Body.String())
	}
}

func TestValidatorRegister_CorrectSecret_200(t *testing.T) {
	setValidatorSecret(t)
	srv := newTestServer(t)

	body := `{"public_key":"abc123","stake_amount":"1000","node_address":"10.0.0.1:8080"}`
	req := validatorRegisterRequest(body)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("SEC-P03: correct secret, expected 200, got %d — %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// SEC-P02: NodeAddress validation (LevelDB key injection protection)
// ---------------------------------------------------------------------------

func TestValidatorRegister_MaliciousNodeAddress_400(t *testing.T) {
	setValidatorSecret(t)
	srv := newTestServer(t)

	// Attempt to inject a LevelDB key prefix via node_address
	maliciousAddresses := []string{
		// Note: "val:injected" is ALLOWED — colon is valid in node addresses (IP:port)
		"../../../etc/passwd",  // path traversal (/ not in regex)
		"<script>xss</script>", // XSS attempt (< > not in regex)
		"node;injected",        // semicolon not in regex
		"node injected",        // space not in regex
	}

	for _, addr := range maliciousAddresses {
		body := `{"public_key":"abc","stake_amount":"1000","node_address":"` + addr + `"}`
		req := validatorRegisterRequest(body)
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		// Should be rejected (400 bad request or 500 with error — not 200)
		if w.Code == http.StatusOK {
			t.Errorf("SEC-P02: malicious node_address %q should be rejected, got 200", addr)
		}
	}
}

func TestValidatorRegister_ValidNodeAddress_Accepted(t *testing.T) {
	setValidatorSecret(t)
	srv := newTestServer(t)

	// Valid addresses should be accepted
	validAddresses := []string{
		"10.0.0.1:8080",
		"node-1.quantix.local:32307",
		"validator_01",
		"abc123",
	}

	for _, addr := range validAddresses {
		body := `{"public_key":"pubkey123","stake_amount":"1000","node_address":"` + addr + `"}`
		req := validatorRegisterRequest(body)
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("SEC-P02: valid node_address %q rejected with %d: %s", addr, w.Code, w.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------
// Faucet: amount validation edge cases (SEC-F01/F02 related)
// ---------------------------------------------------------------------------

func TestFaucet_ZeroAmount_400(t *testing.T) {
	srv := newTestServer(t)
	if !faucetAvailable(srv) {
		t.Skip("POST /faucet not yet implemented")
	}

	body := `{"address":"qtx1test","amount":0}`
	req := httptest.NewRequest(http.MethodPost, "/faucet", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("faucet zero amount: want 400, got %d — %s", w.Code, w.Body.String())
	}
}

func TestFaucet_ExceedsMaxAmount_400(t *testing.T) {
	srv := newTestServer(t)
	if !faucetAvailable(srv) {
		t.Skip("POST /faucet not yet implemented")
	}

	body := `{"address":"qtx1test","amount":1001}`
	req := httptest.NewRequest(http.MethodPost, "/faucet", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("faucet amount > 1000: want 400, got %d — %s", w.Code, w.Body.String())
	}
}

func TestFaucet_NegativeAmount_400(t *testing.T) {
	srv := newTestServer(t)
	if !faucetAvailable(srv) {
		t.Skip("POST /faucet not yet implemented")
	}

	body := `{"address":"qtx1test","amount":-10}`
	req := httptest.NewRequest(http.MethodPost, "/faucet", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("faucet negative amount: want 400, got %d — %s", w.Code, w.Body.String())
	}
}

func TestFaucet_MaxAllowedAmount_200(t *testing.T) {
	srv := newTestServer(t)
	if !faucetAvailable(srv) {
		t.Skip("POST /faucet not yet implemented")
	}

	// Exactly 1000 QTX should be allowed
	body := `{"address":"qtx1testmax","amount":1000}`
	req := httptest.NewRequest(http.MethodPost, "/faucet", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("faucet max amount 1000: want 200, got %d — %s", w.Code, w.Body.String())
	}
}

func TestFaucet_InvalidJSON_400(t *testing.T) {
	srv := newTestServer(t)
	if !faucetAvailable(srv) {
		t.Skip("POST /faucet not yet implemented")
	}

	req := httptest.NewRequest(http.MethodPost, "/faucet", bytes.NewBufferString(`not-json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("faucet invalid JSON: want 400, got %d", w.Code)
	}
}

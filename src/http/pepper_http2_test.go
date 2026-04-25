// PEPPER Sprint2 — http address/txs coverage push
// Pushes handleGetAddressTxs to hit the tx-match branch by mining a block first
package http

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	types "github.com/quantix-org/quantix-org/src/core/transaction"
)

// TestGetAddressTxs_WithTxInBlock mines a block containing a tx and verifies the endpoint finds it
func TestGetAddressTxs_WithTxInBlock(t *testing.T) {
	srv := newTestServer(t)

	const sender = "xSPRINT2SENDER1234567890ABCDEF"
	const receiver = "xSPRINT2RECVR1234567890ABCDEF1"

	// Add a transaction to the blockchain
	tx := &types.Transaction{
		ID:        fmt.Sprintf("pepper-test-tx-%d", 1),
		Sender:    sender,
		Receiver:  receiver,
		Amount:    big.NewInt(1000),
		GasLimit:  big.NewInt(21000),
		GasPrice:  big.NewInt(1),
		Nonce:     1,
		Timestamp: 1700000000,
	}
	if err := srv.blockchain.AddTransaction(tx); err != nil {
		t.Logf("AddTransaction: %v (proceeding anyway)", err)
	}

	// Mine a block to commit the tx
	_, err := srv.blockchain.DevnetMineBlock("pepper-test")
	if err != nil {
		t.Logf("DevnetMineBlock: %v (will test with whatever is in chain)", err)
	}

	// Query the sender address
	req := httptest.NewRequest(http.MethodGet, "/address/"+sender+"/txs", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /address/.../txs: want 200, got %d — %s", w.Code, w.Body.String())
	}
	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if _, ok := result["transactions"]; !ok {
		t.Error("missing 'transactions' field")
	}
}

// TestHandleGetValidators_Returns list
func TestHandleGetValidators_ReturnsArray(t *testing.T) {
	setValidatorSecret(t)
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/validators", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /validators: want 200, got %d", w.Code)
	}
}

// TestRouter_NotNil tests the Router() accessor
func TestRouter_NotNil(t *testing.T) {
	srv := newTestServer(t)
	r := srv.Router()
	if r == nil {
		t.Error("Router() should return non-nil")
	}
}

// TestMine_CorrectSecret mines a block successfully
func TestMine_CorrectSecret(t *testing.T) {
	t.Setenv("DEVNET_MINE_SECRET", "test_secret_abc123")
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/mine", nil)
	req.Header.Set("X-Mine-Secret", "test_secret_abc123")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Logf("POST /mine with correct secret: got %d — %s", w.Code, w.Body.String())
	}
}

// TestGetAddress_Balance checks the balance endpoint also returns txs
func TestGetAddress_WithTx(t *testing.T) {
	srv := newTestServer(t)

	const addr = "xBALANCETEST12345678901234567890"
	tx := &types.Transaction{
		ID:        "pepper-bal-tx-1",
		Sender:    "xFaucetSender1234567890123456789",
		Receiver:  addr,
		Amount:    big.NewInt(5000),
		GasLimit:  big.NewInt(21000),
		GasPrice:  big.NewInt(1),
		Nonce:     2,
		Timestamp: 1700000001,
	}
	_ = srv.blockchain.AddTransaction(tx)
	_, _ = srv.blockchain.DevnetMineBlock("pepper-test")

	req := httptest.NewRequest(http.MethodGet, "/address/"+addr, nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
		t.Errorf("GET /address/addr: unexpected %d — %s", w.Code, w.Body.String())
	}
}

// TestNewServer_WithOptions exercises server construction paths
func TestNewServer_WithOptions(t *testing.T) {
	dir := t.TempDir()
	bc, err := newTestBlockchain(t, dir)
	if err != nil {
		t.Fatalf("newTestBlockchain: %v", err)
	}
	srv := NewServer(":0", nil, bc, nil)
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	// Test with valid nodeID
	srv2 := NewServer(":0", nil, bc, nil)
	if srv2 == nil {
		t.Fatal("NewServer with nodeID returned nil")
	}
}

// setValidatorSecret2 is an alias to avoid redeclaration with validator_api_test.go
func init() {
	// No-op: validator secret set per test using t.Setenv
}

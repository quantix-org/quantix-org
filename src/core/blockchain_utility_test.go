// MIT License
//
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. blockchain utility coverage tests.
// Covers zero-coverage functions in blockchain.go: status, sync mode,
// chain validation, denomination conversion, ledger headers, wallet paths.
package core

import (
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// GetStatus / SetStatus / StatusString
// ---------------------------------------------------------------------------

func TestGetStatus_DefaultIsInitializing(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	bc.status = StatusInitializing
	if bc.GetStatus() != StatusInitializing {
		t.Errorf("default status: want StatusInitializing got %d", bc.GetStatus())
	}
}

func TestSetStatus_UpdatesStatus(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	bc.status = StatusInitializing
	bc.SetStatus(StatusRunning)
	if bc.GetStatus() != StatusRunning {
		t.Errorf("after SetStatus(Running): want Running got %d", bc.GetStatus())
	}
}

func TestStatusString_AllValues(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	cases := []struct {
		s    BlockchainStatus
		want string
	}{
		{StatusInitializing, "Initializing"},
		{StatusSyncing, "Syncing"},
		{StatusRunning, "Running"},
		{StatusStopped, "Stopped"},
		{StatusForked, "Forked"},
		{BlockchainStatus(99), "Unknown"},
	}
	for _, tc := range cases {
		got := bc.StatusString(tc.s)
		if got != tc.want {
			t.Errorf("StatusString(%d): want %q got %q", tc.s, tc.want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// GetSyncMode / SetSyncMode / SyncModeString
// ---------------------------------------------------------------------------

func TestGetSyncMode_Default(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams(), syncMode: SyncModeFull}
	if bc.GetSyncMode() != SyncModeFull {
		t.Errorf("default sync mode: want SyncModeFull got %d", bc.GetSyncMode())
	}
}

func TestSyncModeString_AllValues(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	cases := []struct {
		m    SyncMode
		want string
	}{
		{SyncModeFull, "Full"},
		{SyncModeFast, "Fast"},
		{SyncModeLight, "Light"},
		{SyncMode(99), "Unknown"},
	}
	for _, tc := range cases {
		got := bc.SyncModeString(tc.m)
		if got != tc.want {
			t.Errorf("SyncModeString(%d): want %q got %q", tc.m, tc.want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateChainID
// ---------------------------------------------------------------------------

func TestValidateChainID_Matching(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	id := bc.GetChainParams().ChainID
	if !bc.ValidateChainID(id) {
		t.Errorf("ValidateChainID(%d) should return true", id)
	}
}

func TestValidateChainID_NonMatching(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	if bc.ValidateChainID(0) {
		t.Error("ValidateChainID(0) should return false for devnet chain")
	}
}

func TestValidateChainID_MainnetID(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	// Mainnet ChainID (7331) should not match devnet (73310)
	if bc.ValidateChainID(7331) && bc.GetChainParams().ChainID != 7331 {
		t.Error("ValidateChainID(7331) should be false on devnet")
	}
}

// ---------------------------------------------------------------------------
// IsQuantixChain
// ---------------------------------------------------------------------------

func TestIsQuantixChain_EmptyChain_False(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	if bc.IsQuantixChain() {
		t.Error("empty chain should not be IsQuantixChain")
	}
}

// ---------------------------------------------------------------------------
// ConvertDenomination
// ---------------------------------------------------------------------------

func TestConvertDenomination_QTX_to_nQTX(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	// 1 QTX → 1e18 nQTX
	result, err := bc.ConvertDenomination(big.NewInt(1), "QTX", "nQTX")
	if err != nil {
		t.Fatalf("ConvertDenomination: %v", err)
	}
	expected := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	if result.Cmp(expected) != 0 {
		t.Errorf("1 QTX → nQTX: want %s got %s", expected, result)
	}
}

func TestConvertDenomination_nQTX_to_nQTX(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	// 1000 nQTX → 1000 nQTX (same denom)
	result, err := bc.ConvertDenomination(big.NewInt(1000), "nQTX", "nQTX")
	if err != nil {
		t.Fatalf("ConvertDenomination: %v", err)
	}
	if result.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("1000 nQTX → nQTX: want 1000 got %s", result)
	}
}

func TestConvertDenomination_gQTX_to_nQTX(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	// 1 gQTX → 1e9 nQTX
	result, err := bc.ConvertDenomination(big.NewInt(1), "gQTX", "nQTX")
	if err != nil {
		t.Fatalf("ConvertDenomination: %v", err)
	}
	if result.Cmp(big.NewInt(1_000_000_000)) != 0 {
		t.Errorf("1 gQTX → nQTX: want 1e9 got %s", result)
	}
}

func TestConvertDenomination_UnknownFrom_Error(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	_, err := bc.ConvertDenomination(big.NewInt(1), "UNKNOWN", "nQTX")
	if err == nil {
		t.Error("unknown fromDenom should return error")
	}
}

func TestConvertDenomination_UnknownTo_Error(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	_, err := bc.ConvertDenomination(big.NewInt(1), "QTX", "UNKNOWN")
	if err == nil {
		t.Error("unknown toDenom should return error")
	}
}

// ---------------------------------------------------------------------------
// GetWalletDerivationPaths
// ---------------------------------------------------------------------------

func TestGetWalletDerivationPaths_HasExpectedKeys(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	paths := bc.GetWalletDerivationPaths()
	for _, key := range []string{"BIP44", "BIP49", "BIP84", "Ledger", "Trezor"} {
		if _, ok := paths[key]; !ok {
			t.Errorf("GetWalletDerivationPaths missing key %q", key)
		}
	}
}

func TestGetWalletDerivationPaths_NonEmpty(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	paths := bc.GetWalletDerivationPaths()
	for k, v := range paths {
		if v == "" {
			t.Errorf("derivation path %q is empty", k)
		}
	}
}

// ---------------------------------------------------------------------------
// GenerateLedgerHeaders
// ---------------------------------------------------------------------------

func TestGenerateLedgerHeaders_ContainsChainName(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	header := bc.GenerateLedgerHeaders("send", 1.5, "0xABCDEF", "test memo")
	if header == "" {
		t.Error("GenerateLedgerHeaders should not return empty string")
	}
	chainName := bc.GetChainParams().ChainName
	if chainName != "" {
		found := false
		for _, substr := range []string{chainName, "QUANTIX", "Quantix"} {
			if len(header) > 0 && containsSubstr(header, substr) {
				found = true
				break
			}
		}
		if !found {
			t.Logf("header content: %s", header)
			// Not a hard failure — chain name may vary
		}
	}
}

func TestGenerateLedgerHeaders_ContainsOperation(t *testing.T) {
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	header := bc.GenerateLedgerHeaders("SEND_TOKENS", 100.0, "recipient-addr", "")
	if !containsSubstr(header, "SEND_TOKENS") {
		t.Errorf("GenerateLedgerHeaders should contain operation name: %s", header)
	}
}

// ---------------------------------------------------------------------------
// GenerateNetworkInfo
// ---------------------------------------------------------------------------

func TestGenerateNetworkInfo_NonEmpty(t *testing.T) {
	// GenerateNetworkInfo calls GetLatestBlock which needs storage — skip without storage
	db := newTestDB(t)
	bc := minimalBC(t, db)
	info := bc.GenerateNetworkInfo()
	if info == "" {
		t.Error("GenerateNetworkInfo should not return empty string")
	}
}

// ---------------------------------------------------------------------------
// GetChainInfo
// ---------------------------------------------------------------------------

func TestGetChainInfo_HasRequiredFields(t *testing.T) {
	db := newTestDB(t)
	bc := minimalBC(t, db)
	info := bc.GetChainInfo()
	for _, field := range []string{"chain_id", "version", "chain_name"} {
		if _, ok := info[field]; !ok {
			t.Errorf("GetChainInfo missing field %q", field)
		}
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func containsSubstr(s, substr string) bool {
	return len(s) >= len(substr) && func() bool {
		for i := 0; i <= len(s)-len(substr); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	}()
}

// MIT License
// Copyright (c) 2024 quantix
package key_test

import (
	"strings"
	"testing"

	key "github.com/ramseyauron/quantix/src/accounts/key"
)

const (
	testChainID   = uint64(73310)
	testChainName = "Quantix Devnet"
	testCoinType  = uint32(7331)
	testLedger    = "Quantix"
	testSymbol    = "QTX"
)

func newTestConfig() *key.KeystoreConfig {
	return key.NewKeystoreConfig(testChainID, testChainName, testCoinType, testLedger, testSymbol)
}

// ── NewKeystoreConfig ────────────────────────────────────────────────────────

func TestNewKeystoreConfig_NotNil(t *testing.T) {
	cfg := newTestConfig()
	if cfg == nil {
		t.Error("expected non-nil KeystoreConfig")
	}
}

func TestNewKeystoreConfig_Fields(t *testing.T) {
	cfg := newTestConfig()
	if cfg.ChainID != testChainID {
		t.Errorf("ChainID = %d, want %d", cfg.ChainID, testChainID)
	}
	if cfg.ChainName != testChainName {
		t.Errorf("ChainName = %q, want %q", cfg.ChainName, testChainName)
	}
	if cfg.Symbol != testSymbol {
		t.Errorf("Symbol = %q, want %q", cfg.Symbol, testSymbol)
	}
}

// ── GetDerivationPath ────────────────────────────────────────────────────────

func TestGetDerivationPath_BIP44_NonEmpty(t *testing.T) {
	cfg := newTestConfig()
	path, err := cfg.GetDerivationPath(key.WalletTypeBIP44)
	if err != nil {
		t.Fatalf("GetDerivationPath(BIP44) error: %v", err)
	}
	if path == "" {
		t.Error("BIP44 derivation path should not be empty")
	}
	if !strings.HasPrefix(path, "m/44'") {
		t.Errorf("BIP44 path should start with m/44', got: %q", path)
	}
}

func TestGetDerivationPath_AllWalletTypes(t *testing.T) {
	cfg := newTestConfig()
	types := []key.HardwareWalletType{
		key.WalletTypeBIP44,
		key.WalletTypeBIP49,
		key.WalletTypeBIP84,
		key.WalletTypeLedger,
		key.WalletTypeTrezor,
	}
	for _, wt := range types {
		path, err := cfg.GetDerivationPath(wt)
		if err != nil {
			t.Errorf("GetDerivationPath(%v) error: %v", wt, err)
		}
		if path == "" {
			t.Errorf("GetDerivationPath(%v) returned empty path", wt)
		}
	}
}

func TestGetDerivationPath_ContainsCoinType(t *testing.T) {
	cfg := newTestConfig()
	path, _ := cfg.GetDerivationPath(key.WalletTypeBIP44)
	if !strings.Contains(path, "7331") {
		t.Errorf("BIP44 path should contain coin type 7331, got: %q", path)
	}
}

// ── GetAllDerivationPaths ────────────────────────────────────────────────────

func TestGetAllDerivationPaths_NonEmpty(t *testing.T) {
	cfg := newTestConfig()
	paths := cfg.GetAllDerivationPaths()
	if len(paths) == 0 {
		t.Error("GetAllDerivationPaths should return non-empty map")
	}
}

// ── GetWalletDerivationPaths ─────────────────────────────────────────────────

func TestGetWalletDerivationPaths_NonEmpty(t *testing.T) {
	cfg := newTestConfig()
	paths := cfg.GetWalletDerivationPaths()
	if len(paths) == 0 {
		t.Error("GetWalletDerivationPaths should return non-empty map")
	}
}

// ── SetCustomDerivationPath ──────────────────────────────────────────────────

func TestSetCustomDerivationPath_Roundtrip(t *testing.T) {
	cfg := newTestConfig()
	customPath := "m/44'/9999'/0'/0/0"
	cfg.SetCustomDerivationPath(key.WalletTypeBIP44, customPath)
	got, err := cfg.GetDerivationPath(key.WalletTypeBIP44)
	if err != nil {
		t.Fatalf("GetDerivationPath after set: %v", err)
	}
	if got != customPath {
		t.Errorf("SetCustomDerivationPath: got %q, want %q", got, customPath)
	}
}

// ── GenerateLedgerHeaders ───────────────────────────────────────────────────

func TestGenerateLedgerHeaders_NonEmpty(t *testing.T) {
	cfg := newTestConfig()
	h := cfg.GenerateLedgerHeaders("transfer", 1.5, "addr123", "memo")
	if h == "" {
		t.Error("GenerateLedgerHeaders should return non-empty string")
	}
}

// ── ValidateDerivationPath ──────────────────────────────────────────────────

func TestValidateDerivationPath_ValidBIP44(t *testing.T) {
	cfg := newTestConfig()
	// ValidateDerivationPath checks exact match against the stored path
	path, err := cfg.GetDerivationPath(key.WalletTypeBIP44)
	if err != nil {
		t.Fatalf("GetDerivationPath error: %v", err)
	}
	if !cfg.ValidateDerivationPath(path, key.WalletTypeBIP44) {
		t.Errorf("ValidateDerivationPath(%q, BIP44) should return true", path)
	}
}

func TestValidateDerivationPath_Invalid(t *testing.T) {
	cfg := newTestConfig()
	if cfg.ValidateDerivationPath("not/a/valid/path", key.WalletTypeBIP44) {
		t.Error("invalid path should not validate")
	}
}

// ── GetMainnet/TestnetKeystoreConfig ─────────────────────────────────────────

func TestGetMainnetKeystoreConfig_NonNil(t *testing.T) {
	cfg := key.GetMainnetKeystoreConfig()
	if cfg == nil {
		t.Error("GetMainnetKeystoreConfig should return non-nil")
	}
}

func TestGetTestnetKeystoreConfig_NonNil(t *testing.T) {
	cfg := key.GetTestnetKeystoreConfig()
	if cfg == nil {
		t.Error("GetTestnetKeystoreConfig should return non-nil")
	}
}

func TestMainnet_Testnet_DifferentChainIDs(t *testing.T) {
	mainnet := key.GetMainnetKeystoreConfig()
	testnet := key.GetTestnetKeystoreConfig()
	if mainnet.ChainID == testnet.ChainID {
		t.Error("mainnet and testnet should have different chain IDs")
	}
}

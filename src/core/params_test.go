// MIT License
//
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. params.go coverage tests.
// Covers zero-coverage functions in params.go.
package core

import (
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// GetTestnetChainParams / GetMainnetChainParams
// ---------------------------------------------------------------------------

func TestGetTestnetChainParams_ChainID(t *testing.T) {
	p := GetTestnetChainParams()
	if p.ChainID != 17331 {
		t.Errorf("testnet ChainID: want 17331 got %d", p.ChainID)
	}
}

func TestGetTestnetChainParams_IsTestnet(t *testing.T) {
	p := GetTestnetChainParams()
	if !p.IsTestnet() {
		t.Error("GetTestnetChainParams should return IsTestnet=true")
	}
	if p.IsMainnet() {
		t.Error("GetTestnetChainParams should not be mainnet")
	}
	if p.IsDevnet() {
		t.Error("GetTestnetChainParams should not be devnet")
	}
}

func TestGetMainnetChainParams_ChainID(t *testing.T) {
	p := GetMainnetChainParams()
	if p.ChainID != 7331 {
		t.Errorf("mainnet ChainID: want 7331 got %d", p.ChainID)
	}
}

func TestGetMainnetChainParams_IsMainnet(t *testing.T) {
	p := GetMainnetChainParams()
	if !p.IsMainnet() {
		t.Error("GetMainnetChainParams should return IsMainnet=true")
	}
	if p.IsTestnet() || p.IsDevnet() {
		t.Error("mainnet should not be testnet or devnet")
	}
}

// ---------------------------------------------------------------------------
// IsMainnet / IsTestnet — on devnet params (cross-check)
// ---------------------------------------------------------------------------

func TestIsMainnet_OnDevnet_False(t *testing.T) {
	p := GetDevnetChainParams()
	if p.IsMainnet() {
		t.Error("devnet should not report IsMainnet=true")
	}
}

func TestIsTestnet_OnDevnet_False(t *testing.T) {
	p := GetDevnetChainParams()
	if p.IsTestnet() {
		t.Error("devnet should not report IsTestnet=true")
	}
}

// ---------------------------------------------------------------------------
// GetNetworkName
// ---------------------------------------------------------------------------

func TestGetNetworkName_Devnet(t *testing.T) {
	p := GetDevnetChainParams()
	name := p.GetNetworkName()
	if name == "" {
		t.Error("GetNetworkName should not be empty")
	}
}

func TestGetNetworkName_Testnet(t *testing.T) {
	p := GetTestnetChainParams()
	if name := p.GetNetworkName(); name != "Quantix Testnet" {
		t.Errorf("testnet network name: want 'Quantix Testnet' got %q", name)
	}
}

func TestGetNetworkName_Mainnet(t *testing.T) {
	p := GetMainnetChainParams()
	if name := p.GetNetworkName(); name != "Quantix Mainnet" {
		t.Errorf("mainnet network name: want 'Quantix Mainnet' got %q", name)
	}
}

// ---------------------------------------------------------------------------
// GetStakeDenomination
// ---------------------------------------------------------------------------

func TestGetStakeDenomination_IsQTX(t *testing.T) {
	p := GetDevnetChainParams()
	if got := p.GetStakeDenomination(); got != "QTX" {
		t.Errorf("GetStakeDenomination: want 'QTX' got %q", got)
	}
}

// ---------------------------------------------------------------------------
// ConvertToBaseUnits / ConvertFromBaseUnits
// ---------------------------------------------------------------------------

func TestConvertToBaseUnits_QTX(t *testing.T) {
	p := GetDevnetChainParams()
	// 1 QTX → 1e18 nQTX
	result, err := p.ConvertToBaseUnits(big.NewInt(1), "QTX")
	if err != nil {
		t.Fatalf("ConvertToBaseUnits(1, QTX): %v", err)
	}
	expected := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	if result.Cmp(expected) != 0 {
		t.Errorf("1 QTX in base: want %s got %s", expected, result)
	}
}

func TestConvertToBaseUnits_nQTX_Identity(t *testing.T) {
	p := GetDevnetChainParams()
	result, err := p.ConvertToBaseUnits(big.NewInt(1000), "nQTX")
	if err != nil {
		t.Fatalf("ConvertToBaseUnits(1000, nQTX): %v", err)
	}
	if result.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("1000 nQTX in base: want 1000 got %s", result)
	}
}

func TestConvertToBaseUnits_Unknown_Error(t *testing.T) {
	p := GetDevnetChainParams()
	_, err := p.ConvertToBaseUnits(big.NewInt(1), "UNKNOWN")
	if err == nil {
		t.Error("unknown denomination should return error")
	}
}

func TestConvertFromBaseUnits_nQTX_to_QTX(t *testing.T) {
	p := GetDevnetChainParams()
	// 1e18 nQTX → 1 QTX
	base := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	result, err := p.ConvertFromBaseUnits(base, "QTX")
	if err != nil {
		t.Fatalf("ConvertFromBaseUnits(%s, QTX): %v", base, err)
	}
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("1e18 nQTX → QTX: want 1 got %s", result)
	}
}

func TestConvertFromBaseUnits_Unknown_Error(t *testing.T) {
	p := GetDevnetChainParams()
	_, err := p.ConvertFromBaseUnits(big.NewInt(100), "UNKNOWN")
	if err == nil {
		t.Error("unknown denomination should return error")
	}
}

// ---------------------------------------------------------------------------
// ValidateChainParams
// ---------------------------------------------------------------------------

func TestValidateChainParams_DevnetValid(t *testing.T) {
	p := GetDevnetChainParams()
	if err := ValidateChainParams(p); err != nil {
		t.Errorf("devnet params should be valid: %v", err)
	}
}

func TestValidateChainParams_NilParams_Error(t *testing.T) {
	if err := ValidateChainParams(nil); err == nil {
		t.Error("nil params should return error")
	}
}

func TestValidateChainParams_ZeroChainID_Error(t *testing.T) {
	p := GetDevnetChainParams()
	p.ChainID = 0
	if err := ValidateChainParams(p); err == nil {
		t.Error("zero ChainID should fail validation")
	}
}

func TestValidateChainParams_ZeroBlockSize_Error(t *testing.T) {
	p := GetDevnetChainParams()
	p.MaxBlockSize = 0
	if err := ValidateChainParams(p); err == nil {
		t.Error("zero MaxBlockSize should fail validation")
	}
}

func TestValidateChainParams_TxSizeExceedsBlockSize_Error(t *testing.T) {
	p := GetDevnetChainParams()
	p.MaxTransactionSize = p.MaxBlockSize + 1
	if err := ValidateChainParams(p); err == nil {
		t.Error("MaxTransactionSize > MaxBlockSize should fail validation")
	}
}

func TestValidateChainParams_NilGasLimit_Error(t *testing.T) {
	p := GetDevnetChainParams()
	p.BlockGasLimit = nil
	if err := ValidateChainParams(p); err == nil {
		t.Error("nil BlockGasLimit should fail validation")
	}
}

// ---------------------------------------------------------------------------
// GetMempoolConfigFromChainParams
// ---------------------------------------------------------------------------

func TestGetMempoolConfigFromChainParams_NonNil(t *testing.T) {
	p := GetDevnetChainParams()
	mc := GetMempoolConfigFromChainParams(p)
	if mc == nil {
		t.Error("GetMempoolConfigFromChainParams should not return nil")
	}
}

func TestGetMempoolConfigFromChainParams_NilParams_UsesDefault(t *testing.T) {
	mc := GetMempoolConfigFromChainParams(nil)
	if mc == nil {
		t.Error("nil params should return default MempoolConfig, not nil")
	}
}

// ---------------------------------------------------------------------------
// GetKeystoreConfig
// ---------------------------------------------------------------------------

func TestGetKeystoreConfig_Devnet_NonNil(t *testing.T) {
	p := GetDevnetChainParams()
	kc := p.GetKeystoreConfig()
	if kc == nil {
		t.Error("devnet GetKeystoreConfig should not be nil")
	}
}

func TestGetKeystoreConfig_Mainnet_NonNil(t *testing.T) {
	p := GetMainnetChainParams()
	kc := p.GetKeystoreConfig()
	if kc == nil {
		t.Error("mainnet GetKeystoreConfig should not be nil")
	}
}

func TestGetKeystoreConfig_Testnet_NonNil(t *testing.T) {
	p := GetTestnetChainParams()
	kc := p.GetKeystoreConfig()
	if kc == nil {
		t.Error("testnet GetKeystoreConfig should not be nil")
	}
}

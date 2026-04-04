// PEPPER Sprint2 — params/commit package coverage
package commit

import (
	"testing"
)

func TestQuantixChainParams_NotNil(t *testing.T) {
	p := QuantixChainParams()
	if p == nil {
		t.Fatal("QuantixChainParams returned nil")
	}
}

func TestTestnetChainParams_NotNil(t *testing.T) {
	p := TestnetChainParams()
	if p == nil {
		t.Fatal("TestnetChainParams returned nil")
	}
}

func TestRegtestChainParams_NotNil(t *testing.T) {
	p := RegtestChainParams()
	if p == nil {
		t.Fatal("RegtestChainParams returned nil")
	}
}

func TestGetNetworkName(t *testing.T) {
	p := QuantixChainParams()
	name := p.GetNetworkName()
	if name == "" {
		t.Error("GetNetworkName should return non-empty string")
	}
}

func TestValidateChainID_Valid(t *testing.T) {
	p := QuantixChainParams()
	if !ValidateChainID(p.ChainID) {
		t.Errorf("ValidateChainID(%d) should return true for mainnet chain ID", p.ChainID)
	}
}

func TestValidateChainID_Invalid(t *testing.T) {
	result := ValidateChainID(99999)
	_ = result // just test no panic
}

func TestGenerateHeaders_NotEmpty(t *testing.T) {
	headers := GenerateHeaders("spxhash", "QTX", 100.0, "xTestAddress1234567890ABCDEF1234")
	if headers == "" {
		t.Error("GenerateHeaders should return non-empty string")
	}
}

func TestGenerateLedgerHeaders_NotEmpty(t *testing.T) {
	headers := GenerateLedgerHeaders("transfer", 50.0, "xRecipient12345678901234567890A", "test memo")
	if headers == "" {
		t.Error("GenerateLedgerHeaders should return non-empty string")
	}
}

func TestGenerateTestnetLedgerHeaders_NotEmpty(t *testing.T) {
	headers := GenerateTestnetLedgerHeaders("test_op", 10.0, "xTestnet1234567890ABCDEF123456", "memo")
	if headers == "" {
		t.Error("GenerateTestnetLedgerHeaders should return non-empty string")
	}
}

func TestGenerateGenesisInfo_NotEmpty(t *testing.T) {
	info := GenerateGenesisInfo()
	if info == "" {
		t.Error("GenerateGenesisInfo should return non-empty string")
	}
}

func TestGetSoftForks_NotNil(t *testing.T) {
	forks := GetSoftForks()
	if forks == nil {
		t.Error("GetSoftForks should return non-nil map")
	}
}

package commit

import (
	"testing"
)

func TestQuantixChainParams(t *testing.T) {
	params := QuantixChainParams()
	if params.ChainID != 7331 {
		t.Fatalf("expected chain ID 7331, got %d", params.ChainID)
	}
	if params.Symbol != "QTX" {
		t.Fatalf("expected symbol QTX, got %s", params.Symbol)
	}
	if params.DefaultPort != 32307 {
		t.Fatalf("expected port 32307, got %d", params.DefaultPort)
	}
}

func TestTestnetChainParams(t *testing.T) {
	params := TestnetChainParams()
	if params.ChainID != 17331 {
		t.Fatalf("expected testnet chain ID 17331, got %d", params.ChainID)
	}
}

func TestRegtestChainParams(t *testing.T) {
	params := RegtestChainParams()
	if params.ChainID != 27331 {
		t.Fatalf("expected regtest chain ID 27331, got %d", params.ChainID)
	}
}

func TestValidateChainID(t *testing.T) {
	if !ValidateChainID(7331) {
		t.Fatal("expected 7331 to be a valid chain ID")
	}
	if !ValidateChainID(17331) {
		t.Fatal("expected 17331 to be a valid chain ID")
	}
	if ValidateChainID(9999) {
		t.Fatal("expected 9999 to be invalid chain ID")
	}
}

func TestGetNetworkName(t *testing.T) {
	params := QuantixChainParams()
	name := params.GetNetworkName()
	if name != "Quantix Mainnet" {
		t.Fatalf("expected 'Quantix Mainnet', got '%s'", name)
	}

	testnet := TestnetChainParams()
	if testnet.GetNetworkName() != "Quantix Testnet" {
		t.Fatalf("expected 'Quantix Testnet', got '%s'", testnet.GetNetworkName())
	}
}

func TestGenerateGenesisInfo(t *testing.T) {
	info := GenerateGenesisInfo()
	if info == "" {
		t.Fatal("expected non-empty genesis info")
	}
}

func TestGenerateHeaders(t *testing.T) {
	result := GenerateHeaders("QTX", "QTX", 1.0, "xSomeAddress")
	if result == "" {
		t.Fatal("expected non-empty headers string")
	}
}

func TestChainParametersType(t *testing.T) {
	params := &ChainParameters{
		ChainID:   7331,
		ChainName: "Test",
		Symbol:    "QTX",
	}
	if params.ChainID != 7331 {
		t.Fatal("field assignment failed")
	}
}

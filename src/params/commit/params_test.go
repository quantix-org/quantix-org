// MIT License
// Copyright (c) 2024 quantix

// Q8 smoke tests for params/commit package
// Covers: QuantixChainParams, TestnetChainParams, chain parameter correctness
package commit

import (
	"testing"
)

func TestQuantixChainParams_NonEmpty(t *testing.T) {
	p := QuantixChainParams()
	if p == nil {
		t.Fatal("QuantixChainParams returned nil")
	}
	if p.ChainID == 0 {
		t.Error("ChainID must be non-zero")
	}
	if p.Symbol != "QTX" {
		t.Errorf("expected Symbol=QTX, got %s", p.Symbol)
	}
	if p.DefaultPort == 0 {
		t.Error("DefaultPort must be non-zero")
	}
	if p.MagicNumber == 0 {
		t.Error("MagicNumber must be non-zero")
	}
	if p.ChainName == "" {
		t.Error("ChainName must not be empty")
	}
}

func TestQuantixChainParams_Values(t *testing.T) {
	p := QuantixChainParams()
	if p.ChainID != 7331 {
		t.Errorf("expected ChainID=7331, got %d", p.ChainID)
	}
	if p.DefaultPort != 32307 {
		t.Errorf("expected DefaultPort=32307, got %d", p.DefaultPort)
	}
	if p.MagicNumber != 0x53504858 {
		t.Errorf("expected MagicNumber=0x53504858, got 0x%X", p.MagicNumber)
	}
}

func TestTestnetChainParams_DifferentFromMainnet(t *testing.T) {
	mainnet := QuantixChainParams()
	testnet := TestnetChainParams()

	if testnet.ChainID == mainnet.ChainID {
		t.Error("testnet and mainnet must have different ChainIDs")
	}
	if testnet.GenesisHash == mainnet.GenesisHash {
		t.Error("testnet and mainnet must have different GenesisHash")
	}
	if testnet.BIP44CoinType == mainnet.BIP44CoinType {
		t.Error("testnet and mainnet must use different BIP44 coin types")
	}
}

func TestChainParams_IsDeterministic(t *testing.T) {
	p1 := QuantixChainParams()
	p2 := QuantixChainParams()
	if p1.ChainID != p2.ChainID {
		t.Error("QuantixChainParams is not deterministic")
	}
	if p1.Symbol != p2.Symbol {
		t.Error("QuantixChainParams Symbol not deterministic")
	}
}

package params

import (
	"testing"
)

func TestDenomConstants(t *testing.T) {
	if nQTX != 1 {
		t.Fatalf("expected nQTX = 1, got %v", nQTX)
	}
	if gQTX != 1e9 {
		t.Fatalf("expected gQTX = 1e9, got %v", gQTX)
	}
	if QTX != 1e18 {
		t.Fatalf("expected QTX = 1e18, got %v", QTX)
	}
}

func TestMaximumSupply(t *testing.T) {
	expected := 5e9 * QTX
	if MaximumSupply != expected {
		t.Fatalf("expected MaximumSupply = %v, got %v", expected, MaximumSupply)
	}
}

func TestGetQTXTokenInfo(t *testing.T) {
	info := GetQTXTokenInfo()
	if info.Symbol != "QTX" {
		t.Fatalf("expected symbol QTX, got %s", info.Symbol)
	}
	if info.Decimals != 18 {
		t.Fatalf("expected 18 decimals, got %d", info.Decimals)
	}
	if info.Denominations["nQTX"] != 1 {
		t.Fatalf("expected nQTX = 1, got %d", info.Denominations["nQTX"])
	}
	if info.Denominations["gQTX"] != 1e9 {
		t.Fatalf("expected gQTX = 1e9, got %d", info.Denominations["gQTX"])
	}
	if info.Denominations["QTX"] != 1e18 {
		t.Fatalf("expected QTX = 1e18, got %d", info.Denominations["QTX"])
	}
}

func TestConvertToBase(t *testing.T) {
	amount, err := ConvertToBase(1.0, "QTX")
	if err != nil {
		t.Fatal(err)
	}
	if amount != uint64(QTX) {
		t.Fatalf("expected %d, got %d", uint64(QTX), amount)
	}
}

func TestConvertFromBase(t *testing.T) {
	amount, err := ConvertFromBase(uint64(QTX), "QTX")
	if err != nil {
		t.Fatal(err)
	}
	if amount != 1.0 {
		t.Fatalf("expected 1.0, got %f", amount)
	}
}

func TestConvertUnknownDenomination(t *testing.T) {
	_, err := ConvertToBase(1.0, "UNKNOWN")
	if err == nil {
		t.Fatal("expected error for unknown denomination")
	}
}

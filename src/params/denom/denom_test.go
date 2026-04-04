// MIT License
// Copyright (c) 2024 quantix

// Tests for params/denom package
package params

import (
	"strings"
	"testing"
)

func TestGetQTXTokenInfo(t *testing.T) {
	info := GetQTXTokenInfo()
	if info == nil {
		t.Fatal("expected non-nil token info")
	}
	if info.Symbol != "QTX" {
		t.Errorf("expected symbol QTX, got %s", info.Symbol)
	}
	if info.Decimals != 18 {
		t.Errorf("expected 18 decimals, got %d", info.Decimals)
	}
	if info.BIP44CoinType != 7331 {
		t.Errorf("expected coin type 7331, got %d", info.BIP44CoinType)
	}
	if _, ok := info.Denominations["nQTX"]; !ok {
		t.Error("expected nQTX denomination")
	}
	if _, ok := info.Denominations["QTX"]; !ok {
		t.Error("expected QTX denomination")
	}
}

func TestConvertToBase(t *testing.T) {
	cases := []struct {
		amount float64
		denom  string
		want   uint64
		errMsg string
	}{
		{1, "nQTX", 1, ""},
		{1, "gQTX", 1e9, ""},
		{1, "QTX", 1e18, ""},
		{5, "gQTX", 5e9, ""},
		{1, "unknown", 0, "unknown denomination"},
	}
	for _, tc := range cases {
		got, err := ConvertToBase(tc.amount, tc.denom)
		if tc.errMsg != "" {
			if err == nil || !strings.Contains(err.Error(), tc.errMsg) {
				t.Errorf("ConvertToBase(%v, %q): expected error containing %q, got %v", tc.amount, tc.denom, tc.errMsg, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ConvertToBase(%v, %q): unexpected error: %v", tc.amount, tc.denom, err)
		}
		if got != tc.want {
			t.Errorf("ConvertToBase(%v, %q) = %d, want %d", tc.amount, tc.denom, got, tc.want)
		}
	}
}

func TestConvertFromBase(t *testing.T) {
	cases := []struct {
		base   uint64
		denom  string
		want   float64
		errMsg string
	}{
		{1e9, "gQTX", 1, ""},
		{1e18, "QTX", 1, ""},
		{1, "nQTX", 1, ""},
		{1, "unknown", 0, "unknown denomination"},
	}
	for _, tc := range cases {
		got, err := ConvertFromBase(tc.base, tc.denom)
		if tc.errMsg != "" {
			if err == nil || !strings.Contains(err.Error(), tc.errMsg) {
				t.Errorf("ConvertFromBase(%d, %q): expected error %q, got %v", tc.base, tc.denom, tc.errMsg, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ConvertFromBase(%d, %q): unexpected error: %v", tc.base, tc.denom, err)
		}
		if got != tc.want {
			t.Errorf("ConvertFromBase(%d, %q) = %v, want %v", tc.base, tc.denom, got, tc.want)
		}
	}
}

func TestValidateAddressFormat(t *testing.T) {
	valid := []string{
		"spx1234567890abcdefghijklmno",  // 29 chars, starts with spx
		"tspx1234567890abcdefghijklmno", // 30 chars, starts with tspx
	}
	for _, addr := range valid {
		if !ValidateAddressFormat(addr) {
			t.Errorf("expected valid address: %s", addr)
		}
	}
	invalid := []string{
		"short",
		"abc1234567890abcdef",
		"",
	}
	for _, addr := range invalid {
		if ValidateAddressFormat(addr) {
			t.Errorf("expected invalid address: %s", addr)
		}
	}
}

func TestGetDenominationInfo(t *testing.T) {
	info := GetDenominationInfo()
	if !strings.Contains(info, "QTX") {
		t.Error("expected QTX in denomination info")
	}
	if !strings.Contains(info, "nQTX") {
		t.Error("expected nQTX in denomination info")
	}
}

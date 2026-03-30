// MIT License
//
// Copyright (c) 2024 quantix
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/params/denom/config.go
package params

import "fmt"

// TokenInfo provides comprehensive information about QTX tokens
type TokenInfo struct {
	Name          string            `json:"name"`
	Symbol        string            `json:"symbol"`
	Decimals      uint8             `json:"decimals"`
	TotalSupply   uint64            `json:"total_supply"`
	Denominations map[string]uint64 `json:"denominations"`
	BIP44CoinType uint32            `json:"bip44_coin_type"`
	ChainID       uint64            `json:"chain_id"`
}

// GetQTXTokenInfo returns comprehensive QTX token information
func GetQTXTokenInfo() *TokenInfo {
	return &TokenInfo{
		Name:          "Quantix",
		Symbol:        "QTX",
		Decimals:      18,
		TotalSupply:   MaximumSupply / QTX, // Convert to base units
		BIP44CoinType: 7331,
		ChainID:       7331,
		Denominations: map[string]uint64{
			"nQTX": nQTX,
			"gQTX": gQTX,
			"QTX":  QTX,
		},
	}
}

// ConvertToBase converts any denomination to base units (nQTX)
func ConvertToBase(amount float64, denomination string) (uint64, error) {
	info := GetQTXTokenInfo()
	multiplier, exists := info.Denominations[denomination]
	if !exists {
		return 0, fmt.Errorf("unknown denomination: %s", denomination)
	}

	// Convert to base units (nQTX)
	baseAmount := amount * float64(multiplier)
	if baseAmount < 0 {
		return 0, fmt.Errorf("amount cannot be negative")
	}

	return uint64(baseAmount), nil
}

// ConvertFromBase converts base units (nQTX) to specified denomination
func ConvertFromBase(baseAmount uint64, denomination string) (float64, error) {
	info := GetQTXTokenInfo()
	multiplier, exists := info.Denominations[denomination]
	if !exists {
		return 0, fmt.Errorf("unknown denomination: %s", denomination)
	}

	return float64(baseAmount) / float64(multiplier), nil
}

// ValidateAddressFormat validates QTX address format (basic version)
func ValidateAddressFormat(address string) bool {
	// Basic validation - in production, implement proper cryptographic validation
	if len(address) < 26 || len(address) > 42 {
		return false
	}

	// Check if it starts with "spx" for mainnet or "tspx" for testnet
	if address[:3] != "spx" && address[:4] != "tspx" {
		return false
	}

	return true
}

// GetDenominationInfo returns human-readable information about denominations
func GetDenominationInfo() string {
	info := GetQTXTokenInfo()

	return fmt.Sprintf(
		"=== QTX DENOMINATIONS ===\n"+
			"Token: %s (%s)\n"+
			"Decimals: %d\n"+
			"Base Unit: nQTX (1e%d)\n"+
			"Intermediate: gQTX (1e%d)\n"+
			"Main Unit: QTX (1e%d)\n"+
			"Total Supply: %.2f QTX\n"+
			"BIP44 Coin Type: %d\n"+
			"Chain ID: %d\n"+
			"========================",
		info.Name,
		info.Symbol,
		info.Decimals,
		0,  // nQTX exponent
		9,  // gQTX exponent
		18, // QTX exponent
		float64(info.TotalSupply),
		info.BIP44CoinType,
		info.ChainID,
	)
}

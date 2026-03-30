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

// go/src/params/denom/denom.go
package params

// These are the multipliers for QTX denominations, which help to represent
// different units of the QTX coins in the Quantix blockchain, similar to how
// currencies like Bitcoin and Ethereum use smaller units such as satoshis and wei.
// The base unit is nQTX (nano QTX), which is the smallest denomination, and
// larger units such as gQTX (giga QTX) and QTX (1 full coin) are represented
// by multiplying nQTX values.

// SIPS0007 https://github.com/quantix/sips/wiki/SIPS0007

const (
	// Denominations
	nQTX = 1e0  // 1 nQTX (nano QTX) is the smallest unit of QTX, similar to "wei" in Ethereum.
	gQTX = 1e9  // 1 gQTX (giga QTX) equals 1e9 nQTX. It's a larger denomination used for easier representation.
	QTX  = 1e18 // 1 QTX equals 1e18 nQTX.

	// Maximum supply of QTX set to 5 billion coins (5e9 QTX)
	MaximumSupply = 5e9 * QTX // This is 5 billion QTX, equivalent to 5e9 * 1e18 nQTX.
)

// In the same way that 1 Ether = 1e18 wei, here:
// 1 QTX = 1e18 nQTX, and 1 gQTX = 1e9 nQTX.
//
// Example of conversions:

// 1. Converting gQTX to nQTX:
// To convert an amount in gQTX to nQTX, multiply the value by the gQTX multiplier (1e9).
// For example, if you have 5 gQTX, the conversion to nQTX would be:
// valueInGQTX := new(big.Int).SetInt64(5)                // 5 gQTX
// valueInNQTX := new(big.Int).Mul(valueInGQTX, big.NewInt(gQTX)) // 5 * 1e9 = 5e9 nQTX
// Result: valueInNQTX is now equal to 5,000,000,000 nQTX

// 2. Converting QTX to nQTX:
// To convert an amount in QTX to nQTX, multiply the value by the QTX multiplier (1e18).
// For example, if you have 2 QTX, the conversion to nQTX would be:
// valueInQTX := new(big.Int).SetInt64(2)                 // 2 QTX
// valueInNSPX2 := new(big.Int).Mul(valueInQTX, big.NewInt(QTX)) // 2 * 1e18 = 2e18 nQTX
// Result: valueInNSPX2 is now equal to 2,000,000,000,000,000,000 nQTX

// 3. Converting nQTX to gQTX:
// To convert an amount in nQTX back to gQTX, divide the value by the gQTX multiplier (1e9).
// For example, if you have 1,000,000,000 nQTX, the conversion to gQTX would be:s
// valueInNSPX3 := new(big.Int).SetInt64(1000000000)          // 1,000,000,000 nQTX
// valueInGQTX2 := new(big.Int).Div(valueInNSPX3, big.NewInt(gQTX)) // 1,000,000,000 / 1e9 = 1 gQTX
// Result: valueInGSPX2 is now equal to 1 gQTX

// 4. Converting nQTX to QTX:
// To convert an amount in nQTX to QTX, divide the value by the QTX multiplier (1e18).
// For example, if you have 1,000,000,000,000,000,000 nQTX, the conversion to QTX would be:
// valueInNSPX4 := new(big.Int).SetInt64(1000000000000000000) // 1,000,000,000,000,000,000 nQTX
// valueInQTX2 := new(big.Int).Div(valueInNSPX4, big.NewInt(QTX)) // 1,000,000,000,000,000,000 / 1e18 = 1 QTX
// Result: valueInSPX2 is now equal to 1 QTX

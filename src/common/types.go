// MIT License
//
// # Copyright (c) 2024 quantix-org
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

// go/src/common/types.go
package common

import spxhash "github.com/quantix-org/quantix-org/src/spxhash/hash"

// Params represents the configuration for QuantixHash.
type Params struct {
	BitSize int
}

// Predefined Params for 256-bit hashing
var spxParams = Params{
	BitSize: 256,
}

// SpxHash hashes the given data using the QuantixHash algorithm with the predefined parameters.
func QuantixHash(data []byte) []byte {
	// Use the default params (256-bit configuration)
	params := spxParams

	// Create a new QuantixHash instance with the configured bit size
	quantixHash := spxhash.NewQuantixHash(params.BitSize, data)

	// Return the final hash for the data
	return quantixHash.GetHash(data)
}

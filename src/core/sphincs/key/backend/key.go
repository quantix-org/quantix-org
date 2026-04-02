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
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,q
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/core/sphincs/key/backend/key.go
package key

import (
	"errors"
	"fmt"
	"log"

	params "github.com/ramseyauron/quantix/src/core/sphincs/config"
	"github.com/ramseyauron/quantix/src/crypto/SPHINCSPLUS-golang/sphincs"
)

// KeyManager is responsible for managing key generation using SPHINCS+ parameters.
type KeyManager struct {
	Params *params.SPHINCSParameters // Holds SPHINCS+ parameters.
}

// NewKeyManager initializes a new KeyManager instance using SPHINCS+ parameters.
func NewKeyManager() (*KeyManager, error) {
	spxParams, err := params.NewSPHINCSParameters()
	if err != nil {
		// Log the error class only — never log key bytes or key sizes.
		log.Printf("NewKeyManager: failed to initialize SPHINCS+ parameters")
		return nil, err
	}
	return &KeyManager{Params: spxParams}, nil
}

// Getter method for SPHINCS parameters
func (km *KeyManager) GetSPHINCSParameters() *params.SPHINCSParameters {
	return km.Params
}

// GenerateKey generates a new SPHINCS+ private and public key pair.
//
// F-07 / F-19: all informational log lines that exposed key component sizes,
// serialisation lengths, or key-operation timing have been removed.  Only
// error-class log lines are kept, and they never reference key material.
func (km *KeyManager) GenerateKey() (*SPHINCS_SK, *sphincs.SPHINCS_PK, error) {
	// Ensure parameters are initialized.
	if km.Params == nil || km.Params.Params == nil {
		log.Printf("GenerateKey: missing SPHINCS+ parameters in KeyManager")
		return nil, nil, errors.New("missing SPHINCS+ parameters in KeyManager")
	}

	// Generate the SPHINCS+ key pair using the configured parameters.
	sk, pk := sphincs.Spx_keygen(km.Params.Params)
	if sk == nil || pk == nil {
		log.Printf("GenerateKey: key generation returned nil")
		return nil, nil, errors.New("key generation failed: returned nil for SK or PK")
	}

	// Ensure the keys have valid fields.
	if len(sk.SKseed) == 0 || len(sk.SKprf) == 0 || len(sk.PKseed) == 0 || len(sk.PKroot) == 0 {
		log.Printf("GenerateKey: key generation produced empty fields")
		return nil, nil, errors.New("key generation failed: empty key fields")
	}

	// No success log here — logging key-generation events leaks timing metadata
	// that assists key-usage profiling (F-07).

	// Wrap and return the generated private and public keys.
	return &SPHINCS_SK{
		SKseed: sk.SKseed,
		SKprf:  sk.SKprf,
		PKseed: sk.PKseed,
		PKroot: sk.PKroot,
	}, pk, nil
}

// SerializeSK serializes the SPHINCS private key to a byte slice.
func (sk *SPHINCS_SK) SerializeSK() ([]byte, error) {
	if sk == nil {
		return nil, errors.New("private key is nil")
	}

	// Validate key fields.
	if len(sk.SKseed) == 0 || len(sk.SKprf) == 0 || len(sk.PKseed) == 0 || len(sk.PKroot) == 0 {
		return nil, errors.New("invalid private key: empty fields")
	}

	// Combine the SKseed, SKprf, PKseed, and PKroot into a single byte slice.
	// F-07 / F-19: no log here — logging serialization success/size leaks key
	// structural metadata to log aggregation systems.
	data := append(sk.SKseed, sk.SKprf...)
	data = append(data, sk.PKseed...)
	data = append(data, sk.PKroot...)

	return data, nil
}

// SerializeKeyPair serializes a SPHINCS private and public key pair to byte slices.
func (km *KeyManager) SerializeKeyPair(sk *SPHINCS_SK, pk *sphincs.SPHINCS_PK) ([]byte, []byte, error) {
	if sk == nil || pk == nil {
		return nil, nil, errors.New("private or public key is nil")
	}

	// Serialize the private key.
	skBytes, err := sk.SerializeSK()
	if err != nil {
		log.Printf("SerializeKeyPair: failed to serialize private key")
		return nil, nil, fmt.Errorf("failed to serialize private key: %v", err)
	}

	// Serialize the public key.
	pkBytes, err := pk.SerializePK()
	if err != nil {
		log.Printf("SerializeKeyPair: failed to serialize public key")
		return nil, nil, fmt.Errorf("failed to serialize public key: %v", err)
	}

	// No success log — see F-07 / F-19.
	return skBytes, pkBytes, nil
}

// DeserializeKeyPair reconstructs a SPHINCS private and public key pair from byte slices.
func (km *KeyManager) DeserializeKeyPair(skBytes, pkBytes []byte) (*sphincs.SPHINCS_SK, *sphincs.SPHINCS_PK, error) {
	if km.Params == nil || km.Params.Params == nil {
		log.Printf("DeserializeKeyPair: missing parameters in KeyManager")
		return nil, nil, errors.New("missing parameters in KeyManager")
	}
	if len(skBytes) == 0 {
		log.Printf("DeserializeKeyPair: empty private key bytes")
		return nil, nil, errors.New("empty private key bytes")
	}

	// F-07 / F-19: removed "deserializing key pair" info log — it reveals when
	// the node accesses private key material and assists timing-based profiling.

	sk, err := sphincs.DeserializeSK(km.Params.Params, skBytes)
	if err != nil {
		log.Printf("DeserializeKeyPair: failed to deserialize private key")
		return nil, nil, fmt.Errorf("failed to deserialize private key: %v", err)
	}
	pk, err := sphincs.DeserializePK(km.Params.Params, pkBytes)
	if err != nil {
		log.Printf("DeserializeKeyPair: failed to deserialize public key")
		return nil, nil, fmt.Errorf("failed to deserialize public key: %v", err)
	}
	return sk, pk, nil
}

// DeserializePublicKey deserializes only the public key from byte slices.
func (km *KeyManager) DeserializePublicKey(pkBytes []byte) (*sphincs.SPHINCS_PK, error) {
	if km.Params == nil || km.Params.Params == nil {
		log.Printf("DeserializePublicKey: missing parameters in KeyManager")
		return nil, errors.New("missing parameters in KeyManager")
	}
	if len(pkBytes) == 0 {
		log.Printf("DeserializePublicKey: empty public key bytes")
		return nil, errors.New("empty public key bytes")
	}
	// Deserialize the public key from bytes.
	pk, err := sphincs.DeserializePK(km.Params.Params, pkBytes)
	if err != nil {
		log.Printf("DeserializePublicKey: failed to deserialize public key")
		return nil, fmt.Errorf("failed to deserialize public key: %v", err)
	}
	return pk, nil
}

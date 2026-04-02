// MIT License
//
// # Copyright (c) 2024 quantix
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

// go/src/handshake/aes.go
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
)

// NewEncryptionKey creates a new AES-GCM encryption key from a shared secret.
//
// F-08: the previous version logged the first 16 bytes of the shared secret
// (hex-encoded) at Info level on every handshake.  Even a partial secret in a
// log file provides a partial oracle to an attacker with log access.  The log
// line has been removed entirely — shared secrets must never appear in any log
// output regardless of level.
func NewEncryptionKey(sharedSecret []byte) (*EncryptionKey, error) {
	// Ensure the shared secret is long enough for AES-256 (32 bytes)
	if len(sharedSecret) < 32 {
		return nil, errors.New("shared secret too short for AES-256")
	}

	// Create AES block cipher with the first 32 bytes of the shared secret
	block, err := aes.NewCipher(sharedSecret[:32])
	if err != nil {
		return nil, err
	}

	// Wrap the AES block cipher in a GCM (Galois/Counter Mode) for authenticated encryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Return a new EncryptionKey object — no logging of key material (F-08).
	return &EncryptionKey{
		SharedSecret: sharedSecret,
		AESGCM:       aesGCM,
	}, nil
}

// Encrypt encrypts the given plaintext using AES-GCM.
func (enc *EncryptionKey) Encrypt(plaintext []byte) ([]byte, error) {
	// Ensure encryption key is properly initialized
	if enc == nil || enc.AESGCM == nil {
		return nil, errors.New("encryption key is nil")
	}

	// Generate a random nonce of appropriate size
	nonce := make([]byte, enc.AESGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt the plaintext using AES-GCM and prepend the nonce.
	// F-08: nonce logging removed — nonces in logs assist ciphertext correlation.
	ciphertext := enc.AESGCM.Seal(nil, nonce, plaintext, nil)

	// Return the combined nonce and ciphertext
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts the given ciphertext using AES-GCM.
func (enc *EncryptionKey) Decrypt(ciphertext []byte) ([]byte, error) {
	// Check for valid encryption key
	if enc == nil || enc.AESGCM == nil {
		return nil, errors.New("encryption key is nil")
	}

	// Ensure ciphertext includes a nonce
	if len(ciphertext) < enc.AESGCM.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Extract the nonce and the actual ciphertext.
	// F-08: nonce logging removed.
	nonce := ciphertext[:enc.AESGCM.NonceSize()]
	encrypted := ciphertext[enc.AESGCM.NonceSize():]

	// Decrypt the message using AES-GCM
	plaintext, err := enc.AESGCM.Open(nil, nonce, encrypted, nil)
	if err != nil {
		log.Printf("Decrypt: AES-GCM open failed")
		return nil, err
	}
	return plaintext, nil
}

// SecureMessage serializes and encrypts the message struct.
func SecureMessage(msg *Message, enc *EncryptionKey) ([]byte, error) {
	// Encode the message to JSON
	data, err := msg.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode message: %v", err)
	}
	// F-08: removed info log with msg.Type and data length — type metadata in
	// logs leaks protocol traffic patterns.

	// Encrypt the data using the EncryptionKey
	ciphertext, err := enc.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message: %v", err)
	}
	// F-08: removed ciphertext-length log.
	return ciphertext, nil
}

// DecodeSecureMessage decrypts and deserializes an encrypted message.
func DecodeSecureMessage(data []byte, enc *EncryptionKey) (*Message, error) {
	// Check encryption key
	if enc == nil {
		return nil, errors.New("encryption key is nil")
	}

	// F-08: removed data-length and plaintext-length logs — they reveal traffic
	// volume metadata that can be correlated with application events.

	// Decrypt message
	plaintext, err := enc.Decrypt(data)
	if err != nil {
		return nil, err
	}

	// Parse plaintext JSON into Message struct
	var msg Message
	if err := json.Unmarshal(plaintext, &msg); err != nil {
		return nil, err
	}

	// Validate the message contents
	if err := msg.ValidateMessage(); err != nil {
		return nil, err
	}

	// Return parsed message
	return &msg, nil
}

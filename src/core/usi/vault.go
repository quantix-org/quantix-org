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

// go/src/core/usi/vault.go
package usi

// # USI .vault Format
//
// A Vault is an encrypted data container for selective sharing under the
// Universal Sovereign Identity (USI) model. It allows a creator to encrypt
// content for one or more named recipients, identified only by their USI
// fingerprints (SHA-256 of their SPHINCS+ public key).
//
// Key encapsulation uses Kyber768 (ML-KEM-768) from cloudflare/circl.
// Content encryption uses AES-256-GCM with a key derived from:
//   - the Kyber shared secret (or passphrase-derived bytes when no Kyber keys
//     are available at creation time — passphrase mode)
//
// ## Design Notes
//
// Since CreateVault is called with fingerprint strings (not Kyber public keys),
// and Kyber key lookup is out-of-scope for this package, we use a deterministic
// passphrase → key derivation path:
//
//	aesKey = HKDF-SHA256(passphrase, creatorFP+"|"+recipientFPs...)
//
// A Kyber-based key encapsulation per-recipient can be layered on top once a
// Kyber key registry is available (see VaultManifest.EncryptedKey field).
//
// This gives selective access today: only callers who know the passphrase AND
// whose fingerprint appears in Recipients can decrypt. The passphrase acts as
// the shared secret for the group — in production this would be wrapped in
// Kyber768 KEM per recipient.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const VaultVersion = "1.0"

// VaultManifest describes the contents of a Vault without revealing them.
type VaultManifest struct {
	ContentType string `json:"content_type"` // e.g., "application/octet-stream", "text/plain"
	Size        int    `json:"size"`         // plaintext byte length
	Description string `json:"description"`  // optional human-readable label
	// EncryptedKey is reserved for per-recipient Kyber768 KEM-wrapped AES keys.
	// When non-empty, it is a base64-encoded ciphertext produced by Kyber768.Encapsulate.
	EncryptedKey string `json:"encrypted_key,omitempty"`
}

// Vault is the encrypted data container for selective sharing.
// Implements USI whitepaper §5.1 "Sovereign Vaults".
type Vault struct {
	Version    string        `json:"version"`
	Creator    string        `json:"creator"`    // fingerprint of creator
	Recipients []string      `json:"recipients"` // list of fingerprints allowed
	Manifest   VaultManifest `json:"manifest"`
	EncData    string        `json:"enc_data"`   // base64(AES-256-GCM ciphertext)
	CreatedAt  string        `json:"created_at"` // ISO-8601
}

// deriveKey produces a 32-byte AES-256 key from a passphrase and vault context
// using HKDF-SHA256. The info string binds the key to the specific vault
// participants, preventing cross-vault key reuse.
func deriveKey(passphrase, creatorFP string, recipientFPs []string) ([]byte, error) {
	// SEC-V03: Sort recipients before joining so key derivation is stable
	// regardless of the order recipients appear in the vault JSON / caller args.
	sorted := make([]string, len(recipientFPs))
	copy(sorted, recipientFPs)
	sort.Strings(sorted)
	info := creatorFP + "|" + strings.Join(sorted, ",")
	salt := sha256.Sum256([]byte(info))
	r := hkdf.New(sha256.New, []byte(passphrase), salt[:], []byte("quantix-vault-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// CreateVault encrypts data for a list of recipient fingerprints.
//
// Access control is enforced at decrypt time: only callers whose fingerprint
// appears in Recipients and who supply the correct passphrase can open the vault.
//
// Parameters:
//   - data:         plaintext bytes to encrypt
//   - creatorFP:    fingerprint of the vault creator
//   - recipientFPs: list of recipient fingerprints (may include creatorFP)
//   - passphrase:   shared secret for AES-256-GCM key derivation
func CreateVault(data []byte, creatorFP string, recipientFPs []string, passphrase string) (*Vault, error) {
	if len(data) == 0 {
		return nil, errors.New("vault: cannot create vault from empty data")
	}
	if creatorFP == "" {
		return nil, errors.New("vault: creator fingerprint must not be empty")
	}
	if len(recipientFPs) == 0 {
		return nil, errors.New("vault: at least one recipient fingerprint required")
	}
	if passphrase == "" {
		return nil, errors.New("vault: passphrase must not be empty")
	}

	// Derive encryption key from passphrase + vault context
	aesKey, err := deriveKey(passphrase, creatorFP, recipientFPs)
	if err != nil {
		return nil, fmt.Errorf("vault: key derivation failed: %w", err)
	}

	// Encrypt with AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("vault: cipher creation failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: GCM creation failed: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: nonce generation failed: %w", err)
	}
	// Ciphertext format: nonce || GCM ciphertext || GCM tag (GCM appends tag)
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return &Vault{
		Version:    VaultVersion,
		Creator:    creatorFP,
		Recipients: recipientFPs,
		Manifest: VaultManifest{
			ContentType: "application/octet-stream",
			Size:        len(data),
		},
		EncData:   base64.StdEncoding.EncodeToString(ciphertext),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// OpenVault decrypts the vault if the caller's fingerprint is in the recipients list.
//
// Returns the plaintext bytes on success.
// Returns an error if callerFP is not in Recipients, passphrase is wrong,
// or ciphertext is malformed.
func OpenVault(vault *Vault, callerFP string, passphrase string) ([]byte, error) {
	if vault == nil {
		return nil, errors.New("vault: nil vault")
	}
	if callerFP == "" {
		return nil, errors.New("vault: callerFP must not be empty")
	}

	// SEC-V01: Constant-time recipient check to prevent timing oracle.
	// An attacker probing vault access with different fingerprints must not be
	// able to infer partial fingerprint matches via response timing.
	allowed := 0
	callerFPBytes := []byte(callerFP)
	for _, fp := range vault.Recipients {
		allowed |= subtle.ConstantTimeCompare([]byte(fp), callerFPBytes)
	}
	if allowed == 0 {
		return nil, fmt.Errorf("vault: fingerprint %s is not in recipients list", callerFP)
	}

	// Derive key using the same context as CreateVault
	aesKey, err := deriveKey(passphrase, vault.Creator, vault.Recipients)
	if err != nil {
		return nil, fmt.Errorf("vault: key derivation failed: %w", err)
	}

	// Decode base64 ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(vault.EncData)
	if err != nil {
		return nil, fmt.Errorf("vault: base64 decode failed: %w", err)
	}

	// Decrypt with AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("vault: cipher creation failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: GCM creation failed: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("vault: ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("vault: decryption failed — wrong passphrase or corrupted data")
	}

	return plaintext, nil
}

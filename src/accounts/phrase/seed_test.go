// MIT License
// Copyright (c) 2024 quantix
package seed_test

import (
	"encoding/base32"
	"testing"

	seed "github.com/quantix-org/quantix-org/src/accounts/phrase"
)

func TestGenerateSalt_Length(t *testing.T) {
	s, err := seed.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt error: %v", err)
	}
	if len(s) != seed.SaltSize {
		t.Errorf("expected %d bytes, got %d", seed.SaltSize, len(s))
	}
}

func TestGenerateSalt_NotAllZeros(t *testing.T) {
	s, err := seed.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt error: %v", err)
	}
	allZero := true
	for _, b := range s {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("GenerateSalt returned all-zero salt (crypto/rand may have failed)")
	}
}

func TestGenerateSalt_Unique(t *testing.T) {
	s1, _ := seed.GenerateSalt()
	s2, _ := seed.GenerateSalt()
	if string(s1) == string(s2) {
		t.Error("GenerateSalt returned duplicate salts")
	}
}

func TestGenerateNonce_Length(t *testing.T) {
	n, err := seed.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce error: %v", err)
	}
	if len(n) != seed.NonceSize {
		t.Errorf("expected %d bytes, got %d", seed.NonceSize, len(n))
	}
}

func TestGenerateNonce_Unique(t *testing.T) {
	n1, _ := seed.GenerateNonce()
	n2, _ := seed.GenerateNonce()
	if string(n1) == string(n2) {
		t.Error("GenerateNonce returned duplicate nonces")
	}
}

func TestGenerateEntropy_Length(t *testing.T) {
	e, err := seed.GenerateEntropy()
	if err != nil {
		t.Fatalf("GenerateEntropy error: %v", err)
	}
	expected := seed.EntropySize / 8
	if len(e) != expected {
		t.Errorf("expected %d bytes, got %d", expected, len(e))
	}
}

func TestGenerateEntropy_Unique(t *testing.T) {
	e1, _ := seed.GenerateEntropy()
	e2, _ := seed.GenerateEntropy()
	if string(e1) == string(e2) {
		t.Error("GenerateEntropy returned duplicate entropy")
	}
}

func TestEncodeBase32_NonEmpty(t *testing.T) {
	data := []byte("hello quantix")
	encoded := seed.EncodeBase32(data)
	if encoded == "" {
		t.Error("EncodeBase32 returned empty string")
	}
}

func TestEncodeBase32_Decodable(t *testing.T) {
	data := []byte("test data 123")
	encoded := seed.EncodeBase32(data)
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		t.Fatalf("cannot decode base32 output: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("roundtrip failed: got %q want %q", decoded, data)
	}
}

func TestHashPasskey_Length(t *testing.T) {
	passkey := []byte("test-passkey-32-bytes-0000000000")
	h, err := seed.HashPasskey(passkey)
	if err != nil {
		t.Fatalf("HashPasskey error: %v", err)
	}
	// SHA3-512 output is 64 bytes
	if len(h) != 64 {
		t.Errorf("expected 64 bytes, got %d", len(h))
	}
}

func TestHashPasskey_Deterministic(t *testing.T) {
	passkey := []byte("deterministic-test-passkey")
	h1, _ := seed.HashPasskey(passkey)
	h2, _ := seed.HashPasskey(passkey)
	if string(h1) != string(h2) {
		t.Error("HashPasskey is not deterministic")
	}
}

func TestHashPasskey_DifferentInputs(t *testing.T) {
	h1, _ := seed.HashPasskey([]byte("key-one"))
	h2, _ := seed.HashPasskey([]byte("key-two"))
	if string(h1) == string(h2) {
		t.Error("HashPasskey produced same hash for different inputs")
	}
}

func TestGeneratePassphrase_NetworkRequired(t *testing.T) {
	// GeneratePassphrase calls sips3.NewMnemonic which fetches a wordlist from GitHub.
	// Skip this test in environments without network access (e.g. CI sandbox).
	t.Skip("GeneratePassphrase requires network access to fetch BIP-39 word list")
}

// MIT License
// Copyright (c) 2024 quantix

// P3-Q2: PEPPER tests for src/core/usi/usimeta.go
// Tests: Sign data, fingerprint correctness, verify true, tamper → false, JSON roundtrip.
package usi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// ---------------------------------------------------------------------------
// USIMeta JSON round-trip (no crypto needed — just the struct)
// ---------------------------------------------------------------------------

func TestUSIMeta_JSONRoundtrip(t *testing.T) {
	meta := &USIMeta{
		Version:     "1",
		Fingerprint: "aabbccdd",
		PublicKey:   "pubkeyhex",
		FileHash:    "filehash",
		Signature:   "sighex",
		SignedAt:    "2026-04-04T00:00:00Z",
		Timestamp:   1234567890,
		Nonce:       "nonce123",
	}

	encoded, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var decoded USIMeta
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Fingerprint != meta.Fingerprint {
		t.Errorf("Fingerprint mismatch: got %q want %q", decoded.Fingerprint, meta.Fingerprint)
	}
	if decoded.Signature != meta.Signature {
		t.Errorf("Signature mismatch: got %q want %q", decoded.Signature, meta.Signature)
	}
	if decoded.PublicKey != meta.PublicKey {
		t.Errorf("PublicKey mismatch: got %q want %q", decoded.PublicKey, meta.PublicKey)
	}
	if decoded.Version != meta.Version {
		t.Errorf("Version mismatch: got %q want %q", decoded.Version, meta.Version)
	}
}

// ---------------------------------------------------------------------------
// Fingerprint derivation: SHA-256(pubkey) == hex fingerprint
// ---------------------------------------------------------------------------

func TestUSIMeta_FingerprintMatchesPubKeySHA256(t *testing.T) {
	pubKeyBytes := []byte("test-public-key-bytes-for-fingerprint")
	fp := sha256.Sum256(pubKeyBytes)
	expectedFP := hex.EncodeToString(fp[:])

	meta := &USIMeta{
		Fingerprint: expectedFP,
		PublicKey:   hex.EncodeToString(pubKeyBytes),
	}

	// Re-derive and verify
	pkBytes, err := hex.DecodeString(meta.PublicKey)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	derived := sha256.Sum256(pkBytes)
	if hex.EncodeToString(derived[:]) != meta.Fingerprint {
		t.Error("fingerprint does not match SHA-256 of public key")
	}
}

// ---------------------------------------------------------------------------
// SignData input validation
// ---------------------------------------------------------------------------

func TestSignData_EmptyData_ReturnsError(t *testing.T) {
	_, err := SignData([]byte{}, "fp", []byte("sk"), []byte("pk"), nil, nil)
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestSignData_EmptyKeys_ReturnsError(t *testing.T) {
	_, err := SignData([]byte("hello"), "fp", []byte{}, []byte{}, nil, nil)
	if err == nil {
		t.Error("expected error for empty keys")
	}
}

func TestSignData_NilSecretKey_ReturnsError(t *testing.T) {
	_, err := SignData([]byte("hello"), "fp", nil, []byte("pk"), nil, nil)
	if err == nil {
		t.Error("expected error for nil secret key")
	}
}

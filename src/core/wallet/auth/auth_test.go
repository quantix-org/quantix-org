// MIT License
// Copyright (c) 2024 quantix
package auth_test

import (
	"bytes"
	"encoding/base32"
	"testing"

	auth "github.com/quantix-org/quantix-org/src/core/wallet/auth"
)

func TestEncodeBase32_Roundtrip(t *testing.T) {
	data := []byte("quantix-auth-test")
	encoded := auth.EncodeBase32(data)
	decoded, err := auth.DecodeBase32(encoded)
	if err != nil {
		t.Fatalf("DecodeBase32 error: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("roundtrip failed: got %x want %x", decoded, data)
	}
}

func TestEncodeBase32_NoPadding(t *testing.T) {
	encoded := auth.EncodeBase32([]byte("test"))
	for _, c := range encoded {
		if c == '=' {
			t.Error("EncodeBase32 should not include padding characters")
		}
	}
}

func TestDecodeBase32_InvalidInput(t *testing.T) {
	_, err := auth.DecodeBase32("not-valid-base32!!!")
	if err == nil {
		t.Error("expected error for invalid base32 input")
	}
}

func TestDecodeBase32_EmptyString(t *testing.T) {
	decoded, err := auth.DecodeBase32("")
	if err != nil {
		t.Fatalf("unexpected error for empty string: %v", err)
	}
	if len(decoded) != 0 {
		t.Errorf("expected empty slice, got %x", decoded)
	}
}

func TestGenerateHMAC_NonNil(t *testing.T) {
	mac, err := auth.GenerateHMAC([]byte("data"), []byte("key"))
	if err != nil {
		t.Fatalf("GenerateHMAC error: %v", err)
	}
	if mac == nil {
		t.Error("expected non-nil HMAC")
	}
}

func TestGenerateHMAC_Deterministic(t *testing.T) {
	m1, _ := auth.GenerateHMAC([]byte("data"), []byte("key"))
	m2, _ := auth.GenerateHMAC([]byte("data"), []byte("key"))
	if !bytes.Equal(m1, m2) {
		t.Error("GenerateHMAC is not deterministic")
	}
}

func TestGenerateHMAC_DifferentKeys(t *testing.T) {
	m1, _ := auth.GenerateHMAC([]byte("data"), []byte("key-one"))
	m2, _ := auth.GenerateHMAC([]byte("data"), []byte("key-two"))
	if bytes.Equal(m1, m2) {
		t.Error("different keys should produce different HMACs")
	}
}

func TestGenerateHMAC_DifferentData(t *testing.T) {
	m1, _ := auth.GenerateHMAC([]byte("data-A"), []byte("key"))
	m2, _ := auth.GenerateHMAC([]byte("data-B"), []byte("key"))
	if bytes.Equal(m1, m2) {
		t.Error("different data should produce different HMACs")
	}
}

func TestGenerateHMAC_Length(t *testing.T) {
	// HMAC-SHA3-512 produces 64 bytes
	mac, _ := auth.GenerateHMAC([]byte("data"), []byte("key"))
	if len(mac) != 64 {
		t.Errorf("expected 64-byte HMAC, got %d", len(mac))
	}
}

func TestGenerateChainCode_NonNil(t *testing.T) {
	fp, err := auth.GenerateChainCode("test-passphrase", []byte("combined-parts"))
	if err != nil {
		t.Fatalf("GenerateChainCode error: %v", err)
	}
	if fp == nil {
		t.Error("expected non-nil chain code")
	}
}

func TestGenerateChainCode_Deterministic(t *testing.T) {
	// Note: GenerateChainCode also stores into internal map, so same inputs → same output
	fp1, _ := auth.GenerateChainCode("passphrase-X", []byte("parts-Y"))
	fp2, _ := auth.GenerateChainCode("passphrase-X", []byte("parts-Y"))
	if !bytes.Equal(fp1, fp2) {
		t.Error("GenerateChainCode should be deterministic for same inputs")
	}
}

func TestGenerateChainCode_DifferentPassphrases(t *testing.T) {
	fp1, _ := auth.GenerateChainCode("phrase-one", []byte("parts"))
	fp2, _ := auth.GenerateChainCode("phrase-two", []byte("parts"))
	if bytes.Equal(fp1, fp2) {
		t.Error("different passphrases should yield different chain codes")
	}
}

func TestVerifyFingerPrint_Valid(t *testing.T) {
	passphrase := "verify-test-passphrase"
	parts := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Generate chain code (stores fingerprint internally)
	_, err := auth.GenerateChainCode(passphrase, parts)
	if err != nil {
		t.Fatalf("GenerateChainCode error: %v", err)
	}

	// Encode parts as base32 (what VerifyFingerPrint expects)
	b32Passkey := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(parts)

	ok, err := auth.VerifyFingerPrint(b32Passkey, passphrase)
	if err != nil {
		t.Fatalf("VerifyFingerPrint error: %v", err)
	}
	if !ok {
		t.Error("expected VerifyFingerPrint to return true")
	}
}

func TestVerifyFingerPrint_WrongPassphrase(t *testing.T) {
	passphrase := "correct-passphrase-abc"
	parts := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	_, err := auth.GenerateChainCode(passphrase, parts)
	if err != nil {
		t.Fatalf("GenerateChainCode error: %v", err)
	}

	b32Passkey := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(parts)

	// Use wrong passphrase — should fail (either error or false)
	ok, _ := auth.VerifyFingerPrint(b32Passkey, "wrong-passphrase-xyz")
	if ok {
		t.Error("VerifyFingerPrint should return false for wrong passphrase")
	}
}

func TestVerifyFingerPrint_InvalidBase32(t *testing.T) {
	_, err := auth.VerifyFingerPrint("!!!invalid!!!", "passphrase")
	if err == nil {
		t.Error("expected error for invalid base32 passkey")
	}
}

func TestVerifyFingerPrint_NoStoredFingerprint(t *testing.T) {
	// Use a key that was never stored
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("never-stored-12345"))
	ok, err := auth.VerifyFingerPrint(b32, "any-passphrase")
	if ok || err == nil {
		t.Error("expected false + error for unstored fingerprint")
	}
}

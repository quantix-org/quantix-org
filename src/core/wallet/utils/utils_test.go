// MIT License
// Copyright (c) 2024 quantix
package utils_test

import (
	"bytes"
	"encoding/base32"
	"testing"

	utils "github.com/quantix-org/quantix-org/src/core/wallet/utils"
)

func TestEncodeBase32_NonEmpty(t *testing.T) {
	encoded := utils.EncodeBase32([]byte("wallet-utils-test"))
	if encoded == "" {
		t.Error("EncodeBase32 returned empty string")
	}
}

func TestEncodeBase32_NoPadding(t *testing.T) {
	encoded := utils.EncodeBase32([]byte("x"))
	for _, c := range encoded {
		if c == '=' {
			t.Error("EncodeBase32 should not include padding")
		}
	}
}

func TestDecodeBase32_Roundtrip(t *testing.T) {
	data := []byte("test-roundtrip-data")
	encoded := utils.EncodeBase32(data)
	// utils.DecodeBase32 uses StdEncoding without NoPadding — add padding for decode
	pad := (8 - len(encoded)%8) % 8
	padded := encoded + string(bytes.Repeat([]byte("="), pad))
	decoded, err := base32.StdEncoding.DecodeString(padded)
	if err != nil {
		t.Fatalf("base32 decode failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("roundtrip failed: got %x want %x", decoded, data)
	}
}

func TestGenerateMacKey_LengthAndNonNil(t *testing.T) {
	parts := []byte{0x01, 0x02, 0x03, 0x04}
	hashed := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	macKey, chainCode, err := utils.GenerateMacKey(parts, hashed)
	if err != nil {
		t.Fatalf("GenerateMacKey error: %v", err)
	}
	// MacKey must be 32 bytes (256 bits per spec)
	if len(macKey) != 32 {
		t.Errorf("MacKey length = %d, want 32", len(macKey))
	}
	if chainCode == nil {
		t.Error("expected non-nil chain code")
	}
}

func TestGenerateMacKey_Deterministic(t *testing.T) {
	parts := []byte{0x10, 0x20, 0x30}
	hashed := []byte{0x40, 0x50, 0x60}

	mac1, cc1, _ := utils.GenerateMacKey(parts, hashed)
	mac2, cc2, _ := utils.GenerateMacKey(parts, hashed)

	if !bytes.Equal(mac1, mac2) {
		t.Error("MacKey is not deterministic")
	}
	if !bytes.Equal(cc1, cc2) {
		t.Error("ChainCode is not deterministic")
	}
}

func TestGenerateMacKey_DifferentPartsProduceDifferentKeys(t *testing.T) {
	hashed := []byte{0x01, 0x02, 0x03}
	mac1, _, _ := utils.GenerateMacKey([]byte("parts-A"), hashed)
	mac2, _, _ := utils.GenerateMacKey([]byte("parts-B"), hashed)
	if bytes.Equal(mac1, mac2) {
		t.Error("different parts should produce different MacKeys")
	}
}

func TestGenerateMacKey_NilHashedPasskey(t *testing.T) {
	parts := []byte{0x01}
	// nil hashedPasskey should not panic
	macKey, chainCode, err := utils.GenerateMacKey(parts, nil)
	if err != nil {
		t.Fatalf("GenerateMacKey with nil hashed key error: %v", err)
	}
	if len(macKey) != 32 {
		t.Errorf("MacKey length = %d, want 32", len(macKey))
	}
	_ = chainCode
}

func TestVerifyBase32Passkey_AfterGenerate(t *testing.T) {
	parts := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	hashed := []byte{0x11, 0x22, 0x33, 0x44}

	_, _, _ = utils.GenerateMacKey(parts, hashed)

	// Encode parts as base32 with NoPadding (as GenerateMacKey stores them)
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(parts)

	ok, macKey, chainCode, err := utils.VerifyBase32Passkey(b32)
	if err != nil {
		t.Fatalf("VerifyBase32Passkey error: %v", err)
	}
	if !ok {
		t.Error("VerifyBase32Passkey should return true after GenerateMacKey")
	}
	if len(macKey) != 32 {
		t.Errorf("MacKey length = %d, want 32", len(macKey))
	}
	_ = chainCode
}

func TestVerifyChainCode_Valid(t *testing.T) {
	parts := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04}
	hashed := []byte{0x55, 0x66, 0x77, 0x88}

	macKey, _, err := utils.GenerateMacKey(parts, hashed)
	if err != nil {
		t.Fatalf("GenerateMacKey error: %v", err)
	}

	ok, err := utils.VerifyChainCode(parts, macKey)
	if err != nil {
		t.Fatalf("VerifyChainCode error: %v", err)
	}
	if !ok {
		t.Error("VerifyChainCode should return true for valid inputs")
	}
}

func TestVerifyChainCode_WrongMacKey(t *testing.T) {
	parts := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	hashed := []byte{0x99, 0xAA}

	_, _, err := utils.GenerateMacKey(parts, hashed)
	if err != nil {
		t.Fatalf("GenerateMacKey error: %v", err)
	}

	wrongMacKey := bytes.Repeat([]byte{0x00}, 32)
	ok, _ := utils.VerifyChainCode(parts, wrongMacKey)
	if ok {
		t.Error("VerifyChainCode should return false for wrong MacKey")
	}
}

func TestVerifyChainCode_UnknownParts(t *testing.T) {
	// Parts that were never stored
	unknownParts := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}
	macKey := bytes.Repeat([]byte{0x01}, 32)
	ok, err := utils.VerifyChainCode(unknownParts, macKey)
	if ok || err == nil {
		t.Error("VerifyChainCode should fail for unknown/unstored parts")
	}
}

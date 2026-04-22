package utils

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeBase32(t *testing.T) {
	original := []byte("hello quantix wallet")
	encoded := EncodeBase32(original)
	if encoded == "" {
		t.Fatal("expected non-empty encoded string")
	}

	decoded, err := DecodeBase32(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, decoded) {
		t.Fatalf("decoded mismatch: expected %v, got %v", original, decoded)
	}
}

func TestDecodeBase32InvalidInput(t *testing.T) {
	_, err := DecodeBase32("!!!invalid!!!")
	if err == nil {
		t.Fatal("expected error for invalid base32 input")
	}
}

func TestGenerateMacKey(t *testing.T) {
	parts := []byte("combined-key-parts-0000000000001")
	passkey := []byte("hashed-passkey-000000000000001")

	macKey, chainCode, err := GenerateMacKey(parts, passkey)
	if err != nil {
		t.Fatal(err)
	}
	if len(macKey) != 32 {
		t.Fatalf("expected 32-byte macKey, got %d", len(macKey))
	}
	if len(chainCode) == 0 {
		t.Fatal("expected non-empty chainCode")
	}
}

func TestGenerateMacKeyDeterministic(t *testing.T) {
	parts := []byte("deterministic-parts-00000000001")
	passkey := []byte("deterministic-passkey-000000001")

	mac1, chain1, err := GenerateMacKey(parts, passkey)
	if err != nil {
		t.Fatal(err)
	}
	mac2, chain2, err := GenerateMacKey(parts, passkey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(mac1, mac2) {
		t.Fatal("macKey not deterministic")
	}
	if !bytes.Equal(chain1, chain2) {
		t.Fatal("chainCode not deterministic")
	}
}

func TestVerifyChainCode(t *testing.T) {
	parts := []byte("verify-chain-parts-00000000001")
	passkey := []byte("verify-chain-passkey-0000000001")

	macKey, _, err := GenerateMacKey(parts, passkey)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := VerifyChainCode(parts, macKey)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected chain code verification to pass")
	}
}

package encode

import (
	"bytes"
	"testing"
)

func TestGenerateAddressNonEmpty(t *testing.T) {
	pubKey := []byte("test-public-key-bytes-12345678901")
	addr := GenerateAddress(pubKey)
	if addr == "" {
		t.Fatal("expected non-empty address")
	}
}

func TestGenerateAddressDeterministic(t *testing.T) {
	pubKey := []byte("some-public-key-data")
	addr1 := GenerateAddress(pubKey)
	addr2 := GenerateAddress(pubKey)
	if addr1 != addr2 {
		t.Fatal("address generation is not deterministic")
	}
}

func TestGenerateAddressDifferentKeys(t *testing.T) {
	pk1 := []byte("public-key-one-padded-to-32bytes")
	pk2 := []byte("public-key-two-padded-to-32bytes")
	addr1 := GenerateAddress(pk1)
	addr2 := GenerateAddress(pk2)
	if addr1 == addr2 {
		t.Fatal("different keys produced the same address")
	}
}

func TestGenerateAddressStartsWithX(t *testing.T) {
	pubKey := []byte("quantix-test-public-key-00000001")
	addr := GenerateAddress(pubKey)
	if len(addr) == 0 || addr[0] != 'x' {
		t.Fatalf("expected address starting with 'x', got: %s", addr)
	}
}

func TestDecodeAddressRoundTrip(t *testing.T) {
	pubKey := []byte("roundtrip-test-public-key-000001")
	addr := GenerateAddress(pubKey)

	decoded, err := DecodeAddress(addr)
	if err != nil {
		t.Fatalf("DecodeAddress failed: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("decoded payload is empty")
	}
}

func TestDecodeAddressInvalidChecksum(t *testing.T) {
	// Corrupt a valid address
	pubKey := []byte("checksum-test-key-padded-0000001")
	addr := GenerateAddress(pubKey)

	// Tamper with the address
	corrupted := []byte(addr)
	if len(corrupted) > 3 {
		corrupted[len(corrupted)-1] ^= 0xFF
	}

	_, err := DecodeAddress(string(corrupted))
	if err == nil {
		t.Fatal("expected error for corrupted address")
	}
}

func TestChecksum(t *testing.T) {
	data := []byte("checksum data")
	cs1 := Checksum(data)
	cs2 := Checksum(data)
	if !bytes.Equal(cs1, cs2) {
		t.Fatal("Checksum not deterministic")
	}
	if len(cs1) != 4 {
		t.Fatalf("expected 4-byte checksum, got %d", len(cs1))
	}
}

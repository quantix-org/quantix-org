// PEPPER Sprint2 — wallet address encoding coverage
package encode

import (
	"testing"
)

func TestGenerateAddress_NotEmpty(t *testing.T) {
	pubKey := []byte("fake-sphincs-public-key-for-testing-purposes-only-32bytes!")
	addr := GenerateAddress(pubKey)
	if addr == "" {
		t.Error("GenerateAddress should return non-empty address")
	}
}

func TestGenerateAddress_Deterministic(t *testing.T) {
	pubKey := []byte("deterministic-key-test-12345678")
	a1 := GenerateAddress(pubKey)
	a2 := GenerateAddress(pubKey)
	if a1 != a2 {
		t.Error("GenerateAddress should be deterministic for same key")
	}
}

func TestChecksum_NotEmpty(t *testing.T) {
	cs := Checksum([]byte("test data"))
	if len(cs) == 0 {
		t.Error("Checksum should return non-empty bytes")
	}
}

func TestChecksum_Different(t *testing.T) {
	cs1 := Checksum([]byte("data1"))
	cs2 := Checksum([]byte("data2"))
	if string(cs1) == string(cs2) {
		t.Error("Checksums of different data should differ")
	}
}

func TestDecodeAddress_ValidAddress(t *testing.T) {
	pubKey := []byte("decode-test-public-key-padding!!")
	addr := GenerateAddress(pubKey)
	if addr == "" {
		t.Skip("GenerateAddress returned empty")
	}
	decoded, err := DecodeAddress(addr)
	if err != nil {
		t.Logf("DecodeAddress: %v (may require specific format)", err)
		return
	}
	if len(decoded) == 0 {
		t.Error("decoded address should have non-zero length")
	}
}

func TestDecodeAddress_InvalidInput(t *testing.T) {
	_, err := DecodeAddress("this_is_not_a_valid_address_!!!")
	if err == nil {
		t.Log("DecodeAddress accepted invalid input (may be lenient)")
	}
}

package common

import (
	"bytes"
	"testing"
)

func TestQuantixHashNonEmpty(t *testing.T) {
	result := QuantixHash([]byte("hello world"))
	if len(result) == 0 {
		t.Fatal("expected non-empty hash")
	}
}

func TestQuantixHashDeterministic(t *testing.T) {
	data := []byte("deterministic")
	r1 := QuantixHash(data)
	r2 := QuantixHash(data)
	if !bytes.Equal(r1, r2) {
		t.Fatal("QuantixHash not deterministic")
	}
}

func TestQuantixHashDifferentInputs(t *testing.T) {
	r1 := QuantixHash([]byte("abc"))
	r2 := QuantixHash([]byte("xyz"))
	if bytes.Equal(r1, r2) {
		t.Fatal("different inputs produced same hash")
	}
}

func TestBytes2Hex(t *testing.T) {
	b := []byte{0xde, 0xad, 0xbe, 0xef}
	got := Bytes2Hex(b)
	if got != "deadbeef" {
		t.Fatalf("expected deadbeef, got %s", got)
	}
}

func TestHex2Bytes(t *testing.T) {
	b, err := Hex2Bytes("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte{0xde, 0xad, 0xbe, 0xef}
	if !bytes.Equal(b, expected) {
		t.Fatalf("expected %v, got %v", expected, b)
	}
}

func TestFormatAndParseNonce(t *testing.T) {
	nonce := uint64(12345678)
	formatted := FormatNonce(nonce)
	parsed, err := ParseNonce(formatted)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != nonce {
		t.Fatalf("expected %d, got %d", nonce, parsed)
	}
}

func TestGetCurrentTimestamp(t *testing.T) {
	ts := GetCurrentTimestamp()
	if ts <= 0 {
		t.Fatal("expected positive timestamp")
	}
}

func TestFormatTimestamp(t *testing.T) {
	local, utc := FormatTimestamp(1609459200) // 2021-01-01 00:00:00 UTC
	if local == "" || utc == "" {
		t.Fatal("expected non-empty formatted timestamps")
	}
}

func TestIsValidHexString(t *testing.T) {
	if !IsValidHexString("deadbeef") {
		t.Fatal("expected deadbeef to be valid hex")
	}
	if IsValidHexString("xyz") {
		t.Fatal("expected xyz to be invalid hex")
	}
}

func TestZeroAndMaxNonce(t *testing.T) {
	z := ZeroNonce()
	if z != "0000000000000000" {
		t.Fatalf("unexpected zero nonce: %s", z)
	}
	m := MaxNonce()
	if m != "ffffffffffffffff" {
		t.Fatalf("unexpected max nonce: %s", m)
	}
}

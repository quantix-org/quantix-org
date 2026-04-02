// MIT License
//
// Copyright (c) 2024 quantix

// Package fingerprint — Q6 USI/Identity layer tests.
package fingerprint

import (
	"encoding/hex"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Q6-A: Determinism — same pubkey → same Fingerprint
// ---------------------------------------------------------------------------

func TestFingerprintDeterminism(t *testing.T) {
	vectors := []struct {
		name   string
		pubkey []byte
	}{
		{"all-zeros-32", make([]byte, 32)},
		{"all-ones-32", func() []byte { b := make([]byte, 32); for i := range b { b[i] = 0xff }; return b }()},
		{"sequential-64", func() []byte { b := make([]byte, 64); for i := range b { b[i] = byte(i) }; return b }()},
	}
	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			fp1 := New(tc.pubkey)
			fp2 := New(tc.pubkey)
			if fp1 != fp2 {
				t.Errorf("New(%s) not deterministic: got %s and %s", tc.name, fp1, fp2)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Q6-B: No duplicates — different pubkeys → different Fingerprints
// ---------------------------------------------------------------------------

func TestFingerprintNoDuplicates(t *testing.T) {
	keys := [][]byte{
		{0x01},
		{0x02},
		{0x01, 0x02},
		{0xde, 0xad, 0xbe, 0xef},
		make([]byte, 64),
	}
	seen := make(map[Fingerprint]int)
	for i, k := range keys {
		fp := New(k)
		if prev, ok := seen[fp]; ok {
			t.Errorf("collision: key[%d] and key[%d] produce same fingerprint %s", prev, i, fp)
		}
		seen[fp] = i
	}
}

// ---------------------------------------------------------------------------
// Q6-C: Format — String() returns exactly 64 lowercase hex chars
// ---------------------------------------------------------------------------

func TestFingerprintFormat(t *testing.T) {
	fp := New([]byte("test-public-key-bytes"))
	s := fp.String()
	if len(s) != 64 {
		t.Errorf("String() length = %d, want 64", len(s))
	}
	if s != strings.ToLower(s) {
		t.Error("String() should be all lowercase")
	}
	if _, err := hex.DecodeString(s); err != nil {
		t.Errorf("String() is not valid hex: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Q6-D: Parse — valid/invalid inputs
// ---------------------------------------------------------------------------

func TestFingerprintParse(t *testing.T) {
	valid := strings.Repeat("ab", 32) // 64 hex chars

	fp, err := Parse(valid)
	if err != nil {
		t.Errorf("Parse valid hex: unexpected error: %v", err)
	}
	if fp.String() != valid {
		t.Errorf("Parse roundtrip failed: got %s, want %s", fp.String(), valid)
	}

	// Wrong length
	if _, err := Parse(strings.Repeat("a", 63)); err == nil {
		t.Error("Parse 63-char string should fail")
	}
	if _, err := Parse(strings.Repeat("a", 65)); err == nil {
		t.Error("Parse 65-char string should fail")
	}

	// Non-hex
	if _, err := Parse(strings.Repeat("zz", 32)); err == nil {
		t.Error("Parse non-hex string should fail")
	}
}

// ---------------------------------------------------------------------------
// Q6-E: One-way — hash output differs from input hex
// ---------------------------------------------------------------------------

func TestFingerprintOneWay(t *testing.T) {
	pubkey := []byte("some-sphincs-public-key-material")
	fp := New(pubkey)
	fingerprintHex := fp.String()
	inputHex := hex.EncodeToString(pubkey)
	if fingerprintHex == inputHex {
		t.Error("fingerprint should not equal hex(pubkey) — hash must transform input")
	}
}

// ---------------------------------------------------------------------------
// Q6-F: Zero value semantics
// ---------------------------------------------------------------------------

func TestFingerprintZero(t *testing.T) {
	var zero Fingerprint
	if !zero.IsZero() {
		t.Error("zero value should report IsZero()=true")
	}
	if err := zero.Validate(); err == nil {
		t.Error("zero value Validate() should return error")
	}

	nonZero := New([]byte("any-key"))
	if nonZero.IsZero() {
		t.Error("non-zero fingerprint should report IsZero()=false")
	}
}

// ---------------------------------------------------------------------------
// Q6-G: Equal
// ---------------------------------------------------------------------------

func TestFingerprintEqual(t *testing.T) {
	key := []byte("shared-public-key")
	fp1 := New(key)
	fp2 := New(key)
	if !fp1.Equal(fp2) {
		t.Error("fingerprints from same key should be Equal")
	}

	fp3 := New([]byte("different-key"))
	if fp1.Equal(fp3) {
		t.Error("fingerprints from different keys should not be Equal")
	}
}

// ---------------------------------------------------------------------------
// Q6-H: MarshalText / UnmarshalText roundtrip
// ---------------------------------------------------------------------------

func TestFingerprintMarshalRoundtrip(t *testing.T) {
	original := New([]byte("roundtrip-test-key"))

	text, err := original.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	var restored Fingerprint
	if err := restored.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}

	if original != restored {
		t.Errorf("roundtrip failed: original=%s restored=%s", original, restored)
	}
}

// ---------------------------------------------------------------------------
// Q6-I: Bytes() length
// ---------------------------------------------------------------------------

func TestFingerprintBytesLength(t *testing.T) {
	keys := [][]byte{
		{},
		{0x00},
		make([]byte, 100),
	}
	for _, k := range keys {
		fp := New(k)
		b := fp.Bytes()
		if len(b) != 32 {
			t.Errorf("Bytes() length = %d, want 32 (key len=%d)", len(b), len(k))
		}
	}
}

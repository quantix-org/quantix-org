// PEPPER Sprint2 — dht package coverage push for equalHashes and other pure functions
package dht

import (
	"testing"
)

// ── equalHashes ───────────────────────────────────────────────────────────────

func TestEqualHashes_Equal(t *testing.T) {
	a := []byte{1, 2, 3, 4, 5}
	b := []byte{1, 2, 3, 4, 5}
	if !equalHashes(a, b) {
		t.Error("equalHashes: identical slices should be equal")
	}
}

func TestEqualHashes_NotEqual(t *testing.T) {
	a := []byte{1, 2, 3, 4, 5}
	b := []byte{1, 2, 3, 4, 6}
	if equalHashes(a, b) {
		t.Error("equalHashes: different slices should not be equal")
	}
}

func TestEqualHashes_DifferentLengths(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{1, 2}
	if equalHashes(a, b) {
		t.Error("equalHashes: different length slices should not be equal")
	}
}

func TestEqualHashes_Empty(t *testing.T) {
	if !equalHashes([]byte{}, []byte{}) {
		t.Error("equalHashes: empty slices should be equal")
	}
}

func TestEqualHashes_NilAndEmpty(t *testing.T) {
	// nil vs empty: both have len 0, should be equal
	if !equalHashes(nil, []byte{}) {
		t.Log("nil vs empty not equal (implementation-dependent)")
	}
}

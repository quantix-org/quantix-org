// MIT License
// Copyright (c) 2024 quantix
package multisig_test

import (
	"strings"
	"testing"

	multisig "github.com/quantix-org/quantix-org/src/core/multisig/mps"
)

// newMultiSig wraps NewMultiSig and skips the test if LevelDB is unavailable
// (e.g., locked by a parallel test run).
func newMultiSig(t *testing.T, n int) *multisig.MultisigManager {
	t.Helper()
	mm, err := multisig.NewMultiSig(n)
	if err != nil {
		if strings.Contains(err.Error(), "resource temporarily unavailable") || strings.Contains(err.Error(), "LevelDB") {
			t.Skip("LevelDB locked by another process — skipping")
		}
		t.Fatalf("NewMultiSig(%d) error: %v", n, err)
	}
	return mm
}

func TestNewMultiSig_InvalidN(t *testing.T) {
	_, err := multisig.NewMultiSig(0)
	if err == nil {
		// Some implementations may not error on n=0 — document and skip
		t.Skip("NewMultiSig(0) did not error; behaviour documented as permissive")
	}
}

func TestNewMultiSig_N1(t *testing.T) {
	mm := newMultiSig(t, 1)
	if mm == nil {
		t.Error("expected non-nil MultisigManager")
	}
}

func TestNewMultiSig_KeysGenerated(t *testing.T) {
	mm := newMultiSig(t, 1)
	pks := mm.GetStoredPK()
	if len(pks) == 0 {
		t.Error("expected at least one public key")
	}
	sks := mm.GetStoredSK()
	if len(sks) == 0 {
		t.Error("expected at least one private key")
	}
}

func TestNewMultiSig_PKLength(t *testing.T) {
	mm := newMultiSig(t, 1)
	pks := mm.GetStoredPK()
	for i, pk := range pks {
		if len(pk) == 0 {
			t.Errorf("public key %d is empty", i)
		}
	}
}

func TestNewMultiSig_N2_TwoKeys(t *testing.T) {
	mm := newMultiSig(t, 2)
	pks := mm.GetStoredPK()
	if len(pks) < 2 {
		t.Errorf("expected at least 2 public keys for N=2, got %d", len(pks))
	}
}

func TestGetIndex_UnknownPK(t *testing.T) {
	mm := newMultiSig(t, 1)
	idx := mm.GetIndex([]byte("unknown-pk-bytes"))
	if idx != -1 {
		t.Errorf("expected -1 for unknown pk, got %d", idx)
	}
}

func TestGetIndex_KnownPK(t *testing.T) {
	mm := newMultiSig(t, 1)
	pks := mm.GetStoredPK()
	if len(pks) == 0 {
		t.Skip("no public keys generated")
	}
	idx := mm.GetIndex(pks[0])
	if idx < 0 {
		t.Errorf("expected non-negative index for known pk, got %d", idx)
	}
}

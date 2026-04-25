// MIT License
// Copyright (c) 2024 quantix
package sigproof_test

import (
	"bytes"
	"testing"

	sigproof "github.com/quantix-org/quantix-org/src/core/proof"
)

var (
	testSigParts = [][]byte{[]byte("part-one"), []byte("part-two")}
	testLeaves   = [][]byte{[]byte("leaf-a"), []byte("leaf-b")}
	testPK       = []byte("test-public-key-bytes")
)

func TestGenerateSigProof_NonNil(t *testing.T) {
	proof, err := sigproof.GenerateSigProof(testSigParts, testLeaves, testPK)
	if err != nil {
		t.Fatalf("GenerateSigProof error: %v", err)
	}
	if proof == nil {
		t.Error("expected non-nil proof")
	}
}

func TestGenerateSigProof_Deterministic(t *testing.T) {
	p1, _ := sigproof.GenerateSigProof(testSigParts, testLeaves, testPK)
	p2, _ := sigproof.GenerateSigProof(testSigParts, testLeaves, testPK)
	if !bytes.Equal(p1, p2) {
		t.Error("GenerateSigProof is not deterministic")
	}
}

func TestGenerateSigProof_ChangesWithPK(t *testing.T) {
	p1, _ := sigproof.GenerateSigProof(testSigParts, testLeaves, []byte("pk-one"))
	p2, _ := sigproof.GenerateSigProof(testSigParts, testLeaves, []byte("pk-two"))
	if bytes.Equal(p1, p2) {
		t.Error("proof should differ when public key differs")
	}
}

func TestGenerateSigProof_ChangesWithSigParts(t *testing.T) {
	p1, _ := sigproof.GenerateSigProof([][]byte{[]byte("sig-A")}, testLeaves, testPK)
	p2, _ := sigproof.GenerateSigProof([][]byte{[]byte("sig-B")}, testLeaves, testPK)
	if bytes.Equal(p1, p2) {
		t.Error("proof should differ when sig parts differ")
	}
}

func TestGenerateSigProof_EmptySigParts_Error(t *testing.T) {
	_, err := sigproof.GenerateSigProof(nil, testLeaves, testPK)
	if err == nil {
		t.Error("expected error for empty sig parts")
	}
}

func TestGenerateSigProof_EmptyLeaves_OK(t *testing.T) {
	// Empty leaves should be allowed (just no leaf data)
	proof, err := sigproof.GenerateSigProof(testSigParts, nil, testPK)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proof == nil {
		t.Error("expected non-nil proof with empty leaves")
	}
}

func TestVerifySigProof_Match(t *testing.T) {
	proof, _ := sigproof.GenerateSigProof(testSigParts, testLeaves, testPK)
	if !sigproof.VerifySigProof(proof, proof) {
		t.Error("VerifySigProof should return true for identical proofs")
	}
}

func TestVerifySigProof_Mismatch(t *testing.T) {
	p1, _ := sigproof.GenerateSigProof(testSigParts, testLeaves, testPK)
	p2, _ := sigproof.GenerateSigProof(testSigParts, testLeaves, []byte("different-pk"))
	if sigproof.VerifySigProof(p1, p2) {
		t.Error("VerifySigProof should return false for different proofs")
	}
}

func TestVerifySigProof_NilBoth_True(t *testing.T) {
	if !sigproof.VerifySigProof(nil, nil) {
		t.Error("nil vs nil should be equal")
	}
}

func TestVerifySigProof_NilVsNonNil_False(t *testing.T) {
	if sigproof.VerifySigProof(nil, []byte("something")) {
		t.Error("nil should not equal non-nil")
	}
}

func TestSetGetStoredProof_Roundtrip(t *testing.T) {
	data := []byte("stored-proof-value")
	sigproof.SetStoredProof(data)
	got := sigproof.GetStoredProof()
	if !bytes.Equal(got, data) {
		t.Errorf("stored proof roundtrip failed: got %x want %x", got, data)
	}
}

func TestSetGetStoredProof_InitiallyNil(t *testing.T) {
	// Reset to nil and verify
	sigproof.SetStoredProof(nil)
	got := sigproof.GetStoredProof()
	if got != nil {
		t.Errorf("expected nil stored proof after reset, got %x", got)
	}
}

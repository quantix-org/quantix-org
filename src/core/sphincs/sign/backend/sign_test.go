// MIT License
// Copyright (c) 2024 quantix
package sign_test

import (
	"bytes"
	"testing"

	backend "github.com/quantix-org/quantix-org/src/core/sphincs/sign/backend"
)

// ── SigCommitment ───────────────────────────────────────────────────────────

func TestSigCommitment_Length(t *testing.T) {
	c := backend.SigCommitment(
		[]byte("sig"), []byte("pk"), []byte("ts"), []byte("nonce"), []byte("msg"),
	)
	if len(c) != 32 {
		t.Errorf("SigCommitment length = %d, want 32", len(c))
	}
}

func TestSigCommitment_Deterministic(t *testing.T) {
	args := func() []byte {
		return backend.SigCommitment(
			[]byte("sig"), []byte("pk"), []byte("ts"), []byte("nonce"), []byte("msg"),
		)
	}
	if !bytes.Equal(args(), args()) {
		t.Error("SigCommitment should be deterministic")
	}
}

func TestSigCommitment_DifferentSig(t *testing.T) {
	c1 := backend.SigCommitment([]byte("sig-A"), []byte("pk"), []byte("ts"), []byte("nonce"), []byte("msg"))
	c2 := backend.SigCommitment([]byte("sig-B"), []byte("pk"), []byte("ts"), []byte("nonce"), []byte("msg"))
	if bytes.Equal(c1, c2) {
		t.Error("different sigBytes should produce different commitments")
	}
}

func TestSigCommitment_DifferentPK(t *testing.T) {
	c1 := backend.SigCommitment([]byte("sig"), []byte("pk-one"), []byte("ts"), []byte("nonce"), []byte("msg"))
	c2 := backend.SigCommitment([]byte("sig"), []byte("pk-two"), []byte("ts"), []byte("nonce"), []byte("msg"))
	if bytes.Equal(c1, c2) {
		t.Error("different pkBytes should produce different commitments")
	}
}

func TestSigCommitment_DifferentTimestamp(t *testing.T) {
	c1 := backend.SigCommitment([]byte("sig"), []byte("pk"), []byte("ts1"), []byte("nonce"), []byte("msg"))
	c2 := backend.SigCommitment([]byte("sig"), []byte("pk"), []byte("ts2"), []byte("nonce"), []byte("msg"))
	if bytes.Equal(c1, c2) {
		t.Error("different timestamps should produce different commitments")
	}
}

func TestSigCommitment_DifferentNonce(t *testing.T) {
	c1 := backend.SigCommitment([]byte("sig"), []byte("pk"), []byte("ts"), []byte("nonce-1"), []byte("msg"))
	c2 := backend.SigCommitment([]byte("sig"), []byte("pk"), []byte("ts"), []byte("nonce-2"), []byte("msg"))
	if bytes.Equal(c1, c2) {
		t.Error("different nonces should produce different commitments")
	}
}

func TestSigCommitment_DifferentMessage(t *testing.T) {
	c1 := backend.SigCommitment([]byte("sig"), []byte("pk"), []byte("ts"), []byte("nonce"), []byte("msg-A"))
	c2 := backend.SigCommitment([]byte("sig"), []byte("pk"), []byte("ts"), []byte("nonce"), []byte("msg-B"))
	if bytes.Equal(c1, c2) {
		t.Error("different messages should produce different commitments")
	}
}

func TestSigCommitment_NilInputs_NoPanel(t *testing.T) {
	// All-nil inputs should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SigCommitment panicked with nil inputs: %v", r)
		}
	}()
	c := backend.SigCommitment(nil, nil, nil, nil, nil)
	if len(c) != 32 {
		t.Errorf("SigCommitment with nil inputs length = %d, want 32", len(c))
	}
}

// ── CommitmentLeaf ──────────────────────────────────────────────────────────

func TestCommitmentLeaf_Length(t *testing.T) {
	leaf := backend.CommitmentLeaf([]byte("commitment-bytes"))
	if len(leaf) != 32 {
		t.Errorf("CommitmentLeaf length = %d, want 32", len(leaf))
	}
}

func TestCommitmentLeaf_Deterministic(t *testing.T) {
	c := []byte("test-commitment")
	l1 := backend.CommitmentLeaf(c)
	l2 := backend.CommitmentLeaf(c)
	if !bytes.Equal(l1, l2) {
		t.Error("CommitmentLeaf should be deterministic")
	}
}

func TestCommitmentLeaf_DifferentInputs(t *testing.T) {
	l1 := backend.CommitmentLeaf([]byte("commitment-A"))
	l2 := backend.CommitmentLeaf([]byte("commitment-B"))
	if bytes.Equal(l1, l2) {
		t.Error("different commitment inputs should yield different leaves")
	}
}

func TestCommitmentLeaf_NotEqualToInput(t *testing.T) {
	input := []byte("test-commitment-data")
	leaf := backend.CommitmentLeaf(input)
	if bytes.Equal(leaf, input) {
		t.Error("CommitmentLeaf output should differ from input")
	}
}

// ── VerifyCommitmentInRoot ──────────────────────────────────────────────────

func TestVerifyCommitmentInRoot_NilInputs_False(t *testing.T) {
	if backend.VerifyCommitmentInRoot(nil, nil) {
		t.Error("VerifyCommitmentInRoot(nil, nil) should return false")
	}
}

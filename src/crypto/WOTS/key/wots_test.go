// MIT License
// Copyright (c) 2024 quantix
package wots_test

import (
	"bytes"
	"testing"

	wots "github.com/quantix-org/quantix-org/src/crypto/WOTS/key"
)

// ── WOTSParams ──────────────────────────────────────────────────────────────

func TestNewWOTSParams_Values(t *testing.T) {
	p := wots.NewWOTSParams()
	if p.W != 16 {
		t.Errorf("W = %d, want 16", p.W)
	}
	if p.N != 32 {
		t.Errorf("N = %d, want 32", p.N)
	}
	if p.T != 67 {
		t.Errorf("T = %d, want 67 (T1=64 + T2=3)", p.T)
	}
	if p.T1 != 64 {
		t.Errorf("T1 = %d, want 64", p.T1)
	}
	if p.T2 != 3 {
		t.Errorf("T2 = %d, want 3", p.T2)
	}
}

func TestNewWOTSParams_TEqualsT1PlusT2(t *testing.T) {
	p := wots.NewWOTSParams()
	if p.T != p.T1+p.T2 {
		t.Errorf("T (%d) != T1+T2 (%d)", p.T, p.T1+p.T2)
	}
}

func TestNewWOTSParams_Deterministic(t *testing.T) {
	p1 := wots.NewWOTSParams()
	p2 := wots.NewWOTSParams()
	if p1.W != p2.W || p1.N != p2.N || p1.T != p2.T {
		t.Error("NewWOTSParams should be deterministic")
	}
}

// ── GenerateKeyPair ─────────────────────────────────────────────────────────

func TestGenerateKeyPair_NotNil(t *testing.T) {
	params := wots.NewWOTSParams()
	sk, pk, err := wots.GenerateKeyPair(params)
	if err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	if sk == nil {
		t.Error("private key is nil")
	}
	if pk == nil {
		t.Error("public key is nil")
	}
}

func TestGenerateKeyPair_KeyLengths(t *testing.T) {
	params := wots.NewWOTSParams()
	sk, pk, _ := wots.GenerateKeyPair(params)
	if len(sk.Key) != params.T {
		t.Errorf("private key has %d components, want %d", len(sk.Key), params.T)
	}
	if len(pk.Key) != params.T {
		t.Errorf("public key has %d components, want %d", len(pk.Key), params.T)
	}
}

func TestGenerateKeyPair_Unique(t *testing.T) {
	params := wots.NewWOTSParams()
	_, pk1, _ := wots.GenerateKeyPair(params)
	_, pk2, _ := wots.GenerateKeyPair(params)
	// Two independently generated key pairs should differ
	if bytes.Equal(pk1.Key[0], pk2.Key[0]) {
		t.Error("two key pairs should not have identical public keys")
	}
}

// ── Sign / Verify ───────────────────────────────────────────────────────────

func TestSign_Verify_Valid(t *testing.T) {
	params := wots.NewWOTSParams()
	sk, pk, err := wots.GenerateKeyPair(params)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	msg := []byte("quantix-test-message")
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := pk.Verify(msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("expected Verify to return true for valid sig")
	}
}

func TestSign_Verify_WrongMessage(t *testing.T) {
	params := wots.NewWOTSParams()
	sk, pk, _ := wots.GenerateKeyPair(params)

	sig, _ := sk.Sign([]byte("original-message"))
	ok, _ := pk.Verify([]byte("tampered-message"), sig)
	if ok {
		t.Error("Verify should return false for wrong message")
	}
}

func TestSign_Verify_WrongKey(t *testing.T) {
	params := wots.NewWOTSParams()
	sk1, _, _ := wots.GenerateKeyPair(params)
	_, pk2, _ := wots.GenerateKeyPair(params)

	msg := []byte("test-message")
	sig, _ := sk1.Sign(msg)
	ok, _ := pk2.Verify(msg, sig)
	if ok {
		t.Error("Verify should return false when verifying with wrong public key")
	}
}

func TestSign_NotNil(t *testing.T) {
	params := wots.NewWOTSParams()
	sk, _, _ := wots.GenerateKeyPair(params)
	sig, err := sk.Sign([]byte("msg"))
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}
	if sig == nil {
		t.Error("signature is nil")
	}
}

func TestSign_DifferentMessages_DifferentSigs(t *testing.T) {
	params := wots.NewWOTSParams()
	sk, _, _ := wots.GenerateKeyPair(params)

	sig1, _ := sk.Sign([]byte("msg-alpha"))
	sig2, _ := sk.Sign([]byte("msg-beta"))
	if bytes.Equal(sig1.Sig[0], sig2.Sig[0]) {
		t.Error("different messages should produce different signatures")
	}
}

// ── KeyManager ──────────────────────────────────────────────────────────────

func TestNewKeyManager_NotNil(t *testing.T) {
	km, err := wots.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager error: %v", err)
	}
	if km == nil {
		t.Error("expected non-nil KeyManager")
	}
}

func TestKeyManager_SignAndRotate_NotNil(t *testing.T) {
	km, err := wots.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager error: %v", err)
	}

	sig, currentPK, nextPK, err := km.SignAndRotate([]byte("test-message"))
	if err != nil {
		t.Fatalf("SignAndRotate error: %v", err)
	}
	if sig == nil {
		t.Error("signature is nil")
	}
	if currentPK == nil {
		t.Error("currentPK is nil")
	}
	if nextPK == nil {
		t.Error("nextPK is nil")
	}
}

func TestKeyManager_SignAndRotate_PKRotates(t *testing.T) {
	km, _ := wots.NewKeyManager()
	_, pk1, _, _ := km.SignAndRotate([]byte("msg1"))
	_, pk2, _, _ := km.SignAndRotate([]byte("msg2"))
	// After rotation, the current PK on the second call should be the next PK from the first
	// At minimum, verify two public keys are returned and they differ
	if bytes.Equal(pk1.Key[0], pk2.Key[0]) {
		t.Error("consecutive SignAndRotate calls should use different current public keys")
	}
}

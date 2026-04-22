// MIT License
// Copyright (c) 2024 quantix-org

package key

import (
	"bytes"
	"testing"
)

// ============================================================
// KEY MANAGER INIT
// ============================================================

// TestNewKeyManager verifies KeyManager initializes without error
func TestNewKeyManager(t *testing.T) {
	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager() failed: %v", err)
	}
	if km == nil {
		t.Fatal("NewKeyManager() returned nil")
	}
	if km.Params == nil {
		t.Fatal("KeyManager.Params is nil")
	}
	if km.Params.Params == nil {
		t.Fatal("KeyManager.Params.Params is nil")
	}
}

// TestGetSPHINCSParameters verifies parameters are accessible
func TestGetSPHINCSParameters(t *testing.T) {
	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager() failed: %v", err)
	}
	p := km.GetSPHINCSParameters()
	if p == nil {
		t.Fatal("GetSPHINCSParameters() returned nil")
	}
}

// ============================================================
// KEY GENERATION
// ============================================================

// TestGenerateKey verifies keypair generation succeeds and fields are non-empty
func TestGenerateKey(t *testing.T) {
	km, _ := NewKeyManager()
	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	if sk == nil {
		t.Fatal("GenerateKey() returned nil SK")
	}
	if pk == nil {
		t.Fatal("GenerateKey() returned nil PK")
	}

	// All fields must be non-empty
	if len(sk.SKseed) == 0 {
		t.Error("SK.SKseed is empty")
	}
	if len(sk.SKprf) == 0 {
		t.Error("SK.SKprf is empty")
	}
	if len(sk.PKseed) == 0 {
		t.Error("SK.PKseed is empty")
	}
	if len(sk.PKroot) == 0 {
		t.Error("SK.PKroot is empty")
	}
	if len(pk.PKseed) == 0 {
		t.Error("PK.PKseed is empty")
	}
	if len(pk.PKroot) == 0 {
		t.Error("PK.PKroot is empty")
	}
}

// TestGenerateKeyUniqueness verifies two generated keypairs are different
func TestGenerateKeyUniqueness(t *testing.T) {
	km, _ := NewKeyManager()

	sk1, pk1, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("first GenerateKey() failed: %v", err)
	}
	sk2, pk2, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("second GenerateKey() failed: %v", err)
	}

	if bytes.Equal(sk1.SKseed, sk2.SKseed) {
		t.Error("two generated SK.SKseed are identical — RNG may be broken")
	}
	if bytes.Equal(pk1.PKroot, pk2.PKroot) {
		t.Error("two generated PK.PKroot are identical — RNG may be broken")
	}
}

// TestSKPKConsistency verifies SK and PK share the same PKseed and PKroot
func TestSKPKConsistency(t *testing.T) {
	km, _ := NewKeyManager()
	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	if !bytes.Equal(sk.PKseed, pk.PKseed) {
		t.Error("SK.PKseed does not match PK.PKseed")
	}
	if !bytes.Equal(sk.PKroot, pk.PKroot) {
		t.Error("SK.PKroot does not match PK.PKroot")
	}
}

// ============================================================
// SERIALIZATION / DESERIALIZATION
// ============================================================

// TestSerializeDeserializeRoundtrip verifies keys survive a full serialize→deserialize round
func TestSerializeDeserializeRoundtrip(t *testing.T) {
	km, _ := NewKeyManager()
	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		t.Fatalf("SerializeKeyPair() failed: %v", err)
	}
	if len(skBytes) == 0 {
		t.Fatal("SerializeKeyPair() produced empty skBytes")
	}
	if len(pkBytes) == 0 {
		t.Fatal("SerializeKeyPair() produced empty pkBytes")
	}

	dsk, dpk, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		t.Fatalf("DeserializeKeyPair() failed: %v", err)
	}

	// Deserialized keys must match original
	if !bytes.Equal(dsk.SKseed, sk.SKseed) {
		t.Error("deserialized SK.SKseed does not match original")
	}
	if !bytes.Equal(dsk.SKprf, sk.SKprf) {
		t.Error("deserialized SK.SKprf does not match original")
	}
	if !bytes.Equal(dsk.PKseed, sk.PKseed) {
		t.Error("deserialized SK.PKseed does not match original")
	}
	if !bytes.Equal(dsk.PKroot, sk.PKroot) {
		t.Error("deserialized SK.PKroot does not match original")
	}
	if !bytes.Equal(dpk.PKseed, pk.PKseed) {
		t.Error("deserialized PK.PKseed does not match original")
	}
	if !bytes.Equal(dpk.PKroot, pk.PKroot) {
		t.Error("deserialized PK.PKroot does not match original")
	}
}

// TestDeserializePublicKeyOnly verifies PK-only deserialization works
func TestDeserializePublicKeyOnly(t *testing.T) {
	km, _ := NewKeyManager()
	_, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	pkBytes, err := pk.SerializePK()
	if err != nil {
		t.Fatalf("SerializePK() failed: %v", err)
	}

	dpk, err := km.DeserializePublicKey(pkBytes)
	if err != nil {
		t.Fatalf("DeserializePublicKey() failed: %v", err)
	}

	if !bytes.Equal(dpk.PKseed, pk.PKseed) {
		t.Error("deserialized PK.PKseed does not match original")
	}
	if !bytes.Equal(dpk.PKroot, pk.PKroot) {
		t.Error("deserialized PK.PKroot does not match original")
	}
}

// TestDeserializeEmptySkBytes verifies empty SK bytes are rejected
func TestDeserializeEmptySkBytes(t *testing.T) {
	km, _ := NewKeyManager()
	_, pk, _ := km.GenerateKey()
	pkBytes, _ := pk.SerializePK()

	_, _, err := km.DeserializeKeyPair([]byte{}, pkBytes)
	if err == nil {
		t.Error("expected error for empty skBytes, got nil")
	}
}

// TestDeserializePublicKeyEmpty verifies empty PK bytes are rejected
func TestDeserializePublicKeyEmpty(t *testing.T) {
	km, _ := NewKeyManager()
	_, err := km.DeserializePublicKey([]byte{})
	if err == nil {
		t.Error("expected error for empty pkBytes, got nil")
	}
}

// TestSerializeNilKeys verifies nil keys are rejected gracefully
func TestSerializeNilKeys(t *testing.T) {
	km, _ := NewKeyManager()

	_, _, err := km.SerializeKeyPair(nil, nil)
	if err == nil {
		t.Error("expected error for nil SK and PK, got nil")
	}
}

// TestSerializeSKNil verifies nil SK is rejected
func TestSerializeSKNil(t *testing.T) {
	var sk *SPHINCS_SK
	_, err := sk.SerializeSK()
	if err == nil {
		t.Error("expected error for nil SK, got nil")
	}
}

// ============================================================
// KEY SIZE EXPECTATIONS
// ============================================================

// TestKeyByteSizes verifies key sizes are within expected STHINCS ranges
func TestKeyByteSizes(t *testing.T) {
	km, _ := NewKeyManager()
	sk, pk, _ := km.GenerateKey()
	skBytes, pkBytes, _ := km.SerializeKeyPair(sk, pk)

	// SPHINCS+ / STHINCS key sizes depend on parameter set.
	// Typical ranges: PK ~32-64 bytes, SK ~64-128 bytes
	if len(pkBytes) < 32 {
		t.Errorf("pkBytes too short: %d bytes (expected >= 32)", len(pkBytes))
	}
	if len(skBytes) < 64 {
		t.Errorf("skBytes too short: %d bytes (expected >= 64)", len(skBytes))
	}
	// SK should be larger than PK (contains PKseed + PKroot embedded)
	if len(skBytes) < len(pkBytes) {
		t.Errorf("skBytes (%d) shorter than pkBytes (%d) — unexpected", len(skBytes), len(pkBytes))
	}
}

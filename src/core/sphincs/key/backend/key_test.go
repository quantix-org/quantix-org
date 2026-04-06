// MIT License
// Copyright (c) 2024 quantix
package key_test

import (
	"bytes"
	"testing"

	key "github.com/ramseyauron/quantix/src/core/sphincs/key/backend"
)

// ── NewKeyManager ───────────────────────────────────────────────────────────

func TestNewKeyManager_NotNil(t *testing.T) {
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager error: %v", err)
	}
	if km == nil {
		t.Error("expected non-nil KeyManager")
	}
}

func TestNewKeyManager_HasParams(t *testing.T) {
	km, _ := key.NewKeyManager()
	if km.GetSPHINCSParameters() == nil {
		t.Error("KeyManager should have non-nil SPHINCS parameters")
	}
}

func TestNewKeyManager_ParamsHaveN(t *testing.T) {
	km, _ := key.NewKeyManager()
	p := km.GetSPHINCSParameters()
	if p.Params.N == 0 {
		t.Error("SPHINCS parameters N should be non-zero")
	}
}

// ── GenerateKey ─────────────────────────────────────────────────────────────

func TestGenerateKey_NotNil(t *testing.T) {
	km, _ := key.NewKeyManager()
	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}
	if sk == nil {
		t.Error("private key is nil")
	}
	if pk == nil {
		t.Error("public key is nil")
	}
}

func TestGenerateKey_SKFieldsNonEmpty(t *testing.T) {
	km, _ := key.NewKeyManager()
	sk, _, _ := km.GenerateKey()
	if len(sk.SKseed) == 0 {
		t.Error("SKseed is empty")
	}
	if len(sk.SKprf) == 0 {
		t.Error("SKprf is empty")
	}
	if len(sk.PKseed) == 0 {
		t.Error("PKseed is empty")
	}
	if len(sk.PKroot) == 0 {
		t.Error("PKroot is empty")
	}
}

func TestGenerateKey_Unique(t *testing.T) {
	km, _ := key.NewKeyManager()
	sk1, _, _ := km.GenerateKey()
	sk2, _, _ := km.GenerateKey()
	// Two generated key pairs should not share SKseed
	if bytes.Equal(sk1.SKseed, sk2.SKseed) {
		t.Error("two independent key pairs should not share SKseed")
	}
}

func TestGenerateKey_PKFieldsNonEmpty(t *testing.T) {
	km, _ := key.NewKeyManager()
	_, pk, _ := km.GenerateKey()
	if len(pk.PKseed) == 0 {
		t.Error("PK.PKseed is empty")
	}
	if len(pk.PKroot) == 0 {
		t.Error("PK.PKroot is empty")
	}
}

// ── SerializeSK ─────────────────────────────────────────────────────────────

func TestSerializeSK_NonEmpty(t *testing.T) {
	km, _ := key.NewKeyManager()
	sk, _, _ := km.GenerateKey()
	skBytes, err := sk.SerializeSK()
	if err != nil {
		t.Fatalf("SerializeSK error: %v", err)
	}
	if len(skBytes) == 0 {
		t.Error("serialized SK is empty")
	}
}

func TestSerializeSK_Deterministic(t *testing.T) {
	km, _ := key.NewKeyManager()
	sk, _, _ := km.GenerateKey()
	b1, _ := sk.SerializeSK()
	b2, _ := sk.SerializeSK()
	if !bytes.Equal(b1, b2) {
		t.Error("SerializeSK should be deterministic")
	}
}

// ── SerializeKeyPair / DeserializeKeyPair ────────────────────────────────────

func TestSerializeKeyPair_RoundtripPK(t *testing.T) {
	km, _ := key.NewKeyManager()
	sk, pk, _ := km.GenerateKey()

	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		t.Fatalf("SerializeKeyPair error: %v", err)
	}
	if len(skBytes) == 0 || len(pkBytes) == 0 {
		t.Error("serialized key bytes should not be empty")
	}

	_, pkDeserialized, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		t.Fatalf("DeserializeKeyPair error: %v", err)
	}

	// Public key fields should roundtrip
	if !bytes.Equal(pk.PKseed, pkDeserialized.PKseed) {
		t.Error("PKseed did not roundtrip through serialization")
	}
	if !bytes.Equal(pk.PKroot, pkDeserialized.PKroot) {
		t.Error("PKroot did not roundtrip through serialization")
	}
}

func TestDeserializeKeyPair_InvalidSKBytes_Error(t *testing.T) {
	km, _ := key.NewKeyManager()
	_, _, err := km.DeserializeKeyPair([]byte("bad"), []byte("bad"))
	if err == nil {
		t.Error("expected error for invalid SK bytes")
	}
}

// ── DeserializePublicKey ─────────────────────────────────────────────────────

func TestDeserializePublicKey_Roundtrip(t *testing.T) {
	km, _ := key.NewKeyManager()
	sk, pk, _ := km.GenerateKey()
	_, pkBytes, _ := km.SerializeKeyPair(sk, pk)

	pkDeserialized, err := km.DeserializePublicKey(pkBytes)
	if err != nil {
		t.Fatalf("DeserializePublicKey error: %v", err)
	}
	if pkDeserialized == nil {
		t.Error("deserialized PK is nil")
	}
	if !bytes.Equal(pk.PKseed, pkDeserialized.PKseed) {
		t.Error("PKseed did not roundtrip via DeserializePublicKey")
	}
}

func TestDeserializePublicKey_InvalidBytes_Error(t *testing.T) {
	km, _ := key.NewKeyManager()
	_, err := km.DeserializePublicKey([]byte("garbage"))
	if err == nil {
		t.Error("expected error for invalid public key bytes")
	}
}

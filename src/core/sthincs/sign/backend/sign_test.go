// MIT License
// Copyright (c) 2024 quantix-org

package sign

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	key "github.com/quantix-org/quantix-org/src/core/sthincs/key/backend"
	"github.com/syndtr/goleveldb/leveldb"
)

// ============================================================
// HELPERS
// ============================================================

// testDB opens a temporary LevelDB instance and returns a cleanup func
func testDB(t *testing.T) (*leveldb.DB, func()) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "testdb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("failed to open test LevelDB: %v", err)
	}
	return db, func() {
		db.Close()
		os.RemoveAll(dir)
	}
}

// testManager creates a fully initialized STHINCSManager backed by a temp LevelDB
func testManager(t *testing.T) (*STHINCSManager, func()) {
	t.Helper()
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager() failed: %v", err)
	}
	db, cleanup := testDB(t)
	params := km.GetSPHINCSParameters()
	mgr := NewSTHINCSManager(db, km, params)
	return mgr, cleanup
}

// generateKeypair returns a deserialized SK/PK pair for signing tests
func generateKeypair(t *testing.T, km *key.KeyManager) (*key.SPHINCS_SK, interface{}) {
	t.Helper()
	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		t.Fatalf("SerializeKeyPair() failed: %v", err)
	}
	dsk, dpk, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		t.Fatalf("DeserializeKeyPair() failed: %v", err)
	}
	_ = dsk
	return sk, dpk
}

// ============================================================
// CONSTRUCTOR TESTS
// ============================================================

// TestNewSTHINCSManager verifies manager initializes correctly
func TestNewSTHINCSManager(t *testing.T) {
	mgr, cleanup := testManager(t)
	defer cleanup()
	if mgr == nil {
		t.Fatal("NewSTHINCSManager() returned nil")
	}
}

// TestNewSTHINCSManagerNilPanics verifies nil params cause panic
func TestNewSTHINCSManagerNilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil KeyManager/params, got none")
		}
	}()
	NewSTHINCSManager(nil, nil, nil)
}

// ============================================================
// TIMESTAMP + NONCE REPLAY PREVENTION
// ============================================================

// TestStoreAndCheckTimestampNonce verifies store → check roundtrip
func TestStoreAndCheckTimestampNonce(t *testing.T) {
	mgr, cleanup := testManager(t)
	defer cleanup()

	ts := []byte{0x00, 0x00, 0x00, 0x00, 0x67, 0xA1, 0xB2, 0xC3}
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	// Not seen yet
	exists, err := mgr.CheckTimestampNonce(ts, nonce)
	if err != nil {
		t.Fatalf("CheckTimestampNonce() error: %v", err)
	}
	if exists {
		t.Fatal("fresh ts/nonce should not exist yet")
	}

	// Store it
	if err := mgr.StoreTimestampNonce(ts, nonce); err != nil {
		t.Fatalf("StoreTimestampNonce() error: %v", err)
	}

	// Now it should exist
	exists, err = mgr.CheckTimestampNonce(ts, nonce)
	if err != nil {
		t.Fatalf("CheckTimestampNonce() after store error: %v", err)
	}
	if !exists {
		t.Fatal("ts/nonce should exist after storing")
	}
}

// TestTimestampNonceDifferentNonces verifies different nonces are independent
func TestTimestampNonceDifferentNonces(t *testing.T) {
	mgr, cleanup := testManager(t)
	defer cleanup()

	ts := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	nonce1 := bytes.Repeat([]byte{0xAA}, 16)
	nonce2 := bytes.Repeat([]byte{0xBB}, 16)

	_ = mgr.StoreTimestampNonce(ts, nonce1)

	exists, _ := mgr.CheckTimestampNonce(ts, nonce2)
	if exists {
		t.Error("different nonce should not match stored ts/nonce pair")
	}
}

// TestTimestampNonceSameTimeDifferentNonce verifies same ts + different nonce = fresh
func TestTimestampNonceSameTimeDifferentNonce(t *testing.T) {
	mgr, cleanup := testManager(t)
	defer cleanup()

	ts := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	n1 := make([]byte, 16)
	n2 := make([]byte, 16)
	n2[0] = 0x01 // different by 1 byte

	_ = mgr.StoreTimestampNonce(ts, n1)
	exists, _ := mgr.CheckTimestampNonce(ts, n2)
	if exists {
		t.Error("ts with different nonce should not match")
	}
}

// TestTimestampNonceNoDBErrors verifies nil DB returns errors
func TestTimestampNonceNoDBErrors(t *testing.T) {
	km, _ := key.NewKeyManager()
	params := km.GetSPHINCSParameters()
	mgr := NewSTHINCSManager(nil, km, params)

	ts := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	nonce := make([]byte, 16)

	if err := mgr.StoreTimestampNonce(ts, nonce); err == nil {
		t.Error("expected error storing to nil DB")
	}
	if _, err := mgr.CheckTimestampNonce(ts, nonce); err == nil {
		t.Error("expected error checking nil DB")
	}
}

// ============================================================
// SIGNATURE HASH REPLAY PREVENTION
// ============================================================

// TestComputeSignatureHash verifies hash is deterministic and non-empty
func TestComputeSignatureHash(t *testing.T) {
	mgr, cleanup := testManager(t)
	defer cleanup()

	data := []byte("test-signature-data")
	h1 := mgr.ComputeSignatureHash(data)
	h2 := mgr.ComputeSignatureHash(data)

	if len(h1) == 0 {
		t.Fatal("ComputeSignatureHash returned empty hash")
	}
	if !bytes.Equal(h1, h2) {
		t.Error("ComputeSignatureHash not deterministic for same input")
	}
}

// TestComputeSignatureHashDifferentInputs verifies different data yields different hashes
func TestComputeSignatureHashDifferentInputs(t *testing.T) {
	mgr, cleanup := testManager(t)
	defer cleanup()

	h1 := mgr.ComputeSignatureHash([]byte("data-A"))
	h2 := mgr.ComputeSignatureHash([]byte("data-B"))

	if bytes.Equal(h1, h2) {
		t.Error("different inputs should produce different hashes")
	}
}

// TestStoreAndCheckSignatureHash verifies store → detect replay
func TestStoreAndCheckSignatureHash(t *testing.T) {
	mgr, cleanup := testManager(t)
	defer cleanup()

	sigBytes := []byte("fake-sig-bytes-for-testing")

	// Not seen yet
	seen, err := mgr.CheckSignatureHash(sigBytes)
	if err != nil {
		t.Fatalf("CheckSignatureHash() error: %v", err)
	}
	if seen {
		t.Fatal("fresh signature hash should not exist")
	}

	// Store it
	if err := mgr.StoreSignatureHash(sigBytes); err != nil {
		t.Fatalf("StoreSignatureHash() error: %v", err)
	}

	// Now should be detected as replay
	seen, err = mgr.CheckSignatureHash(sigBytes)
	if err != nil {
		t.Fatalf("CheckSignatureHash() after store error: %v", err)
	}
	if !seen {
		t.Fatal("signature hash should be detected as replay after storing")
	}
}

// TestSignatureHashDifferentSigsIndependent verifies different sigs are independent
func TestSignatureHashDifferentSigsIndependent(t *testing.T) {
	mgr, cleanup := testManager(t)
	defer cleanup()

	sig1 := []byte("signature-one")
	sig2 := []byte("signature-two")

	_ = mgr.StoreSignatureHash(sig1)

	seen, _ := mgr.CheckSignatureHash(sig2)
	if seen {
		t.Error("different signature should not be flagged as replay")
	}
}

// TestSignatureHashNilDBErrors verifies nil DB returns errors
func TestSignatureHashNilDBErrors(t *testing.T) {
	km, _ := key.NewKeyManager()
	params := km.GetSPHINCSParameters()
	mgr := NewSTHINCSManager(nil, km, params)

	if err := mgr.StoreSignatureHash([]byte("sig")); err == nil {
		t.Error("expected error storing to nil DB")
	}
	if _, err := mgr.CheckSignatureHash([]byte("sig")); err == nil {
		t.Error("expected error checking nil DB")
	}
}

// ============================================================
// PUBLIC KEY REGISTRY
// ============================================================

// TestPublicKeyRegistryRegisterAndLookup verifies registration and lookup
func TestPublicKeyRegistryRegisterAndLookup(t *testing.T) {
	registry := NewPublicKeyRegistry()

	pkBytes := []byte("fake-public-key")
	registry.Register("alice", pkBytes)

	got, ok := registry.Lookup("alice")
	if !ok {
		t.Fatal("expected to find 'alice' in registry")
	}
	if !bytes.Equal(got, pkBytes) {
		t.Error("retrieved pkBytes does not match registered value")
	}
}

// TestPublicKeyRegistryUnknownIdentity verifies unknown identity returns false
func TestPublicKeyRegistryUnknownIdentity(t *testing.T) {
	registry := NewPublicKeyRegistry()

	_, ok := registry.Lookup("eve")
	if ok {
		t.Error("unknown identity should not be found in registry")
	}
}

// TestPublicKeyRegistryTOFU verifies first registration wins (TOFU)
func TestPublicKeyRegistryTOFU(t *testing.T) {
	registry := NewPublicKeyRegistry()

	original := []byte("original-key")
	attacker := []byte("attacker-key")

	registry.Register("alice", original)
	registry.Register("alice", attacker) // should be rejected (TOFU)

	got, _ := registry.Lookup("alice")
	if !bytes.Equal(got, original) {
		t.Error("TOFU violation: second registration should not overwrite first")
	}
}

// TestPublicKeyRegistryMultipleIdentities verifies independent identities
func TestPublicKeyRegistryMultipleIdentities(t *testing.T) {
	registry := NewPublicKeyRegistry()

	registry.Register("alice", []byte("alice-key"))
	registry.Register("bob", []byte("bob-key"))

	a, _ := registry.Lookup("alice")
	b, _ := registry.Lookup("bob")

	if bytes.Equal(a, b) {
		t.Error("alice and bob should have different keys")
	}
}

// TestVerifyIdentityKnown verifies known identity passes
func TestVerifyIdentityKnown(t *testing.T) {
	registry := NewPublicKeyRegistry()
	pkBytes := []byte("some-public-key")
	registry.Register("alice", pkBytes)

	if !registry.VerifyIdentity("alice", pkBytes) {
		t.Error("VerifyIdentity should return true for matching identity+key")
	}
}

// TestVerifyIdentityWrongKey verifies wrong key fails
func TestVerifyIdentityWrongKey(t *testing.T) {
	registry := NewPublicKeyRegistry()
	registry.Register("alice", []byte("real-key"))

	if registry.VerifyIdentity("alice", []byte("wrong-key")) {
		t.Error("VerifyIdentity should return false for mismatched key")
	}
}

// TestVerifyIdentityUnknown verifies unknown identity fails
func TestVerifyIdentityUnknown(t *testing.T) {
	registry := NewPublicKeyRegistry()

	if registry.VerifyIdentity("nobody", []byte("any-key")) {
		t.Error("VerifyIdentity should return false for unknown identity")
	}
}

// ============================================================
// SIGN + VERIFY END-TO-END
// ============================================================

// TestSignAndVerify verifies the full sign→verify flow
func TestSignAndVerify(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	km, _ := key.NewKeyManager()
	params := km.GetSPHINCSParameters()
	mgr := NewSTHINCSManager(db, km, params)

	sk, pk, _ := km.GenerateKey()
	skBytes, pkBytes, _ := km.SerializeKeyPair(sk, pk)
	dsk, dpk, _ := km.DeserializeKeyPair(skBytes, pkBytes)

	message := []byte("test transaction")

	sig, merkleRoot, timestamp, nonce, commitment, err := mgr.SignMessage(message, dsk, dpk)
	if err != nil {
		t.Fatalf("SignMessage() failed: %v", err)
	}
	if sig == nil {
		t.Fatal("SignMessage() returned nil sig")
	}
	if merkleRoot == nil {
		t.Fatal("SignMessage() returned nil merkleRoot")
	}
	if len(timestamp) == 0 {
		t.Fatal("SignMessage() returned empty timestamp")
	}
	if len(nonce) == 0 {
		t.Fatal("SignMessage() returned empty nonce")
	}
	if len(commitment) == 0 {
		t.Fatal("SignMessage() returned empty commitment")
	}

	// Verify the signature locally
	valid := mgr.VerifySignature(message, timestamp, nonce, sig, dpk, merkleRoot, commitment, false)
	if !valid {
		t.Fatal("VerifySignature() returned false for valid signature")
	}
}

// TestSignAndVerifyWrongMessage verifies tampered message fails verification
func TestSignAndVerifyWrongMessage(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	km, _ := key.NewKeyManager()
	params := km.GetSPHINCSParameters()
	mgr := NewSTHINCSManager(db, km, params)

	sk, pk, _ := km.GenerateKey()
	skBytes, pkBytes, _ := km.SerializeKeyPair(sk, pk)
	dsk, dpk, _ := km.DeserializeKeyPair(skBytes, pkBytes)

	message := []byte("original message")
	tampered := []byte("tampered message")

	sig, merkleRoot, timestamp, nonce, commitment, err := mgr.SignMessage(message, dsk, dpk)
	if err != nil {
		t.Fatalf("SignMessage() failed: %v", err)
	}

	// Verify with tampered message — should fail
	valid := mgr.VerifySignature(tampered, timestamp, nonce, sig, dpk, merkleRoot, commitment, false)
	if valid {
		t.Fatal("VerifySignature() should return false for tampered message")
	}
}

// TestSignatureNonceUniqueness verifies two SignMessage calls produce different nonces
func TestSignatureNonceUniqueness(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	km, _ := key.NewKeyManager()
	params := km.GetSPHINCSParameters()
	mgr := NewSTHINCSManager(db, km, params)

	sk, pk, _ := km.GenerateKey()
	skBytes, pkBytes, _ := km.SerializeKeyPair(sk, pk)
	dsk, dpk, _ := km.DeserializeKeyPair(skBytes, pkBytes)

	message := []byte("same message")

	_, _, _, nonce1, _, err1 := mgr.SignMessage(message, dsk, dpk)
	_, _, _, nonce2, _, err2 := mgr.SignMessage(message, dsk, dpk)

	if err1 != nil || err2 != nil {
		t.Fatalf("SignMessage() errors: %v, %v", err1, err2)
	}
	if bytes.Equal(nonce1, nonce2) {
		t.Error("two SignMessage calls produced identical nonces — RNG may be broken")
	}
}

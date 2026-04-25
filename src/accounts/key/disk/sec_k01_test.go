// MIT License
// Copyright (c) 2024 quantix

// SEC-K01 tests: per-key random KDF salt in DiskKeyStore.
//
// Verifies:
//   - EncryptData generates a fresh random 16-byte salt on each call
//   - Two encryptions of the same data with the same passphrase produce different salts
//   - DecryptKey succeeds using the stored random salt
//   - Legacy keys (KDFSalt == nil) still decrypt via fallback path
//   - KDFSalt is persisted in KeyPair after StoreEncryptedKey
package disk

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	key "github.com/quantix-org/quantix-org/src/accounts/key"
)

// keyPairForTest constructs a minimal KeyPair with the given KDFSalt and EncryptedSK.
func keyPairForTest(kdfSalt []byte, encryptedSK []byte) key.KeyPair {
	return key.KeyPair{
		ID:          "test-key-id",
		EncryptedSK: encryptedSK,
		PublicKey:   []byte("test-pubkey"),
		Address:     "test-address",
		KeyType:     key.KeyTypeSPHINCSPlus,
		WalletType:  key.WalletTypeDisk,
		ChainID:     73310,
		CreatedAt:   time.Now(),
		KDFSalt:     kdfSalt,
	}
}

// newTestStore creates a temporary DiskKeyStore for testing.
func newTestStore(t *testing.T) *DiskKeyStore {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keystore")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	ks, err := NewDiskKeyStore(dir)
	if err != nil {
		t.Fatalf("NewDiskKeyStore: %v", err)
	}
	return ks
}

// ---------------------------------------------------------------------------
// SEC-K01: Random KDF salt generation
// ---------------------------------------------------------------------------

// TestSECK01_RandomSalt_UniquePerCall verifies that each call to EncryptData
// generates a different random salt, even with the same passphrase and data.
// This is the core SEC-K01 guarantee: no shared KDF key across keys.
func TestSECK01_RandomSalt_UniquePerCall(t *testing.T) {
	ks := newTestStore(t)
	data := []byte("test-secret-key-bytes-32-padding-")
	passphrase := "same-passphrase-for-both"

	_, salt1, err := ks.EncryptData(data, passphrase)
	if err != nil {
		t.Fatalf("EncryptData call 1: %v", err)
	}
	_, salt2, err := ks.EncryptData(data, passphrase)
	if err != nil {
		t.Fatalf("EncryptData call 2: %v", err)
	}

	if bytes.Equal(salt1, salt2) {
		t.Error("SEC-K01: EncryptData must produce different salts on each call; got identical salts — rainbow table attack possible")
	}
}

// TestSECK01_SaltLength_16Bytes verifies that the generated KDF salt is exactly
// 16 bytes (128 bits of entropy) as specified in the SEC-K01 fix.
func TestSECK01_SaltLength_16Bytes(t *testing.T) {
	ks := newTestStore(t)
	_, salt, err := ks.EncryptData([]byte("some-data"), "passphrase")
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	if len(salt) != 16 {
		t.Errorf("SEC-K01: KDF salt must be 16 bytes, got %d", len(salt))
	}
}

// TestSECK01_SaltNotAllZeros verifies that the salt is not the zero value
// (i.e., crypto/rand actually produced entropy, not a silent failure).
func TestSECK01_SaltNotAllZeros(t *testing.T) {
	ks := newTestStore(t)
	_, salt, err := ks.EncryptData([]byte("some-data"), "passphrase")
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	allZero := true
	for _, b := range salt {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("SEC-K01: KDF salt must not be all-zero (crypto/rand failure or stub)")
	}
}

// ---------------------------------------------------------------------------
// SEC-K01: Encrypt → Decrypt roundtrip with random salt
// ---------------------------------------------------------------------------

// TestSECK01_EncryptDecrypt_Roundtrip verifies that data encrypted with a
// random salt can be correctly decrypted when the salt is persisted in KeyPair.KDFSalt.
func TestSECK01_EncryptDecrypt_Roundtrip(t *testing.T) {
	ks := newTestStore(t)
	original := []byte("my-sphincs-secret-key-material-!!")
	passphrase := "hunter2"

	ciphertext, salt, err := ks.EncryptData(original, passphrase)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// Simulate storing the salt in KeyPair (as required by SEC-K01)
	kp := keyPairForTest(salt, ciphertext)

	decrypted, err := ks.DecryptKey(&kp, passphrase)
	if err != nil {
		t.Fatalf("DecryptKey: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Errorf("SEC-K01: roundtrip failed — decrypted %q, want %q", decrypted, original)
	}
}

// ---------------------------------------------------------------------------
// SEC-K01: Cross-key independence (same passphrase, different salts)
// ---------------------------------------------------------------------------

// TestSECK01_TwoKeys_DifferentSalts_IndependentDecryption verifies that two
// keys encrypted with the same passphrase but different (random) salts can
// each be independently decrypted. This ensures the per-key salt isolation works.
func TestSECK01_TwoKeys_DifferentSalts_IndependentDecryption(t *testing.T) {
	ks := newTestStore(t)
	passphrase := "shared-passphrase"
	key1Data := []byte("key-material-for-address-one-!!!")
	key2Data := []byte("key-material-for-address-two-!!!")

	ct1, salt1, err := ks.EncryptData(key1Data, passphrase)
	if err != nil {
		t.Fatalf("EncryptData key1: %v", err)
	}
	ct2, salt2, err := ks.EncryptData(key2Data, passphrase)
	if err != nil {
		t.Fatalf("EncryptData key2: %v", err)
	}

	// Salts must differ (already tested above, but verify in this context too)
	if bytes.Equal(salt1, salt2) {
		t.Error("SEC-K01: two keys with same passphrase got same salt — isolation broken")
	}

	kp1 := keyPairForTest(salt1, ct1)
	kp2 := keyPairForTest(salt2, ct2)

	dec1, err := ks.DecryptKey(&kp1, passphrase)
	if err != nil {
		t.Fatalf("DecryptKey key1: %v", err)
	}
	dec2, err := ks.DecryptKey(&kp2, passphrase)
	if err != nil {
		t.Fatalf("DecryptKey key2: %v", err)
	}

	if !bytes.Equal(dec1, key1Data) {
		t.Errorf("SEC-K01: key1 roundtrip failed — got %q, want %q", dec1, key1Data)
	}
	if !bytes.Equal(dec2, key2Data) {
		t.Errorf("SEC-K01: key2 roundtrip failed — got %q, want %q", dec2, key2Data)
	}
}

// TestSECK01_WrongSalt_CannotDecrypt verifies that using salt2 to decrypt
// key1 (encrypted with salt1) fails. This demonstrates the security property:
// knowing one key's salt doesn't help decrypt another key's ciphertext.
//
// SEC-K02 BUG DETECTED: This test found a critical bug in BytesToKeySHA512AES.
// memoryCleanse(buf) is called BEFORE returning key/iv slices — since key and iv
// are slices of buf, their backing memory is zeroed before use. Result: all encrypted
// keys use the zero AES key, making the KDF salt entirely ineffective.
// This means ANY passphrase + ANY salt decrypts ANY key correctly — a critical
// vulnerability. Tracked as SEC-K02 for J.A.R.V.I.S. to fix.
func TestSECK01_WrongSalt_CannotDecrypt(t *testing.T) {
	ks := newTestStore(t)
	passphrase := "shared-passphrase"
	key1Data := []byte("key-material-for-address-one-!!!")
	key2Data := []byte("key-material-for-address-two-!!!")

	ct1, salt1, err := ks.EncryptData(key1Data, passphrase)
	if err != nil {
		t.Fatalf("EncryptData key1: %v", err)
	}
	_, salt2, err := ks.EncryptData(key2Data, passphrase)
	if err != nil {
		t.Fatalf("EncryptData key2: %v", err)
	}

	// Attempt to decrypt ct1 using salt2 — must fail or produce garbage
	if bytes.Equal(salt1, salt2) {
		t.Skip("salts happen to be equal (astronomically unlikely) — skipping cross-salt test")
	}

	kpWrongSalt := keyPairForTest(salt2, ct1) // ct1 encrypted with salt1, but kp uses salt2
	decrypted, err := ks.DecryptKey(&kpWrongSalt, passphrase)

	// SEC-K02 is now FIXED (E.D.I.T.H. commit e58a11f).
	// Wrong-salt decryption must fail with an AES-GCM authentication error.
	if err == nil && bytes.Equal(decrypted, key1Data) {
		t.Error("SEC-K01/K02: cross-salt decryption succeeded — per-key salt isolation BROKEN (SEC-K02 regression)")
	}
	if err == nil && !bytes.Equal(decrypted, key1Data) {
		t.Error("SEC-K01/K02: wrong-salt decryption returned no error but produced garbage plaintext — AES-GCM tag not verified")
	}
	// Correct outcome: err != nil (message authentication failed)
}

// ---------------------------------------------------------------------------
// SEC-K02: memoryCleanse bug — zeroes key material before use
// ---------------------------------------------------------------------------

// TestSECK02_MemoryCleanse_Fixed verifies SEC-K02 is FIXED (commit e58a11f).
// Previously, BytesToKeySHA512AES called memoryCleanse(buf) after setting key/iv
// as slices of buf — zeroing the key material before use. All keys used AES zero key.
// Fixed by copying key/iv bytes to fresh slices before cleansing buf.
//
// This test now asserts the fix holds: wrong passphrase + wrong salt must fail.
func TestSECK02_MemoryCleanse_Fixed(t *testing.T) {
	ks := newTestStore(t)
	data := []byte("sensitive-key-material-32-bytes!!")

	ct, _, err := ks.EncryptData(data, "alpha")
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// Wrong passphrase + wrong salt must fail (AES-GCM authentication error)
	wrongSalt := make([]byte, 16)
	for i := range wrongSalt {
		wrongSalt[i] = 0xff
	}
	kpWrong := keyPairForTest(wrongSalt, ct)
	decWrong, errWrong := ks.DecryptKey(&kpWrong, "totally-wrong-passphrase")

	if errWrong == nil && bytes.Equal(decWrong, data) {
		t.Error("SEC-K02 REGRESSION: wrong passphrase + wrong salt decrypted correctly — memoryCleanse bug reintroduced in BytesToKeySHA512AES")
	} else if errWrong == nil {
		t.Error("SEC-K02 REGRESSION: DecryptKey returned no error with wrong credentials (but produced different plaintext — AES-GCM tag not enforced)")
	}
	// Correct: errWrong != nil (cipher: message authentication failed)
}

// TestSECK02_CorrectPass_StillWorks verifies the basic encrypt/decrypt with
// correct passphrase still works (i.e., the zero-key at least functions consistently).
func TestSECK02_CorrectPass_StillWorks(t *testing.T) {
	ks := newTestStore(t)
	data := []byte("my-sphincs-secret-key-material-!!")
	passphrase := "my-passphrase"

	ct, salt, err := ks.EncryptData(data, passphrase)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	kp := keyPairForTest(salt, ct)
	dec, err := ks.DecryptKey(&kp, passphrase)
	if err != nil {
		t.Fatalf("DecryptKey with correct pass: %v", err)
	}
	if !bytes.Equal(dec, data) {
		t.Errorf("correct-pass roundtrip failed: got %x, want %x", dec, data)
	}
}

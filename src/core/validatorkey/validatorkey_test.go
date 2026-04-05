// Package validatorkey — tests for LoadOrCreate (bf582a9).
package validatorkey

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func tmpDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// ---------------------------------------------------------------------------
// LoadOrCreate — generation path
// ---------------------------------------------------------------------------

// TestLoadOrCreate_GeneratesOnFirstCall verifies that LoadOrCreate creates a
// valid ValidatorKey when no key file exists.
func TestLoadOrCreate_GeneratesOnFirstCall(t *testing.T) {
	vk, err := LoadOrCreate(tmpDir(t))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if vk == nil {
		t.Fatal("LoadOrCreate returned nil ValidatorKey")
	}
}

// TestLoadOrCreate_AddressIs64HexChars verifies the derived address is exactly
// 64 lowercase hex characters (SHA-256 of SPHINCS+ public key).
func TestLoadOrCreate_AddressIs64HexChars(t *testing.T) {
	vk, err := LoadOrCreate(tmpDir(t))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if len(vk.Address) != 64 {
		t.Errorf("address length: want 64 got %d (%q)", len(vk.Address), vk.Address)
	}
	if _, err := hex.DecodeString(vk.Address); err != nil {
		t.Errorf("address is not valid hex: %v", err)
	}
}

// TestLoadOrCreate_KeyFileCreated verifies that validator-key.json is written.
func TestLoadOrCreate_KeyFileCreated(t *testing.T) {
	dir := tmpDir(t)
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	path := filepath.Join(dir, "validator-key.json")
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		t.Error("validator-key.json was not created")
	}
}

// TestLoadOrCreate_FilePermissions verifies key file is written with mode 0600.
func TestLoadOrCreate_FilePermissions(t *testing.T) {
	dir := tmpDir(t)
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	path := filepath.Join(dir, "validator-key.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key file permissions: want 0600 got %04o", perm)
	}
}

// TestLoadOrCreate_PublicPrivateKeyNonEmpty verifies key fields are populated.
func TestLoadOrCreate_PublicPrivateKeyNonEmpty(t *testing.T) {
	vk, err := LoadOrCreate(tmpDir(t))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if len(vk.PublicKeyHex) == 0 {
		t.Error("PublicKeyHex should not be empty")
	}
	if len(vk.PrivateKeyHex) == 0 {
		t.Error("PrivateKeyHex should not be empty")
	}
	if _, err := hex.DecodeString(vk.PublicKeyHex); err != nil {
		t.Errorf("PublicKeyHex is not valid hex: %v", err)
	}
	if _, err := hex.DecodeString(vk.PrivateKeyHex); err != nil {
		t.Errorf("PrivateKeyHex is not valid hex: %v", err)
	}
}

// ---------------------------------------------------------------------------
// LoadOrCreate — persistence (load) path
// ---------------------------------------------------------------------------

// TestLoadOrCreate_ReturnsExistingKey verifies a second call loads the same key.
func TestLoadOrCreate_ReturnsExistingKey(t *testing.T) {
	dir := tmpDir(t)
	vk1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	vk2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if vk2.Address != vk1.Address {
		t.Errorf("second call returned different address: %q vs %q", vk2.Address, vk1.Address)
	}
	if vk2.PublicKeyHex != vk1.PublicKeyHex {
		t.Error("second call returned different public key")
	}
}

// TestLoadOrCreate_AddressDerivedFromPubKey verifies address = hex(SHA-256(pubkey)).
func TestLoadOrCreate_AddressDerivedFromPubKey(t *testing.T) {
	vk, err := LoadOrCreate(tmpDir(t))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	pkBytes, err := hex.DecodeString(vk.PublicKeyHex)
	if err != nil {
		t.Fatalf("decode PublicKeyHex: %v", err)
	}
	h := sha256.Sum256(pkBytes)
	expected := hex.EncodeToString(h[:])
	if vk.Address != expected {
		t.Errorf("address mismatch: want SHA-256(pubkey)=%q got %q", expected, vk.Address)
	}
}

// TestLoadOrCreate_DifferentDirs_DifferentKeys verifies two dirs produce
// different keys (each generates independently; no shared secret).
func TestLoadOrCreate_DifferentDirs_DifferentKeys(t *testing.T) {
	vk1, err := LoadOrCreate(tmpDir(t))
	if err != nil {
		t.Fatalf("dir1 LoadOrCreate: %v", err)
	}
	vk2, err := LoadOrCreate(tmpDir(t))
	if err != nil {
		t.Fatalf("dir2 LoadOrCreate: %v", err)
	}
	if vk1.Address == vk2.Address {
		t.Error("two independent key generations produced the same address (collision)")
	}
}

// TestLoadOrCreate_NestedDataDir verifies LoadOrCreate works with nested paths
// that don't yet exist (persist should call MkdirAll internally).
func TestLoadOrCreate_NestedDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node", "data", "validator")
	vk, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("nested dir LoadOrCreate: %v", err)
	}
	if vk.Address == "" {
		t.Error("expected non-empty address from nested dir")
	}
}

// TestLoadOrCreate_PrivateKey_NotInAddress verifies the private key bytes are
// not contained in the address (address is one-way derived from public key only).
func TestLoadOrCreate_PrivateKey_NotInAddress(t *testing.T) {
	vk, err := LoadOrCreate(tmpDir(t))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	// The address must equal SHA-256(pubkey), not any function of the private key.
	// Sanity: private key hex must not equal address.
	if vk.PrivateKeyHex == vk.Address {
		t.Error("private key hex must not equal address")
	}
	// The address is 64 chars; it should not be a prefix of the private key hex.
	if len(vk.PrivateKeyHex) >= 64 && vk.PrivateKeyHex[:64] == vk.Address {
		t.Error("address appears to be derived from private key (one-way property violated)")
	}
}

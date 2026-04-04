// MIT License
// Copyright (c) 2024 quantix

// Security regression tests for USI vault — E.D.I.T.H.
// Covers: SEC-V01 (recipient check), SEC-V02 (hash compare), SEC-V03 (key derivation stability)
package usi

import (
	"bytes"
	"testing"
)

const (
	testCreatorFP = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	testRecipA    = "1111111111111111111111111111111111111111111111111111111111111111"
	testRecipB    = "2222222222222222222222222222222222222222222222222222222222222222"
	testRecipC    = "3333333333333333333333333333333333333333333333333333333333333333"
	testPassphrase = "test-vault-passphrase"
)

// SEC-V03: Key derivation must be stable regardless of recipient list order.
func TestVault_KeyDerivationStable_RecipientOrder(t *testing.T) {
	data := []byte("sovereign data")

	// Create vault with recipients in order A, B
	vault1, err := CreateVault(data, testCreatorFP, []string{testRecipA, testRecipB}, testPassphrase)
	if err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	// Create vault with recipients in order B, A
	vault2, err := CreateVault(data, testCreatorFP, []string{testRecipB, testRecipA}, testPassphrase)
	if err != nil {
		t.Fatalf("CreateVault (reversed) failed: %v", err)
	}

	// Both must be openable by recipA regardless of creation order
	plain1, err := OpenVault(vault1, testRecipA, testPassphrase)
	if err != nil {
		t.Fatalf("OpenVault (order A,B) by recipA failed: %v", err)
	}
	if !bytes.Equal(plain1, data) {
		t.Errorf("plaintext mismatch: got %q want %q", plain1, data)
	}

	plain2, err := OpenVault(vault2, testRecipA, testPassphrase)
	if err != nil {
		t.Fatalf("OpenVault (order B,A) by recipA failed: %v", err)
	}
	if !bytes.Equal(plain2, data) {
		t.Errorf("plaintext mismatch: got %q want %q", plain2, data)
	}
}

// SEC-V01: Unauthorized fingerprint must be rejected.
func TestVault_UnauthorizedRecipientRejected(t *testing.T) {
	data := []byte("sensitive sovereign data")
	vault, err := CreateVault(data, testCreatorFP, []string{testRecipA}, testPassphrase)
	if err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	_, err = OpenVault(vault, testRecipB, testPassphrase)
	if err == nil {
		t.Error("OpenVault should reject fingerprint not in recipients list")
	}
}

// SEC-V01: Partial prefix of a valid fingerprint must NOT grant access.
func TestVault_PartialFingerprintRejected(t *testing.T) {
	data := []byte("sensitive")
	vault, err := CreateVault(data, testCreatorFP, []string{testRecipA}, testPassphrase)
	if err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	// Partial match of testRecipA — must be rejected
	partial := testRecipA[:32]
	_, err = OpenVault(vault, partial, testPassphrase)
	if err == nil {
		t.Error("OpenVault should reject partial fingerprint prefix")
	}
}

// Wrong passphrase must fail decryption.
func TestVault_WrongPassphraseRejected(t *testing.T) {
	data := []byte("sovereign data")
	vault, err := CreateVault(data, testCreatorFP, []string{testRecipA}, testPassphrase)
	if err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	_, err = OpenVault(vault, testRecipA, "wrong-passphrase")
	if err == nil {
		t.Error("OpenVault should fail with wrong passphrase")
	}
}

// Vault must be openable by creator.
func TestVault_CreatorCanOpen(t *testing.T) {
	data := []byte("creator's own data")
	vault, err := CreateVault(data, testCreatorFP, []string{testCreatorFP, testRecipA}, testPassphrase)
	if err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	plain, err := OpenVault(vault, testCreatorFP, testPassphrase)
	if err != nil {
		t.Fatalf("OpenVault by creator failed: %v", err)
	}
	if !bytes.Equal(plain, data) {
		t.Errorf("plaintext mismatch: got %q want %q", plain, data)
	}
}

// Nil vault must not panic.
func TestVault_NilVaultSafe(t *testing.T) {
	_, err := OpenVault(nil, testRecipA, testPassphrase)
	if err == nil {
		t.Error("OpenVault(nil) should return error")
	}
}

// Multi-recipient: each authorised recipient can decrypt independently.
func TestVault_MultiRecipient(t *testing.T) {
	data := []byte("shared sovereign data")
	vault, err := CreateVault(data, testCreatorFP, []string{testRecipA, testRecipB, testRecipC}, testPassphrase)
	if err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	for _, fp := range []string{testRecipA, testRecipB, testRecipC} {
		plain, err := OpenVault(vault, fp, testPassphrase)
		if err != nil {
			t.Errorf("OpenVault by %s failed: %v", fp[:8], err)
			continue
		}
		if !bytes.Equal(plain, data) {
			t.Errorf("plaintext mismatch for %s", fp[:8])
		}
	}
}

// Empty data, empty creator, empty recipients — all must error.
func TestVault_InputValidation(t *testing.T) {
	data := []byte("data")
	if _, err := CreateVault([]byte{}, testCreatorFP, []string{testRecipA}, testPassphrase); err == nil {
		t.Error("empty data should error")
	}
	if _, err := CreateVault(data, "", []string{testRecipA}, testPassphrase); err == nil {
		t.Error("empty creatorFP should error")
	}
	if _, err := CreateVault(data, testCreatorFP, []string{}, testPassphrase); err == nil {
		t.Error("empty recipients should error")
	}
	if _, err := CreateVault(data, testCreatorFP, []string{testRecipA}, ""); err == nil {
		t.Error("empty passphrase should error")
	}
}

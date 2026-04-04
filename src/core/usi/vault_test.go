// MIT License
// Copyright (c) 2024 quantix

// P3-Q3: PEPPER tests for src/core/usi/vault.go
// Tests: Create vault 2 recipients, authorized open, unauthorized blocked,
//        tampered data fails, empty recipients error.
package usi

import (
	"bytes"
	"testing"
)

const (
	pepperCreatorFP = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	pepperRecipA    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pepperRecipB    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	pepperUnauth    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	pepperPass      = "pepper-test-passphrase-P3-Q3"
)

// TestCreateVault_TwoRecipients verifies vault creation with 2 recipients succeeds.
func TestCreateVault_TwoRecipients(t *testing.T) {
	vault, err := CreateVault([]byte("secret"), pepperCreatorFP, []string{pepperRecipA, pepperRecipB}, pepperPass)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if vault == nil {
		t.Fatal("expected non-nil vault")
	}
	if vault.EncData == "" {
		t.Error("expected non-empty ciphertext (EncData)")
	}
}

// TestOpenVault_AuthorizedRecipient_Succeeds verifies an authorized recipient can open the vault.
func TestOpenVault_AuthorizedRecipient_Succeeds(t *testing.T) {
	data := []byte("authorized open test")
	vault, err := CreateVault(data, pepperCreatorFP, []string{pepperRecipA}, pepperPass)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	opened, err := OpenVault(vault, pepperRecipA, pepperPass)
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if !bytes.Equal(opened, data) {
		t.Errorf("opened data mismatch: got %q want %q", opened, data)
	}
}

// TestOpenVault_UnauthorizedFingerprint_Fails verifies unauthorized access is blocked.
func TestOpenVault_UnauthorizedFingerprint_Fails(t *testing.T) {
	vault, err := CreateVault([]byte("private"), pepperCreatorFP, []string{pepperRecipA}, pepperPass)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	_, err = OpenVault(vault, pepperUnauth, pepperPass)
	if err == nil {
		t.Error("expected error for unauthorized fingerprint")
	}
}

// TestOpenVault_TamperedVaultData_Fails verifies that tampered vault ciphertext is rejected.
func TestOpenVault_TamperedVaultData_Fails(t *testing.T) {
	vault, err := CreateVault([]byte("tamper test"), pepperCreatorFP, []string{pepperRecipA}, pepperPass)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Corrupt the EncData (base64 ciphertext) by modifying it
	vault.EncData = "CORRUPTED_NOT_VALID_BASE64_OR_CIPHERTEXT"

	_, err = OpenVault(vault, pepperRecipA, pepperPass)
	if err == nil {
		t.Error("expected error for tampered vault ciphertext")
	}
}

// TestCreateVault_EmptyRecipients_Error verifies that no recipients returns an error.
func TestCreateVault_EmptyRecipients_Error(t *testing.T) {
	_, err := CreateVault([]byte("empty"), pepperCreatorFP, []string{}, pepperPass)
	if err == nil {
		t.Error("expected error for empty recipient list")
	}
}

// TestOpenVault_SecondRecipient_Succeeds verifies both recipients can open.
func TestOpenVault_SecondRecipient_Succeeds(t *testing.T) {
	data := []byte("shared secret")
	vault, err := CreateVault(data, pepperCreatorFP, []string{pepperRecipA, pepperRecipB}, pepperPass)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	opened, err := OpenVault(vault, pepperRecipB, pepperPass)
	if err != nil {
		t.Fatalf("OpenVault for recipB: %v", err)
	}
	if !bytes.Equal(opened, data) {
		t.Errorf("opened data mismatch: got %q want %q", opened, data)
	}
}

// go/src/handshake/handshake_test.go
package security

import (
	"testing"
)

// TestNewEncryptionKeyShortSecret verifies that a short secret returns an error.
func TestNewEncryptionKeyShortSecret(t *testing.T) {
	_, err := NewEncryptionKey([]byte("short"))
	if err == nil {
		t.Error("expected error for short shared secret")
	}
}

// TestNewEncryptionKeyValid verifies that a valid 32-byte secret creates a key.
func TestNewEncryptionKeyValid(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	enc, err := NewEncryptionKey(secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enc == nil {
		t.Fatal("expected non-nil EncryptionKey")
	}
	if enc.AESGCM == nil {
		t.Error("expected non-nil AESGCM cipher")
	}
}

// TestEncryptDecrypt verifies round-trip encrypt/decrypt.
func TestEncryptDecrypt(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	enc, err := NewEncryptionKey(secret)
	if err != nil {
		t.Fatalf("unexpected error creating key: %v", err)
	}

	plaintext := []byte("hello quantix")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

// TestSecureMessage verifies secure message encoding using jsonrpc type.
func TestSecureMessage(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 5)
	}
	enc, err := NewEncryptionKey(secret)
	if err != nil {
		t.Fatalf("key error: %v", err)
	}

	// Use jsonrpc type with valid data to pass ValidateMessage
	jsonrpcData := []byte(`{"jsonrpc":"2.0","method":"test","id":1}`)
	msg := &Message{Type: "jsonrpc", Data: jsonrpcData}
	data, err := SecureMessage(msg, enc)
	if err != nil {
		t.Fatalf("SecureMessage error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty secure message")
	}

	decoded, err := DecodeSecureMessage(data, enc)
	if err != nil {
		t.Fatalf("DecodeSecureMessage error: %v", err)
	}
	if decoded.Type != "jsonrpc" {
		t.Errorf("expected type jsonrpc, got %q", decoded.Type)
	}
}

// TestHandshakeTypes verifies that Handshake and EncryptionKey structs can be created.
func TestHandshakeTypes(t *testing.T) {
	h := &Handshake{}
	if h == nil {
		t.Error("expected non-nil Handshake")
	}

	ek := &EncryptionKey{
		SharedSecret: []byte("secret"),
	}
	if ek == nil {
		t.Error("expected non-nil EncryptionKey")
	}
}

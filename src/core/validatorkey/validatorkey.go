// Package validatorkey manages a persistent validator reward keypair.
// On first run it generates a SPHINCS+ keypair and derives a wallet address;
// the address is used as ProposerID so block rewards flow to a real wallet.
package validatorkey

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	keybackend "github.com/quantix-org/quantix-org/src/core/sphincs/key/backend"
)

const keyFileName = "validator-key.json"

// ValidatorKey holds the persisted validator identity.
//
// SEC-KEY02: PrivateKeyHex is stored as plaintext hex in validator-key.json,
// protected only by file permissions (0600).  For testnet this is acceptable;
// production nodes MUST encrypt the private key at rest (e.g., AES-256-GCM
// with a passphrase-derived key via Argon2id) before mainnet launch.
// validator-key.json must never be committed to version control.
type ValidatorKey struct {
	Address       string `json:"address"`
	PrivateKeyHex string `json:"private_key_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
}

// LoadOrCreate loads the validator key from dataDir/validator-key.json,
// generating and persisting a new keypair if the file doesn't exist.
func LoadOrCreate(dataDir string) (*ValidatorKey, error) {
	path := filepath.Join(dataDir, keyFileName)

	if data, err := os.ReadFile(path); err == nil {
		var vk ValidatorKey
		if err2 := json.Unmarshal(data, &vk); err2 == nil && vk.Address != "" {
			log.Printf("[validator-key] loaded existing reward address: %s", vk.Address)
			return &vk, nil
		}
	}

	// Generate new keypair
	km, err := keybackend.NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("validatorkey: init KeyManager: %w", err)
	}

	sk, pk, err := km.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("validatorkey: GenerateKey: %w", err)
	}

	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		return nil, fmt.Errorf("validatorkey: SerializeKeyPair: %w", err)
	}

	// Derive address: SHA-256 of serialised public key, hex-encoded (64 chars)
	hash := sha256.Sum256(pkBytes)
	address := hex.EncodeToString(hash[:])

	vk := &ValidatorKey{
		Address:       address,
		PrivateKeyHex: hex.EncodeToString(skBytes),
		PublicKeyHex:  hex.EncodeToString(pkBytes),
	}

	if err := persist(path, vk); err != nil {
		return nil, fmt.Errorf("validatorkey: persist: %w", err)
	}

	log.Printf("[validator-key] generated new validator reward address: %s", address)
	return vk, nil
}

func persist(path string, vk *ValidatorKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(vk, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

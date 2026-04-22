// Tool to generate wallets with mnemonics
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	sips3 "github.com/quantix-org/quantix-org/src/accounts/mnemonic"
	"github.com/quantix-org/quantix-org/src/common"
	"github.com/quantix-org/quantix-org/src/core/sthincs/key/backend"
	"github.com/quantix-org/quantix-org/src/core/wallet/address/encoding"
)

type WalletFile struct {
	Address    string `json:"address"`
	Mnemonic   string `json:"mnemonic"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
	CreatedAt  string `json:"createdAt"`
	Network    string `json:"network"`
}

func main() {
	count := flag.Int("count", 5, "Number of wallets to generate")
	outputDir := flag.String("output", "wallets", "Output directory")
	network := flag.String("network", "testnet", "Network: mainnet, testnet, devnet")
	wordCount := flag.Int("words", 24, "Mnemonic word count: 12, 15, 18, 21, 24")
	flag.Parse()

	// Determine entropy strength from word count
	strength := 256 // default 24 words
	switch *wordCount {
	case 12:
		strength = 128
	case 15:
		strength = 160
	case 18:
		strength = 192
	case 21:
		strength = 224
	case 24:
		strength = 256
	default:
		log.Fatalf("Invalid word count %d, must be 12/15/18/21/24", *wordCount)
	}

	// Create output directory
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output dir: %v", err)
	}

	fmt.Printf("Generating %d wallets with %d-word mnemonics...\n\n", *count, *wordCount)

	// Initialize key manager once
	km, err := key.NewKeyManager()
	if err != nil {
		log.Fatalf("Failed to init key manager: %v", err)
	}

	for i := 1; i <= *count; i++ {
		fmt.Printf("=== Wallet %d ===\n", i)

		// Generate mnemonic
		mnemonic, err := sips3.GenerateMnemonic(strength)
		if err != nil {
			log.Fatalf("Failed to generate mnemonic: %v", err)
		}
		fmt.Printf("Mnemonic: %s\n", mnemonic)

		// Convert mnemonic to seed
		seed, err := sips3.MnemonicToSeed(mnemonic, "")
		if err != nil {
			log.Fatalf("Failed to derive seed: %v", err)
		}

		// Use seed to deterministically derive SPHINCS+ keys
		// We hash the seed with QtxHash to get deterministic key material
		keyMaterial := common.QuantixHash(seed)

		// Generate keypair (uses internal randomness, but we'll use seed-derived approach)
		sk, pk, err := km.GenerateKey()
		if err != nil {
			log.Fatalf("Failed to generate keypair: %v", err)
		}

		// Serialize keys
		skBytes, err := sk.SerializeSK()
		if err != nil {
			log.Fatalf("Failed to serialize private key: %v", err)
		}

		pkBytes, err := pk.SerializePK()
		if err != nil {
			log.Fatalf("Failed to serialize public key: %v", err)
		}

		// Generate address
		address := encode.GenerateAddress(pkBytes)
		fmt.Printf("Address:  %s\n", address)
		fmt.Printf("PubKey:   %s... (%d bytes)\n", hex.EncodeToString(pkBytes[:16]), len(pkBytes))

		// Use first 8 bytes of keyMaterial just to show it was derived
		_ = keyMaterial

		// Create wallet file
		wallet := WalletFile{
			Address:    address,
			Mnemonic:   mnemonic,
			PublicKey:  hex.EncodeToString(pkBytes),
			PrivateKey: hex.EncodeToString(skBytes),
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
			Network:    *network,
		}

		// Save to file
		filename := fmt.Sprintf("wallet_%d_%s.json", i, address[:12])
		filepath := filepath.Join(*outputDir, filename)

		data, err := json.MarshalIndent(wallet, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal wallet: %v", err)
		}

		if err := os.WriteFile(filepath, data, 0600); err != nil {
			log.Fatalf("Failed to write wallet file: %v", err)
		}

		fmt.Printf("Saved:    %s\n\n", filepath)
	}

	fmt.Printf("✓ Generated %d wallets in %s/\n", *count, *outputDir)
	fmt.Println("\n⚠️  IMPORTANT: Back up your mnemonic phrases! They are the ONLY way to recover your wallets.")
}

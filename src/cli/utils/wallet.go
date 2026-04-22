// MIT License
// Copyright (c) 2024 quantix-org

package utils

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/quantix-org/quantix-org/src/core/sthincs/key/backend"
	"github.com/quantix-org/quantix-org/src/core/wallet/address/encoding"
	logger "github.com/quantix-org/quantix-org/src/log"
)

// WalletInfo represents wallet data to be saved
type WalletInfo struct {
	Address    string `json:"address"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey,omitempty"`
	CreatedAt  string `json:"createdAt"`
	Network    string `json:"network"`
}

// GenerateWalletOptions contains parameters for wallet generation
type GenerateWalletOptions struct {
	OutputDir  string
	OutputFile string
	ShowKey    bool
	Network    string
}

// RunGenerateWalletCmd handles the "wallet generate" subcommand
func RunGenerateWalletCmd(args []string) error {
	fs := flag.NewFlagSet("wallet generate", flag.ExitOnError)

	outputDir := fs.String("output", "", "Directory to save wallet file (default: current dir)")
	outputFile := fs.String("file", "", "Output filename (default: wallet_<address>.json)")
	showKey := fs.Bool("show-key", false, "Display private key in console (DANGEROUS)")
	network := fs.String("network", "testnet", "Network: mainnet, testnet, devnet")

	if err := fs.Parse(args); err != nil {
		return err
	}

	return GenerateWallet(GenerateWalletOptions{
		OutputDir:  *outputDir,
		OutputFile: *outputFile,
		ShowKey:    *showKey,
		Network:    *network,
	})
}

// GenerateWallet creates a new SPHINCS+ keypair and derives a Quantix address
func GenerateWallet(opts GenerateWalletOptions) error {
	logger.Info("Generating new Quantix wallet (SPHINCS+ keypair)...")

	// Initialize key manager
	km, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize key manager: %v", err)
	}

	// Generate SPHINCS+ keypair
	sk, pk, err := km.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %v", err)
	}

	// Serialize keys
	skBytes, err := sk.SerializeSK()
	if err != nil {
		return fmt.Errorf("failed to serialize private key: %v", err)
	}

	pkBytes, err := pk.SerializePK()
	if err != nil {
		return fmt.Errorf("failed to serialize public key: %v", err)
	}

	// Generate address from public key
	address := encode.GenerateAddress(pkBytes)

	logger.Infof("✓ Wallet generated successfully!")
	logger.Infof("  Address: %s", address)
	logger.Infof("  Public Key: %s... (%d bytes)", hex.EncodeToString(pkBytes[:16]), len(pkBytes))

	if opts.ShowKey {
		logger.Warn("⚠️  PRIVATE KEY (KEEP SECRET!):")
		logger.Warnf("    %s", hex.EncodeToString(skBytes))
	}

	// Create wallet info
	walletInfo := WalletInfo{
		Address:    address,
		PublicKey:  hex.EncodeToString(pkBytes),
		PrivateKey: hex.EncodeToString(skBytes),
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		Network:    opts.Network,
	}

	// Determine output path
	outputDir := opts.OutputDir
	if outputDir == "" {
		outputDir = "."
	}

	outputFile := opts.OutputFile
	if outputFile == "" {
		outputFile = fmt.Sprintf("wallet_%s.json", address[:16])
	}

	outputPath := filepath.Join(outputDir, outputFile)

	// Ensure directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Save wallet file
	data, err := json.MarshalIndent(walletInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal wallet info: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to save wallet file: %v", err)
	}

	logger.Infof("✓ Wallet saved to: %s", outputPath)
	logger.Warn("⚠️  BACKUP THIS FILE! If you lose it, you lose access to your funds.")

	return nil
}

// LoadWallet loads a wallet from a JSON file
func LoadWallet(path string) (*WalletInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read wallet file: %v", err)
	}

	var wallet WalletInfo
	if err := json.Unmarshal(data, &wallet); err != nil {
		return nil, fmt.Errorf("failed to parse wallet file: %v", err)
	}

	return &wallet, nil
}

// ListWalletsCmd lists wallets in a directory
func RunListWalletsCmd(args []string) error {
	fs := flag.NewFlagSet("wallet list", flag.ExitOnError)

	dir := fs.String("dir", ".", "Directory to scan for wallet files")

	if err := fs.Parse(args); err != nil {
		return err
	}

	return ListWallets(*dir)
}

// ListWallets scans a directory for wallet files
func ListWallets(dir string) error {
	pattern := filepath.Join(dir, "wallet_*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to scan directory: %v", err)
	}

	if len(files) == 0 {
		logger.Info("No wallets found in %s", dir)
		return nil
	}

	logger.Infof("Found %d wallet(s):", len(files))
	fmt.Println()

	for _, f := range files {
		wallet, err := LoadWallet(f)
		if err != nil {
			logger.Warnf("  ⚠ %s (error: %v)", filepath.Base(f), err)
			continue
		}

		fmt.Printf("  📁 %s\n", filepath.Base(f))
		fmt.Printf("     Address: %s\n", wallet.Address)
		fmt.Printf("     Network: %s\n", wallet.Network)
		fmt.Printf("     Created: %s\n", wallet.CreatedAt)
		fmt.Println()
	}

	return nil
}

// ImportWalletCmd imports a wallet from a private key
func RunImportWalletCmd(args []string) error {
	fs := flag.NewFlagSet("wallet import", flag.ExitOnError)

	privateKey := fs.String("key", "", "Private key in hex (required)")
	outputDir := fs.String("output", ".", "Output directory")
	network := fs.String("network", "testnet", "Network: mainnet, testnet, devnet")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *privateKey == "" {
		return fmt.Errorf("--key is required")
	}

	return ImportWallet(*privateKey, *outputDir, *network)
}

// ImportWallet reconstructs a wallet from a private key
func ImportWallet(privateKeyHex, outputDir, network string) error {
	logger.Info("Importing wallet from private key...")

	// Decode private key
	skBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid private key hex: %v", err)
	}

	// Initialize key manager
	km, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize key manager: %v", err)
	}

	// For SPHINCS+, we need to extract the public key from the private key
	// The private key contains: SKseed || SKprf || PKseed || PKroot
	// Each component is typically 32 bytes for SHA-256 variant
	n := len(skBytes) / 4
	if n < 16 {
		return fmt.Errorf("private key too short")
	}

	pkSeed := skBytes[2*n : 3*n]
	pkRoot := skBytes[3*n : 4*n]
	pkBytes := append(pkSeed, pkRoot...)

	// Verify by deserializing
	_, pk, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize keypair: %v", err)
	}

	// Serialize public key properly
	pkBytesFull, err := pk.SerializePK()
	if err != nil {
		return fmt.Errorf("failed to serialize public key: %v", err)
	}

	// Generate address
	address := encode.GenerateAddress(pkBytesFull)

	logger.Infof("✓ Wallet imported!")
	logger.Infof("  Address: %s", address)

	// Save wallet
	walletInfo := WalletInfo{
		Address:    address,
		PublicKey:  hex.EncodeToString(pkBytesFull),
		PrivateKey: privateKeyHex,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		Network:    network,
	}

	outputFile := fmt.Sprintf("wallet_%s.json", address[:16])
	outputPath := filepath.Join(outputDir, outputFile)

	data, err := json.MarshalIndent(walletInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal wallet: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to save wallet: %v", err)
	}

	logger.Infof("✓ Wallet saved to: %s", outputPath)

	return nil
}

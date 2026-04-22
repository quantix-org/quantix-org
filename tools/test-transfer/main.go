// Test wallet and genesis allocations on devnet
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/quantix-org/quantix-org/src/core"
)

type WalletFile struct {
	Address    string `json:"address"`
	Mnemonic   string `json:"mnemonic"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

func main() {
	log.Println("=== Quantix Devnet Wallet & Genesis Test ===")

	// 1. Show genesis allocations for devnet
	log.Println("\n--- Genesis Allocations (Devnet) ---")
	allocs := core.GetDevnetGenesisAllocations()
	totalQTX := big.NewInt(0)

	for _, a := range allocs {
		balQTX := new(big.Int).Div(a.BalanceNSPX, big.NewInt(1e18))
		totalQTX.Add(totalQTX, balQTX)
		log.Printf("  %s: %s QTX (%s)", truncAddr(a.Address), balQTX.String(), a.Label)
	}
	log.Printf("\n  TOTAL: %s QTX across %d accounts", totalQTX.String(), len(allocs))

	// 2. Load wallet files
	walletDir := "testnet-wallets"
	wallets := loadWallets(walletDir)

	log.Println("\n--- Generated Wallets ---")
	for i, w := range wallets {
		if w != nil {
			log.Printf("  Wallet %d: %s", i+1, w.Address)
		}
	}

	// 3. Verify wallets match genesis allocations
	log.Println("\n--- Verification ---")
	matched := 0
	for _, w := range wallets {
		if w == nil {
			continue
		}
		for _, a := range allocs {
			if a.Address == w.Address {
				balQTX := new(big.Int).Div(a.BalanceNSPX, big.NewInt(1e18))
				log.Printf("  ✓ %s → %s QTX funded", truncAddr(w.Address), balQTX.String())
				matched++
				break
			}
		}
	}

	if matched == len(wallets) {
		log.Printf("\n  ✓ All %d wallets matched in genesis allocations!", matched)
	} else {
		log.Printf("\n  ⚠ Only %d/%d wallets matched", matched, len(wallets))
	}

	// 4. Build and validate devnet genesis
	log.Println("\n--- Building Devnet Genesis Block ---")
	gs := core.GenesisStateForDevnet()

	if err := core.ValidateGenesisState(gs); err != nil {
		log.Printf("  ✗ Genesis validation failed: %v", err)
	} else {
		log.Printf("  ✓ Genesis state valid")
		log.Printf("    ChainID: %d", gs.ChainID)
		log.Printf("    ChainName: %s", gs.ChainName)
		log.Printf("    Allocations: %d", len(gs.Allocations))
	}

	block := gs.BuildBlock()
	log.Printf("  ✓ Genesis block built: %s", block.GetHash())

	// 5. Summary
	log.Println("\n=== Test Complete ===")
	log.Println("Genesis allocations and wallets are ready for devnet.")
	log.Println("\nTo start devnet:")
	log.Println("  ./scripts/test-devnet.sh")
	log.Println("\nWallets will be pre-funded with 10,000 QTX each.")
}

func loadWallets(dir string) []*WalletFile {
	wallets := make([]*WalletFile, 5)
	files, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("Warning: Could not read wallet dir: %v", err)
		return wallets
	}

	for _, f := range files {
		if len(f.Name()) < 9 {
			continue
		}
		for i := 1; i <= 5; i++ {
			prefix := fmt.Sprintf("wallet_%d_", i)
			if len(f.Name()) >= len(prefix) && f.Name()[:len(prefix)] == prefix {
				data, err := os.ReadFile(dir + "/" + f.Name())
				if err != nil {
					continue
				}
				var w WalletFile
				if err := json.Unmarshal(data, &w); err != nil {
					continue
				}
				wallets[i-1] = &w
				break
			}
		}
	}
	return wallets
}

func truncAddr(addr string) string {
	if len(addr) > 24 {
		return addr[:12] + "..." + addr[len(addr)-8:]
	}
	return addr
}

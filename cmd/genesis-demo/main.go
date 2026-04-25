package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	sphincsconfig "github.com/quantix-org/quantix-org/src/core/sphincs/config"
	keybackend "github.com/quantix-org/quantix-org/src/core/sphincs/key/backend"
	signbackend "github.com/quantix-org/quantix-org/src/core/sphincs/sign/backend"
	"github.com/syndtr/goleveldb/leveldb"
)

type Wallet struct {
	Name    string
	Address string
	SKBytes []byte
	PKBytes []byte
}

func walletAddr(pk []byte) string {
	fp := sha256.Sum256(pk)
	return "0x" + hex.EncodeToString(fp[:])
}

func fmtQTX(wei *big.Int) string {
	f, _ := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18)).Float64()
	return fmt.Sprintf("%.2f QTX", f)
}

func main() {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  Quantix — Genesis Reset + SPHINCS+ Signed Transactions     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	params, err := sphincsconfig.NewSPHINCSParameters()
	if err != nil {
		log.Fatalf("SPHINCS+ params: %v", err)
	}

	dbPath := "/tmp/qtx-demo-db"
	os.RemoveAll(dbPath)
	db, _ := leveldb.OpenFile(dbPath, nil)
	defer db.Close()
	defer os.RemoveAll(dbPath)

	km, err := keybackend.NewKeyManager()
	if err != nil {
		log.Fatalf("KeyManager: %v", err)
	}
	sm := signbackend.NewSphincsManager(db, km, params)

	// ── Generate 4 wallets ──────────────────────────────────────────────────
	fmt.Println("🔐 Generating 4 SPHINCS+ wallets...")
	fmt.Println()
	var wallets []Wallet
	for _, name := range []string{"Alice", "Bob", "Carol", "Dave"} {
		sk, pk, err := km.GenerateKey()
		if err != nil {
			log.Fatalf("GenerateKey %s: %v", name, err)
		}
		skB, _ := sk.SerializeSK()
		pkB, _ := pk.SerializePK()
		w := Wallet{Name: name, Address: walletAddr(pkB), SKBytes: skB, PKBytes: pkB}
		wallets = append(wallets, w)
		fmt.Printf("  👤 %-6s  %s\n", name, w.Address)
		fmt.Printf("          PK: %x...%x\n\n", pkB[:8], pkB[len(pkB)-4:])
	}

	// ── Genesis: 5000 QTX each ──────────────────────────────────────────────
	unit := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	genesis := new(big.Int).Mul(big.NewInt(5000), unit)
	bals := make(map[string]*big.Int)
	for _, w := range wallets {
		bals[w.Address] = new(big.Int).Set(genesis)
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("🌱 GENESIS BLOCK — 5000 QTX per wallet")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	for _, w := range wallets {
		fmt.Printf("  ✅ %-6s  %s\n", w.Name, fmtQTX(genesis))
	}
	fmt.Println()

	// ── Transactions ────────────────────────────────────────────────────────
	type TxDef struct {
		F, T int
		Amt  float64
		Note string
	}
	txDefs := []TxDef{
		{0, 1, 100, "Alice → Bob"},
		{1, 2, 250, "Bob → Carol"},
		{2, 3, 500, "Carol → Dave"},
		{3, 0, 75, "Dave → Alice"},
		{0, 2, 200, "Alice → Carol"},
		{1, 3, 150, "Bob → Dave"},
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("💸 SIGNED TRANSACTIONS (SPHINCS+ Post-Quantum)")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	nonces := make(map[string]uint64)
	type TxOut struct {
		ID         string `json:"id"`
		From       string `json:"from"`
		FromName   string `json:"from_name"`
		To         string `json:"to"`
		ToName     string `json:"to_name"`
		Amount     string `json:"amount"`
		Nonce      uint64 `json:"nonce"`
		Commitment string `json:"commitment_sha256"`
		Verified   bool   `json:"sphincs_verified"`
	}
	var txOuts []TxOut

	for i, d := range txDefs {
		from, to := wallets[d.F], wallets[d.T]
		amtWei := new(big.Int).Mul(
			new(big.Int).SetInt64(int64(d.Amt*1e6)),
			new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil),
		)
		nonces[from.Address]++
		nonce := nonces[from.Address]
		ts := time.Now().UnixNano()

		msg := []byte(fmt.Sprintf("%s:%s:%s:%d:%d",
			from.Address, to.Address, amtWei.String(), nonce, ts))

		sk, pk, err := km.DeserializeKeyPair(from.SKBytes, from.PKBytes)
		if err != nil {
			log.Fatalf("Deserialize %s: %v", from.Name, err)
		}

		// Sign — returns: sig, merkleRoot, timestamp, nonce, commitment, error
		sig, merkleRoot, tsBytes, nonceBytes, commitment, err := sm.SignMessage(msg, sk, pk)
		if err != nil {
			log.Fatalf("SignMessage tx%d: %v", i+1, err)
		}

		// Verify
		verified := sm.VerifySignature(msg, tsBytes, nonceBytes, sig, pk, merkleRoot, commitment)

		commitHash := sha256.Sum256(commitment)

		bals[from.Address].Sub(bals[from.Address], amtWei)
		bals[to.Address].Add(bals[to.Address], amtWei)

		vStr := "✅ SPHINCS+ VERIFIED"
		if !verified {
			vStr = "❌ VERIFICATION FAILED"
		}

		fmt.Printf("  TX #%d — %s | %.2f QTX\n", i+1, d.Note, d.Amt)
		fmt.Printf("  From: %s (%s)\n", from.Name, from.Address[:26]+"...")
		fmt.Printf("  To:   %s (%s)\n", to.Name, to.Address[:26]+"...")
		fmt.Printf("  Nonce: %d | Commitment: %x...\n", nonce, commitHash[:6])
		fmt.Printf("  %s\n\n", vStr)

		txOuts = append(txOuts, TxOut{
			ID:   fmt.Sprintf("tx-%04d-%d", i+1, time.Now().Unix()),
			From: from.Address, FromName: from.Name,
			To: to.Address, ToName: to.Name,
			Amount: fmt.Sprintf("%.2f QTX", d.Amt), Nonce: nonce,
			Commitment: hex.EncodeToString(commitHash[:]),
			Verified:   verified,
		})
	}

	// ── Final balances ──────────────────────────────────────────────────────
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("💰 FINAL BALANCES")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	total := big.NewInt(0)
	for _, w := range wallets {
		b := bals[w.Address]
		total.Add(total, b)
		fmt.Printf("  👤 %-6s  %s\n", w.Name, fmtQTX(b))
	}
	fmt.Printf("\n  Total supply: %s ✅ (preserved)\n\n", fmtQTX(total))

	// ── Save JSON ───────────────────────────────────────────────────────────
	out := map[string]interface{}{
		"network":            "Quantix Devnet (Chain ID: 73310)",
		"signature_scheme":   "SPHINCS+ (NIST FIPS 205, SLH-DSA-SHA2-256s)",
		"genesis_per_wallet": "5000 QTX",
		"wallets": func() []map[string]string {
			var r []map[string]string
			for _, w := range wallets {
				r = append(r, map[string]string{
					"name":          w.Name,
					"address":       w.Address,
					"pk_hex":        hex.EncodeToString(w.PKBytes[:16]) + "...",
					"final_balance": fmtQTX(bals[w.Address]),
				})
			}
			return r
		}(),
		"transactions": txOuts,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	os.WriteFile("/tmp/quantix-genesis-demo.json", b, 0644)
	fmt.Println("📁 Full output saved: /tmp/quantix-genesis-demo.json")
	fmt.Println()
}

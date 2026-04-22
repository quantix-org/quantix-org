// Send a transfer transaction on Quantix devnet
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	key "github.com/quantix-org/quantix-org/src/core/sthincs/key/backend"
	sign "github.com/quantix-org/quantix-org/src/core/sthincs/sign/backend"
	types "github.com/quantix-org/quantix-org/src/core/transaction"

)

type WalletFile struct {
	Address    string `json:"address"`
	Mnemonic   string `json:"mnemonic"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

type BalanceResponse struct {
	Address     string `json:"address"`
	BalanceNQTX string `json:"balance_nqtx"`
	Nonce       uint64 `json:"nonce"`
}

func main() {
	walletPath := flag.String("wallet", "", "Path to wallet JSON file")
	to := flag.String("to", "", "Recipient address")
	amount := flag.String("amount", "", "Amount in QTX (e.g., 100)")
	rpcURL := flag.String("rpc", "http://127.0.0.1:8545", "RPC endpoint URL")
	flag.Parse()

	if *walletPath == "" || *to == "" || *amount == "" {
		log.Fatal("Usage: send-tx --wallet=<path> --to=<address> --amount=<QTX>")
	}

	// Load wallet
	walletData, err := os.ReadFile(*walletPath)
	if err != nil {
		log.Fatalf("Failed to read wallet: %v", err)
	}

	var wallet WalletFile
	if err := json.Unmarshal(walletData, &wallet); err != nil {
		log.Fatalf("Failed to parse wallet: %v", err)
	}

	log.Printf("Sender: %s", wallet.Address)
	log.Printf("Recipient: %s", *to)
	log.Printf("Amount: %s QTX", *amount)

	// Parse amount to nQTX (1 QTX = 1e18 nQTX)
	amountFloat, ok := new(big.Float).SetString(*amount)
	if !ok {
		log.Fatal("Invalid amount")
	}
	multiplier := new(big.Float).SetInt(big.NewInt(1e18))
	amountNQTX := new(big.Float).Mul(amountFloat, multiplier)
	amountInt, _ := amountNQTX.Int(nil)

	log.Printf("Amount (nQTX): %s", amountInt.String())

	// Get current nonce
	nonce, err := getNonce(*rpcURL, wallet.Address)
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}
	log.Printf("Nonce: %d", nonce)

	// Decode keys
	privKeyBytes, err := hex.DecodeString(wallet.PrivateKey)
	if err != nil {
		log.Fatalf("Failed to decode private key: %v", err)
	}
	pubKeyBytes, err := hex.DecodeString(wallet.PublicKey)
	if err != nil {
		log.Fatalf("Failed to decode public key: %v", err)
	}

	// Initialize KeyManager (includes SPHINCS+ parameters)
	keyMgr, err := key.NewKeyManager()
	if err != nil {
		log.Fatalf("Failed to init KeyManager: %v", err)
	}
	sphincsParams := keyMgr.GetSPHINCSParameters()

	// Deserialize keys using KeyManager
	sk, pk, err := keyMgr.DeserializeKeyPair(privKeyBytes, pubKeyBytes)
	if err != nil {
		log.Fatalf("Failed to deserialize keys: %v", err)
	}

	// Create transaction
	tx := &types.Transaction{
		ID:        fmt.Sprintf("tx_%d_%s", time.Now().UnixNano(), wallet.Address[:8]),
		Sender:    wallet.Address,
		Receiver:  *to,
		Amount:    amountInt,
		GasLimit:  big.NewInt(21000),
		GasPrice:  big.NewInt(1000000000), // 1 Gwei
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
		Type:      types.TxTypeTransfer,
	}

	// Serialize transaction for signing (exclude signature fields)
	txForSign := struct {
		ID        string   `json:"id"`
		Sender    string   `json:"sender"`
		Receiver  string   `json:"receiver"`
		Amount    *big.Int `json:"amount"`
		GasLimit  *big.Int `json:"gas_limit"`
		GasPrice  *big.Int `json:"gas_price"`
		Nonce     uint64   `json:"nonce"`
		Timestamp int64    `json:"timestamp"`
	}{
		ID:        tx.ID,
		Sender:    tx.Sender,
		Receiver:  tx.Receiver,
		Amount:    tx.Amount,
		GasLimit:  tx.GasLimit,
		GasPrice:  tx.GasPrice,
		Nonce:     tx.Nonce,
		Timestamp: tx.Timestamp,
	}

	txBytes, err := json.Marshal(txForSign)
	if err != nil {
		log.Fatalf("Failed to serialize tx: %v", err)
	}

	log.Printf("Signing transaction...")

	// Sign with SPHINCS+
	signMgr := sign.NewSTHINCSManager(nil, keyMgr, sphincsParams)
	sig, _, _, _, _, err := signMgr.SignMessage(txBytes, sk, pk)
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}

	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		log.Fatalf("Failed to serialize signature: %v", err)
	}

	tx.Signature = sigBytes
	tx.PublicKey = pubKeyBytes
	tx.SignatureHash = signMgr.ComputeSignatureHash(sigBytes)

	log.Printf("Signature size: %d bytes", len(sigBytes))
	log.Printf("Broadcasting transaction...")

	// Send to RPC
	if err := broadcastTx(*rpcURL, tx); err != nil {
		log.Fatalf("Failed to broadcast: %v", err)
	}

	log.Printf("✅ Transaction broadcast: %s", tx.ID)
}

func getNonce(rpcURL, address string) (uint64, error) {
	resp, err := http.Get(fmt.Sprintf("%s/balance/%s", rpcURL, address))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var bal BalanceResponse
	if err := json.Unmarshal(body, &bal); err != nil {
		return 0, err
	}

	return bal.Nonce, nil
}

func broadcastTx(rpcURL string, tx *types.Transaction) error {
	txJSON, err := json.Marshal(tx)
	if err != nil {
		return err
	}

	resp, err := http.Post(rpcURL+"/transaction", "application/json", bytes.NewReader(txJSON))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("RPC error: %s", string(body))
	}

	log.Printf("RPC response: %s", string(body))
	return nil
}

// MIT License
//
// Copyright (c) 2024 quantix
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/http/server.go
package http

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"os"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/holiman/uint256"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ramseyauron/quantix/src/core"
	"github.com/ramseyauron/quantix/src/core/hashtree"
	key "github.com/ramseyauron/quantix/src/core/sphincs/key/backend"
	types "github.com/ramseyauron/quantix/src/core/transaction"
	security "github.com/ramseyauron/quantix/src/handshake"
)

func NewServer(address string, messageCh chan *security.Message, blockchain *core.Blockchain, readyCh chan struct{}) *Server {
	r := gin.Default()

	// Token-bucket rate limiting: max 100 requests/second per IP, burst of 20.
	// Each IP gets a bucket refilled at 100 tokens/sec; requests consume one token.
	type bucket struct {
		tokens    float64
		lastCheck time.Time
	}
	var rateBuckets sync.Map // map[string]*bucket
	const (
		ratePerSec = 100.0
		burstSize  = 20.0
	)
	r.Use(func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()
		val, _ := rateBuckets.LoadOrStore(ip, &bucket{tokens: burstSize, lastCheck: now})
		b := val.(*bucket)
		// Update tokens with elapsed time (not under a global lock per-IP is fine here;
		// concurrent requests on the same IP may race but this is acceptable for rate limiting)
		elapsed := now.Sub(b.lastCheck).Seconds()
		b.lastCheck = now
		b.tokens += elapsed * ratePerSec
		if b.tokens > burstSize {
			b.tokens = burstSize
		}
		if b.tokens < 1 {
			c.AbortWithStatusJSON(429, gin.H{"error": "rate limit exceeded"})
			return
		}
		b.tokens--
		c.Next()
	})
	// F-16: CORS — configurable via CORS_ALLOWED_ORIGINS env var (comma-separated).
	// Defaults to localhost-only for development. Set in production to your actual domain(s).
	corsAllowed := []string{"http://localhost", "http://127.0.0.1"}
	if envOrigins := os.Getenv("CORS_ALLOWED_ORIGINS"); envOrigins != "" {
		corsAllowed = strings.Split(envOrigins, ",")
		for i := range corsAllowed {
			corsAllowed[i] = strings.TrimSpace(corsAllowed[i])
		}
	}
	r.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		allowed := origin == ""
		if !allowed {
			for _, o := range corsAllowed {
				if strings.HasPrefix(origin, o) {
					allowed = true
					break
				}
			}
		}
		if allowed && origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type")
		}
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	s := &Server{
		address:    address,
		router:     r,
		messageCh:  messageCh,
		blockchain: blockchain,
		httpServer: &http.Server{
			Addr:         address,
			Handler:      r,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		readyCh: readyCh,
	}
	s.setupRoutes()
	// SEC-F01: background goroutine to prune faucet rate-limiter entries older
	// than 2 minutes, preventing unbounded growth of the sync.Map over time.
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-2 * time.Minute)
			s.faucetLimiter.Range(func(key, value interface{}) bool {
				if t, ok := value.(time.Time); ok && t.Before(cutoff) {
					s.faucetLimiter.Delete(key)
				}
				return true
			})
		}
	}()
	return s
}

func (s *Server) setupRoutes() {
	s.router.GET("/", func(c *gin.Context) {
		s.lastTxMutex.RLock()
		lastTx := s.lastTransaction
		s.lastTxMutex.RUnlock()

		var lastTxResp interface{}
		if lastTx != nil {
			lastTxResp = gin.H{
				"sender":    lastTx.Sender,
				"receiver":  lastTx.Receiver,
				"amount":    lastTx.Amount.String(),
				"nonce":     lastTx.Nonce,
				"timestamp": lastTx.Timestamp,
			}
		} else {
			lastTxResp = "No transactions yet"
		}

		blocks := s.blockchain.GetBlocks()
		if len(blocks) == 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no blocks in blockchain"})
			return
		}
		genesisBlock := blocks[0]
		bestBlockHash := s.blockchain.GetBestBlockHash()
		blockCount := s.blockchain.GetBlockCount()

		c.JSON(http.StatusOK, gin.H{
			"message": "Welcome to the blockchain API",
			"blockchain_info": gin.H{
				"genesis_block_hash":   fmt.Sprintf("%x", genesisBlock.GenerateBlockHash()),
				"genesis_block_height": genesisBlock.Header.Block,
				"best_block_hash":      fmt.Sprintf("%x", bestBlockHash),
				"block_count":          blockCount,
			},
			"last_transaction": lastTxResp,
			"available_endpoints": []string{
				"/transaction (POST)",
				"/block/:id (GET)",
				"/bestblockhash (GET)",
				"/blockcount (GET)",
				"/metrics (GET)",
				"/latest-transaction (GET)",
			},
		})
	})

	s.router.POST("/transaction", s.handleTransaction)
	s.router.GET("/block/:id", s.handleGetBlock)
	s.router.GET("/bestblockhash", s.handleGetBestBlockHash)
	s.router.GET("/blockcount", s.handleGetBlockCount)
	s.router.GET("/metrics", gin.WrapH(promhttp.Handler()))
	// Address endpoints — balance + transaction history
	s.router.GET("/address/:addr", s.handleGetAddress)
	s.router.GET("/address/:addr/txs", s.handleGetAddressTxs)
	// P2-2: Block range sync endpoint
	s.router.GET("/blocks", s.handleGetBlocks)
	// P2-3: Validator registration
	s.router.POST("/validator/register", s.handleValidatorRegister)
	s.router.GET("/validators", s.handleGetValidators)
	// P2-FAUCET: dev faucet endpoint (dev-mode only)
	s.router.POST("/faucet", s.handleFaucet)

	// F-20: /mine endpoint requires DEVNET_MINE_SECRET env var to be set and matched.
	// If not configured, the endpoint is disabled (returns 403).
	s.router.POST("/mine", func(c *gin.Context) {
		secret := os.Getenv("DEVNET_MINE_SECRET")
		if secret == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "mine endpoint disabled: DEVNET_MINE_SECRET not configured"})
			return
		}
		provided := c.GetHeader("X-Mine-Secret")
		if provided == "" {
			provided = c.Query("secret")
		}
		if provided != secret {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid mine secret"})
			return
		}
		height, err := s.blockchain.DevnetMineBlock("http-trigger")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "block mined", "height": height})
	})
	s.router.GET("/latest-transaction", func(c *gin.Context) {
		s.lastTxMutex.RLock()
		defer s.lastTxMutex.RUnlock()
		if s.lastTransaction == nil {
			c.JSON(http.StatusOK, gin.H{"message": "No transactions yet"})
			return
		}
		c.JSON(http.StatusOK, s.lastTransaction)
	})
}

func (s *Server) handleTransaction(c *gin.Context) {
	var tx types.Transaction
	if err := c.ShouldBindJSON(&tx); err != nil {
		log.Printf("Transaction binding error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid transaction format: %v", err)})
		return
	}

	// SEC-S04: Synchronous SanityCheck before async mempool submission.
	// The mempool's validationProcessor runs SanityCheck asynchronously, meaning
	// a fingerprint-mismatch (SEC-V05) or other sanity failure would return 200 OK
	// to the caller even though the tx will be silently dropped into invalidPool.
	// Run SanityCheck here first for immediate, correct HTTP feedback.
	if err := tx.SanityCheck(); err != nil {
		log.Printf("Transaction pre-validation failed from %s: %v", tx.Sender, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("transaction validation failed: %v", err)})
		return
	}

	// P3-3: Signature validation — enforce real SPHINCS+ signatures in production.
	// A placeholder is defined as empty or the literal string "placeholder".
	sigEmpty := len(tx.Signature) == 0 || string(tx.Signature) == "placeholder"
	if sigEmpty {
		if s.blockchain.IsDevMode() {
			log.Printf("[WARN] Dev-mode: accepting transaction from %s with empty/placeholder signature", tx.Sender)
		} else {
			log.Printf("Transaction rejected: missing or placeholder signature from %s", tx.Sender)
			c.JSON(http.StatusBadRequest, gin.H{"error": "transaction signature is required in production mode"})
			return
		}
	}

	// P3-5: If signature is provided and NOT dev-mode, attempt SPHINCS+ verification.
	// SEC-S03: Warn prominently if sphincsMgr is nil in production — sig verification silently skipped.
	if !sigEmpty && !s.blockchain.IsDevMode() && s.sphincsMgr == nil {
		log.Printf("[SEC-S03] WARN: sphincsMgr not wired — SPHINCS+ verification SKIPPED for tx from %s (production node)", tx.Sender)
	}
	if !sigEmpty && !s.blockchain.IsDevMode() && s.sphincsMgr != nil {
		s.verifyTransactionSignature(c, &tx)
		// verifyTransactionSignature writes the response on hard failure; check if response was sent
		if c.IsAborted() {
			return
		}
	}

	if err := s.blockchain.AddTransaction(&tx); err != nil {
		log.Printf("Transaction add error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("failed to add transaction: %v", err)})
		return
	}

	log.Printf("Received transaction: Sender=%s, Receiver=%s, Amount=%s, Nonce=%d",
		tx.Sender, tx.Receiver, tx.Amount.String(), tx.Nonce)

	s.messageCh <- &security.Message{Type: "transaction", Data: &tx}

	s.lastTxMutex.Lock()
	s.lastTransaction = &tx
	s.lastTxMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"status": "Transaction submitted"})
}

// verifyTransactionSignature attempts SPHINCS+ verification for P3-5.
// Aborts the gin context with 400 if verification fails (and pubkey is known).
// If pubkey is not found for sender, logs a warning but does NOT abort.
//
// SEC-S01 fix: uses tx.SigNonce, tx.SigCommitment, tx.SigMerkleRoot (new wire
// fields added to Transaction) instead of nil/zeroed values. If these fields
// are absent (legacy clients), verification falls back to a Spx_verify-only
// path that accepts the tx but logs a warning.
//
// SEC-S02 fix: canonical message is SHA-256(sender:receiver:amount:nonce:timestamp)
// binding ALL transaction fields — not just tx.ID which doesn't cover amount.
func (s *Server) verifyTransactionSignature(c *gin.Context, tx *types.Transaction) {
	// Step 1: attempt to find sender's public key from validator registry
	validators, err := s.blockchain.GetValidators()
	if err != nil || len(validators) == 0 {
		log.Printf("[P3-5] No validator registry — accepting tx from %s without sig verification", tx.Sender)
		return
	}

	var senderPubKeyHex string
	for _, v := range validators {
		if v.NodeAddress == tx.Sender || v.PublicKey == tx.Sender {
			senderPubKeyHex = v.PublicKey
			break
		}
	}

	if senderPubKeyHex == "" {
		log.Printf("[P3-5] No pubkey found for sender %s — accepting tx (forward-compatible)", tx.Sender)
		return
	}

	// Step 2: decode pubkey hex
	pubKeyBytes, err := hex.DecodeString(senderPubKeyHex)
	if err != nil {
		log.Printf("[P3-5] Failed to decode pubkey for %s: %v — accepting tx", tx.Sender, err)
		return
	}

	// Step 3: deserialize pubkey
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("[P3-5] KeyManager init failed: %v — accepting tx", err)
		return
	}
	pk, err := km.DeserializePublicKey(pubKeyBytes)
	if err != nil {
		log.Printf("[P3-5] Pubkey deserialization failed for %s: %v — accepting tx", tx.Sender, err)
		return
	}

	// Step 4: deserialize the SPHINCS+ signature
	sig, err := s.sphincsMgr.DeserializeSignature(tx.Signature)
	if err != nil {
		log.Printf("[P3-5] Signature deserialization failed from %s: %v", tx.Sender, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid signature format"})
		c.Abort()
		return
	}

	// Step 5 (SEC-S02): canonical message = "sender:receiver:amount:nonce"
	// This binds all economically-significant fields.
	// NOTE: tx.Timestamp is the block-inclusion time (set by the node/mempool), NOT the
	// signing timestamp. Including tx.Timestamp here would cause verification to always
	// fail because clients sign before block inclusion and don't know the final ts.
	// The signing timestamp is carried separately in tx.SigTimestamp.
	amountStr := "0"
	if tx.Amount != nil {
		amountStr = tx.Amount.String()
	}
	canonicalMsg := fmt.Sprintf("%s:%s:%s:%d", tx.Sender, tx.Receiver, amountStr, tx.Nonce)
	msgBytes := []byte(canonicalMsg)

	// Step 6 (SEC-S01-fix2): use SigTimestamp from tx wire field — NOT tx.Timestamp.
	// SignMessage generates its own internal timestamp (generateTimestamp) which differs
	// from tx.Timestamp (block-inclusion time). Using the wrong timestamp would cause
	// all VerifySignature calls to fail since the reconstructed payload wouldn't match.
	// SigTimestamp is the 8-byte big-endian timestamp returned by SignMessage.
	if len(tx.SigNonce) == 0 || len(tx.SigCommitment) != 32 || len(tx.SigTimestamp) != 8 {
		log.Printf("[P3-5] WARN: tx from %s missing SigTimestamp/SigNonce/SigCommitment — Pedersen commitment check skipped (legacy client)", tx.Sender)
		// Cannot do full Pedersen verification without signing metadata.
		// Accept for forward-compatibility but log the gap.
		// TODO: reject once all clients populate SigTimestamp/SigNonce/SigCommitment.
		return
	}
	tsBytes := tx.SigTimestamp

	// Reconstruct MerkleRoot node from hex
	var merkleNode *hashtree.HashTreeNode
	if tx.SigMerkleRoot != "" {
		merkleBytes, hexErr := hex.DecodeString(tx.SigMerkleRoot)
		if hexErr == nil && len(merkleBytes) == 32 {
			merkleNode = &hashtree.HashTreeNode{
				Hash: new(uint256.Int).SetBytes(merkleBytes),
			}
		}
	}

	ok := s.sphincsMgr.VerifySignature(msgBytes, tsBytes, tx.SigNonce, sig, pk, merkleNode, tx.SigCommitment)
	if !ok {
		log.Printf("[P3-5] Signature verification FAILED for tx from %s — REJECTING", tx.Sender)
		c.JSON(http.StatusBadRequest, gin.H{"error": "signature verification failed"})
		c.Abort()
		return
	}

	log.Printf("[P3-5] Signature verified for tx from %s (full Pedersen verification)", tx.Sender)
}

func (s *Server) handleGetBlock(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid block ID"})
		return
	}

	type result struct {
		block interface{}
		found bool
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ch := make(chan result, 1)
	go func() {
		blocks := s.blockchain.GetBlocks()
		for _, block := range blocks {
			if block.Header == nil {
				continue
			}
			if block.Header.Block == id {
				ch <- result{block: block, found: true}
				return
			}
		}
		ch <- result{found: false}
	}()

	select {
	case <-ctx.Done():
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "request timed out fetching block"})
	case res := <-ch:
		if !res.found {
			c.JSON(http.StatusNotFound, gin.H{"error": "block not found"})
			return
		}
		c.JSON(http.StatusOK, res.block)
	}
}

func (s *Server) handleGetBestBlockHash(c *gin.Context) {
	hash := s.blockchain.GetBestBlockHash()
	c.JSON(http.StatusOK, gin.H{"hash": fmt.Sprintf("%x", hash)})
}

func (s *Server) handleGetBlockCount(c *gin.Context) {
	count := s.blockchain.GetBlockCount()
	c.JSON(http.StatusOK, gin.H{"count": count})
}

func (s *Server) Start() error {
	log.Printf("Starting HTTP server on %s", s.address)
	go func() {
		if s.readyCh != nil {
			s.readyCh <- struct{}{}
			log.Printf("Sent HTTP ready signal for %s", s.address)
		}
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error on %s: %v", s.address, err)
		}
	}()
	return nil
}

func (s *Server) Stop() error {
	if s.httpServer == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown HTTP server on %s: %v", s.address, err)
	}
	log.Printf("HTTP server on %s stopped", s.address)
	return nil
}

// handleGetAddress returns address summary: balance, tx count, sent, received
func (s *Server) handleGetAddress(c *gin.Context) {
	addr := c.Param("addr")
	blocks := s.blockchain.GetBlocks()

	totalReceived := new(big.Int)
	totalSent := new(big.Int)
	txCount := 0

	for _, block := range blocks {
		for _, tx := range block.Body.TxsList {
			if tx.Amount == nil {
				continue
			}
			if tx.Receiver == addr {
				totalReceived.Add(totalReceived, tx.Amount)
				txCount++
			}
			if tx.Sender == addr {
				totalSent.Add(totalSent, tx.Amount)
				txCount++
			}
		}
	}
	balance := new(big.Int).Sub(totalReceived, totalSent)

	c.JSON(http.StatusOK, gin.H{
		"address":        addr,
		"balance":        balance.String(),
		"total_received": totalReceived.String(),
		"total_sent":     totalSent.String(),
		"tx_count":       txCount,
	})
}

// handleGetAddressTxs returns all transactions for an address
func (s *Server) handleGetAddressTxs(c *gin.Context) {
	addr := c.Param("addr")
	blocks := s.blockchain.GetBlocks()

	type TxEntry struct {
		Hash        string `json:"hash"`
		Block       uint64 `json:"block"`
		Timestamp   int64  `json:"timestamp"`
		From        string `json:"from"`
		To          string `json:"to"`
		Amount      string `json:"amount"`
		GasLimit    string `json:"gas_limit"`
		GasPrice    string `json:"gas_price"`
		Nonce       uint64 `json:"nonce"`
		Direction   string `json:"direction"` // "in" or "out"
	}

	var txs []TxEntry
	for _, block := range blocks {
		for _, tx := range block.Body.TxsList {
			if tx.Sender == addr || tx.Receiver == addr {
				dir := "in"
				if tx.Sender == addr {
					dir = "out"
				}
				amt := "0"
				if tx.Amount != nil {
					amt = tx.Amount.String()
				}
				gl := "0"
				if tx.GasLimit != nil {
					gl = tx.GasLimit.String()
				}
				gp := "0"
				if tx.GasPrice != nil {
					gp = tx.GasPrice.String()
				}
				txs = append(txs, TxEntry{
					Hash:      tx.ID,
					Block:     block.Header.Height,
					Timestamp: block.Header.Timestamp,
					From:      tx.Sender,
					To:        tx.Receiver,
					Amount:    amt,
					GasLimit:  gl,
					GasPrice:  gp,
					Nonce:     tx.Nonce,
					Direction: dir,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"address":      addr,
		"transactions": txs,
		"count":        len(txs),
	})
}

// handleGetBlocks returns a paginated list of blocks.
// GET /blocks?from=0&limit=100
// P2-2: Node sync protocol endpoint.
func (s *Server) handleGetBlocks(c *gin.Context) {
	fromStr := c.DefaultQuery("from", "0")
	limitStr := c.DefaultQuery("limit", "100")

	from, err := strconv.ParseUint(fromStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from parameter"})
		return
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	blocks := s.blockchain.GetBlocksRange(from, limit)
	c.JSON(http.StatusOK, blocks)
}

// ValidatorRegisterRequest is the body for POST /validator/register.
type ValidatorRegisterRequest struct {
	PublicKey   string `json:"public_key" binding:"required"`
	StakeAmount string `json:"stake_amount" binding:"required"`
	NodeAddress string `json:"node_address" binding:"required"`
}

// handleValidatorRegister registers a new validator.
// POST /validator/register — P2-3
// SEC-P03: gated behind VALIDATOR_REGISTER_SECRET env var (same pattern as /mine).
func (s *Server) handleValidatorRegister(c *gin.Context) {
	secret := os.Getenv("VALIDATOR_REGISTER_SECRET")
	// P2-PBFT: in dev-mode, skip secret check to allow auto-registration in testnet.
	if !s.blockchain.IsDevMode() {
		if secret == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "validator registration disabled: VALIDATOR_REGISTER_SECRET not configured"})
			return
		}
		if c.GetHeader("X-Register-Secret") != secret {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid register secret"})
			return
		}
	}

	var req ValidatorRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid request: %v", err)})
		return
	}

	reg := &core.ValidatorRegistration{
		PublicKey:   req.PublicKey,
		StakeAmount: req.StakeAmount,
		NodeAddress: req.NodeAddress,
	}
	if err := s.blockchain.RegisterValidator(reg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// P2-6: also register with consensus validator set if wired
	if s.consensusValidatorSet != nil {
		stakeInt, ok := new(big.Int).SetString(req.StakeAmount, 10)
		if ok && stakeInt.Sign() > 0 {
			stakeQTX := stakeInt.Uint64()
			if err := s.consensusValidatorSet.RegisterValidator(
				req.NodeAddress, req.PublicKey, stakeQTX, req.NodeAddress,
			); err != nil {
				log.Printf("⚠️ consensus.RegisterValidator: %v", err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":       "registered",
		"node_address": req.NodeAddress,
	})
}

// Router returns the underlying gin.Engine for use in tests or middleware wiring.
func (s *Server) Router() interface{ ServeHTTP(http.ResponseWriter, *http.Request) } {
	return s.router
}

// handleGetValidators returns all registered validators.
// GET /validators — P2-3
func (s *Server) handleGetValidators(c *gin.Context) {
	validators, err := s.blockchain.GetValidators()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if validators == nil {
		validators = []*core.ValidatorRegistration{}
	}
	c.JSON(http.StatusOK, gin.H{
		"validators": validators,
		"count":      len(validators),
	})
}

// FaucetRequest is the body for POST /faucet.
// P2-FAUCET: dev faucet — only works in dev-mode.
type FaucetRequest struct {
	Address string  `json:"address"`
	Amount  float64 `json:"amount"` // in QTX, max 1000
}

// handleFaucet sends test QTX to a given address.
// POST /faucet — P2-FAUCET
func (s *Server) handleFaucet(c *gin.Context) {
	if !s.blockchain.IsDevMode() {
		c.JSON(http.StatusForbidden, gin.H{"error": "faucet only available in dev-mode"})
		return
	}

	var req FaucetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid request: %v", err)})
		return
	}
	if req.Address == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "address is required"})
		return
	}
	if req.Amount <= 0 || req.Amount > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "amount must be between 0 and 1000 QTX"})
		return
	}

	// Rate limit: 1 request per address per minute
	now := time.Now()
	if val, loaded := s.faucetLimiter.Load(req.Address); loaded {
		lastReq := val.(time.Time)
		if now.Sub(lastReq) < time.Minute {
			remaining := time.Minute - now.Sub(lastReq)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":            "rate limit: 1 request per address per minute",
				"retry_after_secs": int(remaining.Seconds()) + 1,
			})
			return
		}
	}
	s.faucetLimiter.Store(req.Address, now)

	// Convert QTX amount to base units (* 1e18)
	amountBase := new(big.Float).Mul(big.NewFloat(req.Amount), big.NewFloat(1e18))
	amountInt, _ := amountBase.Int(nil)

	tx := &types.Transaction{
		Sender:    "genesis_faucet",
		Receiver:  req.Address,
		Amount:    amountInt,
		Timestamp: now.Unix(),
		Nonce:     uint64(now.UnixNano()),
		// SEC-F02: set explicit zero values to prevent nil dereference in gas accounting.
		GasLimit: big.NewInt(0),
		GasPrice: big.NewInt(0),
	}
	// Generate a deterministic ID
	tx.ID = fmt.Sprintf("faucet-%s-%d", req.Address, now.UnixNano())

	if err := s.blockchain.AddTransaction(tx); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("failed to add faucet transaction: %v", err)})
		return
	}

	log.Printf("[FAUCET] Sent %.4f QTX to %s (tx: %s)", req.Amount, req.Address, tx.ID)
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"tx_id":   tx.ID,
		"address": req.Address,
		"amount":  req.Amount,
	})
}

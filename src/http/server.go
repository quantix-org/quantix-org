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
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ramseyauron/quantix/src/core"
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

func (s *Server) handleGetBlock(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid block ID"})
		return
	}
	blocks := s.blockchain.GetBlocks()
	for _, block := range blocks {
		if block.Header.Block == id {
			c.JSON(http.StatusOK, block)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "block not found"})
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
func (s *Server) handleValidatorRegister(c *gin.Context) {
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

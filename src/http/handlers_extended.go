// go/src/http/handlers_extended.go
package http

import (
	"fmt"
	"math/big"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/quantix-org/quantix-org/src/core"
	types "github.com/quantix-org/quantix-org/src/core/transaction"
)

// stakeRequest is the JSON body for /stake, /unstake, /register-validator.
type stakeRequest struct {
	Sender    string `json:"sender"`
	Amount    string `json:"amount"`
	NodeID    string `json:"node_id"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

func (s *Server) handleStake(c *gin.Context) {
	s.handleStakeTx(c, types.TxTypeStake)
}

func (s *Server) handleUnstake(c *gin.Context) {
	s.handleStakeTx(c, types.TxTypeUnstake)
}

func (s *Server) handleRegisterValidator(c *gin.Context) {
	s.handleStakeTx(c, types.TxTypeRegisterValidator)
}

func (s *Server) handleStakeTx(c *gin.Context, txType types.TxType) {
	var req stakeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	amount := new(big.Int)
	if req.Amount != "" {
		if _, ok := amount.SetString(req.Amount, 10); !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid amount"})
			return
		}
	}

	tx := &types.Transaction{
		Sender:   req.Sender,
		Receiver: req.Sender,
		Amount:   amount,
		Type:     txType,
		Data:     []byte(req.NodeID),
	}

	if err := s.blockchain.AddTransaction(tx); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "submitted", "tx_type": txType.String()})
}

func (s *Server) handleGetValidators(c *gin.Context) {
	records, err := s.blockchain.GetAllStakes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type validatorResp struct {
		NodeID        string `json:"node_id"`
		StakeNQTX     string `json:"stake_nqtx"`
		RewardAddress string `json:"reward_address"`
		Active        bool   `json:"active"`
	}

	validators := make([]validatorResp, 0, len(records))
	for _, r := range records {
		validators = append(validators, validatorResp{
			NodeID:        r.NodeID,
			StakeNQTX:     r.StakeNQTX.String(),
			RewardAddress: r.RewardAddress,
			Active:        r.Active,
		})
	}

	totalStaked := s.blockchain.GetTotalStakedFromDB()

	c.JSON(http.StatusOK, gin.H{
		"validators":   validators,
		"total_staked": totalStaked.String(),
		"count":        len(validators),
	})
}

func (s *Server) handleGetBalance(c *gin.Context) {
	address := c.Param("address")
	balNQTX, nonce := s.blockchain.GetAddressInfo(address)

	// Convert nQTX → QTX (divide by 1e18)
	balQTX := new(big.Float).Quo(
		new(big.Float).SetInt(balNQTX),
		new(big.Float).SetInt(big.NewInt(1e18)),
	)

	c.JSON(http.StatusOK, gin.H{
		"address":      address,
		"balance_nqtx": balNQTX.String(),
		"balance_qtx":  fmt.Sprintf("%.18f", balQTX),
		"nonce":        nonce,
	})
}

func (s *Server) handleGetMempool(c *gin.Context) {
	txs := s.blockchain.GetMempoolTxs()
	c.JSON(http.StatusOK, gin.H{
		"pending_count": len(txs),
		"pending_txs":   txs,
	})
}

func (s *Server) handleGetTransaction(c *gin.Context) {
	txid := c.Param("txid")
	tx, err := s.blockchain.GetTransactionByIDString(txid)
	if err != nil || tx == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "transaction not found"})
		return
	}
	c.JSON(http.StatusOK, tx)
}

func (s *Server) handleGetBlockByHeight(c *gin.Context) {
	nStr := c.Param("n")
	n, err := strconv.ParseUint(nStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid height"})
		return
	}
	block := s.blockchain.GetBlockByHeight(n)
	if block == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "block not found"})
		return
	}
	c.JSON(http.StatusOK, block)
}

func (s *Server) handleGetAccountTxs(c *gin.Context) {
	address := c.Param("address")
	txs := s.blockchain.GetTransactionsByAddress(address)
	c.JSON(http.StatusOK, gin.H{
		"address": address,
		"count":   len(txs),
		"txs":     txs,
	})
}

func (s *Server) handleGetChainInfo(c *gin.Context) {
	height := s.blockchain.GetBlockCount()
	bestHash := fmt.Sprintf("%x", s.blockchain.GetBestBlockHash())
	totalSupply, validators, tps := s.blockchain.GetChainSummary()

	c.JSON(http.StatusOK, gin.H{
		"chain_id":          73310,
		"chain_name":        "Quantix Devnet",
		"symbol":            "QTX",
		"height":            height,
		"best_hash":         bestHash,
		"total_supply_nqtx": totalSupply,
		"validators":        validators,
		"tps":               tps,
	})
}

// Ensure the core package is used.
var _ *core.Blockchain = nil

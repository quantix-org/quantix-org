// MIT License
// Copyright (c) 2024 quantix-org

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RPCClient is a JSON-RPC client for the Quantix node.
type RPCClient struct {
	endpoint string
	client   *http.Client
}

// NewRPCClient creates a new RPC client.
func NewRPCClient(endpoint string) *RPCClient {
	return &RPCClient{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// =====================================================
// Data Types
// =====================================================

// Block represents a block for the explorer.
type Block struct {
	Number     uint64 `json:"number"`
	Hash       string `json:"hash"`
	ParentHash string `json:"parent_hash"`
	Timestamp  string `json:"timestamp"`
	Validator  string `json:"validator"`
	TxCount    int    `json:"tx_count"`
	GasUsed    uint64 `json:"gas_used"`
	GasLimit   uint64 `json:"gas_limit"`
	StateRoot  string `json:"state_root"`
	TxRoot     string `json:"tx_root"`
	Size       uint64 `json:"size"`
}

// Transaction represents a transaction for the explorer.
type Transaction struct {
	Hash        string `json:"hash"`
	BlockNumber uint64 `json:"block_number"`
	BlockHash   string `json:"block_hash"`
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	GasUsed     uint64 `json:"gas_used"`
	GasPrice    string `json:"gas_price"`
	Nonce       uint64 `json:"nonce"`
	Status      string `json:"status"`
	Timestamp   string `json:"timestamp"`
	Type        string `json:"type"` // "transfer", "contract_call", "contract_deploy"
	Input       string `json:"input,omitempty"`
}

// AddressInfo represents address information for the explorer.
type AddressInfo struct {
	Address     string `json:"address"`
	Balance     string `json:"balance"`
	TxCount     uint64 `json:"tx_count"`
	IsContract  bool   `json:"is_contract"`
	IsValidator bool   `json:"is_validator"`
	Staked      string `json:"staked,omitempty"`
	Code        string `json:"code,omitempty"`
}

// NetworkStats represents network statistics.
type NetworkStats struct {
	BlockHeight       uint64  `json:"block_height"`
	TotalTransactions uint64  `json:"total_transactions"`
	ValidatorCount    int     `json:"validator_count"`
	TotalStaked       string  `json:"total_staked"`
	AvgBlockTime      float64 `json:"avg_block_time"`
	TPS24h            float64 `json:"tps_24h"`
	TotalSupply       string  `json:"total_supply"`
	CirculatingSupply string  `json:"circulating_supply"`
}

// Validator represents a validator for the explorer.
type Validator struct {
	Address      string  `json:"address"`
	Stake        string  `json:"stake"`
	Commission   float64 `json:"commission"`
	Uptime       float64 `json:"uptime"`
	BlocksProposed uint64 `json:"blocks_proposed"`
	Active       bool    `json:"active"`
}

// SearchResult represents a search result.
type SearchResult struct {
	Type string `json:"type"` // "block", "tx", "address", "not_found"
	ID   string `json:"id"`
}

// =====================================================
// RPC Methods
// =====================================================

// rpcRequest makes a JSON-RPC request.
func (c *RPCClient) rpcRequest(method string, params []interface{}) (json.RawMessage, error) {
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Post(c.endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", result.Error.Code, result.Error.Message)
	}

	return result.Result, nil
}

// GetBlocks returns recent blocks.
func (c *RPCClient) GetBlocks(limit, offset int) ([]*Block, error) {
	// For now, return mock data
	// In production, this would call qtx_getBlocksByRange or similar
	
	blocks := make([]*Block, limit)
	baseHeight := uint64(1000000 - offset)
	
	for i := 0; i < limit; i++ {
		height := baseHeight - uint64(i)
		blocks[i] = &Block{
			Number:     height,
			Hash:       fmt.Sprintf("0x%064x", height*12345),
			ParentHash: fmt.Sprintf("0x%064x", (height-1)*12345),
			Timestamp:  time.Now().Add(-time.Duration(i*10) * time.Second).Format(time.RFC3339),
			Validator:  "qtx1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs",
			TxCount:    int(height % 50),
			GasUsed:    uint64(height%10) * 100000,
			GasLimit:   10000000,
			StateRoot:  fmt.Sprintf("0x%064x", height*54321),
			TxRoot:     fmt.Sprintf("0x%064x", height*67890),
			Size:       uint64(1000 + height%5000),
		}
	}
	
	return blocks, nil
}

// GetBlock returns a single block by hash or number.
func (c *RPCClient) GetBlock(id string) (*Block, error) {
	// Parse block number or use hash
	var number uint64
	if strings.HasPrefix(id, "0x") {
		// It's a hash, would look up by hash
		number = 1000000
	} else {
		var err error
		number, err = strconv.ParseUint(id, 10, 64)
		if err != nil {
			return nil, err
		}
	}
	
	return &Block{
		Number:     number,
		Hash:       fmt.Sprintf("0x%064x", number*12345),
		ParentHash: fmt.Sprintf("0x%064x", (number-1)*12345),
		Timestamp:  time.Now().Add(-time.Duration(1000000-number) * 10 * time.Second).Format(time.RFC3339),
		Validator:  "qtx1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs",
		TxCount:    int(number % 50),
		GasUsed:    uint64(number%10) * 100000,
		GasLimit:   10000000,
		StateRoot:  fmt.Sprintf("0x%064x", number*54321),
		TxRoot:     fmt.Sprintf("0x%064x", number*67890),
		Size:       uint64(1000 + number%5000),
	}, nil
}

// GetTransaction returns a transaction by hash.
func (c *RPCClient) GetTransaction(hash string) (*Transaction, error) {
	return &Transaction{
		Hash:        hash,
		BlockNumber: 1000000,
		BlockHash:   "0x" + strings.Repeat("a", 64),
		From:        "qtx1sender0000000000000000000000000000000",
		To:          "qtx1receiver00000000000000000000000000000",
		Value:       "1000000000000000000", // 1 QTX
		GasUsed:     71000,
		GasPrice:    "1000000000", // 1 gQTX
		Nonce:       42,
		Status:      "Success",
		Timestamp:   time.Now().Format(time.RFC3339),
		Type:        "transfer",
	}, nil
}

// GetAddressInfo returns address information.
func (c *RPCClient) GetAddressInfo(address string) (*AddressInfo, error) {
	isValidator := strings.HasPrefix(address, "qtx1val")
	
	info := &AddressInfo{
		Address:     address,
		Balance:     "5000000000000000000000", // 5000 QTX
		TxCount:     150,
		IsContract:  strings.HasSuffix(address, "contract"),
		IsValidator: isValidator,
	}
	
	if isValidator {
		info.Staked = "32000000000000000000" // 32 QTX
	}
	
	return info, nil
}

// GetStats returns network statistics.
func (c *RPCClient) GetStats() (*NetworkStats, error) {
	return &NetworkStats{
		BlockHeight:       1000000,
		TotalTransactions: 5000000,
		ValidatorCount:    50,
		TotalStaked:       "1600000000000000000000", // 1600 QTX
		AvgBlockTime:      10.2,
		TPS24h:            15.5,
		TotalSupply:       "5000000000000000000000000000", // 5B QTX
		CirculatingSupply: "4250000000000000000000000000", // 4.25B QTX
	}, nil
}

// GetValidators returns the validator set.
func (c *RPCClient) GetValidators() ([]*Validator, error) {
	validators := make([]*Validator, 10)
	
	for i := 0; i < 10; i++ {
		validators[i] = &Validator{
			Address:        fmt.Sprintf("qtx1validator%d00000000000000000000000", i),
			Stake:          fmt.Sprintf("%d000000000000000000", 32+i*10), // 32+ QTX
			Commission:     5.0,
			Uptime:         99.5 - float64(i)*0.1,
			BlocksProposed: uint64(10000 - i*500),
			Active:         true,
		}
	}
	
	return validators, nil
}

// Search performs a universal search.
func (c *RPCClient) Search(query string) *SearchResult {
	query = strings.TrimSpace(query)
	
	// Check if it's a block number
	if _, err := strconv.ParseUint(query, 10, 64); err == nil {
		return &SearchResult{Type: "block", ID: query}
	}
	
	// Check if it's a transaction hash (0x + 64 hex chars)
	if strings.HasPrefix(query, "0x") && len(query) == 66 {
		return &SearchResult{Type: "tx", ID: query}
	}
	
	// Check if it's a Quantix address
	if strings.HasPrefix(query, "qtx1") && len(query) == 42 {
		return &SearchResult{Type: "address", ID: query}
	}
	
	// Check if it's a block hash
	if strings.HasPrefix(query, "0x") && len(query) == 66 {
		return &SearchResult{Type: "block", ID: query}
	}
	
	return &SearchResult{Type: "not_found", ID: ""}
}

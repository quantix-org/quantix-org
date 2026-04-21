// go/src/core/api_helpers.go
package core

import (
	"math/big"

	types "github.com/quantix-org/quantix-org/src/core/transaction"
	logger "github.com/quantix-org/quantix-org/src/log"
)

// GetAddressInfo returns the balance (nQTX) and nonce for an address.
func (bc *Blockchain) GetAddressInfo(address string) (*big.Int, uint64) {
	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Warn("GetAddressInfo: %v", err)
		return big.NewInt(0), 0
	}
	bal := stateDB.GetBalance(address)
	nonce := stateDB.GetNonce(address)
	return bal, nonce
}

// GetMempoolTxs returns pending transactions from the mempool.
func (bc *Blockchain) GetMempoolTxs() []*types.Transaction {
	if bc.mempool == nil {
		return nil
	}
	return bc.mempool.GetPendingTransactions()
}

// GetBlockByHeight returns the block at the given height (alias for GetBlockByNumber).
func (bc *Blockchain) GetBlockByHeight(height uint64) *types.Block {
	return bc.GetBlockByNumber(height)
}

// GetTransactionsByAddress scans all in-memory blocks for txs involving address.
func (bc *Blockchain) GetTransactionsByAddress(address string) []*types.Transaction {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	var result []*types.Transaction
	for _, block := range bc.chain {
		for _, tx := range block.Body.TxsList {
			if tx.Sender == address || tx.Receiver == address {
				result = append(result, tx)
			}
		}
	}
	return result
}

// GetChainSummary returns chain-level summary data for the API.
// Returns: totalSupplyNQTX string, validator count, current TPS.
func (bc *Blockchain) GetChainSummary() (string, int, float64) {
	stateDB, err := bc.newStateDB()
	totalSupply := "0"
	if err == nil {
		totalSupply = stateDB.GetTotalSupply().String()
	}

	records, _ := bc.GetAllStakes()
	validatorCount := len(records)

	tps := 0.0
	if bc.tpsMonitor != nil {
		stats := bc.tpsMonitor.GetStats()
		if v, ok := stats["current_tps"]; ok {
			if f, ok2 := v.(float64); ok2 {
				tps = f
			}
		}
	}

	return totalSupply, validatorCount, tps
}

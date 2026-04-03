// MIT License
// Copyright (c) 2024 quantix

// go/src/core/validators.go
//
// P2-3: Validator registration stored in LevelDB under prefix "val:".
package core

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	logger "github.com/ramseyauron/quantix/src/log"
)

// ValidatorRegistration holds data submitted to POST /validator/register.
type ValidatorRegistration struct {
	PublicKey   string    `json:"public_key"`
	StakeAmount string    `json:"stake_amount"` // decimal string, in QTX
	NodeAddress string    `json:"node_address"`
	RegisteredAt time.Time `json:"registered_at"`
	Active      bool      `json:"active"`
}

const valKeyPrefix = "val:"

// RegisterValidator stores a validator registration in LevelDB.
func (bc *Blockchain) RegisterValidator(reg *ValidatorRegistration) error {
	if reg.NodeAddress == "" {
		return fmt.Errorf("node_address is required")
	}
	if reg.PublicKey == "" {
		return fmt.Errorf("public_key is required")
	}

	// Validate stake amount
	stake, ok := new(big.Int).SetString(reg.StakeAmount, 10)
	if !ok || stake.Sign() <= 0 {
		return fmt.Errorf("stake_amount must be a positive integer (QTX units)")
	}

	reg.RegisteredAt = time.Now().UTC()
	reg.Active = true

	data, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("marshal validator: %w", err)
	}

	db, err := bc.storage.GetDB()
	if err != nil {
		return fmt.Errorf("storage DB unavailable: %w", err)
	}

	key := valKeyPrefix + reg.NodeAddress
	if err := db.Put(key, data); err != nil {
		return fmt.Errorf("store validator: %w", err)
	}

	logger.Info("✅ Registered validator %s with stake %s QTX", reg.NodeAddress, reg.StakeAmount)
	return nil
}

// GetValidators returns all registered validators from LevelDB.
func (bc *Blockchain) GetValidators() ([]*ValidatorRegistration, error) {
	db, err := bc.storage.GetDB()
	if err != nil {
		return nil, fmt.Errorf("storage DB unavailable: %w", err)
	}

	// Use GetAll-style iteration: iterate key range "val:" → "val:~"
	// LevelDB DB only exposes Get/Put/Delete; iterate via db.GetAll prefix approach
	// or use the raw leveldb iterator.
	// We access the underlying leveldb via a helper if available, else scan known keys.
	// Since database.DB doesn't expose an Iterator, we use a prefix scan helper.
	results, err := db.GetByPrefix(valKeyPrefix)
	if err != nil {
		return nil, fmt.Errorf("scan validators: %w", err)
	}

	var validators []*ValidatorRegistration
	for k, v := range results {
		if !strings.HasPrefix(k, valKeyPrefix) {
			continue
		}
		var reg ValidatorRegistration
		if err := json.Unmarshal(v, &reg); err != nil {
			logger.Warn("Failed to unmarshal validator %s: %v", k, err)
			continue
		}
		validators = append(validators, &reg)
	}
	return validators, nil
}

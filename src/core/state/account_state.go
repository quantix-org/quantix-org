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

// go/src/core/state/account_state.go
package database

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
)

const (
	// accPrefix is the LevelDB key prefix for AccountState records.
	// Distinct from state_db.go's "acct:" prefix to avoid key collisions.
	accPrefix = "acc:"
)

// AccountState holds the persistent state for a single account address.
type AccountState struct {
	Address string   `json:"address"`
	Balance *big.Int `json:"balance"` // in nQTX
	Nonce   uint64   `json:"nonce"`
}

// accountStateRecord is the JSON shape persisted to LevelDB.
// big.Int is stored as a decimal string for clean round-trip serialization.
type accountStateRecord struct {
	Balance string `json:"balance"`
	Nonce   uint64 `json:"nonce"`
}

// key returns the LevelDB key for this account.
func (a *AccountState) key() string {
	return accPrefix + a.Address
}

// Save writes the AccountState to LevelDB.
func (a *AccountState) Save(db *DB) error {
	if a.Balance == nil {
		a.Balance = big.NewInt(0)
	}
	rec := accountStateRecord{
		Balance: a.Balance.String(),
		Nonce:   a.Nonce,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("AccountState.Save: marshal %s: %w", a.Address, err)
	}
	return db.Put(a.key(), data)
}

// LoadAccountState loads an AccountState from LevelDB by address.
// Returns a zero-balance AccountState (not an error) if the key is absent.
func LoadAccountState(db *DB, address string) (*AccountState, error) {
	key := accPrefix + address
	data, err := db.Get(key)
	if err != nil {
		// Key not found → return a fresh zero account (not an error condition).
		return &AccountState{Address: address, Balance: big.NewInt(0), Nonce: 0}, nil
	}
	var rec accountStateRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("LoadAccountState: unmarshal %s: %w", address, err)
	}
	bal, ok := new(big.Int).SetString(rec.Balance, 10)
	if !ok {
		bal = big.NewInt(0)
	}
	return &AccountState{Address: address, Balance: bal, Nonce: rec.Nonce}, nil
}

// DeleteAccountState removes an account record from LevelDB.
func DeleteAccountState(db *DB, address string) error {
	return db.Delete(accPrefix + address)
}

// GetBalance returns a copy of the account's balance in nQTX.
func GetBalance(db *DB, address string) (*big.Int, error) {
	acc, err := LoadAccountState(db, address)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Set(acc.Balance), nil
}

// SetBalance writes a new balance for address to LevelDB.
func SetBalance(db *DB, address string, amount *big.Int) error {
	acc, err := LoadAccountState(db, address)
	if err != nil {
		return err
	}
	if amount == nil {
		amount = big.NewInt(0)
	}
	acc.Balance = new(big.Int).Set(amount)
	return acc.Save(db)
}

// GetNonce returns the current nonce for address.
func GetNonce(db *DB, address string) (uint64, error) {
	acc, err := LoadAccountState(db, address)
	if err != nil {
		return 0, err
	}
	return acc.Nonce, nil
}

// IncrementNonce loads the account, increments its nonce by 1, and persists it.
func IncrementNonce(db *DB, address string) error {
	acc, err := LoadAccountState(db, address)
	if err != nil {
		return err
	}
	acc.Nonce++
	return acc.Save(db)
}

// StateRoot computes a deterministic hash over all account records stored under
// the "acc:" prefix. Keys are sorted before hashing so the root is identical
// regardless of insertion order.
func StateRoot(db *DB) ([]byte, error) {
	keys, err := db.ListKeysWithPrefix(accPrefix)
	if err != nil {
		return nil, fmt.Errorf("StateRoot: list keys: %w", err)
	}

	// An empty state gets a stable sentinel hash.
	if len(keys) == 0 {
		h := sha256.Sum256([]byte("empty-acc-state"))
		return h[:], nil
	}

	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		data, err := db.Get(k)
		if err != nil {
			continue
		}
		leaf := sha256.Sum256(append([]byte(k), data...))
		h.Write(leaf[:])
	}
	return h.Sum(nil), nil
}

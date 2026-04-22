// MIT License
//
// Copyright (c) 2024 quantix-org
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

// go/src/core/svm/vm/storage.go
package vm

import (
	"encoding/binary"
	"fmt"
	"sync"

	"golang.org/x/crypto/sha3"
)

// StorageKey is a 32-byte key for contract storage slots
type StorageKey [32]byte

// StorageValue is a 32-byte value for contract storage slots
type StorageValue [32]byte

// ContractAddress is a 20-byte address identifying a contract
type ContractAddress [20]byte

// ContractStorage manages persistent storage for smart contracts
type ContractStorage struct {
	mu       sync.RWMutex
	storage  map[ContractAddress]map[StorageKey]StorageValue
	dirty    map[ContractAddress]map[StorageKey]bool // Tracks modified slots
	original map[ContractAddress]map[StorageKey]StorageValue // Original values for refunds
}

// NewContractStorage creates a new contract storage instance
func NewContractStorage() *ContractStorage {
	return &ContractStorage{
		storage:  make(map[ContractAddress]map[StorageKey]StorageValue),
		dirty:    make(map[ContractAddress]map[StorageKey]bool),
		original: make(map[ContractAddress]map[StorageKey]StorageValue),
	}
}

// Get retrieves a storage value for a contract
func (cs *ContractStorage) Get(addr ContractAddress, key StorageKey) StorageValue {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if slots, exists := cs.storage[addr]; exists {
		if value, ok := slots[key]; ok {
			return value
		}
	}
	return StorageValue{} // Return zero value if not found
}

// Set stores a value in contract storage
func (cs *ContractStorage) Set(addr ContractAddress, key StorageKey, value StorageValue) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Initialize maps if needed
	if cs.storage[addr] == nil {
		cs.storage[addr] = make(map[StorageKey]StorageValue)
	}
	if cs.dirty[addr] == nil {
		cs.dirty[addr] = make(map[StorageKey]bool)
	}
	if cs.original[addr] == nil {
		cs.original[addr] = make(map[StorageKey]StorageValue)
	}

	// Store original value if this is first modification
	if !cs.dirty[addr][key] {
		cs.original[addr][key] = cs.storage[addr][key]
	}

	cs.storage[addr][key] = value
	cs.dirty[addr][key] = true
}

// Delete removes a storage slot (sets to zero)
func (cs *ContractStorage) Delete(addr ContractAddress, key StorageKey) {
	cs.Set(addr, key, StorageValue{})
}

// GetOriginal returns the original value before any modifications
// Used for gas refund calculations
func (cs *ContractStorage) GetOriginal(addr ContractAddress, key StorageKey) StorageValue {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if original, exists := cs.original[addr]; exists {
		if value, ok := original[key]; ok {
			return value
		}
	}
	return StorageValue{}
}

// IsDirty checks if a storage slot has been modified
func (cs *ContractStorage) IsDirty(addr ContractAddress, key StorageKey) bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if dirty, exists := cs.dirty[addr]; exists {
		return dirty[key]
	}
	return false
}

// GetDirtyKeys returns all modified keys for a contract
func (cs *ContractStorage) GetDirtyKeys(addr ContractAddress) []StorageKey {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var keys []StorageKey
	if dirty, exists := cs.dirty[addr]; exists {
		for key := range dirty {
			keys = append(keys, key)
		}
	}
	return keys
}

// Commit finalizes all changes (clears dirty tracking)
func (cs *ContractStorage) Commit() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.dirty = make(map[ContractAddress]map[StorageKey]bool)
	cs.original = make(map[ContractAddress]map[StorageKey]StorageValue)
}

// Revert undoes all uncommitted changes
func (cs *ContractStorage) Revert() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Restore original values
	for addr, slots := range cs.original {
		for key, value := range slots {
			if cs.storage[addr] != nil {
				cs.storage[addr][key] = value
			}
		}
	}

	cs.dirty = make(map[ContractAddress]map[StorageKey]bool)
	cs.original = make(map[ContractAddress]map[StorageKey]StorageValue)
}

// StorageRoot computes the Merkle root of a contract's storage
// Used for state commitments
func (cs *ContractStorage) StorageRoot(addr ContractAddress) [32]byte {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	slots, exists := cs.storage[addr]
	if !exists || len(slots) == 0 {
		return [32]byte{} // Empty root
	}

	// Simple hash-based root (not a full Merkle tree for simplicity)
	// Production would use a Patricia Merkle Trie
	h := sha3.New256()
	for key, value := range slots {
		h.Write(key[:])
		h.Write(value[:])
	}

	var root [32]byte
	copy(root[:], h.Sum(nil))
	return root
}

// Contract represents a deployed smart contract
type Contract struct {
	Address   ContractAddress
	Code      []byte
	CodeHash  [32]byte
	Storage   *ContractStorage
	Balance   uint64
	Nonce     uint64
	CreatedAt uint64 // Block number when created
}

// NewContract creates a new contract instance
func NewContract(code []byte, creator ContractAddress, nonce uint64, blockNumber uint64) *Contract {
	// Compute contract address: SHA3(creator || nonce)
	h := sha3.New256()
	h.Write(creator[:])
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, nonce)
	h.Write(nonceBytes)

	var addr ContractAddress
	copy(addr[:], h.Sum(nil)[12:32]) // Take last 20 bytes

	// Compute code hash
	codeHash := sha3.Sum256(code)

	return &Contract{
		Address:   addr,
		Code:      code,
		CodeHash:  codeHash,
		Storage:   NewContractStorage(),
		Balance:   0,
		Nonce:     0,
		CreatedAt: blockNumber,
	}
}

// GetCode returns the contract bytecode
func (c *Contract) GetCode() []byte {
	return c.Code
}

// GetCodeHash returns the SHA3-256 hash of the contract code
func (c *Contract) GetCodeHash() [32]byte {
	return c.CodeHash
}

// GetStorage retrieves a storage value
func (c *Contract) GetStorage(key StorageKey) StorageValue {
	return c.Storage.Get(c.Address, key)
}

// SetStorage stores a value
func (c *Contract) SetStorage(key StorageKey, value StorageValue) {
	c.Storage.Set(c.Address, key, value)
}

// ContractRegistry manages deployed contracts
type ContractRegistry struct {
	mu        sync.RWMutex
	contracts map[ContractAddress]*Contract
	storage   *ContractStorage // Shared storage backend
}

// NewContractRegistry creates a new contract registry
func NewContractRegistry() *ContractRegistry {
	return &ContractRegistry{
		contracts: make(map[ContractAddress]*Contract),
		storage:   NewContractStorage(),
	}
}

// Deploy creates and registers a new contract
func (cr *ContractRegistry) Deploy(code []byte, creator ContractAddress, nonce uint64, blockNumber uint64) (*Contract, error) {
	contract := NewContract(code, creator, nonce, blockNumber)
	contract.Storage = cr.storage // Use shared storage

	cr.mu.Lock()
	defer cr.mu.Unlock()

	if _, exists := cr.contracts[contract.Address]; exists {
		return nil, fmt.Errorf("contract already exists at address %x", contract.Address)
	}

	cr.contracts[contract.Address] = contract
	return contract, nil
}

// Get retrieves a contract by address
func (cr *ContractRegistry) Get(addr ContractAddress) (*Contract, bool) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	contract, exists := cr.contracts[addr]
	return contract, exists
}

// Exists checks if a contract exists at the given address
func (cr *ContractRegistry) Exists(addr ContractAddress) bool {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	_, exists := cr.contracts[addr]
	return exists
}

// GetCodeSize returns the size of a contract's code
func (cr *ContractRegistry) GetCodeSize(addr ContractAddress) uint64 {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	if contract, exists := cr.contracts[addr]; exists {
		return uint64(len(contract.Code))
	}
	return 0
}

// GetCodeHash returns the code hash for a contract
func (cr *ContractRegistry) GetCodeHash(addr ContractAddress) [32]byte {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	if contract, exists := cr.contracts[addr]; exists {
		return contract.CodeHash
	}
	return [32]byte{}
}

// Commit commits all storage changes
func (cr *ContractRegistry) Commit() {
	cr.storage.Commit()
}

// Revert reverts all uncommitted storage changes
func (cr *ContractRegistry) Revert() {
	cr.storage.Revert()
}

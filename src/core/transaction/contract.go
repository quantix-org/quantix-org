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

// go/src/core/transaction/contract.go
package types

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// ContractDeployment represents a contract deployment transaction
type ContractDeployment struct {
	// Core deployment data
	Code      []byte `json:"code"`       // Contract bytecode
	InitCode  []byte `json:"init_code"`  // Initialization bytecode (optional)
	Salt      []byte `json:"salt"`       // Salt for CREATE2-style deployment (optional)
	
	// Metadata
	Name        string `json:"name,omitempty"`        // Human-readable contract name
	Version     string `json:"version,omitempty"`     // Contract version
	Description string `json:"description,omitempty"` // Contract description
	
	// Constructor parameters (ABI-encoded)
	ConstructorArgs []byte `json:"constructor_args,omitempty"`
}

// NewContractDeployment creates a new contract deployment
func NewContractDeployment(code []byte) *ContractDeployment {
	return &ContractDeployment{
		Code: code,
	}
}

// WithInitCode sets the initialization code
func (cd *ContractDeployment) WithInitCode(initCode []byte) *ContractDeployment {
	cd.InitCode = initCode
	return cd
}

// WithSalt sets the CREATE2 salt
func (cd *ContractDeployment) WithSalt(salt []byte) *ContractDeployment {
	cd.Salt = salt
	return cd
}

// WithMetadata sets contract metadata
func (cd *ContractDeployment) WithMetadata(name, version, description string) *ContractDeployment {
	cd.Name = name
	cd.Version = version
	cd.Description = description
	return cd
}

// WithConstructorArgs sets constructor arguments
func (cd *ContractDeployment) WithConstructorArgs(args []byte) *ContractDeployment {
	cd.ConstructorArgs = args
	return cd
}

// CodeHash returns SHA3-256 hash of the contract code
func (cd *ContractDeployment) CodeHash() [32]byte {
	return sha3.Sum256(cd.Code)
}

// ComputeAddress computes the contract address using CREATE semantics
// Address = SHA3(deployer || nonce)[12:32]
func (cd *ContractDeployment) ComputeAddress(deployer [20]byte, nonce uint64) [20]byte {
	h := sha3.New256()
	h.Write(deployer[:])
	
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, nonce)
	h.Write(nonceBytes)
	
	hash := h.Sum(nil)
	var addr [20]byte
	copy(addr[:], hash[12:32])
	return addr
}

// ComputeCreate2Address computes the contract address using CREATE2 semantics
// Address = SHA3(0xff || deployer || salt || codeHash)[12:32]
func (cd *ContractDeployment) ComputeCreate2Address(deployer [20]byte) ([20]byte, error) {
	if cd.Salt == nil || len(cd.Salt) != 32 {
		return [20]byte{}, fmt.Errorf("CREATE2 requires 32-byte salt")
	}
	
	h := sha3.New256()
	h.Write([]byte{0xff})
	h.Write(deployer[:])
	h.Write(cd.Salt)
	
	codeHash := cd.CodeHash()
	h.Write(codeHash[:])
	
	hash := h.Sum(nil)
	var addr [20]byte
	copy(addr[:], hash[12:32])
	return addr, nil
}

// Validate validates the contract deployment
func (cd *ContractDeployment) Validate() error {
	if len(cd.Code) == 0 {
		return fmt.Errorf("contract code cannot be empty")
	}
	
	// Maximum code size: 24KB (similar to Ethereum's limit)
	const maxCodeSize = 24 * 1024
	if len(cd.Code) > maxCodeSize {
		return fmt.Errorf("contract code exceeds maximum size of %d bytes", maxCodeSize)
	}
	
	// Validate init code if present
	if len(cd.InitCode) > maxCodeSize {
		return fmt.Errorf("init code exceeds maximum size of %d bytes", maxCodeSize)
	}
	
	// Validate salt if present
	if cd.Salt != nil && len(cd.Salt) != 32 {
		return fmt.Errorf("salt must be exactly 32 bytes")
	}
	
	return nil
}

// Serialize serializes the contract deployment to JSON
func (cd *ContractDeployment) Serialize() ([]byte, error) {
	return json.Marshal(cd)
}

// DeserializeContractDeployment deserializes a contract deployment from JSON
func DeserializeContractDeployment(data []byte) (*ContractDeployment, error) {
	var cd ContractDeployment
	if err := json.Unmarshal(data, &cd); err != nil {
		return nil, err
	}
	return &cd, nil
}

// ContractCall represents a call to an existing contract
type ContractCall struct {
	// Target contract
	To       [20]byte `json:"to"`        // Contract address
	
	// Call data
	Input    []byte   `json:"input"`     // Function selector + encoded arguments
	Value    uint64   `json:"value"`     // QTX to send with call
	GasLimit uint64   `json:"gas_limit"` // Maximum gas for this call
	
	// Static call flag (view functions)
	Static   bool     `json:"static,omitempty"` // If true, no state modification allowed
}

// NewContractCall creates a new contract call
func NewContractCall(to [20]byte, input []byte) *ContractCall {
	return &ContractCall{
		To:       to,
		Input:    input,
		GasLimit: 100000, // Default gas limit
	}
}

// WithValue sets the QTX value to send
func (cc *ContractCall) WithValue(value uint64) *ContractCall {
	cc.Value = value
	return cc
}

// WithGasLimit sets the gas limit
func (cc *ContractCall) WithGasLimit(gasLimit uint64) *ContractCall {
	cc.GasLimit = gasLimit
	return cc
}

// AsStatic marks this as a static (read-only) call
func (cc *ContractCall) AsStatic() *ContractCall {
	cc.Static = true
	return cc
}

// FunctionSelector returns the first 4 bytes of the input (function selector)
func (cc *ContractCall) FunctionSelector() [4]byte {
	var selector [4]byte
	if len(cc.Input) >= 4 {
		copy(selector[:], cc.Input[:4])
	}
	return selector
}

// CallData returns the arguments portion of the input (after selector)
func (cc *ContractCall) CallData() []byte {
	if len(cc.Input) <= 4 {
		return []byte{}
	}
	return cc.Input[4:]
}

// Serialize serializes the contract call to JSON
func (cc *ContractCall) Serialize() ([]byte, error) {
	return json.Marshal(cc)
}

// DeserializeContractCall deserializes a contract call from JSON
func DeserializeContractCall(data []byte) (*ContractCall, error) {
	var cc ContractCall
	if err := json.Unmarshal(data, &cc); err != nil {
		return nil, err
	}
	return &cc, nil
}

// ContractEvent represents an event emitted by a contract
type ContractEvent struct {
	Address  [20]byte   `json:"address"`  // Contract that emitted the event
	Topics   [][32]byte `json:"topics"`   // Indexed event topics (up to 4)
	Data     []byte     `json:"data"`     // Non-indexed event data
	LogIndex uint64     `json:"log_index"` // Index within the block
	TxHash   [32]byte   `json:"tx_hash"`  // Transaction that caused this event
}

// NewContractEvent creates a new contract event
func NewContractEvent(address [20]byte, topics [][32]byte, data []byte) *ContractEvent {
	return &ContractEvent{
		Address: address,
		Topics:  topics,
		Data:    data,
	}
}

// AddTopic adds an indexed topic
func (ce *ContractEvent) AddTopic(topic [32]byte) error {
	if len(ce.Topics) >= 4 {
		return fmt.Errorf("maximum 4 topics allowed")
	}
	ce.Topics = append(ce.Topics, topic)
	return nil
}

// Serialize serializes the event to JSON
func (ce *ContractEvent) Serialize() ([]byte, error) {
	return json.Marshal(ce)
}

// ContractExecutionResult represents the result of contract execution
type ContractExecutionResult struct {
	Success      bool             `json:"success"`
	ReturnData   []byte           `json:"return_data,omitempty"`
	GasUsed      uint64           `json:"gas_used"`
	GasRefund    uint64           `json:"gas_refund"`
	Events       []*ContractEvent `json:"events,omitempty"`
	Error        string           `json:"error,omitempty"`
	
	// Contract creation specific
	ContractAddress *[20]byte `json:"contract_address,omitempty"`
}

// Helper functions for address conversion

// AddressFromHex converts a hex string to a 20-byte address
func AddressFromHex(hexStr string) ([20]byte, error) {
	var addr [20]byte
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return addr, err
	}
	if len(bytes) != 20 {
		return addr, fmt.Errorf("address must be 20 bytes, got %d", len(bytes))
	}
	copy(addr[:], bytes)
	return addr, nil
}

// AddressToHex converts a 20-byte address to hex string
func AddressToHex(addr [20]byte) string {
	return hex.EncodeToString(addr[:])
}

// StorageKeyFromUint64 creates a storage key from a uint64 slot number
func StorageKeyFromUint64(slot uint64) [32]byte {
	var key [32]byte
	binary.BigEndian.PutUint64(key[24:], slot)
	return key
}

// StorageValueFromUint64 creates a storage value from a uint64
func StorageValueFromUint64(value uint64) [32]byte {
	var v [32]byte
	binary.BigEndian.PutUint64(v[24:], value)
	return v
}

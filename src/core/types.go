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

// go/src/core/types.go
package core

import (
	"math/big"
	"sync"
	"time"

	"github.com/ramseyauron/quantix/src/consensus"
	types "github.com/ramseyauron/quantix/src/core/transaction"
	"github.com/ramseyauron/quantix/src/pool"
	storage "github.com/ramseyauron/quantix/src/state"
)

// BlockchainStatus represents the current status of the blockchain
type BlockchainStatus int

// SyncMode represents different synchronization modes for the blockchain
type SyncMode int

// BlockImportResult represents the outcome of importing a new block
type BlockImportResult int

// CacheType represents different types of caches used in the blockchain
type CacheType int

// BlockAdapter wraps types.Block to implement consensus.Block interface
type BlockHelper struct {
	block *types.Block
}

// ChainParamsProvider defines an interface to get chain parameters without import cycle
type ChainParamsProvider interface {
	GetChainParams() *QuantixChainParameters
	GetWalletDerivationPaths() map[string]string
}

// Mock implementation for storage package to use
type MockChainParamsProvider struct {
	params *QuantixChainParameters
}

// GenesisConfig defines genesis-specific parameters
type GenesisConfig struct {
	InitialDifficulty *big.Int
	InitialGasLimit   *big.Int
	GenesisNonce      uint64
	GenesisExtraData  []byte
}

// QuantixChainParameters defines the complete blockchain parameters
type QuantixChainParameters struct {
	// Network Identification
	ChainID       uint64
	ChainName     string
	Symbol        string
	GenesisTime   int64
	GenesisHash   string
	Version       string
	MagicNumber   uint32
	DefaultPort   int
	BIP44CoinType uint64
	LedgerName    string
	Denominations map[string]*big.Int

	// Block Configuration
	MaxBlockSize       uint64
	MaxTransactionSize uint64
	TargetBlockSize    uint64
	BlockGasLimit      *big.Int
	BaseBlockReward    *big.Int // Block reward in base units

	// Genesis-specific configuration
	GenesisConfig *GenesisConfig

	// Mempool Configuration
	MempoolConfig *pool.MempoolConfig

	// Consensus Configuration
	ConsensusConfig *ConsensusConfig

	// Performance Configuration
	PerformanceConfig *PerformanceConfig
}

// ConsensusConfig defines consensus-related parameters
type ConsensusConfig struct {
	BlockTime        time.Duration
	EpochLength      uint64
	ValidatorSetSize int
	MaxValidators    int
	MinStakeAmount   *big.Int
	UnbondingPeriod  time.Duration
	SlashingEnabled  bool
	DoubleSignSlash  *big.Int // Slashing amount for double signing
}

// PerformanceConfig defines performance-related parameters
type PerformanceConfig struct {
	MaxConcurrentValidations int
	ValidationTimeout        time.Duration
	CacheSize                int
	PruningInterval          time.Duration
	MaxPeers                 int
	SyncBatchSize            int
}

// Blockchain manages the chain of blocks with state machine replication
// NodeSyncState represents the sync phase of a node joining the network.
type NodeSyncState int

const (
	SyncStateNewNode  NodeSyncState = iota // Node has just started, chain is empty
	SyncStateSyncing                       // Actively fetching blocks from a seed peer
	SyncStateSynced                        // Chain is fully synced
)

type Blockchain struct {
	storage         *storage.Storage
	stateMachine    *storage.StateMachine
	mempool         *pool.Mempool
	chain           []*types.Block
	txIndex         map[string]*types.Transaction
	pendingTx       []*types.Transaction
	lock            sync.RWMutex
	status          BlockchainStatus
	syncMode        SyncMode
	consensusEngine *consensus.Consensus
	chainParams     *QuantixChainParameters

	merkleRootCache map[string]string

	// TPS Monitoring
	tpsMonitor *types.TPSMonitor

	// P2-2: Node sync state machine
	nodeSyncState NodeSyncState
	seedPeers     []string // HTTP addresses of seed peers, e.g. "http://1.2.3.4:8080"
}

// GenesisState holds the complete genesis configuration used to bootstrap a node.
// It is the single source of truth for all genesis-related data: chain identity,
// the block header template, pre-funded accounts, and initial validators.
// Every node in the network must produce an identical GenesisState to guarantee
// consensus on the first block.
type GenesisState struct {
	// ChainID uniquely identifies the network (mainnet = 7331, testnet = 17331).
	ChainID uint64 `json:"chain_id"`

	// ChainName is the human-readable network label shown in logs and wallets.
	ChainName string `json:"chain_name"`

	// Symbol is the native token ticker (e.g. "QTX").
	Symbol string `json:"symbol"`

	// Timestamp is the Unix epoch second at which the genesis block was anchored.
	// All nodes share this value so that slot / epoch calculations are identical.
	Timestamp int64 `json:"timestamp"`

	// ExtraData is an arbitrary byte payload embedded in the genesis block header.
	// It typically encodes the chain motto or a short ASCII description.
	ExtraData []byte `json:"extra_data"`

	// InitialDifficulty is the proof-of-work target used in the genesis header.
	// For PBFT networks this is cosmetic but must still be consistent.
	InitialDifficulty *big.Int `json:"initial_difficulty"`

	// InitialGasLimit caps the total gas that can be consumed in a single block
	// at genesis. Subsequent blocks may adjust this value through governance.
	InitialGasLimit *big.Int `json:"initial_gas_limit"`

	// Nonce is the genesis block nonce, formatted as a fixed-width hex string
	// via common.FormatNonce so every node produces the same value.
	Nonce string `json:"nonce"`

	// Allocations is the ordered list of pre-funded addresses at genesis.
	// The slice ordering is significant: it determines the TxsRoot Merkle root
	// embedded in the genesis block header AND the order of transactions in
	// txs_list inside the block body.  Every node must use the exact same list
	// in the same order.
	Allocations []*GenesisAllocation `json:"allocations"`

	// InitialValidators is the set of validators that are active from block 0.
	// Each entry carries the validator ID, its stake (in nQTX), and a public key.
	InitialValidators []*GenesisValidator `json:"initial_validators"`
}

// GenesisValidator describes a single validator that is active at genesis.
// These entries are consumed by the consensus layer during node initialisation
// to populate the initial ValidatorSet before any on-chain staking transactions
// have been processed.
type GenesisValidator struct {
	// NodeID is the unique string identifier used throughout the consensus layer
	// (e.g. "Node-127.0.0.1:32307").
	NodeID string `json:"node_id"`

	// Address is the hex-encoded 20-byte account address that will receive
	// block rewards earned by this validator.
	Address string `json:"address"`

	// StakeNQTX is the initial stake expressed in nQTX (the smallest unit).
	// Use NewGenesisValidatorStake() to create this value from whole QTX.
	StakeNQTX *big.Int `json:"stake_nspx"`

	// PublicKey is the hex-encoded SPHINCS+ public key associated with this
	// validator. It is stored for future signature verification but is not
	// required to be non-empty at genesis.
	PublicKey string `json:"public_key"`
}

// genesisAllocationEntry is the per-account row written to genesis_state.json.
// It converts *big.Int balance fields to human-readable strings so the file
// can be inspected without a Go runtime.
type genesisAllocationEntry struct {
	// Address is the hex-encoded 20-byte account address without a "0x" prefix.
	Address string `json:"address"`

	// BalanceNQTX is the initial balance expressed in nQTX (smallest unit).
	BalanceNQTX string `json:"balance_nspx"`

	// BalanceQTX is the initial balance expressed in whole QTX (truncated).
	BalanceQTX string `json:"balance_qtx"`

	// Label is a human-readable tag (e.g. "Founders", "Reserve").
	Label string `json:"label"`
}

// genesisValidatorEntry is the per-validator row written to genesis_state.json.
// It mirrors GenesisValidator but expresses big.Int stake fields as strings.
type genesisValidatorEntry struct {
	// NodeID is the unique string identifier used throughout the consensus layer.
	NodeID string `json:"node_id"`

	// Address is the hex-encoded 20-byte reward address for this validator.
	Address string `json:"address"`

	// StakeNQTX is the initial stake expressed in nQTX.
	StakeNQTX string `json:"stake_nspx"`

	// StakeQTX is the initial stake expressed in whole QTX (truncated).
	StakeQTX string `json:"stake_qtx"`

	// PublicKey is the hex-encoded SPHINCS+ public key (may be empty at genesis).
	PublicKey string `json:"public_key,omitempty"`
}

// genesisStateSnapshot is an intermediate representation used exclusively for
// JSON serialisation. It converts *big.Int fields to strings so that the file
// can be read by tools that do not understand Go's big.Int encoding.
// Now includes the full allocation and validator lists so genesis_state.json
// contains real data rather than blank arrays.
type genesisStateSnapshot struct {
	ChainID            uint64 `json:"chain_id"`
	ChainName          string `json:"chain_name"`
	Symbol             string `json:"symbol"`
	Timestamp          int64  `json:"timestamp"`
	TimestampISO       string `json:"timestamp_iso"`
	ExtraData          string `json:"extra_data"`
	InitialDifficulty  string `json:"initial_difficulty"`
	InitialGasLimit    string `json:"initial_gas_limit"`
	Nonce              string `json:"nonce"`
	TotalAllocations   int    `json:"total_allocations"`
	TotalAllocatedNQTX string `json:"total_allocated_nqtx"`
	// TotalAllocatedQTX is the same total expressed in whole QTX for readability.
	TotalAllocatedQTX string `json:"total_allocated_qtx"`
	TotalValidators   int    `json:"total_validators"`
	// Allocations is the full ordered list of pre-funded accounts.
	// This was the field that caused genesis_state.json to appear blank.
	Allocations []genesisAllocationEntry `json:"allocations"`
	// InitialValidators is the full list of genesis validators.
	// omitempty keeps the file clean when the list is empty (most networks).
	InitialValidators []genesisValidatorEntry `json:"initial_validators,omitempty"`
}

// GenesisAllocation represents a single account that is funded at genesis.
// Each entry maps a hex-encoded 20-byte address to an initial balance expressed
// in nQTX (the smallest QTX denomination QTX = 10^18 nQTX).
//
// Allocations are stored in an ordered slice on GenesisState.Allocations.
// The ordering is significant because it determines the allocation Merkle root
// that is embedded in the genesis block header, so every node must use the
// exact same ordered list.
//
// Use one of the constructor functions (NewGenesisAllocation, NewFounderAlloc,
// NewReserveAlloc, etc.) rather than constructing the struct directly.
type GenesisAllocation struct {
	// Address is the hex-encoded 20-byte account address without a "0x" prefix.
	// Example: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	Address string `json:"address"`

	// BalanceNQTX is the initial balance in nQTX (1 QTX = 10^18 nQTX).
	// Use NewGenesisAllocationQTX() to specify the balance in whole QTX.
	BalanceNQTX *big.Int `json:"balance_nspx"`

	// Label is a human-readable tag (e.g. "Founders", "Reserve") used only
	// in log output and the genesis_state.json audit file. It has no effect
	// on consensus or block hash computation.
	Label string `json:"label"`
}

// AllocationSummary provides a breakdown of the genesis token distribution
// grouped by label. It is used for logging and the genesis_state.json audit file.
type AllocationSummary struct {
	// TotalNSPX is the sum of all allocation balances in nQTX.
	TotalNSPX *big.Int `json:"total_nspx"`

	// TotalSPX is TotalNSPX divided by 10^18 (whole QTX, truncated).
	TotalSPX *big.Int `json:"total_spx"`

	// Count is the total number of allocation entries.
	Count int `json:"count"`

	// ByLabel maps each label to the aggregate balance (in nQTX) across all
	// allocations sharing that label.
	ByLabel map[string]*big.Int `json:"by_label"`
}

// AllocationSet is an in-memory index of genesis allocations keyed by the
// normalised (lowercase) hex address. It is built once at startup and used
// for O(1) balance queries during state initialisation.
type AllocationSet struct {
	index map[string]*GenesisAllocation
	total *big.Int // cached total supply in nQTX
}

// ChainPhase identifies which operational phase a network is in.
type ChainPhase string

// ChainCheckpoint captures the state at the moment devnet finishes distribution.
// It is written to disk so testnet/mainnet nodes can bootstrap from it without
// re-running devnet.
type ChainCheckpoint struct {
	Phase           ChainPhase `json:"phase"`             // "devnet"
	GenesisHash     string     `json:"genesis_hash"`      // canonical genesis hash
	TipHeight       uint64     `json:"tip_height"`        // last devnet block height
	TipHash         string     `json:"tip_hash"`          // last devnet block hash
	VaultBalance    string     `json:"vault_balance"`     // should be "0"
	TotalSupply     string     `json:"total_supply"`      // circulating supply in nQTX
	Timestamp       string     `json:"timestamp"`         // RFC3339 when checkpoint was taken
	DistributedNSPX string     `json:"distributed_n_spx"` // total nQTX distributed
}

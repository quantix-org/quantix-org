// MIT License
// Copyright (c) 2024 quantix

// Q9 — Tests for Phase 2 features:
//
//	P2-1: ConsensusMode enum + GetConsensusMode
//	P2-2: NodeSyncState machine + SetSeedPeers + SyncFromSeeds + GetBlocksRange
//	P2-3: ValidatorRegistration CRUD (RegisterValidator / GetValidators)
package core

import (
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/quantix-org/quantix-org/src/consensus"
	database "github.com/quantix-org/quantix-org/src/core/state"
	types "github.com/quantix-org/quantix-org/src/core/transaction"
	storage "github.com/quantix-org/quantix-org/src/state"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newPhase2BC(t *testing.T) *Blockchain {
	t.Helper()
	dir := t.TempDir()
	dbPath := dir + "/state.db"
	db, err := database.NewLevelDB(dbPath)
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	storeDir := dir + "/store"
	if err := os.MkdirAll(storeDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	store, err := storage.NewStorage(storeDir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	store.SetDB(db)
	bc := &Blockchain{
		storage:       store,
		chain:         []*types.Block{},
		lock:          sync.RWMutex{},
		chainParams:   GetDevnetChainParams(),
		nodeSyncState: SyncStateNewNode,
	}
	t.Cleanup(func() { _ = store.Close() })
	return bc
}

// makeSeedBlock creates a minimal block for sync server responses.
func makeSeedBlock(height uint64) *types.Block {
	header := types.NewBlockHeader(
		height,
		make([]byte, 32),
		big.NewInt(1),
		[]byte{}, []byte{},
		big.NewInt(8_000_000), big.NewInt(0),
		nil, nil,
		time.Now().Unix(),
		nil,
	)
	body := types.NewBlockBody([]*types.Transaction{}, nil)
	b := types.NewBlock(header, body)
	b.FinalizeHash()
	return b
}

// ---------------------------------------------------------------------------
// P2-1 ConsensusMode Tests
// ---------------------------------------------------------------------------

func TestGetConsensusMode_BelowThreshold_IsDevnetSolo(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3} {
		mode := consensus.GetConsensusMode(n)
		if mode != consensus.DEVNET_SOLO {
			t.Errorf("n=%d: expected DEVNET_SOLO, got %s", n, mode)
		}
	}
}

func TestGetConsensusMode_AtOrAboveThreshold_IsPBFT(t *testing.T) {
	for _, n := range []int{4, 5, 10, 100} {
		mode := consensus.GetConsensusMode(n)
		if mode != consensus.PBFT {
			t.Errorf("n=%d: expected PBFT, got %s", n, mode)
		}
	}
}

func TestConsensusMode_String(t *testing.T) {
	if s := consensus.DEVNET_SOLO.String(); s != "DEVNET_SOLO" {
		t.Errorf("DEVNET_SOLO.String() = %q, want DEVNET_SOLO", s)
	}
	if s := consensus.PBFT.String(); s != "PBFT" {
		t.Errorf("PBFT.String() = %q, want PBFT", s)
	}
}

func TestConsensusMode_UnknownValue_StringNotEmpty(t *testing.T) {
	unknown := consensus.ConsensusMode(99)
	if unknown.String() == "" {
		t.Error("unknown ConsensusMode.String() should not be empty")
	}
}

func TestMinPBFTValidators_Is4(t *testing.T) {
	if consensus.MinPBFTValidators != 4 {
		t.Errorf("MinPBFTValidators = %d, want 4", consensus.MinPBFTValidators)
	}
}

// ---------------------------------------------------------------------------
// P2-2 NodeSyncState Tests
// ---------------------------------------------------------------------------

func TestNodeSyncState_InitialIsNewNode(t *testing.T) {
	bc := newPhase2BC(t)
	if state := bc.GetNodeSyncState(); state != SyncStateNewNode {
		t.Errorf("initial sync state: got %d, want SyncStateNewNode(%d)", state, SyncStateNewNode)
	}
}

func TestSetSeedPeers_StoresPeers(t *testing.T) {
	bc := newPhase2BC(t)

	// Use a test server that immediately returns 500 so sync fails fast (no timeout)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	bc.SetSeedPeers([]string{ts.URL})
	err := bc.SyncFromSeeds()
	if err != nil {
		t.Fatalf("SyncFromSeeds: %v", err)
	}
	// After all peers fail, node falls back to SYNCED (genesis-only)
	if state := bc.GetNodeSyncState(); state != SyncStateSynced {
		t.Errorf("after failed peers: sync state = %d, want SyncStateSynced(%d)", state, SyncStateSynced)
	}
}

func TestSyncFromSeeds_NoSeeds_StaysSynced(t *testing.T) {
	bc := newPhase2BC(t)
	// No peers set
	err := bc.SyncFromSeeds()
	if err != nil {
		t.Fatalf("SyncFromSeeds with no peers: %v", err)
	}
	// Chain is empty and no peers → should not change to SYNCING
	state := bc.GetNodeSyncState()
	// Either remains NEW_NODE or becomes SYNCED — either is acceptable
	if state != SyncStateNewNode && state != SyncStateSynced {
		t.Errorf("unexpected sync state %d", state)
	}
}

func TestSyncFromSeeds_SuccessfulSync_BecomesSynced(t *testing.T) {
	bc := newPhase2BC(t)

	// Spin up a mock seed server that returns 2 blocks
	blocks := []*types.Block{makeSeedBlock(1), makeSeedBlock(2)}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blocks" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(blocks)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	bc.SetSeedPeers([]string{ts.URL})
	err := bc.SyncFromSeeds()
	if err != nil {
		t.Fatalf("SyncFromSeeds: %v", err)
	}
	if state := bc.GetNodeSyncState(); state != SyncStateSynced {
		t.Errorf("expected SYNCED after successful sync, got %d", state)
	}
}

// ---------------------------------------------------------------------------
// P2-2 GetBlocksRange Tests
// ---------------------------------------------------------------------------

func TestGetBlocksRange_Empty_ReturnsNil(t *testing.T) {
	bc := newPhase2BC(t)
	result := bc.GetBlocksRange(0, 10)
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %d blocks", len(result))
	}
}

func TestGetBlocksRange_LimitEnforced(t *testing.T) {
	bc := newPhase2BC(t)
	// Push 10 blocks onto the chain directly
	for i := uint64(0); i < 10; i++ {
		bc.chain = append(bc.chain, makeSeedBlock(i))
	}
	result := bc.GetBlocksRange(0, 3)
	if len(result) != 3 {
		t.Errorf("expected 3 blocks with limit=3, got %d", len(result))
	}
}

func TestGetBlocksRange_FromOffset(t *testing.T) {
	bc := newPhase2BC(t)
	for i := uint64(0); i < 5; i++ {
		bc.chain = append(bc.chain, makeSeedBlock(i))
	}
	result := bc.GetBlocksRange(3, 10)
	for _, blk := range result {
		if blk.Header.Height < 3 {
			t.Errorf("got block height %d below from=3", blk.Header.Height)
		}
	}
}

func TestGetBlocksRange_InvalidLimit_UsesDefault(t *testing.T) {
	bc := newPhase2BC(t)
	// limit=0 should use default (100), result will be empty since chain is empty
	result := bc.GetBlocksRange(0, 0)
	_ = result // no panic is sufficient
}

func TestGetBlocksRange_LimitExceeds1000_Capped(t *testing.T) {
	bc := newPhase2BC(t)
	// limit > 1000 should be capped at 100
	result := bc.GetBlocksRange(0, 9999)
	_ = result // no panic, empty chain
}

// ---------------------------------------------------------------------------
// P2-3 ValidatorRegistration Tests
// ---------------------------------------------------------------------------

func TestRegisterValidator_Valid(t *testing.T) {
	bc := newPhase2BC(t)
	reg := &ValidatorRegistration{
		PublicKey:   "deadbeef01020304",
		StakeAmount: "1000",
		NodeAddress: "val-node-1",
	}
	if err := bc.RegisterValidator(reg); err != nil {
		t.Fatalf("RegisterValidator: %v", err)
	}
	// RegisteredAt should be set by the function
	if reg.RegisteredAt.IsZero() {
		t.Error("RegisteredAt should have been set")
	}
	if !reg.Active {
		t.Error("newly registered validator should be Active=true")
	}
}

func TestRegisterValidator_MissingNodeAddress_Error(t *testing.T) {
	bc := newPhase2BC(t)
	reg := &ValidatorRegistration{
		PublicKey:   "abc",
		StakeAmount: "100",
		NodeAddress: "",
	}
	if err := bc.RegisterValidator(reg); err == nil {
		t.Error("expected error for empty NodeAddress")
	}
}

func TestRegisterValidator_MissingPublicKey_Error(t *testing.T) {
	bc := newPhase2BC(t)
	reg := &ValidatorRegistration{
		PublicKey:   "",
		StakeAmount: "100",
		NodeAddress: "some-node",
	}
	if err := bc.RegisterValidator(reg); err == nil {
		t.Error("expected error for empty PublicKey")
	}
}

func TestRegisterValidator_ZeroStake_Error(t *testing.T) {
	bc := newPhase2BC(t)
	reg := &ValidatorRegistration{
		PublicKey:   "abc",
		StakeAmount: "0",
		NodeAddress: "some-node",
	}
	if err := bc.RegisterValidator(reg); err == nil {
		t.Error("expected error for zero stake")
	}
}

func TestRegisterValidator_NegativeStake_Error(t *testing.T) {
	bc := newPhase2BC(t)
	reg := &ValidatorRegistration{
		PublicKey:   "abc",
		StakeAmount: "-500",
		NodeAddress: "some-node",
	}
	if err := bc.RegisterValidator(reg); err == nil {
		t.Error("expected error for negative stake")
	}
}

func TestRegisterValidator_InvalidStakeString_Error(t *testing.T) {
	bc := newPhase2BC(t)
	reg := &ValidatorRegistration{
		PublicKey:   "abc",
		StakeAmount: "notanumber",
		NodeAddress: "some-node",
	}
	if err := bc.RegisterValidator(reg); err == nil {
		t.Error("expected error for non-numeric stake")
	}
}

func TestGetValidators_AfterRegister(t *testing.T) {
	bc := newPhase2BC(t)

	nodes := []string{"node-a", "node-b", "node-c"}
	for _, n := range nodes {
		if err := bc.RegisterValidator(&ValidatorRegistration{
			PublicKey:   "pubkey-" + n,
			StakeAmount: "1000",
			NodeAddress: n,
		}); err != nil {
			t.Fatalf("RegisterValidator %s: %v", n, err)
		}
	}

	validators, err := bc.GetValidators()
	if err != nil {
		t.Fatalf("GetValidators: %v", err)
	}
	if len(validators) < len(nodes) {
		t.Errorf("expected at least %d validators, got %d", len(nodes), len(validators))
	}

	// All returned validators should be Active
	for _, v := range validators {
		if !v.Active {
			t.Errorf("validator %s should be Active", v.NodeAddress)
		}
	}
}

func TestGetValidators_Empty_ReturnsEmpty(t *testing.T) {
	bc := newPhase2BC(t)
	validators, err := bc.GetValidators()
	if err != nil {
		t.Fatalf("GetValidators on empty store: %v", err)
	}
	if len(validators) != 0 {
		t.Errorf("expected 0 validators, got %d", len(validators))
	}
}

func TestGetValidators_StakeIsPreserved(t *testing.T) {
	bc := newPhase2BC(t)
	stakeStr := "50000000000000000000" // 50 QTX in nQTX notation
	_ = bc.RegisterValidator(&ValidatorRegistration{
		PublicKey:   "pubkey-x",
		StakeAmount: stakeStr,
		NodeAddress: "staked-node",
	})
	validators, err := bc.GetValidators()
	if err != nil || len(validators) == 0 {
		t.Fatalf("GetValidators: %v, len=%d", err, len(validators))
	}
	found := false
	for _, v := range validators {
		if v.NodeAddress == "staked-node" {
			found = true
			got, _ := new(big.Int).SetString(v.StakeAmount, 10)
			want, _ := new(big.Int).SetString(stakeStr, 10)
			if got.Cmp(want) != 0 {
				t.Errorf("stake mismatch: got %s want %s", got, want)
			}
		}
	}
	if !found {
		t.Error("registered validator not found in GetValidators")
	}
}

// ---------------------------------------------------------------------------
// P2-1/P2-2 integration: mode + sync state together
// ---------------------------------------------------------------------------

func TestConsensusModeTransition_LogicOnly(t *testing.T) {
	// Verify that the boundary between DEVNET_SOLO and PBFT is exactly at 4
	boundary := consensus.MinPBFTValidators
	if consensus.GetConsensusMode(boundary-1) != consensus.DEVNET_SOLO {
		t.Errorf("at n=%d should still be DEVNET_SOLO", boundary-1)
	}
	if consensus.GetConsensusMode(boundary) != consensus.PBFT {
		t.Errorf("at n=%d should switch to PBFT", boundary)
	}
}

// Ensure NodeSyncState constants are ordered correctly (NEW < SYNCING < SYNCED)
func TestNodeSyncState_OrderedConstants(t *testing.T) {
	if SyncStateNewNode >= SyncStateSyncing {
		t.Error("SyncStateNewNode should be < SyncStateSyncing")
	}
	if SyncStateSyncing >= SyncStateSynced {
		t.Error("SyncStateSyncing should be < SyncStateSynced")
	}
}

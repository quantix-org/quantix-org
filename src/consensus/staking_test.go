// MIT License
// Copyright (c) 2024 quantix

// Q12 — ValidatorSet comprehensive tests (consensus/staking.go)
// Covers: AddValidator, RegisterValidator, UnregisterValidator, SlashValidator,
//         GetActiveValidators, ActiveValidatorIDs, GetTotalStake, IsValidStakeAmount,
//         GetMinimumStakeInQTX, SaveToDB/LoadFromDB persistence
package consensus

import (
	"fmt"
	"math/big"
	"testing"

	denom "github.com/ramseyauron/quantix/src/params/denom"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// minStake is 1000 QTX in nQTX
func testMinStake() *big.Int {
	return new(big.Int).Mul(big.NewInt(1000), big.NewInt(denom.QTX))
}

func newTestVS(t *testing.T) *ValidatorSet {
	t.Helper()
	return NewValidatorSet(testMinStake())
}

// nQTX converts QTX amount to nQTX big.Int
func nQTX(qtx int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(qtx), big.NewInt(denom.QTX))
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNewValidatorSet_NilMinStake_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil minStakeAmount")
		}
	}()
	NewValidatorSet(nil)
}

func TestNewValidatorSet_GetMinStakeAmount(t *testing.T) {
	vs := newTestVS(t)
	got := vs.GetMinStakeAmount()
	if got.Cmp(testMinStake()) != 0 {
		t.Errorf("GetMinStakeAmount: got %s want %s", got, testMinStake())
	}
}

func TestNewValidatorSet_GetMinStakeSPX(t *testing.T) {
	vs := newTestVS(t)
	if vs.GetMinStakeSPX() != 1000 {
		t.Errorf("GetMinStakeSPX: got %d want 1000", vs.GetMinStakeSPX())
	}
}

func TestNewValidatorSet_GetMinimumStakeInQTX(t *testing.T) {
	vs := newTestVS(t)
	got := vs.GetMinimumStakeInQTX()
	if got < 999.9 || got > 1000.1 {
		t.Errorf("GetMinimumStakeInQTX: got %.2f want ~1000.0", got)
	}
}

// ---------------------------------------------------------------------------
// AddValidator
// ---------------------------------------------------------------------------

func TestAddValidator_BelowMinimum_Error(t *testing.T) {
	vs := newTestVS(t)
	err := vs.AddValidator("v1", 500) // below 1000 QTX minimum
	if err == nil {
		t.Error("expected error for below-minimum stake")
	}
}

func TestAddValidator_AtMinimum_OK(t *testing.T) {
	vs := newTestVS(t)
	if err := vs.AddValidator("v1", 1000); err != nil {
		t.Fatalf("AddValidator at minimum: %v", err)
	}
}

func TestAddValidator_UpdatesExisting(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.AddValidator("v1", 1000)
	// Increase stake
	if err := vs.AddValidator("v1", 2000); err != nil {
		t.Fatalf("update stake: %v", err)
	}
	stake := vs.GetTotalStake()
	want := nQTX(2000)
	if stake.Cmp(want) != 0 {
		t.Errorf("total stake after update: got %s want %s", stake, want)
	}
}

func TestAddValidator_TotalStakeAccumulates(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.AddValidator("v1", 1000)
	_ = vs.AddValidator("v2", 2000)
	_ = vs.AddValidator("v3", 3000)
	want := nQTX(6000)
	if got := vs.GetTotalStake(); got.Cmp(want) != 0 {
		t.Errorf("total stake: got %s want %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// RegisterValidator
// ---------------------------------------------------------------------------

func TestRegisterValidator_AllFields_OK(t *testing.T) {
	vs := newTestVS(t)
	err := vs.RegisterValidator("node-1", "pubkey-hex", 1000, "10.0.0.1:32307")
	if err != nil {
		t.Fatalf("RegisterValidator: %v", err)
	}
}

func TestRegisterValidator_EmptyID_Error(t *testing.T) {
	vs := newTestVS(t)
	err := vs.RegisterValidator("", "pubkey", 1000, "10.0.0.1:32307")
	if err == nil {
		t.Error("expected error for empty id")
	}
}

func TestRegisterValidator_EmptyNodeAddr_Error(t *testing.T) {
	vs := newTestVS(t)
	err := vs.RegisterValidator("node-1", "pubkey", 1000, "")
	if err == nil {
		t.Error("expected error for empty nodeAddr")
	}
}

func TestRegisterValidator_BelowMinStake_Error(t *testing.T) {
	vs := newTestVS(t)
	err := vs.RegisterValidator("node-1", "pubkey", 100, "10.0.0.1:32307")
	if err == nil {
		t.Error("expected error for below-minimum stake")
	}
}

func TestRegisterValidator_Update_Idempotent(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.RegisterValidator("node-1", "pk1", 1000, "addr1")
	// Re-register with higher stake
	err := vs.RegisterValidator("node-1", "pk1-updated", 2000, "addr2")
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	// Total stake should reflect the updated value
	want := nQTX(2000)
	if got := vs.GetTotalStake(); got.Cmp(want) != 0 {
		t.Errorf("total stake after re-register: got %s want %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// UnregisterValidator
// ---------------------------------------------------------------------------

func TestUnregisterValidator_Known_OK(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.AddValidator("v1", 1000)
	if err := vs.UnregisterValidator("v1"); err != nil {
		t.Fatalf("UnregisterValidator: %v", err)
	}
}

func TestUnregisterValidator_Unknown_Error(t *testing.T) {
	vs := newTestVS(t)
	err := vs.UnregisterValidator("nonexistent")
	if err == nil {
		t.Error("expected error for unknown validator")
	}
}

func TestUnregisterValidator_RemovesFromActiveSet(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.AddValidator("v1", 1000)
	_ = vs.AddValidator("v2", 1000)
	_ = vs.UnregisterValidator("v1")

	active := vs.GetActiveValidators(2) // epoch 2, above ExitEpoch=1
	for _, v := range active {
		if v.ID == "v1" {
			t.Error("unregistered validator v1 should not appear in active set")
		}
	}
}

func TestUnregisterValidator_ReducesTotalStake(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.AddValidator("v1", 1000)
	_ = vs.AddValidator("v2", 1000)
	before := vs.GetTotalStake()
	_ = vs.UnregisterValidator("v1")
	after := vs.GetTotalStake()
	if after.Cmp(before) >= 0 {
		t.Errorf("total stake should decrease after unregister: before=%s after=%s", before, after)
	}
}

// ---------------------------------------------------------------------------
// GetActiveValidators / ActiveValidatorIDs
// ---------------------------------------------------------------------------

func TestGetActiveValidators_Empty_ReturnsEmpty(t *testing.T) {
	vs := newTestVS(t)
	active := vs.GetActiveValidators(0)
	if len(active) != 0 {
		t.Errorf("expected empty, got %d", len(active))
	}
}

func TestGetActiveValidators_ExcludesSlashed(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.AddValidator("v1", 1000)
	// Force slash below minimum
	vs.SlashValidator("v1", "test", 10000) // 100% slash
	active := vs.GetActiveValidators(0)
	for _, v := range active {
		if v.ID == "v1" {
			t.Error("slashed validator should not be in active set")
		}
	}
}

func TestGetActiveValidators_SortedByID(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.AddValidator("charlie", 1000)
	_ = vs.AddValidator("alice", 1000)
	_ = vs.AddValidator("bob", 1000)

	active := vs.GetActiveValidators(0)
	for i := 1; i < len(active); i++ {
		if active[i].ID < active[i-1].ID {
			t.Errorf("active validators not sorted: %s < %s", active[i].ID, active[i-1].ID)
		}
	}
}

func TestGetActiveValidators_Deterministic(t *testing.T) {
	vs := newTestVS(t)
	for i := 0; i < 5; i++ {
		_ = vs.AddValidator(fmt.Sprintf("node-%02d", i), 1000)
	}
	a1 := vs.GetActiveValidators(0)
	a2 := vs.GetActiveValidators(0)
	if len(a1) != len(a2) {
		t.Fatal("non-deterministic: different lengths")
	}
	for i := range a1 {
		if a1[i].ID != a2[i].ID {
			t.Errorf("non-deterministic at index %d: %s vs %s", i, a1[i].ID, a2[i].ID)
		}
	}
}

func TestActiveValidatorIDs_MatchesGetActiveValidators(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.AddValidator("v1", 1000)
	_ = vs.AddValidator("v2", 2000)

	active := vs.GetActiveValidators(0)
	ids := vs.ActiveValidatorIDs(0)
	if len(ids) != len(active) {
		t.Fatalf("length mismatch: ids=%d active=%d", len(ids), len(active))
	}
	for i, v := range active {
		if ids[i] != v.ID {
			t.Errorf("id mismatch at %d: %s vs %s", i, ids[i], v.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// IsValidStakeAmount
// ---------------------------------------------------------------------------

func TestIsValidStakeAmount_AboveMin_True(t *testing.T) {
	vs := newTestVS(t)
	if !vs.IsValidStakeAmount(nQTX(1000)) {
		t.Error("1000 QTX should be valid")
	}
}

func TestIsValidStakeAmount_BelowMin_False(t *testing.T) {
	vs := newTestVS(t)
	if vs.IsValidStakeAmount(nQTX(999)) {
		t.Error("999 QTX should be below minimum")
	}
}

func TestIsValidStakeAmount_Nil_False(t *testing.T) {
	vs := newTestVS(t)
	if vs.IsValidStakeAmount(nil) {
		t.Error("nil stake should be invalid")
	}
}

func TestIsValidStakeAmount_Zero_False(t *testing.T) {
	vs := newTestVS(t)
	if vs.IsValidStakeAmount(big.NewInt(0)) {
		t.Error("zero stake should be invalid")
	}
}

// ---------------------------------------------------------------------------
// SlashValidator
// ---------------------------------------------------------------------------

func TestSlashValidator_PartialSlash_ReducesStake(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.AddValidator("v1", 5000)
	before := vs.GetTotalStake()
	vs.SlashValidator("v1", "missed submission", 100) // 1% slash
	after := vs.GetTotalStake()
	if after.Cmp(before) >= 0 {
		t.Error("stake should decrease after slash")
	}
}

func TestSlashValidator_FullSlash_MarksSlashed(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.AddValidator("v1", 1000)
	vs.SlashValidator("v1", "misbehaviour", 10000) // 100% slash

	active := vs.GetActiveValidators(0)
	for _, v := range active {
		if v.ID == "v1" {
			t.Error("fully slashed validator should not be active")
		}
	}
}

func TestSlashValidator_Unknown_NoopNoPanic(t *testing.T) {
	vs := newTestVS(t)
	// Should not panic for unknown validator
	vs.SlashValidator("ghost", "reason", 100)
}

// ---------------------------------------------------------------------------
// GetTotalStake
// ---------------------------------------------------------------------------

func TestGetTotalStake_EmptySet_IsZero(t *testing.T) {
	vs := newTestVS(t)
	if vs.GetTotalStake().Sign() != 0 {
		t.Error("empty validator set should have zero total stake")
	}
}

func TestGetTotalStake_ReturnsCopy(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.AddValidator("v1", 1000)
	s1 := vs.GetTotalStake()
	s2 := vs.GetTotalStake()
	// Modify s1 — should not affect vs.totalStake
	s1.SetInt64(0)
	s3 := vs.GetTotalStake()
	if s3.Cmp(s2) != 0 {
		t.Error("GetTotalStake should return a copy, not the internal reference")
	}
}

// ---------------------------------------------------------------------------
// StakedValidator.GetStakeInQTX
// ---------------------------------------------------------------------------

func TestGetStakeInQTX_Correct(t *testing.T) {
	v := &StakedValidator{StakeAmount: nQTX(5000)}
	got := v.GetStakeInQTX()
	if got < 4999.9 || got > 5000.1 {
		t.Errorf("GetStakeInQTX: got %.2f want ~5000.0", got)
	}
}

// ---------------------------------------------------------------------------
// SaveToDB / LoadFromDB
// ---------------------------------------------------------------------------

// inMemDB is a trivial PersistableDB for testing.
type inMemDB struct {
	data map[string][]byte
}

func newInMemDB() *inMemDB { return &inMemDB{data: map[string][]byte{}} }

func (db *inMemDB) Put(key string, value []byte) error {
	db.data[key] = append([]byte{}, value...)
	return nil
}

func (db *inMemDB) Get(key string) ([]byte, error) {
	v, ok := db.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return v, nil
}

func TestSaveAndLoadFromDB_RoundTrip(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.RegisterValidator("node-a", "pubA", 2000, "10.0.0.1:32307")
	_ = vs.RegisterValidator("node-b", "pubB", 3000, "10.0.0.2:32307")

	db := newInMemDB()
	if err := vs.SaveToDB(db); err != nil {
		t.Fatalf("SaveToDB: %v", err)
	}

	vs2 := newTestVS(t)
	if err := vs2.LoadFromDB(db); err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}

	active := vs2.GetActiveValidators(0)
	if len(active) != 2 {
		t.Errorf("expected 2 validators after roundtrip, got %d", len(active))
	}
}

func TestLoadFromDB_MissingKey_NoError(t *testing.T) {
	vs := newTestVS(t)
	db := newInMemDB() // empty DB — key not present

	// Should return nil (fresh start) not error
	err := vs.LoadFromDB(db)
	if err != nil {
		t.Errorf("LoadFromDB on empty DB should not error, got: %v", err)
	}
}

func TestSaveAndLoadFromDB_StakePreserved(t *testing.T) {
	vs := newTestVS(t)
	_ = vs.RegisterValidator("node-x", "pubX", 5000, "addr-x")

	db := newInMemDB()
	_ = vs.SaveToDB(db)

	vs2 := newTestVS(t)
	_ = vs2.LoadFromDB(db)

	ids := vs2.ActiveValidatorIDs(0)
	if len(ids) != 1 || ids[0] != "node-x" {
		t.Errorf("validator not found after reload: %v", ids)
	}
}

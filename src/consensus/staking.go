// MIT License
// Copyright (c) 2024 quantix

// consensus/staking.go
package consensus

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"

	logger "github.com/ramseyauron/quantix/src/log"
	denom "github.com/ramseyauron/quantix/src/params/denom"
)

// sips0013 https://github.com/ramseyauron/SIPS/blob/main/.github/workflows/sips0013/sips0013.md

// NewValidatorSet creates a validator set with minimum stake configuration.
func NewValidatorSet(minStakeAmount *big.Int) *ValidatorSet {
	if minStakeAmount == nil {
		panic("minStakeAmount cannot be nil - must be provided from chain parameters")
	}
	return &ValidatorSet{
		validators:     make(map[string]*StakedValidator),
		totalStake:     big.NewInt(0),
		minStakeAmount: minStakeAmount,
	}
}

// GetMinStakeAmount returns a copy of the minimum stake amount.
func (vs *ValidatorSet) GetMinStakeAmount() *big.Int {
	return new(big.Int).Set(vs.minStakeAmount)
}

// GetMinStakeSPX returns the minimum stake in QTX (human-readable).
func (vs *ValidatorSet) GetMinStakeSPX() uint64 {
	minQTX := new(big.Int).Div(vs.minStakeAmount, big.NewInt(1e18))
	return minQTX.Uint64()
}

// AddValidator adds or updates a validator's stake (in QTX).
func (vs *ValidatorSet) AddValidator(id string, stakeSPX uint64) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	stakeNSPX := new(big.Int).Mul(
		big.NewInt(int64(stakeSPX)),
		big.NewInt(denom.QTX),
	)

	if stakeNSPX.Cmp(vs.minStakeAmount) < 0 {
		minStakeSPX := vs.GetMinStakeSPX()
		return fmt.Errorf("stake %d QTX below minimum %d QTX", stakeSPX, minStakeSPX)
	}

	if val, exists := vs.validators[id]; exists {
		vs.totalStake.Sub(vs.totalStake, val.StakeAmount)
		val.StakeAmount = stakeNSPX
		vs.totalStake.Add(vs.totalStake, stakeNSPX)
	} else {
		vs.validators[id] = &StakedValidator{
			ID:          id,
			StakeAmount: stakeNSPX,
		}
		vs.totalStake.Add(vs.totalStake, stakeNSPX)
	}

	logger.Info("✅ Validator %s added/updated with %d QTX stake", id, stakeSPX)
	return nil
}

// RegisterValidator registers a new validator with full details (P2-6).
// id: node ID, pubkey: hex-encoded public key, stake: in QTX units, nodeAddr: network address.
func (vs *ValidatorSet) RegisterValidator(id, pubkey string, stake uint64, nodeAddr string) error {
	if id == "" {
		return fmt.Errorf("validator id is required")
	}
	if nodeAddr == "" {
		return fmt.Errorf("node address is required")
	}

	stakeNSPX := new(big.Int).Mul(
		big.NewInt(int64(stake)),
		big.NewInt(denom.QTX),
	)
	if stakeNSPX.Cmp(vs.minStakeAmount) < 0 {
		return fmt.Errorf("stake %d QTX below minimum %d QTX", stake, vs.GetMinStakeSPX())
	}

	vs.mu.Lock()
	defer vs.mu.Unlock()

	if val, exists := vs.validators[id]; exists {
		vs.totalStake.Sub(vs.totalStake, val.StakeAmount)
		val.StakeAmount = stakeNSPX
		val.NodeAddress = nodeAddr
		if pubkey != "" {
			val.PubKeyHex = pubkey
		}
		val.IsSlashed = false
		vs.totalStake.Add(vs.totalStake, stakeNSPX)
		logger.Info("✅ Validator %s updated: stake=%d QTX, addr=%s", id, stake, nodeAddr)
	} else {
		vs.validators[id] = &StakedValidator{
			ID:              id,
			StakeAmount:     stakeNSPX,
			PubKeyHex:       pubkey,
			NodeAddress:     nodeAddr,
			ActivationEpoch: 0,
		}
		vs.totalStake.Add(vs.totalStake, stakeNSPX)
		logger.Info("✅ Validator %s registered: stake=%d QTX, addr=%s", id, stake, nodeAddr)
	}
	return nil
}

// UnregisterValidator removes a validator from the active set (P2-6).
// Sets ExitEpoch so it is excluded from future epoch sets.
func (vs *ValidatorSet) UnregisterValidator(id string) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	val, exists := vs.validators[id]
	if !exists {
		return fmt.Errorf("validator %s not found", id)
	}

	vs.totalStake.Sub(vs.totalStake, val.StakeAmount)
	// Mark as exited immediately (ExitEpoch=1 is in the past relative to any epoch)
	val.ExitEpoch = 1
	val.StakeAmount = big.NewInt(0)

	logger.Info("🔴 Validator %s unregistered", id)
	return nil
}

// validatorPersistRecord is used for JSON persistence of the validator set.
type validatorPersistRecord struct {
	ID              string `json:"id"`
	StakeQTX        uint64 `json:"stake_qtx"`
	PublicKey       string `json:"public_key"`
	NodeAddress     string `json:"node_address"`
	ActivationEpoch uint64 `json:"activation_epoch"`
	ExitEpoch       uint64 `json:"exit_epoch"`
	IsSlashed       bool   `json:"is_slashed"`
}

const validatorSetDBKey = "consensus:validator_set"

// PersistableDB is the minimal interface needed for validator persistence.
type PersistableDB interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
}

// SaveToDB serializes the validator set to the given database (P2-6).
func (vs *ValidatorSet) SaveToDB(db PersistableDB) error {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	records := make([]*validatorPersistRecord, 0, len(vs.validators))
	for _, v := range vs.validators {
		stakeQTX := uint64(0)
		if v.StakeAmount != nil && v.StakeAmount.Sign() > 0 {
			stakeQTX = new(big.Int).Div(v.StakeAmount, big.NewInt(denom.QTX)).Uint64()
		}
		records = append(records, &validatorPersistRecord{
			ID:              v.ID,
			StakeQTX:        stakeQTX,
			PublicKey:       v.PubKeyHex,
			NodeAddress:     v.NodeAddress,
			ActivationEpoch: v.ActivationEpoch,
			ExitEpoch:       v.ExitEpoch,
			IsSlashed:       v.IsSlashed,
		})
	}

	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("marshal validator set: %w", err)
	}

	if err := db.Put(validatorSetDBKey, data); err != nil {
		return fmt.Errorf("persist validator set: %w", err)
	}

	logger.Info("💾 Persisted %d validators to DB", len(records))
	return nil
}

// LoadFromDB restores the validator set from the given database (P2-6).
// Returns nil error (not found) when the key doesn't exist yet.
func (vs *ValidatorSet) LoadFromDB(db PersistableDB) error {
	data, err := db.Get(validatorSetDBKey)
	if err != nil {
		// Key not found — fresh start is fine
		logger.Info("ℹ️ No persisted validator set found (fresh start)")
		return nil
	}

	var records []*validatorPersistRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("unmarshal validator set: %w", err)
	}

	vs.mu.Lock()
	defer vs.mu.Unlock()

	for _, r := range records {
		stakeNSPX := new(big.Int).Mul(
			big.NewInt(int64(r.StakeQTX)),
			big.NewInt(denom.QTX),
		)
		vs.validators[r.ID] = &StakedValidator{
			ID:              r.ID,
			StakeAmount:     stakeNSPX,
			PubKeyHex:       r.PublicKey,
			NodeAddress:     r.NodeAddress,
			ActivationEpoch: r.ActivationEpoch,
			ExitEpoch:       r.ExitEpoch,
			IsSlashed:       r.IsSlashed,
		}
		vs.totalStake.Add(vs.totalStake, stakeNSPX)
	}

	logger.Info("✅ Loaded %d validators from DB", len(records))
	return nil
}

// IsValidStakeAmount checks if a stake amount meets the minimum requirement.
func (vs *ValidatorSet) IsValidStakeAmount(stakeNSPX *big.Int) bool {
	if stakeNSPX == nil {
		return false
	}
	return stakeNSPX.Cmp(vs.minStakeAmount) >= 0
}

// GetMinimumStakeInQTX returns the minimum stake in QTX as float64.
func (vs *ValidatorSet) GetMinimumStakeInQTX() float64 {
	minStakeSPX := new(big.Float).Quo(
		new(big.Float).SetInt(vs.minStakeAmount),
		new(big.Float).SetFloat64(denom.QTX),
	)
	result, _ := minStakeSPX.Float64()
	return result
}

// GetActiveValidators returns a sorted slice of validators active in epoch.
// Sort order is by validator ID (lexicographic) so every node producing the
// same slice is deterministic — required for consistent VDF slash tracking.
func (vs *ValidatorSet) GetActiveValidators(epoch uint64) []*StakedValidator {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	active := make([]*StakedValidator, 0, len(vs.validators))
	for _, v := range vs.validators {
		if v.IsSlashed {
			continue
		}
		if v.ActivationEpoch > epoch {
			continue
		}
		if v.ExitEpoch != 0 && v.ExitEpoch <= epoch {
			continue
		}
		active = append(active, v)
	}

	sort.Slice(active, func(i, j int) bool {
		return active[i].ID < active[j].ID
	})

	return active
}

// ActiveValidatorIDs is a convenience wrapper used by the VDF epoch finaliser.
// It returns just the IDs of active validators for epoch, in the same
// deterministic order as GetActiveValidators.
func (vs *ValidatorSet) ActiveValidatorIDs(epoch uint64) []string {
	active := vs.GetActiveValidators(epoch)
	ids := make([]string, len(active))
	for i, v := range active {
		ids[i] = v.ID
	}
	return ids
}

// GetTotalStake returns total active stake in nQTX.
func (vs *ValidatorSet) GetTotalStake() *big.Int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	if vs.totalStake == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(vs.totalStake)
}

// GetStakeInQTX returns a validator's stake in QTX as float64.
func (v *StakedValidator) GetStakeInQTX() float64 {
	stakeSPX := new(big.Float).Quo(
		new(big.Float).SetInt(v.StakeAmount),
		new(big.Float).SetFloat64(denom.QTX),
	)
	result, _ := stakeSPX.Float64()
	return result
}

// GetValidatorSet returns this consensus instance's validator set.
func (c *Consensus) GetValidatorSet() *ValidatorSet {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.validatorSet
}

// SlashValidator reduces a validator's stake by penaltyBps basis points
// and marks them slashed if their remaining stake drops below the minimum.
// penaltyBps: 100 = 1 %, 1000 = 10 %.
func (vs *ValidatorSet) SlashValidator(id, reason string, penaltyBps uint64) {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	v, exists := vs.validators[id]
	if !exists {
		logger.Warn("SlashValidator: unknown validator %s", id)
		return
	}

	penalty := new(big.Int).Mul(v.StakeAmount, new(big.Int).SetUint64(penaltyBps))
	penalty.Div(penalty, big.NewInt(10000))

	vs.totalStake.Sub(vs.totalStake, penalty)
	v.StakeAmount.Sub(v.StakeAmount, penalty)

	if v.StakeAmount.Cmp(vs.minStakeAmount) < 0 {
		v.IsSlashed = true
		logger.Warn("🔪 Validator %s SLASHED and ejected — reason: %s (stake now %.2f QTX)",
			id, reason, v.GetStakeInQTX())
	} else {
		logger.Warn("🔪 Validator %s slashed %.2f QTX — reason: %s (remaining %.2f QTX)",
			id, new(big.Float).Quo(
				new(big.Float).SetInt(penalty),
				new(big.Float).SetFloat64(denom.QTX),
			), reason, v.GetStakeInQTX())
	}
}

// FinaliseEpochAndSlash is the epoch-boundary hook that ties the VDF beacon
// and the validator set together.
func (c *Consensus) FinaliseEpochAndSlash(epoch uint64) {
	c.mu.RLock()
	vs := c.validatorSet
	r := c.randao
	c.mu.RUnlock()

	if vs == nil || r == nil {
		return
	}

	activeIDs := vs.ActiveValidatorIDs(epoch)
	slashList := r.FinaliseEpoch(epoch, activeIDs)

	for _, id := range slashList {
		vs.SlashValidator(id, "missed VDF submission", SlashBps)
	}
}

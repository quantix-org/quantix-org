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

// consensus/staking.go
package consensus

import (
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
//
// Call this from the Consensus engine at slot 0 of each new epoch:
//
//	slashList := c.randao.FinaliseEpoch(epoch, c.validatorSet.ActiveValidatorIDs(epoch))
//	for _, id := range slashList {
//	    c.validatorSet.SlashValidator(id, "missed VDF submission", SlashBps)
//	}
//
// The helper below wraps that pattern for convenience.
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

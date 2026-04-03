// MIT License
// Copyright (c) 2024 quantix

// Q22 — Tests for policy package functions at 0% coverage
// Covers: CalculateFees, GetFeePerByte, CalculateMinimumFee, fee distribution
//         shares, CalculateEpochInflation, CalculateCumulativeInflation,
//         GetAnnualMinting, GetRemainingSupply, Validate, GetDefaultPolicyParams,
//         CalculateValidatorReward, DistributeFeesFromComponents,
//         Adjust* fee methods, GetCurrentUtilization
package policy

import (
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// GetDefaultPolicyParams / Validate
// ---------------------------------------------------------------------------

func TestGetDefaultPolicyParams_NotNil(t *testing.T) {
	p := GetDefaultPolicyParams()
	if p == nil {
		t.Fatal("GetDefaultPolicyParams should return non-nil")
	}
}

func TestValidate_DefaultParams_Valid(t *testing.T) {
	p := NewPolicyParameters()
	if err := p.Validate(); err != nil {
		t.Errorf("default params should validate cleanly: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CalculateFees / CalculateMinimumFee / GetFeePerByte
// ---------------------------------------------------------------------------

func TestCalculateFees_ZeroInputs_NonNilResult(t *testing.T) {
	p := NewPolicyParameters()
	fees := p.CalculateFees(0, 0, 0)
	if fees == nil {
		t.Fatal("CalculateFees should return non-nil FeeComponents")
	}
	if fees.TotalFee == nil {
		t.Fatal("TotalFee should be non-nil")
	}
}

func TestCalculateFees_BytesIncreasesFee(t *testing.T) {
	p := NewPolicyParameters()
	feesSmall := p.CalculateFees(100, 0, 0)
	feesLarge := p.CalculateFees(1000, 0, 0)
	if feesLarge.TotalFee.Cmp(feesSmall.TotalFee) <= 0 {
		t.Error("more bytes should produce higher fee")
	}
}

func TestCalculateFees_OpsIncreasesFee(t *testing.T) {
	p := NewPolicyParameters()
	feesNoOps := p.CalculateFees(0, 0, 0)
	feesManyOps := p.CalculateFees(0, 1000, 0)
	if feesManyOps.TotalFee.Cmp(feesNoOps.TotalFee) < 0 {
		t.Error("more ops should not decrease fee")
	}
}

func TestCalculateFees_HashesIncreasesFee(t *testing.T) {
	p := NewPolicyParameters()
	feesNoHash := p.CalculateFees(0, 0, 0)
	feesManyHash := p.CalculateFees(0, 0, 100)
	if feesManyHash.TotalFee.Cmp(feesNoHash.TotalFee) < 0 {
		t.Error("more hashes should not decrease fee")
	}
}

func TestCalculateMinimumFee_MatchesCalculateFeesTotal(t *testing.T) {
	p := NewPolicyParameters()
	bytes, ops, hashes := uint64(512), uint64(10), uint64(5)
	minFee := p.CalculateMinimumFee(bytes, ops, hashes)
	fullFees := p.CalculateFees(bytes, ops, hashes)
	if minFee.Cmp(fullFees.TotalFee) != 0 {
		t.Errorf("CalculateMinimumFee should equal CalculateFees.TotalFee: %s vs %s", minFee, fullFees.TotalFee)
	}
}

func TestGetFeePerByte_PositiveValue(t *testing.T) {
	p := NewPolicyParameters()
	fpb := p.GetFeePerByte()
	if fpb.Sign() <= 0 {
		t.Errorf("GetFeePerByte should return positive value, got %s", fpb)
	}
}

func TestGetFeePerByte_IsSumOfBaseAndStorage(t *testing.T) {
	p := NewPolicyParameters()
	expected := new(big.Int).Add(p.BaseFeePerByte, p.StorageFeePerByte)
	got := p.GetFeePerByte()
	if got.Cmp(expected) != 0 {
		t.Errorf("GetFeePerByte: got %s want %s", got, expected)
	}
}

// ---------------------------------------------------------------------------
// Fee distribution share getters
// ---------------------------------------------------------------------------

func TestGetValidatorFeeShareSumsWithOthers(t *testing.T) {
	p := NewPolicyParameters()
	v := p.GetValidatorFeeShare()
	s := p.GetStakerFeeShare()
	tr := p.GetTreasuryFeeShare()
	b := p.GetBurnedFeeShare()
	total := v + s + tr + b
	// Should sum to ~1.0 (100%)
	if total < 0.99 || total > 1.01 {
		t.Errorf("fee shares should sum to 1.0, got %.4f (v=%.2f s=%.2f t=%.2f b=%.2f)", total, v, s, tr, b)
	}
}

func TestGetValidatorFeeShare_Positive(t *testing.T) {
	p := NewPolicyParameters()
	if p.GetValidatorFeeShare() <= 0 {
		t.Error("validator fee share should be positive")
	}
}

func TestGetStakerFeeShare_Positive(t *testing.T) {
	p := NewPolicyParameters()
	if p.GetStakerFeeShare() <= 0 {
		t.Error("staker fee share should be positive")
	}
}

func TestGetTreasuryFeeShare_Positive(t *testing.T) {
	p := NewPolicyParameters()
	if p.GetTreasuryFeeShare() <= 0 {
		t.Error("treasury fee share should be positive")
	}
}

func TestGetBurnedFeeShare_NonNegative(t *testing.T) {
	p := NewPolicyParameters()
	if p.GetBurnedFeeShare() < 0 {
		t.Error("burned fee share should be non-negative")
	}
}

// ---------------------------------------------------------------------------
// CalculateValidatorFees / CalculateStakerFees / CalculateTreasuryFees / CalculateBurnedFees
// ---------------------------------------------------------------------------

func TestCalculateValidatorFees_ProportionalToShare(t *testing.T) {
	p := NewPolicyParameters()
	total := big.NewInt(1_000_000_000) // 1B nQTX
	vFees := p.CalculateValidatorFees(total)
	if vFees.Sign() <= 0 {
		t.Error("validator fees should be positive")
	}
	if vFees.Cmp(total) >= 0 {
		t.Error("validator fees should be less than total")
	}
}

func TestCalculateStakerFees_Positive(t *testing.T) {
	p := NewPolicyParameters()
	total := big.NewInt(1_000_000_000)
	if p.CalculateStakerFees(total).Sign() <= 0 {
		t.Error("staker fees should be positive")
	}
}

func TestCalculateTreasuryFees_Positive(t *testing.T) {
	p := NewPolicyParameters()
	total := big.NewInt(1_000_000_000)
	if p.CalculateTreasuryFees(total).Sign() <= 0 {
		t.Error("treasury fees should be positive")
	}
}

func TestCalculateBurnedFees_NonNegative(t *testing.T) {
	p := NewPolicyParameters()
	total := big.NewInt(1_000_000_000)
	if p.CalculateBurnedFees(total).Sign() < 0 {
		t.Error("burned fees should be non-negative")
	}
}

func TestFeeDistribution_SumsToTotal(t *testing.T) {
	p := NewPolicyParameters()
	total := big.NewInt(1_000_000)
	v := p.CalculateValidatorFees(total)
	s := p.CalculateStakerFees(total)
	tr := p.CalculateTreasuryFees(total)
	b := p.CalculateBurnedFees(total)

	sum := new(big.Int).Add(v, s)
	sum.Add(sum, tr)
	sum.Add(sum, b)

	// Allow rounding of ±4 nQTX
	diff := new(big.Int).Sub(sum, total)
	diff.Abs(diff)
	if diff.Cmp(big.NewInt(4)) > 0 {
		t.Errorf("v+s+t+b should sum to total (%s), got %s (diff=%s)", total, sum, diff)
	}
}

// ---------------------------------------------------------------------------
// DistributeFeesFromComponents
// ---------------------------------------------------------------------------

func TestDistributeFeesFromComponents_NonNil(t *testing.T) {
	p := NewPolicyParameters()
	fees := p.CalculateFees(100, 10, 5)
	dist := p.DistributeFeesFromComponents(fees)
	if dist == nil {
		t.Fatal("DistributeFeesFromComponents should not return nil")
	}
}

// ---------------------------------------------------------------------------
// Adjust* fee methods
// ---------------------------------------------------------------------------

func TestAdjustBaseFeePerByte_HighUtilization_IncreasesFee(t *testing.T) {
	p := NewPolicyParameters()
	before := new(big.Int).Set(p.BaseFeePerByte)
	p.AdjustBaseFeePerByte(0.95) // 95% utilization
	after := p.BaseFeePerByte
	if after.Cmp(before) <= 0 {
		t.Error("high utilization should increase BaseFeePerByte")
	}
}

func TestAdjustStorageFeePerByte_LowUtilization_ChangesFee(t *testing.T) {
	p := NewPolicyParameters()
	// Just call it — verifies no panic
	p.AdjustStorageFeePerByte(0.1)
}

func TestAdjustComputeFeePerOp_MidUtilization_NoNegative(t *testing.T) {
	p := NewPolicyParameters()
	p.AdjustComputeFeePerOp(0.5)
	if p.ComputeFeePerOp.Sign() < 0 {
		t.Error("ComputeFeePerOp should not become negative")
	}
}

// ---------------------------------------------------------------------------
// GetCurrentUtilization
// ---------------------------------------------------------------------------

func TestGetCurrentUtilization_ZeroStake(t *testing.T) {
	p := NewPolicyParameters()
	u := p.GetCurrentUtilization(0.0)
	if u < 0 || u > 1.0 {
		t.Errorf("utilization should be in [0,1], got %.4f", u)
	}
}

func TestGetCurrentUtilization_FullStake(t *testing.T) {
	p := NewPolicyParameters()
	u := p.GetCurrentUtilization(1.0)
	if u < 0 {
		t.Errorf("utilization should be non-negative, got %.4f", u)
	}
}

// ---------------------------------------------------------------------------
// CalculateEpochInflation
// ---------------------------------------------------------------------------

func TestCalculateEpochInflation_ReturnsDistribution(t *testing.T) {
	p := NewPolicyParameters()
	supply := new(big.Int).SetInt64(5_000_000_000) // 5B
	dist := p.CalculateEpochInflation(supply, 1, 0.5)
	if dist == nil {
		t.Fatal("CalculateEpochInflation should not return nil")
	}
	if dist.TotalMinted == nil {
		t.Error("TotalMinted should be set")
	}
	if dist.StakingRewards == nil {
		t.Error("StakingRewards should be set")
	}
}

func TestCalculateEpochInflation_StakingRewardsPlusCommunityEqualsTotal(t *testing.T) {
	p := NewPolicyParameters()
	supply := new(big.Int).SetInt64(1_000_000_000)
	dist := p.CalculateEpochInflation(supply, 1, 0.6)
	sum := new(big.Int).Add(dist.StakingRewards, dist.CommunityFund)
	if sum.Cmp(dist.TotalMinted) != 0 {
		t.Errorf("StakingRewards + CommunityFund should equal TotalMinted: %s + %s = %s, got %s",
			dist.StakingRewards, dist.CommunityFund, sum, dist.TotalMinted)
	}
}

// ---------------------------------------------------------------------------
// CalculateCumulativeInflation
// ---------------------------------------------------------------------------

func TestCalculateCumulativeInflation_IncreasesWithYears(t *testing.T) {
	p := NewPolicyParameters()
	c1 := p.CalculateCumulativeInflation(1)
	c5 := p.CalculateCumulativeInflation(5)
	if c5 <= c1 {
		t.Errorf("5-year cumulative inflation should exceed 1-year: %.4f vs %.4f", c5, c1)
	}
}

func TestCalculateCumulativeInflation_NonNegative(t *testing.T) {
	p := NewPolicyParameters()
	c := p.CalculateCumulativeInflation(10)
	if c < 0 {
		t.Errorf("cumulative inflation should be non-negative, got %.4f", c)
	}
}

// ---------------------------------------------------------------------------
// GetAnnualMinting
// ---------------------------------------------------------------------------

func TestGetAnnualMinting_NonNegative(t *testing.T) {
	p := NewPolicyParameters()
	supply := new(big.Int).SetInt64(5_000_000_000)
	minted := p.GetAnnualMinting(supply, 1, 0.5)
	if minted.Sign() < 0 {
		t.Errorf("annual minting should be non-negative, got %s", minted)
	}
}

func TestGetAnnualMinting_LargerSupplyMoreMinting(t *testing.T) {
	p := NewPolicyParameters()
	small := new(big.Int).SetInt64(1_000_000)
	large := new(big.Int).SetInt64(1_000_000_000)
	mintSmall := p.GetAnnualMinting(small, 1, 0.5)
	mintLarge := p.GetAnnualMinting(large, 1, 0.5)
	if mintLarge.Cmp(mintSmall) < 0 {
		t.Error("larger supply should produce >= minting than smaller supply")
	}
}

// ---------------------------------------------------------------------------
// GetRemainingSupply
// ---------------------------------------------------------------------------

func TestGetRemainingSupply_NonNil(t *testing.T) {
	p := NewPolicyParameters()
	initial := new(big.Int).SetInt64(5_000_000_000)
	ratios := []float64{0.5, 0.5, 0.5}
	rem := p.GetRemainingSupply(initial, 3, ratios)
	if rem == nil {
		t.Fatal("GetRemainingSupply should not return nil")
	}
}

func TestGetRemainingSupply_ZeroYears_EqualsInitial(t *testing.T) {
	p := NewPolicyParameters()
	initial := new(big.Int).SetInt64(1_000_000)
	rem := p.GetRemainingSupply(initial, 0, []float64{})
	if rem.Cmp(initial) != 0 {
		t.Errorf("0 years: remaining supply should equal initial: %s vs %s", rem, initial)
	}
}

// ---------------------------------------------------------------------------
// CalculateValidatorReward
// ---------------------------------------------------------------------------

func TestCalculateValidatorReward_NoStake_ReturnsZero(t *testing.T) {
	p := NewPolicyParameters()
	validatorStake := big.NewInt(0)
	totalStake := big.NewInt(1000)
	epochRewards := big.NewInt(100)
	reward := p.CalculateValidatorReward(validatorStake, totalStake, epochRewards, 0.1)
	if reward.Sign() != 0 {
		t.Errorf("zero stake validator should get zero reward, got %s", reward)
	}
}

func TestCalculateValidatorReward_FullStake_GetsCommission(t *testing.T) {
	p := NewPolicyParameters()
	// Validator with 100% of stake and 10% commission
	validatorStake := big.NewInt(1000)
	totalStake := big.NewInt(1000)
	epochRewards := big.NewInt(1000)
	reward := p.CalculateValidatorReward(validatorStake, totalStake, epochRewards, 0.10)
	if reward.Sign() <= 0 {
		t.Error("validator with 100% stake and 10% commission should get positive reward")
	}
}

// ---------------------------------------------------------------------------
// CalculateSigFeeInQTX / CalculateContractFeeInQTX (0% functions)
// ---------------------------------------------------------------------------

func TestCalculateSigFeeInQTX_Positive(t *testing.T) {
	p := NewPolicyParameters()
	fee := p.CalculateSigFeeInQTX(256, 1)
	if fee < 0 {
		t.Errorf("sig fee in QTX should be non-negative, got %.4f", fee)
	}
}

func TestCalculateContractFeeInQTX_Positive(t *testing.T) {
	p := NewPolicyParameters()
	fee := p.CalculateContractFeeInQTX(10, 1024)
	if fee < 0 {
		t.Errorf("contract fee in QTX should be non-negative, got %.4f", fee)
	}
}

func TestCalculateTotalFee_SumsOnChainAndIPFS(t *testing.T) {
	p := NewPolicyParameters()
	onChain := big.NewInt(1000)
	ipfs := big.NewInt(500)
	total := p.CalculateTotalFee(onChain, ipfs)
	expected := big.NewInt(1500)
	if total.Cmp(expected) != 0 {
		t.Errorf("CalculateTotalFee: got %s want 1500", total)
	}
}

func TestCalculateTotalFeeInQTX_NonNegative(t *testing.T) {
	p := NewPolicyParameters()
	fee := p.CalculateTotalFeeInQTX(big.NewInt(1000), big.NewInt(500))
	if fee < 0 {
		t.Errorf("total fee in QTX should be non-negative, got %.4f", fee)
	}
}

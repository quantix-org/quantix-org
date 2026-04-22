// MIT License
// Copyright (c) 2024 quantix-org

package policy

import (
	"math/big"
	"testing"
)

// ============================================================
// PARAMS & VALIDATION
// ============================================================

func TestNewPolicyParameters(t *testing.T) {
	p := NewPolicyParameters()
	if p == nil {
		t.Fatal("NewPolicyParameters() returned nil")
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("default params failed validation: %v", err)
	}
}

func TestValidateDefaultParams(t *testing.T) {
	p := NewPolicyParameters()
	if err := p.Validate(); err != nil {
		t.Errorf("Validate() on default params failed: %v", err)
	}
}

func TestValidateZeroBaseFee(t *testing.T) {
	p := NewPolicyParameters()
	p.BaseFeePerByte = big.NewInt(0)
	if err := p.Validate(); err == nil {
		t.Error("expected error for zero BaseFeePerByte, got nil")
	}
}

func TestValidateZeroStorageFee(t *testing.T) {
	p := NewPolicyParameters()
	p.StorageFeePerByte = big.NewInt(0)
	if err := p.Validate(); err == nil {
		t.Error("expected error for zero StorageFeePerByte, got nil")
	}
}

func TestValidateZeroComputeFee(t *testing.T) {
	p := NewPolicyParameters()
	p.ComputeFeePerOp = big.NewInt(0)
	if err := p.Validate(); err == nil {
		t.Error("expected error for zero ComputeFeePerOp, got nil")
	}
}

func TestValidateZeroBlocksPerEpoch(t *testing.T) {
	p := NewPolicyParameters()
	p.BlocksPerEpoch = 0
	if err := p.Validate(); err == nil {
		t.Error("expected error for zero BlocksPerEpoch, got nil")
	}
}

func TestValidateInflationRateOutOfRange(t *testing.T) {
	p := NewPolicyParameters()
	p.InitialInflationRate = 1.5 // > 1.0
	if err := p.Validate(); err == nil {
		t.Error("expected error for inflation rate > 1, got nil")
	}
}

func TestValidateNegativeInflationRate(t *testing.T) {
	p := NewPolicyParameters()
	p.InitialInflationRate = -0.1
	if err := p.Validate(); err == nil {
		t.Error("expected error for negative inflation rate, got nil")
	}
}

// ============================================================
// FEE CALCULATIONS
// ============================================================

func TestCalculateTxFeePositive(t *testing.T) {
	p := NewPolicyParameters()
	fee := p.CalculateTxFee(1024, 1000)
	if fee == nil || fee.Sign() <= 0 {
		t.Errorf("CalculateTxFee() should return positive fee, got %v", fee)
	}
}

func TestCalculateTxFeeZeroInputs(t *testing.T) {
	p := NewPolicyParameters()
	fee := p.CalculateTxFee(0, 0)
	// Should still return at least the base TransactionFee
	if fee.Cmp(p.TransactionFee) < 0 {
		t.Errorf("fee with zero inputs %v should be >= TransactionFee %v", fee, p.TransactionFee)
	}
}

func TestCalculateTxFeeScalesWithSize(t *testing.T) {
	p := NewPolicyParameters()
	fee1 := p.CalculateTxFee(100, 0)
	fee2 := p.CalculateTxFee(200, 0)
	if fee2.Cmp(fee1) <= 0 {
		t.Errorf("larger tx size should produce larger fee: fee1=%v fee2=%v", fee1, fee2)
	}
}

func TestCalculateTxFeeScalesWithOps(t *testing.T) {
	p := NewPolicyParameters()
	fee1 := p.CalculateTxFee(0, 100)
	fee2 := p.CalculateTxFee(0, 200)
	if fee2.Cmp(fee1) <= 0 {
		t.Errorf("more ops should produce larger fee: fee1=%v fee2=%v", fee1, fee2)
	}
}

func TestCalculateTxFeeInSPXPositive(t *testing.T) {
	p := NewPolicyParameters()
	fee := p.CalculateTxFeeInSPX(1024, 1000)
	if fee <= 0 {
		t.Errorf("CalculateTxFeeInSPX() = %v, want > 0", fee)
	}
}

func TestCalculateSigFeePositive(t *testing.T) {
	p := NewPolicyParameters()
	fee := p.CalculateSigFee(1024, 10)
	if fee == nil || fee.Sign() <= 0 {
		t.Errorf("CalculateSigFee() should be positive, got %v", fee)
	}
}

func TestCalculateSigFeeScalesWithMetadata(t *testing.T) {
	p := NewPolicyParameters()
	fee1 := p.CalculateSigFee(100, 0)
	fee2 := p.CalculateSigFee(200, 0)
	if fee2.Cmp(fee1) <= 0 {
		t.Errorf("larger metadata should produce larger sig fee: %v vs %v", fee1, fee2)
	}
}

func TestCalculateContractFeePositive(t *testing.T) {
	p := NewPolicyParameters()
	fee := p.CalculateContractFee(5000, 2048)
	if fee == nil || fee.Sign() <= 0 {
		t.Errorf("CalculateContractFee() should be positive, got %v", fee)
	}
}

func TestCalculateIPFSFeePositive(t *testing.T) {
	p := NewPolicyParameters()
	// 1 GB for 1 month
	fee := p.CalculateIPFSFee(1024*1024*1024, 1)
	if fee <= 0 {
		t.Errorf("CalculateIPFSFee() = %v, want > 0", fee)
	}
}

func TestCalculateIPFSFeeScalesWithDuration(t *testing.T) {
	p := NewPolicyParameters()
	size := uint64(1024 * 1024 * 1024) // 1 GB
	fee1 := p.CalculateIPFSFee(size, 1)
	fee2 := p.CalculateIPFSFee(size, 2)
	if fee2 <= fee1 {
		t.Errorf("longer pin duration should cost more: %v vs %v", fee1, fee2)
	}
}

func TestConvertNSPXToSPX(t *testing.T) {
	p := NewPolicyParameters()
	// 1 QTX = 1e18 nQTX
	oneQTX := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	result := p.ConvertNSPXToSPX(oneQTX)
	if result != 1.0 {
		t.Errorf("ConvertNSPXToSPX(1e18) = %v, want 1.0", result)
	}
}

func TestConvertSPXToNSPX(t *testing.T) {
	p := NewPolicyParameters()
	result := p.ConvertSPXToNSPX(1.0)
	oneQTX := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	if result.Cmp(oneQTX) != 0 {
		t.Errorf("ConvertSPXToNSPX(1.0) = %v, want %v", result, oneQTX)
	}
}

func TestConvertRoundtrip(t *testing.T) {
	p := NewPolicyParameters()
	original := big.NewInt(5_000_000_000) // 5 gQTX in nQTX
	spx := p.ConvertNSPXToSPX(original)
	back := p.ConvertSPXToNSPX(spx)
	// Allow tiny floating point rounding
	diff := new(big.Int).Abs(new(big.Int).Sub(original, back))
	if diff.Cmp(big.NewInt(1000)) > 0 {
		t.Errorf("roundtrip mismatch: original=%v back=%v diff=%v", original, back, diff)
	}
}

// ============================================================
// FEE DISTRIBUTION
// ============================================================

func TestDistributeFeesShares(t *testing.T) {
	p := NewPolicyParameters()
	total := big.NewInt(10000)
	dist := p.DistributeFees(total)

	// Verify shares sum to total
	sum := new(big.Int)
	sum.Add(sum, dist.Validators)
	sum.Add(sum, dist.Stakers)
	sum.Add(sum, dist.Treasury)
	sum.Add(sum, dist.Burned)

	if sum.Cmp(total) != 0 {
		t.Errorf("fee distribution sum %v != total %v", sum, total)
	}
}

func TestDistributeFeesValidatorShare60Pct(t *testing.T) {
	p := NewPolicyParameters()
	total := big.NewInt(10000)
	dist := p.DistributeFees(total)
	expected := big.NewInt(6000) // 60%
	if dist.Validators.Cmp(expected) != 0 {
		t.Errorf("validators share = %v, want %v (60%%)", dist.Validators, expected)
	}
}

func TestDistributeFeesStakersShare25Pct(t *testing.T) {
	p := NewPolicyParameters()
	total := big.NewInt(10000)
	dist := p.DistributeFees(total)
	expected := big.NewInt(2500) // 25%
	if dist.Stakers.Cmp(expected) != 0 {
		t.Errorf("stakers share = %v, want %v (25%%)", dist.Stakers, expected)
	}
}

func TestDistributeFeesTotalIsPreserved(t *testing.T) {
	p := NewPolicyParameters()
	total := big.NewInt(999999) // odd number to test rounding
	dist := p.DistributeFees(total)

	sum := new(big.Int)
	sum.Add(sum, dist.Validators)
	sum.Add(sum, dist.Stakers)
	sum.Add(sum, dist.Treasury)
	sum.Add(sum, dist.Burned)

	if sum.Cmp(total) != 0 {
		t.Errorf("fee distribution with odd total: sum=%v != total=%v", sum, total)
	}
}

func TestDistributeFeesZeroTotal(t *testing.T) {
	p := NewPolicyParameters()
	dist := p.DistributeFees(big.NewInt(0))

	if dist.Validators.Sign() != 0 || dist.Stakers.Sign() != 0 ||
		dist.Treasury.Sign() != 0 || dist.Burned.Sign() != 0 {
		t.Error("zero fees should produce zero distribution in all buckets")
	}
}

func TestGetFeeSharePercentages(t *testing.T) {
	p := NewPolicyParameters()
	total := p.GetValidatorFeeShare() + p.GetStakerFeeShare() + p.GetTreasuryFeeShare() + p.GetBurnedFeeShare()
	if total < 0.999 || total > 1.001 {
		t.Errorf("fee shares don't sum to 1.0: got %.4f", total)
	}
}

// ============================================================
// INFLATION
// ============================================================

func TestCalculateAnnualInflationYear1(t *testing.T) {
	p := NewPolicyParameters()
	rate := p.CalculateAnnualInflation(1)
	if rate != p.InitialInflationRate {
		t.Errorf("year 1 inflation = %v, want %v", rate, p.InitialInflationRate)
	}
}

func TestCalculateAnnualInflationDecays(t *testing.T) {
	p := NewPolicyParameters()
	rate1 := p.CalculateAnnualInflation(1)
	rate2 := p.CalculateAnnualInflation(2)
	rate5 := p.CalculateAnnualInflation(5)

	if rate2 >= rate1 {
		t.Errorf("inflation should decay: year1=%v year2=%v", rate1, rate2)
	}
	if rate5 >= rate2 {
		t.Errorf("inflation should continue decaying: year2=%v year5=%v", rate2, rate5)
	}
}

func TestCalculateAnnualInflationYear0Fallback(t *testing.T) {
	p := NewPolicyParameters()
	// Year 0 should fall back to year 1
	rate0 := p.CalculateAnnualInflation(0)
	rate1 := p.CalculateAnnualInflation(1)
	if rate0 != rate1 {
		t.Errorf("year 0 should fall back to year 1: rate0=%v rate1=%v", rate0, rate1)
	}
}

func TestCalculateAnnualInflationWithStakeAdjustment(t *testing.T) {
	p := NewPolicyParameters()
	base := p.CalculateAnnualInflation(1)

	// At target stake ratio → same as base
	atTarget := p.CalculateAnnualInflationWithStakeAdjustment(1, p.TargetStakeRatio)
	if atTarget <= 0 {
		t.Errorf("inflation at target ratio should be positive, got %v", atTarget)
	}

	// Below target → higher inflation (incentivize staking)
	belowTarget := p.CalculateAnnualInflationWithStakeAdjustment(1, 0.3)
	if belowTarget <= base {
		t.Errorf("inflation below target should be higher: base=%v below=%v", base, belowTarget)
	}

	// Well above target → lower inflation
	aboveTarget := p.CalculateAnnualInflationWithStakeAdjustment(1, 0.99)
	if aboveTarget >= base {
		t.Errorf("inflation above target should be lower: base=%v above=%v", base, aboveTarget)
	}
}

func TestCalculateCumulativeInflationIncreases(t *testing.T) {
	p := NewPolicyParameters()
	cum5 := p.CalculateCumulativeInflation(5)
	cum10 := p.CalculateCumulativeInflation(10)
	if cum10 <= cum5 {
		t.Errorf("cumulative inflation over 10 years should exceed 5 years: %v vs %v", cum10, cum5)
	}
}

func TestGetBlocksPerYear(t *testing.T) {
	p := NewPolicyParameters()
	blocks := p.GetBlocksPerYear()
	// With 12s block time: 365*24*3600/12 = 2,628,000
	expected := uint64(2628000)
	if blocks != expected {
		t.Errorf("GetBlocksPerYear() = %d, want %d", blocks, expected)
	}
}

func TestGetEpochsPerYear(t *testing.T) {
	p := NewPolicyParameters()
	epochs := p.GetEpochsPerYear()
	if epochs == 0 {
		t.Error("GetEpochsPerYear() returned 0")
	}
	// epochs = blocksPerYear / blocksPerEpoch
	expected := p.GetBlocksPerYear() / p.BlocksPerEpoch
	if epochs != expected {
		t.Errorf("GetEpochsPerYear() = %d, want %d", epochs, expected)
	}
}

// ============================================================
// REWARDS
// ============================================================

func TestCalculateValidatorRewardPositive(t *testing.T) {
	p := NewPolicyParameters()
	stake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	total := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	epochRewards := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))

	reward := p.CalculateValidatorReward(stake, total, epochRewards, 0.1)
	if reward == nil || reward.Sign() <= 0 {
		t.Errorf("CalculateValidatorReward() should be positive, got %v", reward)
	}
}

func TestCalculateDelegatorRewardPositive(t *testing.T) {
	p := NewPolicyParameters()
	delStake := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))
	valStake := new(big.Int).Mul(big.NewInt(200), big.NewInt(1e18))
	valRewards := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18))

	reward := p.CalculateDelegatorReward(delStake, valStake, valRewards, 0.1)
	if reward == nil || reward.Sign() <= 0 {
		t.Errorf("CalculateDelegatorReward() should be positive, got %v", reward)
	}
}

func TestCalculateAPYPositive(t *testing.T) {
	p := NewPolicyParameters()
	stake := new(big.Int).Mul(big.NewInt(3_500_000_000), big.NewInt(1e18)) // 3.5B staked
	supply := new(big.Int).Mul(big.NewInt(5_000_000_000), big.NewInt(1e18)) // 5B total

	apy := p.CalculateAPY(stake, supply, 1, 0.7)
	if apy <= 0 {
		t.Errorf("CalculateAPY() = %v, want > 0", apy)
	}
}

// ============================================================
// DYNAMIC BASE RATE
// ============================================================

func TestCalculateDynamicBaseRateHighUtilization(t *testing.T) {
	p := NewPolicyParameters()
	base := big.NewInt(1000)
	// High utilization (above target) → rate increases (capped at +20%)
	newRate := p.CalculateDynamicBaseRate(base, 1.0) // 100% utilization
	if newRate.Cmp(base) <= 0 {
		t.Errorf("high utilization should increase base rate: base=%v new=%v", base, newRate)
	}
}

func TestCalculateDynamicBaseRateLowUtilization(t *testing.T) {
	p := NewPolicyParameters()
	base := big.NewInt(1000)
	// Very low utilization → rate decreases (capped at -20%)
	newRate := p.CalculateDynamicBaseRate(base, 0.0)
	if newRate.Cmp(base) >= 0 {
		t.Errorf("low utilization should decrease base rate: base=%v new=%v", base, newRate)
	}
}

func TestCalculateDynamicBaseRateAtTarget(t *testing.T) {
	p := NewPolicyParameters()
	base := big.NewInt(1000)
	// At exact target → small or no change
	newRate := p.CalculateDynamicBaseRate(base, p.TargetStakeRatio)
	// Should be within ±5% of base
	lower := big.NewInt(950)
	upper := big.NewInt(1050)
	if newRate.Cmp(lower) < 0 || newRate.Cmp(upper) > 0 {
		t.Errorf("at target utilization, rate should be near base: base=%v new=%v", base, newRate)
	}
}

// ============================================================
// FEE COMPONENTS
// ============================================================

func TestCalculateFeesAllComponentsPositive(t *testing.T) {
	p := NewPolicyParameters()
	fees := p.CalculateFees(1024, 500, 10)

	if fees.WriteFee.Sign() <= 0 {
		t.Error("WriteFee should be positive")
	}
	if fees.StorageFee.Sign() <= 0 {
		t.Error("StorageFee should be positive")
	}
	if fees.ComputeFee.Sign() <= 0 {
		t.Error("ComputeFee should be positive")
	}
	if fees.TotalFee.Sign() <= 0 {
		t.Error("TotalFee should be positive")
	}
}

func TestCalculateFeesTotalEqualsSum(t *testing.T) {
	p := NewPolicyParameters()
	fees := p.CalculateFees(1024, 500, 10)

	sum := new(big.Int)
	sum.Add(sum, fees.WriteFee)
	sum.Add(sum, fees.StorageFee)
	sum.Add(sum, fees.ComputeFee)
	sum.Add(sum, fees.HashFee)
	sum.Add(sum, fees.BaseFee)
	sum.Add(sum, fees.TransactionFee)

	if sum.Cmp(fees.TotalFee) != 0 {
		t.Errorf("fee components sum %v != TotalFee %v", sum, fees.TotalFee)
	}
}

func TestGetFeePerByteEqualsWritePlusStorage(t *testing.T) {
	p := NewPolicyParameters()
	feePerByte := p.GetFeePerByte()
	expected := new(big.Int).Add(p.BaseFeePerByte, p.StorageFeePerByte)
	if feePerByte.Cmp(expected) != 0 {
		t.Errorf("GetFeePerByte() = %v, want %v", feePerByte, expected)
	}
}

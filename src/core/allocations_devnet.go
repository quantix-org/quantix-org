// MIT License
// Copyright (c) 2024 quantix-org

package core

import (
	"math/big"
)

// DevnetTestWallets returns allocations for the 5 test wallets generated for devnet testing.
// Each wallet gets 10,000 QTX for testing purposes.
// These use the x-prefixed Base58Check address format from the wallet generator.
func DevnetTestWallets() []*GenesisAllocation {
	return []*GenesisAllocation{
		// Wallet 1: scare feature jealous tube glory vault suggest offer grunt churn scan goat...
		NewGenesisAllocationXAddr("xAAcRj265En1EYT3c8sRecAzDnmck6F2mTDM2zTBGHdY", 10_000, "TestWallet1"),

		// Wallet 2: prepare push term horror accident food oak parrot fossil submit burst course...
		NewGenesisAllocationXAddr("x5Fukm46f3HurmwyjXLDPRVnRMfmc5WxTAnfXmipMCU5H", 10_000, "TestWallet2"),

		// Wallet 3: trust brass slight hurt fog broom manual pumpkin urge young office grit...
		NewGenesisAllocationXAddr("x5wkbxfDEoTZ284vnCD2c3bumJS8ZQRaqM25dgEtFxcMZ", 10_000, "TestWallet3"),

		// Wallet 4: doll soon dolphin escape pool flavor comic behave link hollow smooth unlock...
		NewGenesisAllocationXAddr("x5A2rG8KgBXnEp85q9cWYWwV8csE1Ewt4GTWNW87ZGE26", 10_000, "TestWallet4"),

		// Wallet 5: brief actor fiction short close gather excess pudding fog tragic keep proof...
		NewGenesisAllocationXAddr("x8Cbqq66dD1PjbY9CL5QEJqVKn3RWyKWCeJCUEqWhGyeB", 10_000, "TestWallet5"),
	}
}

// NewGenesisAllocationXAddr creates a GenesisAllocation using an x-prefixed Base58Check address.
// This is used for devnet/testnet wallets that use the modern address format.
// The address is stored as-is (not converted to hex) since the StateDB can handle both formats.
func NewGenesisAllocationXAddr(address string, spx int64, label string) *GenesisAllocation {
	nspx := new(big.Int).Mul(big.NewInt(spx), big.NewInt(1e18))
	return &GenesisAllocation{
		Address:     address,
		BalanceNSPX: nspx,
		Label:       label,
	}
}

// GetDevnetGenesisAllocations returns genesis allocations for devnet including test wallets.
// This includes both the default allocations and the 5 test wallets.
func GetDevnetGenesisAllocations() []*GenesisAllocation {
	// Start with a devnet faucet allocation (1 million QTX for testing)
	allocs := []*GenesisAllocation{
		NewGenesisAllocationXAddr("xFaucet000000000000000000000000000000001", 1_000_000, "DevnetFaucet"),
	}

	// Add the 5 test wallets
	allocs = append(allocs, DevnetTestWallets()...)

	return allocs
}

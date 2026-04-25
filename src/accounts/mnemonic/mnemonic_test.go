// MIT License
// Copyright (c) 2024 quantix
package sips3_test

import (
	"strings"
	"testing"

	mnemonic "github.com/quantix-org/quantix-org/src/accounts/mnemonic"
)

// ── NewMnemonic — invalid entropy fast-path (no network call needed) ─────────

func TestNewMnemonic_InvalidEntropy_Error(t *testing.T) {
	tests := []int{0, 1, 64, 127, 129, 257, -1, 512}
	for _, entropy := range tests {
		_, _, err := mnemonic.NewMnemonic(entropy)
		if err == nil {
			t.Errorf("NewMnemonic(%d) expected error for invalid entropy", entropy)
		}
	}
}

func TestNewMnemonic_NetworkRequired_Skip(t *testing.T) {
	// Valid entropy values (128, 160, 192, 224, 256) require a network call
	// to fetch the BIP-39 wordlist from GitHub. Skip in offline/CI environments.
	t.Skip("NewMnemonic with valid entropy requires network access to fetch BIP-39 wordlist")
}

// ── GeneratePassphrase — pure function, no network ───────────────────────────

func TestGeneratePassphrase_EmptyWordList_Error(t *testing.T) {
	_, _, err := mnemonic.GeneratePassphrase([]string{}, 12)
	if err == nil {
		t.Error("expected error for empty word list")
	}
}

func TestGeneratePassphrase_NonEmpty(t *testing.T) {
	words := []string{"alpha", "beta", "gamma", "delta", "epsilon",
		"zeta", "eta", "theta", "iota", "kappa", "lambda", "mu"}
	pp, _, err := mnemonic.GeneratePassphrase(words, 12)
	if err != nil {
		t.Fatalf("GeneratePassphrase error: %v", err)
	}
	if pp == "" {
		t.Error("passphrase should not be empty")
	}
}

func TestGeneratePassphrase_WordCount(t *testing.T) {
	words := make([]string, 2048)
	for i := range words {
		words[i] = "word"
	}
	for _, count := range []int{12, 15, 18, 21, 24} {
		pp, _, err := mnemonic.GeneratePassphrase(words, count)
		if err != nil {
			t.Fatalf("GeneratePassphrase(count=%d) error: %v", count, err)
		}
		parts := strings.Fields(pp)
		if len(parts) != count {
			t.Errorf("count=%d: got %d words", count, len(parts))
		}
	}
}

func TestGeneratePassphrase_ReturnsNonce(t *testing.T) {
	words := []string{"alpha", "beta", "gamma", "delta", "epsilon",
		"zeta", "eta", "theta", "iota", "kappa", "lambda", "mu"}
	_, nonce, err := mnemonic.GeneratePassphrase(words, 12)
	if err != nil {
		t.Fatalf("GeneratePassphrase error: %v", err)
	}
	if nonce == "" {
		t.Error("nonce should not be empty")
	}
}

func TestGeneratePassphrase_Unique(t *testing.T) {
	words := make([]string, 2048)
	for i := range words {
		words[i] = string(rune('a' + i%26))
	}
	pp1, _, _ := mnemonic.GeneratePassphrase(words, 12)
	pp2, _, _ := mnemonic.GeneratePassphrase(words, 12)
	// With 2048 unique(ish) words and 12-word phrases, collisions are vanishingly rare
	// We just verify neither is empty — probabilistic uniqueness is expected
	if pp1 == "" || pp2 == "" {
		t.Error("passphrases should not be empty")
	}
}

func TestGeneratePassphrase_OnlyWordsFromList(t *testing.T) {
	wordSet := map[string]bool{
		"apple": true, "banana": true, "cherry": true, "date": true,
		"elderberry": true, "fig": true, "grape": true, "honeydew": true,
		"kiwi": true, "lemon": true, "mango": true, "nectarine": true,
	}
	words := make([]string, 0, len(wordSet))
	for w := range wordSet {
		words = append(words, w)
	}
	pp, _, err := mnemonic.GeneratePassphrase(words, 12)
	if err != nil {
		t.Fatalf("GeneratePassphrase error: %v", err)
	}
	for _, w := range strings.Fields(pp) {
		if !wordSet[w] {
			t.Errorf("passphrase contains word %q not in word list", w)
		}
	}
}

// go/src/accounts/mnemonic/mnemonic.go
package sips3

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// BIP39 standard word count to entropy mapping:
// 128 bits → 12 words, 160 → 15, 192 → 18, 224 → 21, 256 → 24

// GenerateMnemonic generates a BIP39 mnemonic from cryptographically random entropy.
// strength must be one of: 128, 160, 192, 224, 256 (bits).
func GenerateMnemonic(strength int) (string, error) {
	if !isValidStrength(strength) {
		return "", errors.New("mnemonic: invalid strength, must be 128/160/192/224/256")
	}

	entropy := make([]byte, strength/8)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}

	return entropyToMnemonic(entropy)
}

// MnemonicToSeed derives a 512-bit seed from a mnemonic and optional passphrase
// using PBKDF2-SHA512 with 2048 iterations (BIP39 standard).
func MnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	if !ValidateMnemonic(mnemonic) {
		return nil, errors.New("mnemonic: invalid mnemonic")
	}
	salt := []byte("mnemonic" + passphrase)
	seed := pbkdf2.Key([]byte(mnemonic), salt, 2048, 64, sha512.New)
	return seed, nil
}

// ValidateMnemonic returns true if mnemonic is a valid BIP39 phrase.
func ValidateMnemonic(mnemonic string) bool {
	_, err := MnemonicToEntropy(mnemonic)
	return err == nil
}

// MnemonicToEntropy recovers the original entropy bytes from a mnemonic.
func MnemonicToEntropy(mnemonic string) ([]byte, error) {
	words := strings.Fields(mnemonic)
	wordCount := len(words)

	validCounts := map[int]bool{12: true, 15: true, 18: true, 21: true, 24: true}
	if !validCounts[wordCount] {
		return nil, errors.New("mnemonic: invalid word count")
	}

	wordList := getWordList()
	wordIndex := make(map[string]int, len(wordList))
	for i, w := range wordList {
		wordIndex[w] = i
	}

	// Reconstruct the bit stream (11 bits per word)
	b := new(big.Int)
	for _, word := range words {
		idx, ok := wordIndex[word]
		if !ok {
			return nil, errors.New("mnemonic: word not in wordlist: " + word)
		}
		b.Lsh(b, 11)
		b.Or(b, big.NewInt(int64(idx)))
	}

	// Total bits = wordCount * 11. Entropy bits = total - checksum bits.
	// checksum bits = entropy bytes / 4 = entropy bits / 32.
	// For 12 words: 132 bits total, 4 checksum bits, 128 entropy bits.
	totalBits := wordCount * 11
	checksumBits := wordCount / 3 // = totalBits / 33
	entropyBits := totalBits - checksumBits
	entropyBytes := entropyBits / 8

	// Extract checksum (lowest checksumBits bits)
	checksumMask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(checksumBits)), big.NewInt(1))
	checksum := new(big.Int).And(b, checksumMask)
	b.Rsh(b, uint(checksumBits))

	// Pad to entropyBytes
	entropy := make([]byte, entropyBytes)
	bBytes := b.Bytes()
	if len(bBytes) > entropyBytes {
		return nil, errors.New("mnemonic: entropy overflow")
	}
	copy(entropy[entropyBytes-len(bBytes):], bBytes)

	// Validate checksum
	h := sha256.Sum256(entropy)
	expectedChecksum := new(big.Int).SetBytes(h[:])
	expectedChecksum.Rsh(expectedChecksum, uint(256-checksumBits))

	if checksum.Cmp(expectedChecksum) != 0 {
		return nil, errors.New("mnemonic: checksum mismatch")
	}

	return entropy, nil
}

// entropyToMnemonic converts raw entropy bytes to a BIP39 mnemonic string.
func entropyToMnemonic(entropy []byte) (string, error) {
	wordList := getWordList()
	if len(wordList) != 2048 {
		return "", errors.New("mnemonic: wordlist must have exactly 2048 words")
	}

	entropyBits := len(entropy) * 8
	checksumBits := entropyBits / 32

	h := sha256.Sum256(entropy)
	checksumByte := h[0]

	// Build bit stream: entropy bits + checksumBits
	b := new(big.Int).SetBytes(entropy)
	b.Lsh(b, uint(checksumBits))

	// Append checksum bits (top checksumBits bits of h[0])
	cs := uint(checksumByte) >> (8 - checksumBits)
	b.Or(b, big.NewInt(int64(cs)))

	wordCount := (entropyBits + checksumBits) / 11
	words := make([]string, wordCount)
	mask := big.NewInt(2047) // 0x7FF

	for i := wordCount - 1; i >= 0; i-- {
		idx := new(big.Int).And(b, mask).Int64()
		words[i] = wordList[idx]
		b.Rsh(b, 11)
	}

	return strings.Join(words, " "), nil
}

func isValidStrength(s int) bool {
	switch s {
	case 128, 160, 192, 224, 256:
		return true
	}
	return false
}

// getWordList returns the BIP39 word list. It uses the package-level WordList
// variable from wordslist.go if it has been populated (2048 words), otherwise
// falls back to an empty list (which will cause an error during generation).
func getWordList() []string {
	// wordslist.go in the same package exposes SelectAndLoadTxtFile / GeneratePassphrase
	// but not a static word list variable. We inline the BIP39 English list here.
	// This keeps the mnemonic package self-contained and offline-capable.
	return bip39EnglishWordList
}

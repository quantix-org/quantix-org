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

// Package usi implements the Universal Sovereign Identity (USI) layer for Quantix.
//
// # USI .usimeta Format
//
// A .usimeta file is an off-chain signature verification artifact that can be
// embedded alongside any document or data to prove authorship without requiring
// a trusted third party.
//
// The format implements Kusuma's whitepaper §4.2 "Detached Signature Manifest":
//
//	.usimeta = {fingerprint, pubkey, file_hash, final_doc_hash, timestamp,
//	            nonce, commitment, merkle_root, signature, signed_at}
//
// Verification flow:
//  1. Compute SHA-256(data) → compare with file_hash
//  2. Deserialize public_key and verify SPHINCS+ signature over data
//  3. Recompute commitment and compare with meta.Commitment
//  4. Recompute Merkle root and compare with meta.MerkleRoot
//  5. Verify fingerprint == SHA-256(public_key)
//  6. Compute SHA-256(data || sig_bytes) → compare with final_doc_hash
package usi

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/holiman/uint256"
	"github.com/ramseyauron/quantix/src/core/hashtree"
	key "github.com/ramseyauron/quantix/src/core/sphincs/key/backend"
	sign "github.com/ramseyauron/quantix/src/core/sphincs/sign/backend"
)

const USIMetaVersion = "1.0"

// USIMeta is the off-chain signature verification file.
// Embeds with any document/data to prove authorship.
// Implements Kusuma whitepaper §4.2.
type USIMeta struct {
	Version      string `json:"version"`
	Fingerprint  string `json:"fingerprint"`    // SHA-256(pubkey) — signer's identity
	PublicKey    string `json:"public_key"`     // hex-encoded SPHINCS+ pubkey
	FileHash     string `json:"file_hash"`      // SHA-256 of the signed content
	FinalDocHash string `json:"final_doc_hash"` // SHA-256(content+signature)
	Timestamp    int64  `json:"timestamp"`
	Nonce        string `json:"nonce"`
	Commitment   string `json:"commitment"`  // SigCommitment output
	MerkleRoot   string `json:"merkle_root"` // from SignMessage
	Signature    string `json:"signature"`   // hex-encoded full SPHINCS+ sig bytes
	SignedAt     string `json:"signed_at"`   // ISO-8601 timestamp
}

// SignData signs arbitrary data (file content, message, etc.) using SPHINCS+
// and returns a USIMeta struct ready to be saved as a .usimeta file.
//
// Parameters:
//   - data:        raw bytes of the content to sign
//   - fingerprint: caller's identity (SHA-256 of pubkey, 64 hex chars)
//   - skBytes:     SPHINCS+ secret key bytes
//   - pkBytes:     SPHINCS+ public key bytes
//   - sm:          initialised SphincsManager (must have non-nil parameters)
//   - km:          KeyManager used for key deserialization
//
// Returns a USIMeta that the caller should persist alongside the signed data.
func SignData(data []byte, fingerprint string, skBytes, pkBytes []byte, sm *sign.SphincsManager, km *key.KeyManager) (*USIMeta, error) {
	if len(data) == 0 {
		return nil, errors.New("usi: cannot sign empty data")
	}
	if len(skBytes) == 0 || len(pkBytes) == 0 {
		return nil, errors.New("usi: secret key and public key must be non-empty")
	}

	// Deserialize keys
	sk, pk, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		return nil, fmt.Errorf("usi: key deserialization failed: %w", err)
	}

	// Sign using SPHINCS+ — returns sig, merkleRoot, timestamp, nonce, commitment
	sig, merkleRoot, tsBytes, nonceBytes, commitment, err := sm.SignMessage(data, sk, pk)
	if err != nil {
		return nil, fmt.Errorf("usi: sign failed: %w", err)
	}

	// Serialize signature to bytes
	sigBytes, err := sm.SerializeSignature(sig)
	if err != nil {
		return nil, fmt.Errorf("usi: signature serialization failed: %w", err)
	}

	// Compute file_hash = SHA-256(data)
	fileHashArr := sha256.Sum256(data)
	fileHash := hex.EncodeToString(fileHashArr[:])

	// Compute final_doc_hash = SHA-256(data || sigBytes)
	finalInput := append(append([]byte(nil), data...), sigBytes...)
	finalHashArr := sha256.Sum256(finalInput)
	finalDocHash := hex.EncodeToString(finalHashArr[:])

	// Decode timestamp bytes to int64
	var ts int64
	if len(tsBytes) == 8 {
		ts = int64(binary.BigEndian.Uint64(tsBytes))
	} else {
		ts = time.Now().Unix()
	}

	// Encode merkle root hash bytes
	var merkleHex string
	if merkleRoot != nil && merkleRoot.Hash != nil {
		merkleHex = hex.EncodeToString(merkleRoot.Hash.Bytes())
	}

	return &USIMeta{
		Version:      USIMetaVersion,
		Fingerprint:  fingerprint,
		PublicKey:    hex.EncodeToString(pkBytes),
		FileHash:     fileHash,
		FinalDocHash: finalDocHash,
		Timestamp:    ts,
		Nonce:        hex.EncodeToString(nonceBytes),
		Commitment:   hex.EncodeToString(commitment),
		MerkleRoot:   merkleHex,
		Signature:    hex.EncodeToString(sigBytes),
		SignedAt:     time.Unix(ts, 0).UTC().Format(time.RFC3339),
	}, nil
}

// VerifyUSIMeta verifies a USIMeta against original data.
//
// Verification steps (all must pass):
//  1. file_hash matches SHA-256(data)
//  2. fingerprint matches SHA-256(public_key)
//  3. SPHINCS+ signature verifies over data
//  4. commitment matches recomputed SigCommitment
//  5. final_doc_hash matches SHA-256(data || sigBytes)
//
// Returns (true, nil) on success, (false, err) with a descriptive error otherwise.
func VerifyUSIMeta(data []byte, meta *USIMeta, sm *sign.SphincsManager, km *key.KeyManager) (bool, error) {
	if meta == nil {
		return false, errors.New("usi: nil USIMeta")
	}

	// --- Step 1: verify file_hash ---
	fileHashArr := sha256.Sum256(data)
	expectedFileHash := hex.EncodeToString(fileHashArr[:])
	if meta.FileHash != expectedFileHash {
		return false, fmt.Errorf("usi: file_hash mismatch: got %s, want %s", meta.FileHash, expectedFileHash)
	}

	// --- Step 2: verify fingerprint = SHA-256(pubkey) ---
	pkBytes, err := hex.DecodeString(meta.PublicKey)
	if err != nil {
		return false, fmt.Errorf("usi: invalid public_key hex: %w", err)
	}
	fpArr := sha256.Sum256(pkBytes)
	expectedFP := hex.EncodeToString(fpArr[:])
	if meta.Fingerprint != expectedFP {
		return false, fmt.Errorf("usi: fingerprint mismatch: got %s, want %s", meta.Fingerprint, expectedFP)
	}

	// --- Step 3: SPHINCS+ verify ---
	sigBytes, err := hex.DecodeString(meta.Signature)
	if err != nil {
		return false, fmt.Errorf("usi: invalid signature hex: %w", err)
	}
	nonceBytes, err := hex.DecodeString(meta.Nonce)
	if err != nil {
		return false, fmt.Errorf("usi: invalid nonce hex: %w", err)
	}

	// Reconstruct timestamp bytes (8-byte big-endian)
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(meta.Timestamp))

	// Deserialize public key
	pk, err := km.DeserializePublicKey(pkBytes)
	if err != nil {
		return false, fmt.Errorf("usi: public key deserialization failed: %w", err)
	}

	// Deserialize signature
	sig, err := sm.DeserializeSignature(sigBytes)
	if err != nil {
		return false, fmt.Errorf("usi: signature deserialization failed: %w", err)
	}

	// VerifySignature checks Spx_verify, commitment, and Merkle root
	expectedCommitmentBytes, err := hex.DecodeString(meta.Commitment)
	if err != nil {
		return false, fmt.Errorf("usi: invalid commitment hex: %w", err)
	}
	expectedMerkleBytes, err := hex.DecodeString(meta.MerkleRoot)
	if err != nil {
		return false, fmt.Errorf("usi: invalid merkle_root hex: %w", err)
	}

	// Reconstruct the expected merkle root node from stored hash bytes.
	// HashTreeNode.Hash is a *uint256.Int (big-endian 32 bytes).
	expectedMerkleNode := &hashtree.HashTreeNode{
		Hash: new(uint256.Int).SetBytes(expectedMerkleBytes),
	}

	ok := sm.VerifySignature(data, tsBytes, nonceBytes, sig, pk, expectedMerkleNode, expectedCommitmentBytes)
	if !ok {
		return false, errors.New("usi: SPHINCS+ signature verification failed")
	}

	// --- Step 4 (commitment already checked inside VerifySignature) ---

	// --- Step 5: verify final_doc_hash ---
	finalInput := append(append([]byte(nil), data...), sigBytes...)
	finalHashArr := sha256.Sum256(finalInput)
	expectedFinalHash := hex.EncodeToString(finalHashArr[:])
	if meta.FinalDocHash != expectedFinalHash {
		return false, fmt.Errorf("usi: final_doc_hash mismatch: got %s, want %s", meta.FinalDocHash, expectedFinalHash)
	}

	return true, nil
}

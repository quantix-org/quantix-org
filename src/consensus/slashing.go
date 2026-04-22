// MIT License
// Copyright (c) 2024 quantix-org

package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// =====================================================
// Slashing Evidence Collection
// =====================================================

// SlashingType defines the type of slashable offense.
type SlashingType int

const (
	// SlashingDoubleSign indicates a validator signed two different blocks at the same height.
	SlashingDoubleSign SlashingType = iota

	// SlashingDoubleVote indicates a validator voted twice in the same round.
	SlashingDoubleVote

	// SlashingInvalidBlock indicates a validator proposed an invalid block.
	SlashingInvalidBlock

	// SlashingDowntime indicates a validator was offline for too long.
	SlashingDowntime

	// SlashingSurroundVote indicates a validator made a surrounding vote (Casper FFG violation).
	SlashingSurroundVote
)

// String returns a human-readable name for the slashing type.
func (st SlashingType) String() string {
	switch st {
	case SlashingDoubleSign:
		return "DOUBLE_SIGN"
	case SlashingDoubleVote:
		return "DOUBLE_VOTE"
	case SlashingInvalidBlock:
		return "INVALID_BLOCK"
	case SlashingDowntime:
		return "DOWNTIME"
	case SlashingSurroundVote:
		return "SURROUND_VOTE"
	default:
		return "UNKNOWN"
	}
}

// SlashingPenalty returns the penalty percentage for a slashing type.
func (st SlashingType) SlashingPenalty() float64 {
	switch st {
	case SlashingDoubleSign:
		return 0.05 // 5% of stake
	case SlashingDoubleVote:
		return 0.05 // 5% of stake
	case SlashingInvalidBlock:
		return 0.10 // 10% of stake
	case SlashingDowntime:
		return 0.01 // 1% of stake
	case SlashingSurroundVote:
		return 0.05 // 5% of stake
	default:
		return 0.01
	}
}

// SlashingEvidence represents evidence of a slashable offense.
type SlashingEvidence struct {
	// Type of slashing offense
	Type SlashingType

	// Validator that committed the offense
	ValidatorID   []byte
	ValidatorAddr string

	// Block height/slot where offense occurred
	Height uint64
	Slot   uint64

	// Evidence data (depends on type)
	// For double-sign: two conflicting signatures
	// For double-vote: two conflicting votes
	Evidence1 []byte
	Evidence2 []byte

	// Signatures on the evidence
	Signature1 []byte
	Signature2 []byte

	// Block hashes (for double-sign)
	BlockHash1 []byte
	BlockHash2 []byte

	// Timestamps
	Timestamp1 time.Time
	Timestamp2 time.Time

	// Reporter who submitted the evidence
	ReporterID   []byte
	ReporterAddr string

	// When evidence was collected
	CollectedAt time.Time

	// Evidence hash for deduplication
	Hash []byte

	// Processing status
	Processed  bool
	ProcessedAt time.Time
	TxHash     []byte // Transaction that processed the evidence
}

// ComputeHash computes a unique hash for this evidence.
func (e *SlashingEvidence) ComputeHash() []byte {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, e.Type)
	h.Write(e.ValidatorID)
	binary.Write(h, binary.BigEndian, e.Height)
	h.Write(e.Evidence1)
	h.Write(e.Evidence2)
	e.Hash = h.Sum(nil)
	return e.Hash
}

// Validate checks if the evidence is valid and complete.
func (e *SlashingEvidence) Validate() error {
	if len(e.ValidatorID) == 0 {
		return errors.New("missing validator ID")
	}

	if e.Height == 0 && e.Slot == 0 {
		return errors.New("missing height/slot")
	}

	switch e.Type {
	case SlashingDoubleSign, SlashingDoubleVote, SlashingSurroundVote:
		if len(e.Evidence1) == 0 || len(e.Evidence2) == 0 {
			return errors.New("missing conflicting evidence")
		}
		if bytes.Equal(e.Evidence1, e.Evidence2) {
			return errors.New("evidence must be different")
		}
		if len(e.Signature1) == 0 || len(e.Signature2) == 0 {
			return errors.New("missing signatures on evidence")
		}
	case SlashingDowntime:
		// Downtime evidence is different - just needs validator ID and duration
	case SlashingInvalidBlock:
		if len(e.Evidence1) == 0 {
			return errors.New("missing invalid block data")
		}
	}

	return nil
}

// =====================================================
// Slashing Evidence Collector
// =====================================================

// SlashingCollector collects and manages slashing evidence.
type SlashingCollector struct {
	mu sync.RWMutex

	// Evidence storage (hash -> evidence)
	evidence map[string]*SlashingEvidence

	// Evidence by validator (validator ID -> list of evidence hashes)
	byValidator map[string][]string

	// Pending evidence (not yet processed on-chain)
	pending []*SlashingEvidence

	// Processed evidence (for historical queries)
	processed []*SlashingEvidence

	// Vote tracking for double-vote detection
	// Key: validator_id + height + round
	votes map[string]*VoteRecord

	// Block tracking for double-sign detection
	// Key: validator_id + height
	blocks map[string]*BlockRecord

	// Configuration
	maxPendingEvidence int
	evidenceExpiry     time.Duration
}

// VoteRecord tracks a validator's vote for double-vote detection.
type VoteRecord struct {
	ValidatorID []byte
	Height      uint64
	Round       uint64
	VoteHash    []byte
	Signature   []byte
	Timestamp   time.Time
}

// BlockRecord tracks a validator's block proposal for double-sign detection.
type BlockRecord struct {
	ValidatorID []byte
	Height      uint64
	BlockHash   []byte
	Signature   []byte
	Timestamp   time.Time
}

// NewSlashingCollector creates a new slashing evidence collector.
func NewSlashingCollector() *SlashingCollector {
	return &SlashingCollector{
		evidence:           make(map[string]*SlashingEvidence),
		byValidator:        make(map[string][]string),
		pending:            make([]*SlashingEvidence, 0),
		processed:          make([]*SlashingEvidence, 0),
		votes:              make(map[string]*VoteRecord),
		blocks:             make(map[string]*BlockRecord),
		maxPendingEvidence: 1000,
		evidenceExpiry:     24 * time.Hour,
	}
}

// RecordVote records a validator's vote and checks for double-voting.
func (sc *SlashingCollector) RecordVote(validatorID []byte, height, round uint64, voteHash, signature []byte) *SlashingEvidence {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	key := makeVoteKey(validatorID, height, round)

	existing, found := sc.votes[key]
	if found {
		// Check if this is a different vote (double-vote)
		if !bytes.Equal(existing.VoteHash, voteHash) {
			evidence := &SlashingEvidence{
				Type:        SlashingDoubleVote,
				ValidatorID: validatorID,
				Height:      height,
				Slot:        round,
				Evidence1:   existing.VoteHash,
				Evidence2:   voteHash,
				Signature1:  existing.Signature,
				Signature2:  signature,
				Timestamp1:  existing.Timestamp,
				Timestamp2:  time.Now(),
				CollectedAt: time.Now(),
			}
			evidence.ComputeHash()

			sc.addEvidence(evidence)
			return evidence
		}
		return nil // Same vote, not a violation
	}

	// Record the vote
	sc.votes[key] = &VoteRecord{
		ValidatorID: validatorID,
		Height:      height,
		Round:       round,
		VoteHash:    voteHash,
		Signature:   signature,
		Timestamp:   time.Now(),
	}

	return nil
}

// RecordBlock records a validator's block proposal and checks for double-signing.
func (sc *SlashingCollector) RecordBlock(validatorID []byte, height uint64, blockHash, signature []byte) *SlashingEvidence {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	key := makeBlockKey(validatorID, height)

	existing, found := sc.blocks[key]
	if found {
		// Check if this is a different block (double-sign)
		if !bytes.Equal(existing.BlockHash, blockHash) {
			evidence := &SlashingEvidence{
				Type:        SlashingDoubleSign,
				ValidatorID: validatorID,
				Height:      height,
				BlockHash1:  existing.BlockHash,
				BlockHash2:  blockHash,
				Evidence1:   existing.BlockHash,
				Evidence2:   blockHash,
				Signature1:  existing.Signature,
				Signature2:  signature,
				Timestamp1:  existing.Timestamp,
				Timestamp2:  time.Now(),
				CollectedAt: time.Now(),
			}
			evidence.ComputeHash()

			sc.addEvidence(evidence)
			return evidence
		}
		return nil // Same block, not a violation
	}

	// Record the block
	sc.blocks[key] = &BlockRecord{
		ValidatorID: validatorID,
		Height:      height,
		BlockHash:   blockHash,
		Signature:   signature,
		Timestamp:   time.Now(),
	}

	return nil
}

// ReportDowntime reports a validator for being offline.
func (sc *SlashingCollector) ReportDowntime(validatorID []byte, missedSlots uint64, reporterID []byte) *SlashingEvidence {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Only slash for significant downtime (e.g., 1000+ missed slots)
	if missedSlots < 1000 {
		return nil
	}

	evidence := &SlashingEvidence{
		Type:        SlashingDowntime,
		ValidatorID: validatorID,
		Slot:        missedSlots,
		ReporterID:  reporterID,
		CollectedAt: time.Now(),
	}
	evidence.ComputeHash()

	sc.addEvidence(evidence)
	return evidence
}

// SubmitEvidence allows external submission of slashing evidence.
func (sc *SlashingCollector) SubmitEvidence(evidence *SlashingEvidence) error {
	if err := evidence.Validate(); err != nil {
		return err
	}

	evidence.ComputeHash()

	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Check for duplicate
	hashStr := string(evidence.Hash)
	if _, exists := sc.evidence[hashStr]; exists {
		return errors.New("evidence already submitted")
	}

	sc.addEvidence(evidence)
	return nil
}

// addEvidence adds evidence to internal storage (caller must hold lock).
func (sc *SlashingCollector) addEvidence(evidence *SlashingEvidence) {
	hashStr := string(evidence.Hash)
	validatorStr := string(evidence.ValidatorID)

	sc.evidence[hashStr] = evidence
	sc.byValidator[validatorStr] = append(sc.byValidator[validatorStr], hashStr)

	if len(sc.pending) < sc.maxPendingEvidence {
		sc.pending = append(sc.pending, evidence)
	}
}

// GetPendingEvidence returns all pending (unprocessed) evidence.
func (sc *SlashingCollector) GetPendingEvidence() []*SlashingEvidence {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	result := make([]*SlashingEvidence, len(sc.pending))
	copy(result, sc.pending)
	return result
}

// MarkProcessed marks evidence as processed on-chain.
func (sc *SlashingCollector) MarkProcessed(evidenceHash, txHash []byte) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	hashStr := string(evidenceHash)
	if evidence, exists := sc.evidence[hashStr]; exists {
		evidence.Processed = true
		evidence.ProcessedAt = time.Now()
		evidence.TxHash = txHash

		// Move from pending to processed
		for i, e := range sc.pending {
			if bytes.Equal(e.Hash, evidenceHash) {
				sc.pending = append(sc.pending[:i], sc.pending[i+1:]...)
				sc.processed = append(sc.processed, evidence)
				break
			}
		}
	}
}

// GetEvidenceByValidator returns all evidence for a validator.
func (sc *SlashingCollector) GetEvidenceByValidator(validatorID []byte) []*SlashingEvidence {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	validatorStr := string(validatorID)
	hashes := sc.byValidator[validatorStr]

	result := make([]*SlashingEvidence, 0, len(hashes))
	for _, hashStr := range hashes {
		if evidence, exists := sc.evidence[hashStr]; exists {
			result = append(result, evidence)
		}
	}

	return result
}

// Prune removes old evidence and vote/block records.
func (sc *SlashingCollector) Prune(currentHeight uint64) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Remove old votes (keep last 1000 heights)
	for key, vote := range sc.votes {
		if currentHeight > vote.Height+1000 {
			delete(sc.votes, key)
		}
	}

	// Remove old blocks (keep last 1000 heights)
	for key, block := range sc.blocks {
		if currentHeight > block.Height+1000 {
			delete(sc.blocks, key)
		}
	}

	// Remove expired evidence
	expiry := time.Now().Add(-sc.evidenceExpiry)
	for hashStr, evidence := range sc.evidence {
		if evidence.CollectedAt.Before(expiry) && evidence.Processed {
			delete(sc.evidence, hashStr)
		}
	}
}

// Stats returns statistics about collected evidence.
func (sc *SlashingCollector) Stats() map[string]int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	stats := map[string]int{
		"total_evidence":     len(sc.evidence),
		"pending_evidence":   len(sc.pending),
		"processed_evidence": len(sc.processed),
		"tracked_votes":      len(sc.votes),
		"tracked_blocks":     len(sc.blocks),
		"validators_with_evidence": len(sc.byValidator),
	}

	// Count by type
	for _, e := range sc.evidence {
		key := "type_" + e.Type.String()
		stats[key]++
	}

	return stats
}

// Helper functions

func makeVoteKey(validatorID []byte, height, round uint64) string {
	h := sha256.New()
	h.Write(validatorID)
	binary.Write(h, binary.BigEndian, height)
	binary.Write(h, binary.BigEndian, round)
	return string(h.Sum(nil)[:16])
}

func makeBlockKey(validatorID []byte, height uint64) string {
	h := sha256.New()
	h.Write(validatorID)
	binary.Write(h, binary.BigEndian, height)
	return string(h.Sum(nil)[:16])
}

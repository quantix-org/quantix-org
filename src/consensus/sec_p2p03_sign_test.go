// PEPPER — SEC-P2P03 signing service and attestation verification tests
// Tests for: HasPublicKey, RegisterPublicKey, GenerateMessageHash, VerifyBlockAttestations
package consensus

import (
	"bytes"
	"crypto"
	"testing"

	types "github.com/ramseyauron/quantix/src/core/transaction"
	"github.com/ramseyauron/quantix/src/crypto/SPHINCSPLUS-golang/sphincs"
)

// makeSigningServiceNoKeys creates a SigningService without generating SPHINCS+ keys,
// allowing fast unit tests for registry/metadata functions.
func makeSigningServiceNoKeys(nodeID string) *SigningService {
	return &SigningService{
		sphincsManager:    nil,
		keyManager:        nil,
		nodeID:            nodeID,
		privateKey:        nil,
		publicKey:         nil,
		publicKeyRegistry: make(map[string]*sphincs.SPHINCS_PK),
	}
}

// ── HasPublicKey ────────────────────────────────────────────────────────────

func TestHasPublicKey_NewService_False(t *testing.T) {
	svc := makeSigningServiceNoKeys("node-0")
	if svc.HasPublicKey("any-node") {
		t.Error("HasPublicKey should return false for fresh service")
	}
}

func TestHasPublicKey_AfterRegister_True(t *testing.T) {
	svc := makeSigningServiceNoKeys("node-0")
	fakePK := &sphincs.SPHINCS_PK{}
	svc.RegisterPublicKey("node-1", fakePK)
	if !svc.HasPublicKey("node-1") {
		t.Error("HasPublicKey should return true after RegisterPublicKey")
	}
}

func TestHasPublicKey_DifferentNode_False(t *testing.T) {
	svc := makeSigningServiceNoKeys("node-0")
	svc.RegisterPublicKey("node-1", &sphincs.SPHINCS_PK{})
	if svc.HasPublicKey("node-9999") {
		t.Error("HasPublicKey should return false for unregistered node")
	}
}

func TestHasPublicKey_MultipleNodes(t *testing.T) {
	svc := makeSigningServiceNoKeys("node-0")
	for i := 1; i <= 5; i++ {
		id := string(rune('0'+i)) // "1".."5"
		svc.RegisterPublicKey("node-"+id, &sphincs.SPHINCS_PK{})
	}
	for i := 1; i <= 5; i++ {
		id := string(rune('0' + i))
		if !svc.HasPublicKey("node-" + id) {
			t.Errorf("HasPublicKey(node-%s) should be true", id)
		}
	}
	// node-0 (self) also registered via self-key field, but we didn't set publicKey
	// so HasPublicKey("node-0") should return false (registry only)
	if svc.HasPublicKey("node-0") {
		t.Error("node-0 was not explicitly registered, should return false")
	}
}

// ── RegisterPublicKey (idempotent overwrite) ────────────────────────────────

func TestRegisterPublicKey_OverwriteAllowed(t *testing.T) {
	svc := makeSigningServiceNoKeys("node-0")
	pk1 := &sphincs.SPHINCS_PK{PKseed: []byte{0x01}}
	pk2 := &sphincs.SPHINCS_PK{PKseed: []byte{0x02}}

	svc.RegisterPublicKey("node-1", pk1)
	svc.RegisterPublicKey("node-1", pk2) // overwrite

	if !svc.HasPublicKey("node-1") {
		t.Error("node-1 should still be registered after overwrite")
	}
}

func TestRegisterPublicKey_NilPK_Registered(t *testing.T) {
	// Registering a nil PK should not panic; HasPublicKey returns true (key in map)
	svc := makeSigningServiceNoKeys("node-0")
	svc.RegisterPublicKey("node-nil", nil)
	if !svc.HasPublicKey("node-nil") {
		t.Error("HasPublicKey should return true even for nil PK (entry was inserted)")
	}
}

// ── GenerateMessageHash ─────────────────────────────────────────────────────

func TestGenerateMessageHash_NonEmpty(t *testing.T) {
	svc := makeSigningServiceNoKeys("node-0")
	h := svc.GenerateMessageHash("proposal", []byte("some data"))
	if len(h) == 0 {
		t.Error("GenerateMessageHash returned empty hash")
	}
}

func TestGenerateMessageHash_SHA256Length(t *testing.T) {
	svc := makeSigningServiceNoKeys("node-0")
	h := svc.GenerateMessageHash("vote", []byte("block-hash-abc"))
	if len(h) != crypto.SHA256.Size() {
		t.Errorf("expected %d bytes, got %d", crypto.SHA256.Size(), len(h))
	}
}

func TestGenerateMessageHash_Deterministic(t *testing.T) {
	svc := makeSigningServiceNoKeys("node-0")
	h1 := svc.GenerateMessageHash("type", []byte("data"))
	h2 := svc.GenerateMessageHash("type", []byte("data"))
	if !bytes.Equal(h1, h2) {
		t.Error("GenerateMessageHash should be deterministic")
	}
}

func TestGenerateMessageHash_TypeAffectsHash(t *testing.T) {
	svc := makeSigningServiceNoKeys("node-0")
	h1 := svc.GenerateMessageHash("proposal", []byte("data"))
	h2 := svc.GenerateMessageHash("vote", []byte("data"))
	if bytes.Equal(h1, h2) {
		t.Error("different message types should produce different hashes")
	}
}

func TestGenerateMessageHash_DataAffectsHash(t *testing.T) {
	svc := makeSigningServiceNoKeys("node-0")
	h1 := svc.GenerateMessageHash("type", []byte("data-A"))
	h2 := svc.GenerateMessageHash("type", []byte("data-B"))
	if bytes.Equal(h1, h2) {
		t.Error("different data should produce different hashes")
	}
}

// ── VerifyBlockAttestations (nil/no-key paths, no SPHINCS+ needed) ──────────

func TestVerifyBlockAttestations_NilBlock_NoError(t *testing.T) {
	// Consensus with nil signingService should skip verification
	c := &Consensus{}
	err := c.VerifyBlockAttestations(nil, false)
	if err != nil {
		t.Errorf("nil block should not produce error, got: %v", err)
	}
}

func TestVerifyBlockAttestations_NilSigningService_NoError(t *testing.T) {
	c := &Consensus{signingService: nil}
	block := &types.Block{}
	err := c.VerifyBlockAttestations(block, false)
	if err != nil {
		t.Errorf("nil signing service should not produce error, got: %v", err)
	}
}

func TestVerifyBlockAttestations_NoAttestations_NoError(t *testing.T) {
	c := &Consensus{signingService: makeSigningServiceNoKeys("node-0")}
	block := &types.Block{Body: types.BlockBody{Attestations: nil}}
	err := c.VerifyBlockAttestations(block, false)
	if err != nil {
		t.Errorf("block with no attestations should not produce error, got: %v", err)
	}
}

func TestVerifyBlockAttestations_EmptySig_NoPubKey_NoError(t *testing.T) {
	// Empty sig from unknown validator → warn, no error (bootstrap compat)
	c := &Consensus{signingService: makeSigningServiceNoKeys("node-0")}
	block := &types.Block{
		Body: types.BlockBody{
			Attestations: []*types.Attestation{
				{ValidatorID: "unknown-validator", Signature: nil, BlockHash: "abc"},
			},
		},
	}
	err := c.VerifyBlockAttestations(block, false)
	if err != nil {
		t.Errorf("empty sig from unknown validator should not error, got: %v", err)
	}
}

func TestVerifyBlockAttestations_EmptySig_KnownValidator_DevMode_NoError(t *testing.T) {
	// Empty sig from KNOWN validator in devMode → warn, no error
	svc := makeSigningServiceNoKeys("node-0")
	svc.RegisterPublicKey("known-val", &sphincs.SPHINCS_PK{})
	c := &Consensus{signingService: svc}
	block := &types.Block{
		Body: types.BlockBody{
			Attestations: []*types.Attestation{
				{ValidatorID: "known-val", Signature: nil, BlockHash: "abc"},
			},
		},
	}
	// devMode=true → no error even from known validator
	err := c.VerifyBlockAttestations(block, true)
	if err != nil {
		t.Errorf("dev-mode: empty sig from known validator should not error, got: %v", err)
	}
}

func TestVerifyBlockAttestations_EmptySig_KnownValidator_ProdMode_Error(t *testing.T) {
	// Empty sig from KNOWN validator in prod mode → hard error
	svc := makeSigningServiceNoKeys("node-0")
	svc.RegisterPublicKey("known-val", &sphincs.SPHINCS_PK{})
	c := &Consensus{signingService: svc}
	block := &types.Block{
		Body: types.BlockBody{
			Attestations: []*types.Attestation{
				{ValidatorID: "known-val", Signature: nil, BlockHash: "abc"},
			},
		},
	}
	// devMode=false → empty sig from known validator must error
	err := c.VerifyBlockAttestations(block, false)
	if err == nil {
		t.Error("prod-mode: empty sig from known validator should return error")
	}
}

func TestVerifyBlockAttestations_UnknownValidator_WithSig_NoError(t *testing.T) {
	// Sig present but no pubkey → warn and skip (bootstrap compat)
	svc := makeSigningServiceNoKeys("node-0")
	c := &Consensus{signingService: svc}
	block := &types.Block{
		Body: types.BlockBody{
			Attestations: []*types.Attestation{
				{ValidatorID: "bootstrap-node", Signature: []byte("some-sig"), BlockHash: "abc"},
			},
		},
	}
	err := c.VerifyBlockAttestations(block, false)
	if err != nil {
		t.Errorf("unknown validator with sig should skip (not error), got: %v", err)
	}
}

func TestVerifyBlockAttestations_NilAttestation_Skipped(t *testing.T) {
	// nil Attestation pointers in slice should be skipped without panic
	svc := makeSigningServiceNoKeys("node-0")
	c := &Consensus{signingService: svc}
	block := &types.Block{
		Body: types.BlockBody{
			Attestations: []*types.Attestation{nil, nil},
		},
	}
	err := c.VerifyBlockAttestations(block, false)
	if err != nil {
		t.Errorf("nil attestations should be skipped, got: %v", err)
	}
}

// ── VerifyAttestation — empty sig fast-path ─────────────────────────────────

func TestVerifyAttestation_EmptySignature_Error(t *testing.T) {
	svc := makeSigningServiceNoKeys("node-0")
	att := &types.Attestation{ValidatorID: "v1", Signature: nil, BlockHash: "abc"}
	ok, err := svc.VerifyAttestation(att)
	if ok || err == nil {
		t.Error("VerifyAttestation with empty signature should return false + error")
	}
}

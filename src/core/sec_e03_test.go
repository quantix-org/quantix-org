// MIT License
//
// Copyright (c) 2024 quantix

// P.E.P.P.E.R. SEC-E03 tests — execution-layer SPHINCS+ signature verification
// Tests the TxSigVerifier interface + StateDB pubkey registration.
package core

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	database "github.com/ramseyauron/quantix/src/core/state"
	types "github.com/ramseyauron/quantix/src/core/transaction"
)

// ---------------------------------------------------------------------------
// Mock TxSigVerifier
// ---------------------------------------------------------------------------

// mockSigVerifier is a controllable TxSigVerifier for testing SEC-E03.
type mockSigVerifier struct {
	// allowedPubKeys holds the set of pubkey bytes that are considered valid.
	allowedPubKeys map[string]struct{}
	calls          int
}

func newMockVerifier(allowedPubKeys ...[]byte) *mockSigVerifier {
	m := &mockSigVerifier{allowedPubKeys: make(map[string]struct{})}
	for _, pk := range allowedPubKeys {
		m.allowedPubKeys[string(pk)] = struct{}{}
	}
	return m
}

func (m *mockSigVerifier) VerifyTxSignature(message, sigTimestamp, sigNonce, sigBytes, senderPubKey []byte) bool {
	m.calls++
	if len(sigBytes) == 0 || len(senderPubKey) == 0 {
		return false
	}
	_, ok := m.allowedPubKeys[string(senderPubKey)]
	return ok
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const (
	secE03Alice = "xSecE03Alice0000000000000000000"
	secE03Bob   = "xSecE03Bob00000000000000000000"
)

var (
	alicePubKey = []byte("alice-pk-32bytes-xxxxxxxxxxxxxxx")
	fakePubKey  = []byte("fake-pk-32-bytes-xxxxxxxxxxxxxxxxx")
)

// makeTxWithSig builds a transaction with a non-empty signature and pubkey set.
func makeTxWithSig(sender, receiver string, amount int64, nonce uint64, pubKey []byte) *types.Transaction {
	tx := makeTx(sender, receiver, amount, nonce)
	tx.SenderPublicKey = pubKey
	h := sha256.Sum256(pubKey)
	tx.Signature = h[:]
	return tx
}

// newBlockchainWithVerifier creates a test blockchain with the mock verifier injected.
func newBlockchainWithVerifier(t *testing.T, verifier *mockSigVerifier, seeds map[string]*big.Int) (*Blockchain, *database.DB) {
	t.Helper()
	db := newTestDB(t)
	seedStateDB(t, db, seeds)
	bc := minimalBC(t, db)
	if verifier != nil {
		bc.SetSigVerifier(verifier)
	}
	bc.SetDevMode(true) // so balance checks on test addresses pass
	return bc, db
}

// makeBlockE03 wraps txs into a minimal block (height 5).
func makeBlockE03(txs []*types.Transaction) *types.Block {
	return makeBlock(5, txs)
}

// ---------------------------------------------------------------------------
// SEC-E03: Invalid signature rejected at execution layer
// ---------------------------------------------------------------------------

// TestSECE03_ValidSig_BlockAccepted verifies that when a valid sig verifier is
// injected, a block with correctly-signed transactions executes successfully.
func TestSECE03_ValidSig_BlockAccepted(t *testing.T) {
	verifier := newMockVerifier(alicePubKey)
	bc, _ := newBlockchainWithVerifier(t, verifier, map[string]*big.Int{
		secE03Alice: big.NewInt(1000),
	})

	tx := makeTxWithSig(secE03Alice, secE03Bob, 100, 0, alicePubKey)
	_, err := bc.ExecuteBlock(makeBlockE03([]*types.Transaction{tx}))
	if err != nil {
		t.Errorf("valid sig should be accepted: %v", err)
	}
	if verifier.calls == 0 {
		t.Error("expected verifier to be called")
	}
}

// TestSECE03_WrongPubKey_BlockRejected verifies that a tx whose SenderPublicKey
// is not recognised by the verifier causes the entire block to be rejected.
func TestSECE03_WrongPubKey_BlockRejected(t *testing.T) {
	verifier := newMockVerifier(alicePubKey) // only alice's real key is accepted
	bc, _ := newBlockchainWithVerifier(t, verifier, map[string]*big.Int{
		secE03Alice: big.NewInt(1000),
	})

	tx := makeTxWithSig(secE03Alice, secE03Bob, 100, 0, fakePubKey)
	_, err := bc.ExecuteBlock(makeBlockE03([]*types.Transaction{tx}))
	if err == nil {
		t.Error("block with wrong pubkey should be rejected at execution layer (SEC-E03)")
	}
}

// TestSECE03_NoPubKey_WithSig_Rejected verifies that a tx with a non-empty
// signature but no known public key (not in tx and not in StateDB) is rejected.
func TestSECE03_NoPubKey_WithSig_Rejected(t *testing.T) {
	verifier := newMockVerifier(alicePubKey)
	bc, _ := newBlockchainWithVerifier(t, verifier, map[string]*big.Int{
		secE03Alice: big.NewInt(1000),
	})

	tx := makeTx(secE03Alice, secE03Bob, 100, 0)
	// Sig present but SenderPublicKey omitted — and not registered in StateDB
	tx.Signature = []byte("some-sig-bytes")
	tx.SenderPublicKey = nil
	_, err := bc.ExecuteBlock(makeBlockE03([]*types.Transaction{tx}))
	if err == nil {
		t.Error("block with sig but no pubkey should be rejected (SEC-E03: pubkey not available)")
	}
}

// TestSECE03_NilVerifier_Skips verifies backward compatibility:
// when no verifier is injected, blocks are accepted without sig check.
func TestSECE03_NilVerifier_Skips(t *testing.T) {
	bc, _ := newBlockchainWithVerifier(t, nil, map[string]*big.Int{
		secE03Alice: big.NewInt(1000),
	})

	tx := makeTx(secE03Alice, secE03Bob, 100, 0)
	tx.Signature = []byte("unverified-random-bytes")
	_, err := bc.ExecuteBlock(makeBlockE03([]*types.Transaction{tx}))
	if err != nil {
		t.Errorf("without verifier, block should be accepted regardless of sig: %v", err)
	}
}

// TestSECE03_StateUnchanged_OnSigFailure verifies that a block rejected by the
// verifier leaves state completely unchanged (atomicity guarantee, whitepaper §5.2).
func TestSECE03_StateUnchanged_OnSigFailure(t *testing.T) {
	verifier := newMockVerifier(alicePubKey)
	bc, db := newBlockchainWithVerifier(t, verifier, map[string]*big.Int{
		secE03Alice: big.NewInt(1000),
	})

	stateDB := NewStateDB(db)
	aliceBefore := new(big.Int).Set(stateDB.GetBalance(secE03Alice))
	bobBefore := new(big.Int).Set(stateDB.GetBalance(secE03Bob))

	tx := makeTxWithSig(secE03Alice, secE03Bob, 100, 0, fakePubKey)
	_, _ = bc.ExecuteBlock(makeBlockE03([]*types.Transaction{tx})) // expected to fail

	stateDB2 := NewStateDB(db)
	aliceAfter := stateDB2.GetBalance(secE03Alice)
	bobAfter := stateDB2.GetBalance(secE03Bob)

	if aliceAfter.Cmp(aliceBefore) != 0 {
		t.Errorf("alice balance should be unchanged: before=%s after=%s", aliceBefore, aliceAfter)
	}
	if bobAfter.Cmp(bobBefore) != 0 {
		t.Errorf("bob balance should be unchanged: before=%s after=%s", bobBefore, bobAfter)
	}
}

// ---------------------------------------------------------------------------
// StateDB: RegisterPublicKey / GetPublicKey (first-write-wins)
// ---------------------------------------------------------------------------

// TestStateDB_RegisterPublicKey_StoresKey verifies basic set/get roundtrip.
func TestStateDB_RegisterPublicKey_StoresKey(t *testing.T) {
	db := newTestDB(t)
	stateDB := NewStateDB(db)

	addr := "xTestAddrPK0000000000000000000"
	pk := []byte("test-pubkey-32bytes-xxxxxxxxxxxx")

	stateDB.RegisterPublicKey(addr, pk)

	got := stateDB.GetPublicKey(addr)
	if string(got) != string(pk) {
		t.Errorf("GetPublicKey: got %x want %x", got, pk)
	}
}

// TestStateDB_RegisterPublicKey_FirstWriteWins verifies that a second
// RegisterPublicKey call does NOT overwrite the first value.
func TestStateDB_RegisterPublicKey_FirstWriteWins(t *testing.T) {
	db := newTestDB(t)
	stateDB := NewStateDB(db)

	addr := "xTestAddrPK0000000000000000000"
	pk1 := []byte("original-pk-32bytes-xxxxxxxxxx")
	pk2 := []byte("replacement-pk-32bytes-xxxxxxxx")

	stateDB.RegisterPublicKey(addr, pk1)
	stateDB.RegisterPublicKey(addr, pk2) // should be ignored

	got := stateDB.GetPublicKey(addr)
	if string(got) != string(pk1) {
		t.Errorf("first-write-wins violated: got %x want %x", got, pk1)
	}
}

// TestStateDB_GetPublicKey_UnknownAddress verifies nil returned for new address.
func TestStateDB_GetPublicKey_UnknownAddress(t *testing.T) {
	db := newTestDB(t)
	stateDB := NewStateDB(db)

	got := stateDB.GetPublicKey("xUnknownAddrPK000000000000000")
	if got != nil {
		t.Errorf("unknown address should return nil, got %x", got)
	}
}

// TestStateDB_RegisterPublicKey_MultipleAddresses verifies independent per-address storage.
func TestStateDB_RegisterPublicKey_MultipleAddresses(t *testing.T) {
	db := newTestDB(t)
	stateDB := NewStateDB(db)

	addrs := make([]string, 5)
	keys := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		addrs[i] = fmt.Sprintf("xAddrPK%02d000000000000000000000", i)
		keys[i] = []byte(fmt.Sprintf("pk-for-addr-%02d-padding-xxxxxxxxxx", i))
		stateDB.RegisterPublicKey(addrs[i], keys[i])
	}

	for i := 0; i < 5; i++ {
		got := stateDB.GetPublicKey(addrs[i])
		if string(got) != string(keys[i]) {
			t.Errorf("addr[%d]: got %x want %x", i, got, keys[i])
		}
	}
}

// TestStateDB_RegisterPublicKey_NilKeyIgnored verifies that nil pubkey is safely ignored.
func TestStateDB_RegisterPublicKey_NilKeyIgnored(t *testing.T) {
	db := newTestDB(t)
	stateDB := NewStateDB(db)

	addr := "xTestAddrPKNil0000000000000000"
	stateDB.RegisterPublicKey(addr, nil) // should be a no-op

	got := stateDB.GetPublicKey(addr)
	if got != nil {
		t.Errorf("after nil registration, GetPublicKey should return nil, got %x", got)
	}
}

// ---------------------------------------------------------------------------
// Whitepaper SEC-E03: Promoted structural test to live runtime test
// ---------------------------------------------------------------------------

// TestCryptographicSovereignty_SEC_E03_RealRejection is the promoted version
// of the previously structural-only Q7 test. Now that sigVerifier is fully
// wired (commit d58cd21), this confirms real runtime rejection behaviour.
func TestCryptographicSovereignty_SEC_E03_RealRejection(t *testing.T) {
	verifier := newMockVerifier(alicePubKey)
	bc, db := newBlockchainWithVerifier(t, verifier, map[string]*big.Int{
		secE03Alice: big.NewInt(500),
	})

	// --- Case 1: valid sig → block executes ---
	validTx := makeTxWithSig(secE03Alice, secE03Bob, 50, 0, alicePubKey)
	_, err := bc.ExecuteBlock(makeBlockE03([]*types.Transaction{validTx}))
	if err != nil {
		t.Fatalf("valid sig should be accepted: %v", err)
	}

	aliceAfterValid := NewStateDB(db).GetBalance(secE03Alice)

	// --- Case 2: forged pubkey → block rejected, state unchanged ---
	forgedTx := makeTxWithSig(secE03Alice, secE03Bob, 100, 1, fakePubKey)
	_, err = bc.ExecuteBlock(makeBlockE03([]*types.Transaction{forgedTx}))
	if err == nil {
		t.Error("forged pubkey should be rejected at execution layer (SEC-E03)")
	}

	aliceAfterForged := NewStateDB(db).GetBalance(secE03Alice)
	if aliceAfterForged.Cmp(aliceAfterValid) != 0 {
		t.Errorf("rejected block must not change state: before=%s after=%s",
			aliceAfterValid, aliceAfterForged)
	}

	// Verify alice was actually debited for the valid case
	expected := new(big.Int).Sub(big.NewInt(500), big.NewInt(50))
	if aliceAfterValid.Cmp(expected) != 0 {
		t.Errorf("alice balance after valid tx: want %s got %s", expected, aliceAfterValid)
	}

	if verifier.calls < 1 {
		t.Error("verifier should have been called at least once")
	}
}

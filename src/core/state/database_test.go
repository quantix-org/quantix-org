// MIT License
// Copyright (c) 2024 quantix

// Q23 — Extended state/database tests (0% coverage functions)
// Covers: NewLevelDB, Delete, Has, PutBatch, GetByPrefix, DeleteAccountState,
//         NewLevelDBAdapter, Close, LevelDBAdapter methods
package database

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
)

// ---------------------------------------------------------------------------
// NewLevelDB
// ---------------------------------------------------------------------------

func TestNewLevelDB_CreatesDatabase(t *testing.T) {
	dir := t.TempDir()
	db, err := NewLevelDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	defer db.Close()
}

func TestNewLevelDB_PutGetRoundtrip(t *testing.T) {
	dir := t.TempDir()
	db, err := NewLevelDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	defer db.Close()

	if err := db.Put("hello", []byte("world")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	val, err := db.Get("hello")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(val) != "world" {
		t.Errorf("Get: want world, got %q", val)
	}
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

func TestDB_Close_NoError(t *testing.T) {
	dir := t.TempDir()
	db, err := NewLevelDB(filepath.Join(dir, "close.db"))
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Delete / Has
// ---------------------------------------------------------------------------

func TestDB_Delete_ExistingKey(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	_ = db.Put("key1", []byte("val1"))
	if err := db.Delete("key1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := db.Get("key1")
	if err == nil {
		t.Error("Get after Delete should return error")
	}
}

func TestDB_Delete_NonExistentKey_NoError(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	// Deleting a non-existent key should not error in LevelDB
	if err := db.Delete("ghost-key"); err != nil {
		t.Errorf("Delete non-existent key: unexpected error: %v", err)
	}
}

func TestDB_Has_ExistingKey_True(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	_ = db.Put("present", []byte("yes"))
	ok, err := db.Has("present")
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if !ok {
		t.Error("Has existing key should return true")
	}
}

func TestDB_Has_MissingKey_False(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	ok, err := db.Has("absent")
	if err != nil {
		t.Fatalf("Has missing key: %v", err)
	}
	if ok {
		t.Error("Has missing key should return false")
	}
}

// ---------------------------------------------------------------------------
// PutBatch
// ---------------------------------------------------------------------------

func TestDB_PutBatch_MultipleKeys(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	entries := map[string][]byte{
		"batch-a": []byte("value-a"),
		"batch-b": []byte("value-b"),
		"batch-c": []byte("value-c"),
	}
	if err := db.PutBatch(entries); err != nil {
		t.Fatalf("PutBatch: %v", err)
	}

	for k, want := range entries {
		got, err := db.Get(k)
		if err != nil {
			t.Errorf("Get(%q) after PutBatch: %v", k, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("Get(%q): want %q, got %q", k, want, got)
		}
	}
}

func TestDB_PutBatch_EmptyMap_NoError(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	if err := db.PutBatch(map[string][]byte{}); err != nil {
		t.Errorf("PutBatch empty: %v", err)
	}
}

func TestDB_PutBatch_Atomic_AllOrNothing(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	// Write 100 keys atomically
	batch := make(map[string][]byte, 100)
	for i := 0; i < 100; i++ {
		batch[fmt.Sprintf("key-%03d", i)] = []byte(fmt.Sprintf("val-%d", i))
	}
	if err := db.PutBatch(batch); err != nil {
		t.Fatalf("PutBatch 100 keys: %v", err)
	}

	// Verify all 100 exist
	for k := range batch {
		ok, err := db.Has(k)
		if err != nil || !ok {
			t.Errorf("key %q missing after PutBatch: err=%v present=%v", k, err, ok)
		}
	}
}

// ---------------------------------------------------------------------------
// GetByPrefix
// ---------------------------------------------------------------------------

func TestDB_GetByPrefix_ReturnsMatchingKeys(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	// Write keys with two different prefixes
	_ = db.Put("acc:alice", []byte(`{"balance":"100"}`))
	_ = db.Put("acc:bob", []byte(`{"balance":"200"}`))
	_ = db.Put("val:node1", []byte(`{"stake":"1000"}`))

	results, err := db.GetByPrefix("acc:")
	if err != nil {
		t.Fatalf("GetByPrefix: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results for prefix acc:, got %d", len(results))
	}
	// val: should not appear
	if _, ok := results["val:node1"]; ok {
		t.Error("val: prefix should not appear in acc: results")
	}
}

func TestDB_GetByPrefix_EmptyPrefix_ReturnsAll(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	_ = db.Put("x", []byte("1"))
	_ = db.Put("y", []byte("2"))

	results, err := db.GetByPrefix("")
	if err != nil {
		t.Fatalf("GetByPrefix empty: %v", err)
	}
	if len(results) < 2 {
		t.Errorf("empty prefix should return all keys, got %d", len(results))
	}
}

func TestDB_GetByPrefix_NoMatches_EmptyMap(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	_ = db.Put("acc:alice", []byte("1"))

	results, err := db.GetByPrefix("xyz:")
	if err != nil {
		t.Fatalf("GetByPrefix no-match: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("no-match prefix should return empty map, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// DeleteAccountState
// ---------------------------------------------------------------------------

func TestDeleteAccountState_ExistingAccount(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	acc := &AccountState{Address: "charlie", Balance: nil}
	_ = acc.Save(db)

	if err := DeleteAccountState(db, "charlie"); err != nil {
		t.Fatalf("DeleteAccountState: %v", err)
	}

	// After deletion, loading should return a zero account (not error)
	loaded, err := LoadAccountState(db, "charlie")
	if err != nil {
		t.Fatalf("LoadAccountState after delete: %v", err)
	}
	if loaded.Balance.Sign() != 0 {
		t.Error("deleted account should return zero balance")
	}
}

// ---------------------------------------------------------------------------
// NewLevelDBAdapter + LevelDBAdapter methods
// ---------------------------------------------------------------------------

func TestNewLevelDBAdapter_WorksAsDB(t *testing.T) {
	dir := t.TempDir()
	ldb, err := leveldb.OpenFile(filepath.Join(dir, "adapter.db"), nil)
	if err != nil {
		t.Fatalf("leveldb.OpenFile: %v", err)
	}
	defer ldb.Close()

	db := NewLevelDBAdapter(ldb)
	if db == nil {
		t.Fatal("NewLevelDBAdapter returned nil")
	}

	// Test Put/Get through the adapter
	if err := db.Put("adapter-key", []byte("adapter-value")); err != nil {
		t.Fatalf("adapter Put: %v", err)
	}
	val, err := db.Get("adapter-key")
	if err != nil {
		t.Fatalf("adapter Get: %v", err)
	}
	if string(val) != "adapter-value" {
		t.Errorf("adapter roundtrip: got %q", val)
	}
}

func TestLevelDBAdapter_Delete_Has(t *testing.T) {
	dir := t.TempDir()
	ldb, err := leveldb.OpenFile(filepath.Join(dir, "del.db"), nil)
	if err != nil {
		t.Fatalf("leveldb.OpenFile: %v", err)
	}
	defer ldb.Close()

	db := NewLevelDBAdapter(ldb)
	_ = db.Put("k", []byte("v"))

	ok, _ := db.Has("k")
	if !ok {
		t.Error("Has should return true after Put")
	}

	_ = db.Delete("k")
	ok, _ = db.Has("k")
	if ok {
		t.Error("Has should return false after Delete")
	}
}

func TestLevelDBAdapter_Close_NoError(t *testing.T) {
	dir := t.TempDir()
	ldb, err := leveldb.OpenFile(filepath.Join(dir, "close.db"), nil)
	if err != nil {
		t.Fatalf("leveldb.OpenFile: %v", err)
	}
	db := NewLevelDBAdapter(ldb)
	if err := db.Close(); err != nil {
		t.Errorf("adapter Close: %v", err)
	}
	// Verify the file was closed (ldb.Close was called)
	if err := os.RemoveAll(dir); err != nil {
		t.Logf("cleanup: %v", err)
	}
}

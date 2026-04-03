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

// go/src/core/state/database.go
package database

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	logger "github.com/ramseyauron/quantix/src/log"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// NewLevelDB initializes a new LevelDB instance at the specified path with retry logic.
// Parameters:
//   - path: File system path where the LevelDB database will be stored
//
// Returns: Database instance and error if initialization fails
func NewLevelDB(path string) (*DB, error) {
	// Define retry constants for database initialization
	const maxRetries = 3               // Maximum number of initialization attempts
	const retryDelay = 1 * time.Second // Delay between retry attempts

	// Create parent directory if it doesn't exist
	// Ensure the directory structure exists before creating the database
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		logger.Error("Failed to create parent directory for LevelDB at %s: %v", path, err)
		return nil, fmt.Errorf("failed to create parent directory for LevelDB at %s: %w", path, err)
	}

	// Attempt to open the database with retry logic
	// Multiple attempts to handle temporary issues like stale locks
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Remove stale lock file before attempting to open
		// This helps recover from previous unclean shutdowns
		if err := removeLockFile(path); err != nil {
			logger.Warn("Failed to remove lock file for LevelDB at %s on attempt %d: %v", path, attempt, err)
		}

		// Attempt to open the LevelDB database
		// ErrorIfExist: false allows opening existing database
		db, err := leveldb.OpenFile(path, &opt.Options{ErrorIfExist: false})
		if err == nil {
			// Successfully opened database
			logger.Info("Successfully opened LevelDB at %s on attempt %d", path, attempt)
			return &DB{
				db:    db,             // Underlying LevelDB instance
				mutex: sync.RWMutex{}, // Read-write mutex for thread safety
			}, nil
		}

		// Log failure for this attempt
		logger.Error("Failed to open LevelDB at %s on attempt %d: %v", path, attempt, err)
		if attempt < maxRetries {
			// Wait before retrying if not the last attempt
			logger.Info("Retrying LevelDB initialization at %s in %v", path, retryDelay)
			time.Sleep(retryDelay)
		}
	}

	// All open attempts failed, attempt recovery
	logger.Warn("All attempts to open LevelDB at %s failed, attempting recovery", path)
	// Try to recover the database from potential corruption
	db, err := leveldb.RecoverFile(path, nil)
	if err != nil {
		// Recovery failed, return error
		logger.Error("Failed to recover LevelDB at %s: %v", path, err)
		return nil, fmt.Errorf("failed to recover LevelDB at %s: %w", path, err)
	}

	// Successfully recovered the database
	logger.Info("Successfully recovered LevelDB at %s", path)
	return &DB{
		db:    db,             // Recovered database instance
		mutex: sync.RWMutex{}, // Read-write mutex for thread safety
	}, nil
}

// removeLockFile removes the LevelDB LOCK file if it exists.
// Parameters:
//   - path: Database directory path
//
// Returns: Error if removal fails (except when file doesn't exist)
func removeLockFile(path string) error {
	// Construct path to the lock file
	lockFile := filepath.Join(path, "LOCK")

	// Check if lock file exists
	if _, err := os.Stat(lockFile); os.IsNotExist(err) {
		// Lock file doesn't exist, nothing to remove
		return nil
	}

	// Attempt to remove the lock file
	if err := os.Remove(lockFile); err != nil {
		// Failed to remove lock file
		return fmt.Errorf("failed to remove lock file at %s: %w", lockFile, err)
	}

	// Successfully removed stale lock file
	logger.Info("Removed stale lock file at %s", lockFile)
	return nil
}

// Close closes the LevelDB instance.
// Returns: Error if closing fails
func (d *DB) Close() error {
	// Acquire write lock to prevent concurrent operations
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Check if database is already closed
	if d.db == nil {
		return nil // Already closed, no error
	}

	// Attempt to close the underlying LevelDB
	if err := d.db.Close(); err != nil {
		logger.Error("Failed to close LevelDB: %v", err)
		return fmt.Errorf("failed to close LevelDB: %w", err)
	}

	// Mark database as closed by setting to nil
	d.db = nil
	logger.Info("Successfully closed LevelDB")
	return nil
}

// Put stores a key-value pair in the database.
// Parameters:
//   - key: String key to store
//   - value: Byte slice value to store
//
// Returns: Error if storage fails
func (d *DB) Put(key string, value []byte) error {
	// Acquire write lock for thread-safe write operation
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Check if database is open
	if d.db == nil {
		return fmt.Errorf("LevelDB is closed")
	}

	// Store key-value pair in LevelDB
	// []byte(key) converts string key to byte slice
	if err := d.db.Put([]byte(key), value, nil); err != nil {
		// Log and return error on failure
		logger.Error("Failed to put key %s in LevelDB: %s", key, err.Error())
		return fmt.Errorf("failed to put key %s in LevelDB: %w", key, err)
	}

	// Log successful storage
	logger.Info("Successfully stored key %s in LevelDB", key)
	return nil
}

// Get retrieves a value by key from the database.
// Parameters:
//   - key: String key to retrieve
//
// Returns: Value as byte slice and error if retrieval fails
func (d *DB) Get(key string) ([]byte, error) {
	// Acquire read lock for concurrent read access
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// Check if database is open
	if d.db == nil {
		return nil, fmt.Errorf("LevelDB is closed")
	}

	// Attempt to retrieve value for key
	data, err := d.db.Get([]byte(key), nil)
	if err != nil {
		// Handle specific error cases
		if err == errors.ErrNotFound {
			// Key doesn't exist in database
			logger.Warn("Key %s not found in LevelDB", key)
			return nil, fmt.Errorf("key %s not found in LevelDB", key)
		}
		// Other error occurred
		logger.Error("Failed to get key %s from LevelDB: %s", key, err.Error())
		return nil, fmt.Errorf("failed to get key %s from LevelDB: %w", key, err)
	}

	// Successfully retrieved value
	logger.Info("Successfully retrieved key %s from LevelDB", key)
	return data, nil
}

// Delete removes a key-value pair from the database.
// Parameters:
//   - key: String key to delete
//
// Returns: Error if deletion fails
func (d *DB) Delete(key string) error {
	// Acquire write lock for thread-safe delete operation
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Check if database is open
	if d.db == nil {
		return fmt.Errorf("LevelDB is closed")
	}

	// Attempt to delete key from database
	if err := d.db.Delete([]byte(key), nil); err != nil {
		// Log and return error on failure
		logger.Error("Failed to delete key %s from LevelDB: %s", key, err.Error())
		return fmt.Errorf("failed to delete key %s from LevelDB: %w", key, err)
	}

	// Log successful deletion
	logger.Info("Successfully deleted key %s from LevelDB", key)
	return nil
}

// Has checks if a key exists in the database.
// Parameters:
//   - key: String key to check
//
// Returns: Boolean indicating existence and error if check fails
func (d *DB) Has(key string) (bool, error) {
	// Acquire read lock for concurrent read access
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// Check if database is open
	if d.db == nil {
		return false, fmt.Errorf("LevelDB is closed")
	}

	// Attempt to get key to check existence
	_, err := d.db.Get([]byte(key), nil)
	if err != nil {
		// Handle specific error cases
		if err == errors.ErrNotFound {
			// Key doesn't exist, return false (not an error)
			return false, nil
		}
		// Other error occurred during check
		logger.Error("Failed to check key %s in LevelDB: %s", key, err.Error())
		return false, fmt.Errorf("failed to check key %s in LevelDB: %w", key, err)
	}

	// Key exists in database
	return true, nil
}

// WrapLevelDB creates a *DB wrapper around an already-open *leveldb.DB instance.
// Use this instead of NewLevelDB when the underlying LevelDB file is already open
// (e.g. shared with SphincsManager) to avoid the "already locked" error.
func WrapLevelDB(ldb *leveldb.DB) *DB {
	return &DB{
		db:    ldb,
		mutex: sync.RWMutex{},
	}
}

// PutBatch writes multiple key-value pairs atomically using a leveldb.Batch.
// If the process crashes mid-write, either all entries land or none do —
// eliminating the partial-state risk of calling Put() in a loop (SEC-E02).
//
// The underlying db must be a *leveldb.DB; if a non-batch adapter is in use
// this falls back gracefully to sequential Put calls with a warning.
func (d *DB) PutBatch(entries map[string][]byte) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.db == nil {
		return fmt.Errorf("LevelDB is closed")
	}

	// Assert that the concrete implementation supports Batch writes.
	ldb, ok := d.db.(*leveldb.DB)
	if !ok {
		// Non-LevelDB adapter (e.g. in tests): fall back to sequential writes.
		logger.Warn("PutBatch: underlying DB does not support leveldb.Batch, falling back to sequential writes")
		for k, v := range entries {
			if err := d.db.Put([]byte(k), v, nil); err != nil {
				return fmt.Errorf("PutBatch(fallback): put %s: %w", k, err)
			}
		}
		return nil
	}

	batch := new(leveldb.Batch)
	for k, v := range entries {
		batch.Put([]byte(k), v)
	}

	if err := ldb.Write(batch, nil); err != nil {
		logger.Error("PutBatch: atomic write failed: %v", err)
		return fmt.Errorf("PutBatch: atomic write failed: %w", err)
	}

	logger.Info("PutBatch: wrote %d entries atomically", len(entries))
	return nil
}

// GetByPrefix returns all key-value pairs whose key starts with the given prefix.
// Used for prefix scans (e.g. iterating all "val:" validator records).
func (d *DB) GetByPrefix(prefix string) (map[string][]byte, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if d.db == nil {
		return nil, fmt.Errorf("LevelDB is closed")
	}

	ldb, ok := d.db.(*leveldb.DB)
	if !ok {
		return nil, fmt.Errorf("GetByPrefix: underlying DB does not support iteration")
	}

	results := make(map[string][]byte)
	iter := ldb.NewIterator(nil, nil)
	defer iter.Release()

	prefixBytes := []byte(prefix)
	for iter.Seek(prefixBytes); iter.Valid(); iter.Next() {
		k := iter.Key()
		if len(k) < len(prefixBytes) {
			break
		}
		// Check prefix match byte-by-byte
		match := true
		for i, b := range prefixBytes {
			if k[i] != b {
				match = false
				break
			}
		}
		if !match {
			break
		}
		val := make([]byte, len(iter.Value()))
		copy(val, iter.Value())
		results[string(k)] = val
	}
	return results, iter.Error()
}

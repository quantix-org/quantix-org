// MIT License
// Copyright (c) 2024 quantix
//
// P3-D1: Load Test Benchmarks — F.R.I.D.A.Y. DevOps
// Run: go test -bench=. ./src/bench/ -benchtime=10s
package bench

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	types "github.com/quantix-org/quantix-org/src/core/transaction"
	"github.com/quantix-org/quantix-org/src/pool"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func makeBenchTx(id int) *types.Transaction {
	return &types.Transaction{
		ID:        fmt.Sprintf("bench-tx-%d", id),
		Sender:    "0xbench0000000000000000000000000000000001",
		Receiver:  "0xbench0000000000000000000000000000000002",
		Amount:    big.NewInt(1),
		GasPrice:  big.NewInt(1),
		GasLimit:  big.NewInt(21000),
		Nonce:     uint64(id),
		Timestamp: time.Now().UnixNano(),
		Signature: []byte("benchsig"),
	}
}

// ── BenchmarkAddTransaction ───────────────────────────────────────────────────
// Measures how many transactions per second the mempool can accept via
// BroadcastTransaction(). This is the primary throughput ceiling.
func BenchmarkAddTransaction(b *testing.B) {
	mp := pool.NewMempool(&pool.MempoolConfig{
		MaxSize:           200000,
		MaxBytes:          500 * 1024 * 1024,
		MaxTxSize:         100 * 1024,
		ValidationTimeout: 30 * time.Second,
		ExpiryTime:        24 * time.Hour,
		MaxBroadcastSize:  200000,
		MaxPendingSize:    200000,
	})
	defer mp.Stop()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tx := makeBenchTx(i)
		_ = mp.BroadcastTransaction(tx)
	}

	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "tx/s")
}

// BenchmarkAddTransactionParallel benchmarks concurrent adds — stress tests locking.
func BenchmarkAddTransactionParallel(b *testing.B) {
	mp := pool.NewMempool(&pool.MempoolConfig{
		MaxSize:           500000,
		MaxBytes:          1024 * 1024 * 1024,
		MaxTxSize:         100 * 1024,
		ValidationTimeout: 30 * time.Second,
		ExpiryTime:        24 * time.Hour,
		MaxBroadcastSize:  500000,
		MaxPendingSize:    500000,
	})
	defer mp.Stop()

	counter := 0
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		localID := 0
		for pb.Next() {
			localID++
			tx := makeBenchTx(counter + localID)
			_ = mp.BroadcastTransaction(tx)
		}
		counter += localID
	})

	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "tx/s")
}

// ── BenchmarkMempoolSelectForBlock ───────────────────────────────────────────
// Measures SelectTransactionsForBlock() — how fast the mempool can fill a block.
func BenchmarkMempoolSelectForBlock(b *testing.B) {
	mp := pool.NewMempool(nil)
	defer mp.Stop()

	// Pre-fill mempool with 5000 transactions
	for i := 0; i < 5000; i++ {
		tx := makeBenchTx(i)
		_ = mp.BroadcastTransaction(tx)
	}
	// Give background workers a moment to move to pending
	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		txs, _ := mp.SelectTransactionsForBlock(1*1024*1024, 512*1024)
		_ = txs
	}

	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "selects/s")
}

// ── BenchmarkMempoolGetStats ──────────────────────────────────────────────────
// How fast can we read stats (used by Prometheus scraper).
func BenchmarkMempoolGetStats(b *testing.B) {
	mp := pool.NewMempool(nil)
	defer mp.Stop()

	for i := 0; i < 1000; i++ {
		_ = mp.BroadcastTransaction(makeBenchTx(i))
	}
	time.Sleep(50 * time.Millisecond)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = mp.GetStats()
	}
}

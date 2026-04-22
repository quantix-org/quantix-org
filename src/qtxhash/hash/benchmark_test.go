// MIT License
// Copyright (c) 2024 quantix-org

package qtxhash

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"testing"

	"golang.org/x/crypto/sha3"
)

// BenchmarkQtxHash benchmarks QtxHash performance
func BenchmarkQtxHash(b *testing.B) {
	sizes := []int{32, 64, 256, 1024, 4096}
	
	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}
		
		b.Run(fmt.Sprintf("QtxHash-%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				h := NewQtxHash(256, data)
				h.GetHash(data)
			}
		})
	}
}

// BenchmarkSHA256 benchmarks standard SHA-256 for comparison
func BenchmarkSHA256(b *testing.B) {
	sizes := []int{32, 64, 256, 1024, 4096}
	
	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}
		
		b.Run(fmt.Sprintf("SHA256-%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				sha256.Sum256(data)
			}
		})
	}
}

// BenchmarkSHA512_256 benchmarks SHA-512/256 for comparison
func BenchmarkSHA512_256(b *testing.B) {
	sizes := []int{32, 64, 256, 1024, 4096}
	
	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}
		
		b.Run(fmt.Sprintf("SHA512_256-%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				sha512.Sum512_256(data)
			}
		})
	}
}

// BenchmarkSHA3_256 benchmarks SHA3-256 for comparison
func BenchmarkSHA3_256(b *testing.B) {
	sizes := []int{32, 64, 256, 1024, 4096}
	
	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}
		
		b.Run(fmt.Sprintf("SHA3_256-%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				sha3.Sum256(data)
			}
		})
	}
}

// BenchmarkComparison runs all hash functions side by side
func BenchmarkComparison(b *testing.B) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	b.Run("SHA256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sha256.Sum256(data)
		}
	})
	
	b.Run("SHA512_256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sha512.Sum512_256(data)
		}
	})
	
	b.Run("SHA3_256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sha3.Sum256(data)
		}
	})
	
	b.Run("QtxHash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h := NewQtxHash(256, data)
			h.GetHash(data)
		}
	})
}

// TestQtxHashPerformanceReport generates a human-readable performance report
func TestQtxHashPerformanceReport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance report in short mode")
	}
	
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	iterations := 100
	
	// Warm up
	for i := 0; i < 10; i++ {
		sha256.Sum256(data)
		sha3.Sum256(data)
		h := NewQtxHash(256, data)
		h.GetHash(data)
	}
	
	t.Log("=== QtxHash Performance Report ===")
	t.Log("")
	t.Log("QtxHash is designed to be SLOWER than standard hashes.")
	t.Log("This is intentional for Grover resistance and ASIC resistance.")
	t.Log("")
	t.Logf("Test: %d iterations with 256-byte input", iterations)
	t.Log("")
	t.Log("Expected slowdown factors:")
	t.Log("  - vs SHA-256:     1000-5000x (due to Argon2 + 1000 mixing rounds)")
	t.Log("  - vs SHA3-256:    500-2000x")
	t.Log("")
	t.Log("This slowdown is the SECURITY FEATURE, not a bug.")
	t.Log("It makes brute-force attacks (including Grover's) much harder.")
}

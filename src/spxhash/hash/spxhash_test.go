// MIT License
// Copyright (c) 2024 quantix

// Tests for spxhash/hash package
package spxhash

import (
	"bytes"
	"testing"
)

func TestNewSphinxHash(t *testing.T) {
	s := NewSphinxHash(256, []byte("test"))
	if s == nil {
		t.Fatal("expected non-nil SphinxHash")
	}
	if s.bitSize != 256 {
		t.Errorf("expected bitSize 256, got %d", s.bitSize)
	}
	if s.salt == nil {
		t.Error("expected non-nil salt")
	}
}

func TestSize(t *testing.T) {
	cases := []struct {
		bitSize int
		want    int
	}{
		{256, 32},
		{384, 48},
		{512, 64},
		{128, 32}, // default
	}
	for _, tc := range cases {
		s := &SphinxHash{bitSize: tc.bitSize}
		if got := s.Size(); got != tc.want {
			t.Errorf("Size() for bitSize %d = %d, want %d", tc.bitSize, got, tc.want)
		}
	}
}

func TestBlockSize(t *testing.T) {
	cases := []struct {
		bitSize int
		want    int
	}{
		{256, 128},
		{384, 128},
		{512, 128},
		{0, 136}, // default
	}
	for _, tc := range cases {
		s := &SphinxHash{bitSize: tc.bitSize}
		if got := s.BlockSize(); got != tc.want {
			t.Errorf("BlockSize() for bitSize %d = %d, want %d", tc.bitSize, got, tc.want)
		}
	}
}

func TestWrite(t *testing.T) {
	s := NewSphinxHash(256, []byte{})
	n, err := s.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes written, got %d", n)
	}
	if !bytes.Equal(s.data, []byte("hello")) {
		t.Errorf("unexpected data: %v", s.data)
	}
	_, _ = s.Write([]byte(" world"))
	if !bytes.Equal(s.data, []byte("hello world")) {
		t.Errorf("unexpected data after second write: %v", s.data)
	}
}

func TestGetHashShortInput(t *testing.T) {
	s := NewSphinxHash(256, []byte{})
	// Short input (< 8 bytes) uses fallback sha512/256 path
	h := s.GetHash([]byte("hi"))
	if len(h) == 0 {
		t.Error("expected non-empty hash for short input")
	}
}

func TestGetHashCaching(t *testing.T) {
	s := NewSphinxHash(256, []byte("seed"))
	data := []byte("cached data input!") // >= 8 bytes
	h1 := s.GetHash(data)
	h2 := s.GetHash(data)
	if !bytes.Equal(h1, h2) {
		t.Error("cached hash should be deterministic")
	}
}

func TestSum(t *testing.T) {
	s := NewSphinxHash(256, []byte{})
	_, _ = s.Write([]byte("hi")) // short data uses fallback
	result := s.Sum([]byte("prefix"))
	if len(result) <= len("prefix") {
		t.Error("Sum should append hash to prefix")
	}
	if !bytes.HasPrefix(result, []byte("prefix")) {
		t.Error("Sum result should start with prefix")
	}
}

func TestRead(t *testing.T) {
	s := NewSphinxHash(256, []byte{})
	_, _ = s.Write([]byte("hi"))
	buf := make([]byte, 32)
	n, _ := s.Read(buf)
	if n == 0 {
		t.Error("expected non-zero bytes read")
	}
}

// Test LRU cache
func TestLRUCache(t *testing.T) {
	cache := NewLRUCache(3)
	cache.Put(1, []byte("one"))
	cache.Put(2, []byte("two"))
	cache.Put(3, []byte("three"))

	val, ok := cache.Get(1)
	if !ok || !bytes.Equal(val, []byte("one")) {
		t.Error("expected to find key 1")
	}

	// Adding 4th element evicts LRU
	cache.Put(4, []byte("four"))
	_, ok = cache.Get(2)
	if ok {
		t.Error("expected key 2 to be evicted")
	}
}

package qtxhash

import (
	"bytes"
	"testing"
)

func TestQtxHashNonEmpty(t *testing.T) {
	data := []byte("hello quantix")
	h := NewQtxHash(256, data)
	result := h.GetHash(data)
	if len(result) == 0 {
		t.Fatal("expected non-empty hash")
	}
}

func TestQtxHashDeterministic(t *testing.T) {
	data := []byte("deterministic test input")
	h1 := NewQtxHash(256, data)
	h2 := NewQtxHash(256, data)
	r1 := h1.GetHash(data)
	r2 := h2.GetHash(data)
	if !bytes.Equal(r1, r2) {
		t.Fatal("hash not deterministic: got different results for same input")
	}
}

func TestQtxHashSensitiveToInput(t *testing.T) {
	data1 := []byte("input one")
	data2 := []byte("input two")
	h1 := NewQtxHash(256, data1)
	h2 := NewQtxHash(256, data2)
	r1 := h1.GetHash(data1)
	r2 := h2.GetHash(data2)
	if bytes.Equal(r1, r2) {
		t.Fatal("different inputs produced the same hash")
	}
}

func TestQtxHashSize256(t *testing.T) {
	data := []byte("size test")
	h := NewQtxHash(256, data)
	result := h.GetHash(data)
	if len(result) != 32 {
		t.Fatalf("expected 32-byte hash for 256-bit, got %d", len(result))
	}
}

func TestQtxHashShortInput(t *testing.T) {
	data := []byte("hi")
	h := NewQtxHash(256, data)
	result := h.GetHash(data)
	if len(result) == 0 {
		t.Fatal("expected non-empty hash for short input")
	}
}

func TestQtxHashWriteSum(t *testing.T) {
	data := []byte("write and sum test")
	h := NewQtxHash(256, data)
	h.Write(data)
	sum := h.Sum(nil)
	if len(sum) == 0 {
		t.Fatal("Sum returned empty")
	}
}

func TestQtxHashSize(t *testing.T) {
	cases := []struct {
		bits     int
		expected int
	}{
		{256, 32},
		{384, 48},
		{512, 64},
		{0, 32}, // default
	}
	for _, c := range cases {
		h := NewQtxHash(c.bits, []byte("x"))
		if h.Size() != c.expected {
			t.Errorf("bitSize=%d: expected size %d, got %d", c.bits, c.expected, h.Size())
		}
	}
}

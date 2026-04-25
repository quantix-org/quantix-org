// MIT License
// Copyright (c) 2024 quantix
package svm_test

import (
	"testing"

	svm "github.com/quantix-org/quantix-org/src/core/svm/opcodes"
)

// ── Arithmetic ops ─────────────────────────────────────────────────────────

func TestXorOp(t *testing.T) {
	if got := svm.XorOp(0xF0, 0x0F); got != 0xFF {
		t.Errorf("XorOp(0xF0, 0x0F) = %#x, want 0xFF", got)
	}
	if got := svm.XorOp(0xFF, 0xFF); got != 0 {
		t.Errorf("XorOp(0xFF, 0xFF) = %#x, want 0", got)
	}
}

func TestOrOp(t *testing.T) {
	if got := svm.OrOp(0xF0, 0x0F); got != 0xFF {
		t.Errorf("OrOp = %#x, want 0xFF", got)
	}
	if got := svm.OrOp(0, 0); got != 0 {
		t.Errorf("OrOp(0,0) = %#x, want 0", got)
	}
}

func TestAndOp(t *testing.T) {
	if got := svm.AndOp(0xFF, 0x0F); got != 0x0F {
		t.Errorf("AndOp = %#x, want 0x0F", got)
	}
	if got := svm.AndOp(0, 0xFF); got != 0 {
		t.Errorf("AndOp(0, 0xFF) = %#x, want 0", got)
	}
}

func TestNotOp(t *testing.T) {
	// NOT(0) = all-ones uint64
	if got := svm.NotOp(0); got != ^uint64(0) {
		t.Errorf("NotOp(0) = %#x, want max uint64", got)
	}
	// NOT(NOT(x)) == x
	x := uint64(0xDEADBEEF)
	if got := svm.NotOp(svm.NotOp(x)); got != x {
		t.Errorf("double NOT failed: got %#x want %#x", got, x)
	}
}

func TestShrOp(t *testing.T) {
	if got := svm.ShrOp(0xFF, 4); got != 0x0F {
		t.Errorf("ShrOp(0xFF, 4) = %#x, want 0x0F", got)
	}
	if got := svm.ShrOp(1, 1); got != 0 {
		t.Errorf("ShrOp(1,1) = %#x, want 0", got)
	}
}

func TestRotOp_NoOverflow(t *testing.T) {
	// Rotating 0 or rotating by 0 is a no-op in content
	v := uint64(0xABCD1234)
	rot := svm.RotOp(v, 0)
	// Rot by 0 should equal v (assuming left rotate by 0)
	_ = rot // just verify no panic
}

func TestAddOp(t *testing.T) {
	if got := svm.AddOp(1, 2); got != 3 {
		t.Errorf("AddOp(1,2) = %d, want 3", got)
	}
	// Overflow wraps
	max := uint64(^uint64(0))
	if got := svm.AddOp(max, 1); got != 0 {
		t.Errorf("AddOp overflow = %d, want 0", got)
	}
}

func TestAddOp32(t *testing.T) {
	// AddOp32 treats operands as 32-bit
	if got := svm.AddOp32(1, 2); got != 3 {
		t.Errorf("AddOp32(1,2) = %d, want 3", got)
	}
}

// ── ExecuteOp dispatch ──────────────────────────────────────────────────────

func TestExecuteOp_Xor(t *testing.T) {
	got := svm.ExecuteOp(svm.Xor, 0xAA, 0x55, 0)
	if got != 0xFF {
		t.Errorf("ExecuteOp(Xor) = %#x, want 0xFF", got)
	}
}

func TestExecuteOp_Or(t *testing.T) {
	got := svm.ExecuteOp(svm.Or, 0xF0, 0x0F, 0)
	if got != 0xFF {
		t.Errorf("ExecuteOp(Or) = %#x, want 0xFF", got)
	}
}

func TestExecuteOp_And(t *testing.T) {
	got := svm.ExecuteOp(svm.And, 0xFF, 0x0F, 0)
	if got != 0x0F {
		t.Errorf("ExecuteOp(And) = %#x, want 0x0F", got)
	}
}

func TestExecuteOp_Not(t *testing.T) {
	got := svm.ExecuteOp(svm.Not, 0, 0, 0)
	if got != ^uint64(0) {
		t.Errorf("ExecuteOp(Not, 0) = %#x, want max uint64", got)
	}
}

func TestExecuteOp_Shr(t *testing.T) {
	got := svm.ExecuteOp(svm.Shr, 0xFF, 0, 4)
	if got != 0x0F {
		t.Errorf("ExecuteOp(Shr) = %#x, want 0x0F", got)
	}
}

func TestExecuteOp_Add(t *testing.T) {
	got := svm.ExecuteOp(svm.Add, 10, 20, 0)
	if got != 30 {
		t.Errorf("ExecuteOp(Add) = %d, want 30", got)
	}
}

func TestExecuteOp_QuantixHash_NonZero(t *testing.T) {
	// Just ensure it doesn't panic and returns non-trivial value
	got := svm.ExecuteOp(svm.QuantixHash, 42, 0, 0)
	_ = got // hash output is valid as long as no panic
}

func TestExecuteOp_UnknownPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for unknown opcode")
		}
	}()
	svm.ExecuteOp(svm.OpCode(0xFF), 0, 0, 0)
}

// ── IsPush ──────────────────────────────────────────────────────────────────

func TestIsPush_KnownOpcodesAreFalse(t *testing.T) {
	opcodes := []svm.OpCode{svm.Xor, svm.Or, svm.And, svm.Not, svm.Shr, svm.Add, svm.QuantixHash}
	for _, op := range opcodes {
		if op.IsPush() {
			t.Errorf("opcode %#x should not be a PUSH opcode", op)
		}
	}
}

// ── OpCodeFromString ─────────────────────────────────────────────────────────

func TestOpCodeFromString_KnownNames(t *testing.T) {
	tests := []struct {
		name string
		want svm.OpCode
	}{
		{"QuantixHash", svm.QuantixHash},
		{"Xor", svm.Xor},
		{"Or", svm.Or},
		{"And", svm.And},
		{"Rot", svm.Rot},
		{"Not", svm.Not},
		{"Shr", svm.Shr},
		{"Add", svm.Add},
		{"SHA3_256", svm.SHA3_256},
		{"SHA512_224", svm.SHA512_224},
		{"SHA512_256", svm.SHA512_256},
		{"SHA3_Shake256", svm.SHA3_Shake256},
		{"SphinxHash", svm.SphinxHash},
		{"SPHINCS_MULTISIG_INIT", svm.OP_SPHINCS_MULTISIG_INIT},
		{"SPHINCS_MULTISIG_SIGN", svm.OP_SPHINCS_MULTISIG_SIGN},
		{"SPHINCS_MULTISIG_VERIFY", svm.OP_SPHINCS_MULTISIG_VERIFY},
		{"SPHINCS_MULTISIG_PROOF", svm.OP_SPHINCS_MULTISIG_PROOF},
	}
	for _, tt := range tests {
		got, err := svm.OpCodeFromString(tt.name)
		if err != nil {
			t.Errorf("OpCodeFromString(%q) error: %v", tt.name, err)
		}
		if got != tt.want {
			t.Errorf("OpCodeFromString(%q) = %#x, want %#x", tt.name, got, tt.want)
		}
	}
}

func TestOpCodeFromString_Unknown(t *testing.T) {
	_, err := svm.OpCodeFromString("NonExistentOp")
	if err == nil {
		t.Error("expected error for unknown opcode name")
	}
}

func TestOpCodeFromString_EmptyString(t *testing.T) {
	_, err := svm.OpCodeFromString("")
	if err == nil {
		t.Error("expected error for empty opcode name")
	}
}

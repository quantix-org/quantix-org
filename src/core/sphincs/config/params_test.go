// MIT License
// Copyright (c) 2024 quantix
package params_test

import (
	"testing"

	params "github.com/quantix-org/quantix-org/src/core/sphincs/config"
)

func TestNewSPHINCSParameters_NotNil(t *testing.T) {
	p, err := params.NewSPHINCSParameters()
	if err != nil {
		t.Fatalf("NewSPHINCSParameters error: %v", err)
	}
	if p == nil {
		t.Error("expected non-nil SPHINCSParameters")
	}
}

func TestNewSPHINCSParameters_InnerParamsNotNil(t *testing.T) {
	p, err := params.NewSPHINCSParameters()
	if err != nil {
		t.Fatalf("NewSPHINCSParameters error: %v", err)
	}
	if p.Params == nil {
		t.Error("expected non-nil inner Params")
	}
}

func TestNewSPHINCSParameters_Deterministic(t *testing.T) {
	p1, _ := params.NewSPHINCSParameters()
	p2, _ := params.NewSPHINCSParameters()
	// Both should be non-nil and contain the same N value (SPHINCS hash size)
	if p1.Params.N != p2.Params.N {
		t.Errorf("N differs across calls: %d vs %d", p1.Params.N, p2.Params.N)
	}
}

func TestNewSPHINCSParameters_SecurityParams(t *testing.T) {
	p, _ := params.NewSPHINCSParameters()
	// SPHINCS+-SHAKE256-128s should have N=16 (128-bit security)
	if p.Params.N == 0 {
		t.Error("N (hash size) should be non-zero")
	}
	if p.Params.H == 0 {
		t.Error("H (hypertree height) should be non-zero")
	}
}

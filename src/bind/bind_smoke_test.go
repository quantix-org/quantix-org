// MIT License
// Copyright (c) 2024 quantix

// go/src/bind/bind_smoke_test.go — Q20 smoke tests for the bind package.
package bind

import (
	"testing"

	"github.com/ramseyauron/quantix/src/network"
)

// ---------------------------------------------------------------------------
// Q20-A: ParseRoles — basic role mapping
// ---------------------------------------------------------------------------

func TestParseRoles_Basic(t *testing.T) {
	tests := []struct {
		rolesStr string
		numNodes int
		want     []network.NodeRole
	}{
		{
			rolesStr: "validator,sender,receiver",
			numNodes: 3,
			want:     []network.NodeRole{network.RoleValidator, network.RoleSender, network.RoleReceiver},
		},
		{
			rolesStr: "validator",
			numNodes: 1,
			want:     []network.NodeRole{network.RoleValidator},
		},
		{
			rolesStr: "invalid",
			numNodes: 1,
			want:     []network.NodeRole{network.RoleNone},
		},
	}

	for _, tc := range tests {
		got := ParseRoles(tc.rolesStr, tc.numNodes)
		if len(got) != len(tc.want) {
			t.Errorf("ParseRoles(%q, %d): want len %d, got len %d", tc.rolesStr, tc.numNodes, len(tc.want), len(got))
			continue
		}
		for i, r := range got {
			if r != tc.want[i] {
				t.Errorf("ParseRoles(%q, %d)[%d]: want %q, got %q", tc.rolesStr, tc.numNodes, i, tc.want[i], r)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Q20-B: ParseRoles — fewer roles than nodes → extras get RoleNone
// ---------------------------------------------------------------------------

func TestParseRoles_PadsWithNone(t *testing.T) {
	got := ParseRoles("validator", 3)
	if len(got) != 3 {
		t.Fatalf("want 3 roles, got %d", len(got))
	}
	if got[0] != network.RoleValidator {
		t.Errorf("got[0]: want validator, got %q", got[0])
	}
	if got[1] != network.RoleNone {
		t.Errorf("got[1]: want none, got %q", got[1])
	}
	if got[2] != network.RoleNone {
		t.Errorf("got[2]: want none, got %q", got[2])
	}
}

// ---------------------------------------------------------------------------
// Q20-C: ParseRoles — empty string → all RoleNone
// ---------------------------------------------------------------------------

func TestParseRoles_EmptyString(t *testing.T) {
	got := ParseRoles("", 2)
	for i, r := range got {
		if r != network.RoleNone {
			t.Errorf("got[%d]: want none, got %q", i, r)
		}
	}
}

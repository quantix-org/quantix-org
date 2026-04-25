// MIT License
// Copyright (c) 2024 quantix

// P3-Q1: PEPPER targeted tests for src/bind — pure utility functions.
package bind

import (
	"testing"

	"github.com/quantix-org/quantix-org/src/network"
)

// ---------------------------------------------------------------------------
// ParseRoles
// ---------------------------------------------------------------------------

func TestParseRoles_Sender(t *testing.T) {
	roles := ParseRoles("sender", 1)
	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}
	if roles[0] != network.RoleSender {
		t.Errorf("expected RoleSender, got %v", roles[0])
	}
}

func TestParseRoles_Receiver(t *testing.T) {
	roles := ParseRoles("receiver", 1)
	if roles[0] != network.RoleReceiver {
		t.Errorf("expected RoleReceiver, got %v", roles[0])
	}
}

func TestParseRoles_Validator(t *testing.T) {
	roles := ParseRoles("validator", 1)
	if roles[0] != network.RoleValidator {
		t.Errorf("expected RoleValidator, got %v", roles[0])
	}
}

func TestParseRoles_Unknown_DefaultsToNone(t *testing.T) {
	roles := ParseRoles("unknown-role", 1)
	if roles[0] != network.RoleNone {
		t.Errorf("expected RoleNone, got %v", roles[0])
	}
}

func TestParseRoles_MultipleRoles(t *testing.T) {
	roles := ParseRoles("sender,validator,receiver", 3)
	if len(roles) != 3 {
		t.Fatalf("expected 3 roles, got %d", len(roles))
	}
	if roles[0] != network.RoleSender {
		t.Errorf("roles[0]: expected RoleSender, got %v", roles[0])
	}
	if roles[1] != network.RoleValidator {
		t.Errorf("roles[1]: expected RoleValidator, got %v", roles[1])
	}
	if roles[2] != network.RoleReceiver {
		t.Errorf("roles[2]: expected RoleReceiver, got %v", roles[2])
	}
}

func TestParseRoles_FewerRolesThanNodes_PadsWithNone(t *testing.T) {
	roles := ParseRoles("sender", 3)
	if len(roles) != 3 {
		t.Fatalf("expected 3 roles, got %d", len(roles))
	}
	if roles[1] != network.RoleNone {
		t.Errorf("roles[1] should be RoleNone, got %v", roles[1])
	}
	if roles[2] != network.RoleNone {
		t.Errorf("roles[2] should be RoleNone, got %v", roles[2])
	}
}

func TestParseRoles_EmptyString_AllNone(t *testing.T) {
	roles := ParseRoles("", 2)
	for i, r := range roles {
		if r != network.RoleNone {
			t.Errorf("roles[%d] should be RoleNone for empty string, got %v", i, r)
		}
	}
}

func TestParseRoles_WithSpaces(t *testing.T) {
	roles := ParseRoles(" validator , sender ", 2)
	if roles[0] != network.RoleValidator {
		t.Errorf("expected RoleValidator after trim, got %v", roles[0])
	}
	if roles[1] != network.RoleSender {
		t.Errorf("expected RoleSender after trim, got %v", roles[1])
	}
}

func TestParseRoles_ZeroNodes_EmptyResult(t *testing.T) {
	roles := ParseRoles("sender,validator", 0)
	if len(roles) != 0 {
		t.Errorf("expected 0 roles, got %d", len(roles))
	}
}

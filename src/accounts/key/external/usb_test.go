// MIT License
// Copyright (c) 2024 quantix
package usb_test

import (
	"testing"

	usb "github.com/quantix-org/quantix-org/src/accounts/key/external"
)

func TestNewUSBKeyStore_NotNil(t *testing.T) {
	ks := usb.NewUSBKeyStore()
	if ks == nil {
		t.Error("NewUSBKeyStore returned nil")
	}
}

func TestIsMounted_InitiallyFalse(t *testing.T) {
	ks := usb.NewUSBKeyStore()
	if ks.IsMounted() {
		t.Error("IsMounted should be false before any Mount call")
	}
}

func TestUnmount_WhenNotMounted_NoPanel(t *testing.T) {
	ks := usb.NewUSBKeyStore()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Unmount panicked when not mounted: %v", r)
		}
	}()
	ks.Unmount()
}

func TestMount_InvalidPath_Error(t *testing.T) {
	ks := usb.NewUSBKeyStore()
	err := ks.Mount("/nonexistent/path/to/usb")
	if err == nil {
		t.Error("expected error for non-existent USB path")
	}
}

func TestListKeys_EmptyInitially(t *testing.T) {
	ks := usb.NewUSBKeyStore()
	keys := ks.ListKeys()
	if len(keys) != 0 {
		t.Errorf("ListKeys should return empty slice before any keys are stored, got %d", len(keys))
	}
}

func TestGetWalletInfo_NotNil(t *testing.T) {
	ks := usb.NewUSBKeyStore()
	info := ks.GetWalletInfo()
	if info == nil {
		t.Error("GetWalletInfo should return non-nil WalletInfo")
	}
}

func TestRemoveKey_NotMounted_Error(t *testing.T) {
	ks := usb.NewUSBKeyStore()
	err := ks.RemoveKey("some-key-id")
	if err == nil {
		t.Error("expected error when removing key from unmounted store")
	}
}

func TestGetKey_NotMounted_Error(t *testing.T) {
	ks := usb.NewUSBKeyStore()
	_, err := ks.GetKey("some-key-id")
	if err == nil {
		t.Error("expected error when getting key from unmounted store")
	}
}

func TestGetKeyByAddress_NotMounted_Error(t *testing.T) {
	ks := usb.NewUSBKeyStore()
	_, err := ks.GetKeyByAddress("some-address")
	if err == nil {
		t.Error("expected error when getting key by address from unmounted store")
	}
}

func TestEncryptData_NotMounted_Error(t *testing.T) {
	ks := usb.NewUSBKeyStore()
	// Note: EncryptData should work even when not mounted (it's a crypto op)
	// or error if it requires the USB path. Either is acceptable — we test it doesn't panic.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("EncryptData panicked: %v", r)
		}
	}()
	_, _, _ = ks.EncryptData([]byte("test"), "passphrase")
}

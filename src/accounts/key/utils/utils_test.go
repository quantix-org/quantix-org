// MIT License
// Copyright (c) 2024 quantix
package utils_test

import (
	"testing"

	utils "github.com/quantix-org/quantix-org/src/accounts/key/utils"
)

func TestNewStorageManager_NotNil(t *testing.T) {
	sm, err := utils.NewStorageManager()
	if err != nil {
		t.Fatalf("NewStorageManager error: %v", err)
	}
	if sm == nil {
		t.Error("expected non-nil StorageManager")
	}
}

func TestGetStorage_Disk_NotNil(t *testing.T) {
	sm, _ := utils.NewStorageManager()
	store := sm.GetStorage("disk")
	if store == nil {
		t.Error("GetStorage(disk) should return non-nil StorageInterface")
	}
}

func TestGetStorage_Unknown_FallbackDisk(t *testing.T) {
	sm, _ := utils.NewStorageManager()
	store := sm.GetStorage("unknown-type")
	if store == nil {
		t.Error("GetStorage with unknown type should fall back to disk (non-nil)")
	}
}

func TestGetStorage_USB_NotNil(t *testing.T) {
	sm, _ := utils.NewStorageManager()
	store := sm.GetStorage("usb")
	if store == nil {
		t.Error("GetStorage(usb) should return non-nil StorageInterface")
	}
}

func TestIsUSBMounted_InitiallyFalse(t *testing.T) {
	sm, _ := utils.NewStorageManager()
	if sm.IsUSBMounted() {
		t.Error("USB should not be mounted immediately after creation")
	}
}

func TestUnmountUSB_NoPanel(t *testing.T) {
	sm, _ := utils.NewStorageManager()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("UnmountUSB panicked: %v", r)
		}
	}()
	sm.UnmountUSB() // should not panic when not mounted
}

func TestGetRecommendedStorage_NonEmpty(t *testing.T) {
	st := utils.GetRecommendedStorage()
	if string(st) == "" {
		t.Error("GetRecommendedStorage should return non-empty storage type")
	}
}

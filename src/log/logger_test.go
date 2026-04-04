// MIT License
// Copyright (c) 2024 quantix

// Tests for src/log package
package logger

import (
	"strings"
	"testing"
)

func TestSetLevel(t *testing.T) {
	SetLevel(DEBUG)
	if currentLevel != DEBUG {
		t.Errorf("expected DEBUG level, got %d", currentLevel)
	}
	SetLevel(INFO)
}

func TestLogBuffer_WriteAndString(t *testing.T) {
	lb := &LogBuffer{}
	data := []byte("hello logger")
	n, err := lb.Write(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}
	if got := lb.String(); got != "hello logger" {
		t.Errorf("unexpected buffer content: %q", got)
	}
}

func TestLogfLevelFilter(t *testing.T) {
	SetLevel(WARN)
	before := buffer.String()
	logf(DEBUG, "should not appear %s", "debug")
	logf(INFO, "should not appear %s", "info")
	after := buffer.String()
	// New content since before
	added := after[len(before):]
	if strings.Contains(added, "should not appear") {
		t.Error("DEBUG/INFO messages should be filtered at WARN level")
	}
	SetLevel(INFO)
}

func TestInfoAndErrorLog(t *testing.T) {
	SetLevel(DEBUG)
	before := buffer.String()
	Info("test info message %d", 42)
	Error("test error message %s", "oops")
	Warn("test warn message")
	Debug("test debug message")
	after := buffer.String()
	added := after[len(before):]
	for _, want := range []string{"test info message 42", "test error message oops", "test warn message", "test debug message"} {
		if !strings.Contains(added, want) {
			t.Errorf("expected %q in logs, got: %s", want, added)
		}
	}
	SetLevel(INFO)
}

func TestInfofWarnfErrorfDebugf(t *testing.T) {
	SetLevel(DEBUG)
	before := buffer.String()
	Infof("infof %d", 1)
	Warnf("warnf %d", 2)
	Errorf("errorf %d", 3)
	Debugf("debugf %d", 4)
	after := buffer.String()
	added := after[len(before):]
	for _, want := range []string{"infof 1", "warnf 2", "errorf 3", "debugf 4"} {
		if !strings.Contains(added, want) {
			t.Errorf("expected %q in logs", want)
		}
	}
	SetLevel(INFO)
}

func TestGetLogs(t *testing.T) {
	Info("getlogs test message")
	logs := GetLogs()
	if !strings.Contains(logs, "getlogs test message") {
		t.Error("GetLogs should return accumulated log content")
	}
}

func TestLevelNames(t *testing.T) {
	if levelNames[DEBUG] != "DEBUG" {
		t.Error("expected DEBUG")
	}
	if levelNames[ERROR] != "ERROR" {
		t.Error("expected ERROR")
	}
}

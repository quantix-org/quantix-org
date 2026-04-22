package logger

import (
	"strings"
	"testing"
)

func TestInfoDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Info panicked: %v", r)
		}
	}()
	Info("test info message %s", "hello")
}

func TestDebugDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Debug panicked: %v", r)
		}
	}()
	SetLevel(DEBUG)
	Debug("test debug message %d", 42)
}

func TestWarnDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Warn panicked: %v", r)
		}
	}()
	Warn("test warn message")
}

func TestErrorDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Error panicked: %v", r)
		}
	}()
	Error("test error message %v", "oops")
}

func TestGetLogs(t *testing.T) {
	Info("unique-log-entry-12345")
	logs := GetLogs()
	if !strings.Contains(logs, "unique-log-entry-12345") {
		t.Fatal("expected log entry to appear in GetLogs()")
	}
}

func TestSetLevel(t *testing.T) {
	// Setting to ERROR should suppress INFO
	SetLevel(ERROR)
	before := GetLogs()
	Info("this-should-not-appear-9876")
	after := GetLogs()
	if after != before {
		// Check that the specific message didn't appear
		if strings.Contains(after[len(before):], "this-should-not-appear-9876") {
			t.Fatal("INFO message appeared despite ERROR level")
		}
	}
	// Reset to INFO
	SetLevel(INFO)
}

func TestInfofDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Infof panicked: %v", r)
		}
	}()
	Infof("infof test %s", "value")
}

func TestDebugfDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Debugf panicked: %v", r)
		}
	}()
	SetLevel(DEBUG)
	Debugf("debugf test")
	SetLevel(INFO)
}

func TestWarnfDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Warnf panicked: %v", r)
		}
	}()
	Warnf("warnf test")
}

func TestErrorfDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Errorf panicked: %v", r)
		}
	}()
	Errorf("errorf test")
}

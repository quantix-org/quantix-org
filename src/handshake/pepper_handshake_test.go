// PEPPER Sprint2 — handshake package coverage push for NewHandshake
package security

import (
	"testing"
)

func TestNewHandshake_NotNil(t *testing.T) {
	h := NewHandshake()
	if h == nil {
		t.Fatal("NewHandshake returned nil")
	}
}

func TestNewHandshake_MetricsNotNil(t *testing.T) {
	h := NewHandshake()
	if h.Metrics == nil {
		t.Fatal("NewHandshake: Metrics is nil")
	}
	if h.Metrics.Latency == nil {
		t.Error("Metrics.Latency should not be nil")
	}
	if h.Metrics.Errors == nil {
		t.Error("Metrics.Errors should not be nil")
	}
}

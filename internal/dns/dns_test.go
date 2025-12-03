package dns

import (
	"context"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	// Test with zero timeout (should use default)
	client := NewClient(0)
	if client.timeout != defaultTimeout {
		t.Errorf("Expected default timeout %v, got %v", defaultTimeout, client.timeout)
	}

	// Test with custom timeout
	customTimeout := 60 * time.Second
	client = NewClient(customTimeout)
	if client.timeout != customTimeout {
		t.Errorf("Expected custom timeout %v, got %v", customTimeout, client.timeout)
	}

	// Test that DNS servers are set
	if len(client.dnsServers) == 0 {
		t.Error("Expected DNS servers to be set")
	}
}

func TestGetSystemDNSServers(t *testing.T) {
	servers := getSystemDNSServers()
	if len(servers) == 0 {
		t.Error("Expected at least one DNS server")
	}

	// Verify all servers have port
	for _, server := range servers {
		if !contains(server, ":") {
			t.Errorf("Server %s should have port", server)
		}
	}
}

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"NXDOMAIN", &testError{"NXDOMAIN"}, true},
		{"no such host", &testError{"no such host"}, true},
		{"Name Error", &testError{"Name Error"}, true},
		{"other error", &testError{"connection refused"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNotFoundError(tt.err)
			if result != tt.expected {
				t.Errorf("isNotFoundError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCategorizeError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"nil error", nil, ""},
		{"NXDOMAIN", &testError{"NXDOMAIN"}, "domain not found (NXDOMAIN)"},
		{"SERVFAIL", &testError{"SERVFAIL"}, "server failure (SERVFAIL)"},
		{"REFUSED", &testError{"REFUSED"}, "query refused"},
		{"no such host", &testError{"no such host"}, "host not found"},
		{"i/o timeout", &testError{"i/o timeout"}, "DNS query timeout"},
		{"connection refused", &testError{"connection refused"}, "DNS server connection refused"},
		{"other error", &testError{"unknown error"}, "unknown error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := categorizeError(tt.err)
			if result != tt.expected {
				t.Errorf("categorizeError() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestDNSResultStructure(t *testing.T) {
	// Test that DNSResult can be created and populated
	result := &DNSResult{
		A:    []string{"1.2.3.4"},
		AAAA: []string{"::1"},
		MX: []MXRecord{
			{Priority: 10, Host: "mail.example.com"},
		},
		TXT:   []string{"v=spf1 include:example.com ~all"},
		NS:    []string{"ns1.example.com"},
		CNAME: "www.example.com",
		SOA: &SOARecord{
			PrimaryNS:  "ns1.example.com",
			AdminEmail: "admin@example.com",
			Serial:     2024010101,
			Refresh:    3600,
			Retry:      600,
			Expire:     604800,
			MinTTL:     300,
		},
	}

	if len(result.A) != 1 {
		t.Errorf("Expected 1 A record, got %d", len(result.A))
	}
	if len(result.MX) != 1 {
		t.Errorf("Expected 1 MX record, got %d", len(result.MX))
	}
	if result.SOA == nil {
		t.Error("Expected SOA record to be set")
	}
}

func TestMXRecordStructure(t *testing.T) {
	mx := MXRecord{
		Priority: 10,
		Host:     "mail.example.com",
	}

	if mx.Priority != 10 {
		t.Errorf("Expected priority 10, got %d", mx.Priority)
	}
	if mx.Host != "mail.example.com" {
		t.Errorf("Expected host mail.example.com, got %s", mx.Host)
	}
}

func TestSOARecordStructure(t *testing.T) {
	soa := &SOARecord{
		PrimaryNS:  "ns1.example.com",
		AdminEmail: "admin@example.com",
		Serial:     2024010101,
		Refresh:    3600,
		Retry:      600,
		Expire:     604800,
		MinTTL:     300,
	}

	if soa.PrimaryNS != "ns1.example.com" {
		t.Errorf("Expected PrimaryNS ns1.example.com, got %s", soa.PrimaryNS)
	}
	if soa.Serial != 2024010101 {
		t.Errorf("Expected Serial 2024010101, got %d", soa.Serial)
	}
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// contains is a helper function
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Note: Integration tests that require actual DNS lookups are skipped
// as they depend on network access and may have inconsistent results.
// These tests focus on unit testing the internal logic.

func TestQueryAllCancellation(t *testing.T) {
	client := NewClient(1 * time.Second)

	// Create a canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := client.QueryAll(ctx, "example.com")

	// Result should have error or be empty due to cancellation
	if result == nil {
		t.Error("Expected result to be non-nil")
	}
}

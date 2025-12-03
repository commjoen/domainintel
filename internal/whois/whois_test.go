package whois

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

	// Test that cache is initialized
	if client.cache == nil {
		t.Error("Expected cache to be initialized")
	}
}

func TestExtractBaseDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple domain", "example.com", "example.com"},
		{"with subdomain", "www.example.com", "example.com"},
		{"multi-level subdomain", "a.b.c.example.com", "example.com"},
		{"UK domain", "www.example.co.uk", "example.co.uk"},
		{"AU domain", "www.example.com.au", "example.com.au"},
		{"with http", "http://example.com", "example.com"},
		{"with https", "https://example.com", "example.com"},
		{"with path", "example.com/path/to/page", "example.com"},
		{"with port", "example.com:8080", "example.com"},
		{"empty string", "", ""},
		{"single part", "localhost", ""},
		{"uppercase", "WWW.EXAMPLE.COM", "example.com"},
		{"with spaces", "  example.com  ", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBaseDomain(tt.input)
			if result != tt.expected {
				t.Errorf("extractBaseDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseDate(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"RFC3339", "2024-01-15T10:30:00Z", false},
		{"ISO date", "2024-01-15", false},
		{"ISO datetime", "2024-01-15 10:30:00", false},
		{"US format", "01/15/2024", false},
		{"invalid", "not a date", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseDate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDate(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
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
		{"timeout", &testError{"connection timeout"}, "WHOIS server timeout"},
		{"connection refused", &testError{"connection refused"}, "WHOIS server connection refused"},
		{"no whois server", &testError{"no whois server found"}, "no WHOIS server found for this TLD"},
		{"rate limit", &testError{"rate limit exceeded"}, "rate limited by WHOIS server"},
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

func TestWHOISResultStructure(t *testing.T) {
	now := time.Now()
	result := &WHOISResult{
		Registrar:       "Example Registrar",
		RegistrantName:  "John Doe",
		RegistrantOrg:   "Example Inc",
		RegistrantEmail: "admin@example.com",
		CreationDate:    &now,
		ExpirationDate:  &now,
		UpdatedDate:     &now,
		Nameservers:     []string{"ns1.example.com", "ns2.example.com"},
		Status:          []string{"clientTransferProhibited"},
		DNSSEC:          "unsigned",
	}

	if result.Registrar != "Example Registrar" {
		t.Errorf("Expected Registrar 'Example Registrar', got %s", result.Registrar)
	}
	if len(result.Nameservers) != 2 {
		t.Errorf("Expected 2 nameservers, got %d", len(result.Nameservers))
	}
}

func TestClientCaching(t *testing.T) {
	client := NewClient(5 * time.Second)

	// Create a test result
	testResult := &WHOISResult{
		Registrar: "Test Registrar",
	}

	// Save to cache
	client.saveToCache("example.com", testResult)

	// Retrieve from cache
	cached := client.getFromCache("example.com")
	if cached == nil {
		t.Fatal("Expected cached result, got nil")
	}
	if cached.Registrar != "Test Registrar" {
		t.Errorf("Expected Registrar 'Test Registrar', got %s", cached.Registrar)
	}

	// Non-existent key
	notCached := client.getFromCache("notexample.com")
	if notCached != nil {
		t.Error("Expected nil for non-cached domain")
	}

	// Clear cache
	client.ClearCache()
	clearedCache := client.getFromCache("example.com")
	if clearedCache != nil {
		t.Error("Expected nil after cache clear")
	}
}

func TestLookupInvalidDomain(t *testing.T) {
	client := NewClient(5 * time.Second)
	ctx := context.Background()

	// Test with invalid domain
	result := client.Lookup(ctx, "")
	if result.Error != "invalid domain" {
		t.Errorf("Expected 'invalid domain' error, got %s", result.Error)
	}
}

func TestLookupCancellation(t *testing.T) {
	client := NewClient(30 * time.Second)

	// Create a canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := client.Lookup(ctx, "example.com")

	// Result should have error or be from cache
	if result == nil {
		t.Error("Expected result to be non-nil")
	}
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// Note: Integration tests that require actual WHOIS lookups are skipped
// as they depend on network access and may be rate-limited.
// These tests focus on unit testing the internal logic.

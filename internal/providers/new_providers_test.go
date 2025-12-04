package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// DNSBL Provider Tests

func TestDNSBLName(t *testing.T) {
	d := NewDNSBL(DNSBLConfig{})
	if d.Name() != "dnsbl" {
		t.Errorf("Expected name 'dnsbl', got %s", d.Name())
	}
}

func TestDNSBLIsAvailable(t *testing.T) {
	d := NewDNSBL(DNSBLConfig{})
	// DNSBL should always be available (no API key required)
	if !d.IsAvailable() {
		t.Error("Expected IsAvailable to be true (no API key required)")
	}
}

func TestDNSBLDefaultLists(t *testing.T) {
	d := NewDNSBL(DNSBLConfig{})
	if len(d.lists) == 0 {
		t.Error("Expected default DNSBL lists to be populated")
	}
	// Should contain at least zen.spamhaus.org
	found := false
	for _, list := range d.lists {
		if list == "zen.spamhaus.org" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected default lists to include zen.spamhaus.org")
	}
}

func TestDNSBLCustomLists(t *testing.T) {
	customLists := []string{"custom1.example.com", "custom2.example.com"}
	d := NewDNSBL(DNSBLConfig{Lists: customLists})
	if len(d.lists) != 2 {
		t.Errorf("Expected 2 custom lists, got %d", len(d.lists))
	}
}

func TestDNSBLCheckNonListedDomain(t *testing.T) {
	d := NewDNSBL(DNSBLConfig{
		Timeout: 2 * time.Second,
		Lists:   []string{"nonexistent.dnsbl.invalid"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := d.Check(ctx, "example.com")

	if result.Provider != "dnsbl" {
		t.Errorf("Expected provider 'dnsbl', got %s", result.Provider)
	}
	// Non-listed domain should not be detected
	if result.Detected {
		t.Error("Expected Detected to be false for non-listed domain")
	}
}

func TestDNSBLContextCancellation(t *testing.T) {
	d := NewDNSBL(DNSBLConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := d.Check(ctx, "example.com")

	if result.Error == "" {
		t.Error("Expected error when context is canceled")
	}
}

// Spamhaus Provider Tests

func TestSpamhausName(t *testing.T) {
	s := NewSpamhaus(SpamhausConfig{})
	if s.Name() != "spamhaus" {
		t.Errorf("Expected name 'spamhaus', got %s", s.Name())
	}
}

func TestSpamhausIsAvailable(t *testing.T) {
	s := NewSpamhaus(SpamhausConfig{})
	// Spamhaus DNS queries are free, no API key required
	if !s.IsAvailable() {
		t.Error("Expected IsAvailable to be true (no API key required)")
	}
}

func TestSpamhausCheckNonListedDomain(t *testing.T) {
	s := NewSpamhaus(SpamhausConfig{Timeout: 2 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// example.com should not be listed in Spamhaus
	result := s.Check(ctx, "example.com")

	if result.Provider != "spamhaus" {
		t.Errorf("Expected provider 'spamhaus', got %s", result.Provider)
	}
	// example.com should not be detected
	if result.Detected {
		t.Error("Expected Detected to be false for example.com")
	}
}

func TestSpamhausReturnCodes(t *testing.T) {
	// Test that return codes are properly defined
	if len(spamhausReturnCodes) == 0 {
		t.Error("Expected spamhausReturnCodes to be populated")
	}

	// Check a known return code
	if _, ok := spamhausReturnCodes["127.0.1.2"]; !ok {
		t.Error("Expected return code 127.0.1.2 to be defined")
	}
}

// Safe Browsing Provider Tests

func TestSafeBrowsingName(t *testing.T) {
	sb := NewSafeBrowsing(SafeBrowsingConfig{})
	if sb.Name() != "safebrowsing" {
		t.Errorf("Expected name 'safebrowsing', got %s", sb.Name())
	}
}

func TestSafeBrowsingIsAvailable(t *testing.T) {
	// Without API key
	sb := NewSafeBrowsing(SafeBrowsingConfig{})
	if sb.IsAvailable() {
		t.Error("Expected IsAvailable to be false without API key")
	}

	// With API key
	sb = NewSafeBrowsing(SafeBrowsingConfig{APIKey: "test-key"})
	if !sb.IsAvailable() {
		t.Error("Expected IsAvailable to be true with API key")
	}
}

func TestSafeBrowsingCheckNoAPIKey(t *testing.T) {
	sb := NewSafeBrowsing(SafeBrowsingConfig{})
	result := sb.Check(context.Background(), "example.com")

	if result.Error == "" {
		t.Error("Expected error without API key")
	}
}

func TestSafeBrowsingCheckMockServer(t *testing.T) {
	// Mock server that returns no threats
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		w.Header().Set("Content-Type", "application/json")
		// Empty matches means no threats
		response := `{"matches": []}`
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	sb := &SafeBrowsing{
		apiKey:  "test-key",
		baseURL: server.URL,
		client:  &http.Client{Timeout: 5 * time.Second},
	}

	result := sb.Check(context.Background(), "example.com")

	if result.Error != "" {
		t.Errorf("Unexpected error: %s", result.Error)
	}
	if result.Detected {
		t.Error("Expected Detected to be false for clean domain")
	}
}

func TestSafeBrowsingCheckMockServerWithThreats(t *testing.T) {
	// Mock server that returns threats
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{
			"matches": [
				{
					"threatType": "MALWARE",
					"platformType": "ANY_PLATFORM",
					"threatEntryType": "URL",
					"threat": {"url": "http://malicious.example.com/"},
					"cacheDuration": "300s"
				}
			]
		}`
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	sb := &SafeBrowsing{
		apiKey:  "test-key",
		baseURL: server.URL,
		client:  &http.Client{Timeout: 5 * time.Second},
	}

	result := sb.Check(context.Background(), "malicious.example.com")

	if result.Error != "" {
		t.Errorf("Unexpected error: %s", result.Error)
	}
	if !result.Detected {
		t.Error("Expected Detected to be true for malicious domain")
	}
	if len(result.Categories) == 0 {
		t.Error("Expected categories to contain threat types")
	}
}

func TestSafeBrowsingCheckMockServerRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	sb := &SafeBrowsing{
		apiKey:  "test-key",
		baseURL: server.URL,
		client:  &http.Client{Timeout: 5 * time.Second},
	}

	result := sb.Check(context.Background(), "example.com")

	if result.Error == "" {
		t.Error("Expected error for rate limit")
	}
}

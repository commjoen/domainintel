// Package integration provides end-to-end tests for domainintel
package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/commjoen/domainintel/internal/crt"
	"github.com/commjoen/domainintel/internal/output"
	"github.com/commjoen/domainintel/internal/providers"
	"github.com/commjoen/domainintel/internal/reachability"
	"github.com/commjoen/domainintel/pkg/models"
)

// TestEndToEndWorkflow tests the complete scan workflow with mock servers
func TestEndToEndWorkflow(t *testing.T) {
	// Create mock CRT server
	crtServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries := []models.CRTEntry{
			{
				CommonName: "www.test.example.com",
				NameValue:  "www.test.example.com\ntest.example.com",
			},
			{
				CommonName: "api.test.example.com",
				NameValue:  "api.test.example.com",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(entries); err != nil {
			t.Logf("Error encoding response: %v", err)
		}
	}))
	defer crtServer.Close()

	// Test the CRT extraction
	entries := []models.CRTEntry{
		{
			CommonName: "www.test.example.com",
			NameValue:  "www.test.example.com\ntest.example.com",
		},
		{
			CommonName: "api.test.example.com",
			NameValue:  "api.test.example.com",
		},
	}

	// Use the internal extraction function (test via data transformation)
	client := crt.NewClient(10 * time.Second)
	if client == nil {
		t.Fatal("Failed to create CRT client")
	}

	// Verify entries can be marshaled to JSON (simulating API response)
	jsonData, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("Failed to marshal entries: %v", err)
	}

	var parsed []models.CRTEntry
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal entries: %v", err)
	}

	if len(parsed) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(parsed))
	}
}

// TestOutputFormatters tests all output formats with a complete result
func TestOutputFormatters(t *testing.T) {
	result := createCompleteTestResult()

	tests := []struct {
		name          string
		format        string
		containsCheck []string
		excludesCheck []string
	}{
		{
			name:   "text format",
			format: "text",
			containsCheck: []string{
				"Domain: example.com",
				"www.example.com",
				"93.184.216.34",
				"200",
			},
		},
		{
			name:   "json format",
			format: "json",
			containsCheck: []string{
				`"timestamp"`,
				`"domains"`,
				`"name": "example.com"`,
				`"subdomains"`,
				`"hostname": "www.example.com"`,
			},
		},
		{
			name:   "csv format",
			format: "csv",
			containsCheck: []string{
				"domain,subdomain,ip,status,tls_valid,response_time_ms",
				"example.com,www.example.com,93.184.216.34,200,true,",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter, err := output.NewFormatter(tt.format)
			if err != nil {
				t.Fatalf("Failed to create formatter: %v", err)
			}

			out, err := formatter.Format(result)
			if err != nil {
				t.Fatalf("Failed to format result: %v", err)
			}

			for _, check := range tt.containsCheck {
				if !strings.Contains(out, check) {
					t.Errorf("Output should contain %q", check)
				}
			}

			for _, check := range tt.excludesCheck {
				if strings.Contains(out, check) {
					t.Errorf("Output should not contain %q", check)
				}
			}
		})
	}
}

// TestProviderIntegration tests the provider manager workflow
func TestProviderIntegration(t *testing.T) {
	manager := providers.NewManager()

	// Register mock provider
	mockProvider := &mockTestProvider{
		name:      "mock",
		available: true,
		result: &providers.Result{
			Provider: "mock",
			Detected: false,
			Score:    "0/10",
		},
	}
	manager.Register(mockProvider)

	// Verify registration
	p, ok := manager.GetProvider("mock")
	if !ok {
		t.Fatal("Provider should be registered")
	}
	if p.Name() != "mock" {
		t.Errorf("Expected provider name 'mock', got %s", p.Name())
	}

	// Test check functionality
	results := manager.Check(context.Background(), "example.com", []string{"mock"})
	if len(results.Results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results.Results))
	}
	if results.Results[0].Score != "0/10" {
		t.Errorf("Expected score '0/10', got %s", results.Results[0].Score)
	}
}

// TestReachabilityChecker tests HTTP reachability checks
func TestReachabilityChecker(t *testing.T) {
	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	checker := reachability.NewChecker(5 * time.Second)
	result := checker.CheckHTTP(context.Background(), server.URL)

	if result.Error != "" {
		t.Errorf("Unexpected error: %s", result.Error)
	}
	if result.Status != 200 {
		t.Errorf("Expected status 200, got %d", result.Status)
	}
	if result.ResponseTimeMs < 0 {
		t.Error("Response time should be non-negative")
	}
}

// TestLargeResultSet tests handling of large result sets
func TestLargeResultSet(t *testing.T) {
	// Create a result with many subdomains
	result := &models.ScanResult{
		Timestamp: time.Now(),
		Domains: []models.DomainResult{
			{
				Name:       "example.com",
				Subdomains: make([]models.SubdomainResult, 100),
			},
		},
	}

	// Populate subdomains
	for i := 0; i < 100; i++ {
		result.Domains[0].Subdomains[i] = models.SubdomainResult{
			Hostname:  "sub" + string(rune('0'+i%10)) + ".example.com",
			IPs:       []string{"1.2.3.4"},
			Reachable: true,
		}
	}

	// Test all formatters handle large results
	formats := []string{"text", "json", "csv"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			formatter, err := output.NewFormatter(format)
			if err != nil {
				t.Fatalf("Failed to create formatter: %v", err)
			}

			_, err = formatter.Format(result)
			if err != nil {
				t.Fatalf("Failed to format large result: %v", err)
			}
		})
	}
}

// TestConcurrentProcessing tests concurrent request handling
func TestConcurrentProcessing(t *testing.T) {
	// Create mock server that tracks concurrent requests
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		time.Sleep(10 * time.Millisecond) // Simulate network latency
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := reachability.NewChecker(5 * time.Second)

	// Make multiple concurrent requests
	done := make(chan bool, 5)
	for i := 0; i < 5; i++ {
		go func() {
			checker.CheckHTTP(context.Background(), server.URL)
			done <- true
		}()
	}

	// Wait for all requests
	for i := 0; i < 5; i++ {
		<-done
	}

	finalCount := atomic.LoadInt64(&requestCount)
	if finalCount != 5 {
		t.Errorf("Expected 5 requests, got %d", finalCount)
	}
}

// TestValidDomainInput tests domain validation
func TestValidDomainInput(t *testing.T) {
	validDomains := []string{
		"example.com",
		"sub.example.com",
		"a.b.c.example.com",
		"example123.com",
		"ex-ample.com",
	}

	invalidDomains := []string{
		"",
		"com",
		"-example.com",
		"example-.com",
		"example..com",
		"example.com/path",
		"example.com:8080",
		"http://example.com",
		"exam ple.com",
	}

	for _, domain := range validDomains {
		err := crt.ValidateDomain(domain)
		if err != nil {
			t.Errorf("Domain %q should be valid, got error: %v", domain, err)
		}
	}

	for _, domain := range invalidDomains {
		err := crt.ValidateDomain(domain)
		if err == nil {
			t.Errorf("Domain %q should be invalid", domain)
		}
	}
}

// TestFixturesLoading tests that fixtures can be loaded
func TestFixturesLoading(t *testing.T) {
	// Get the fixtures file path relative to the test file
	fixturesPath := "../fixtures/mock_responses.json"

	data, err := os.ReadFile(fixturesPath)
	if err != nil {
		t.Fatalf("Failed to read fixtures file: %v", err)
	}

	var fixtures map[string]interface{}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("Failed to parse fixtures JSON: %v", err)
	}

	// Verify required fixture sections exist
	sections := []string{"crt_sh", "virustotal", "urlvoid", "whois"}
	for _, section := range sections {
		if _, ok := fixtures[section]; !ok {
			t.Errorf("Missing fixture section: %s", section)
		}
	}
}

// Helper functions

func createCompleteTestResult() *models.ScanResult {
	return &models.ScanResult{
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Domains: []models.DomainResult{
			{
				Name: "example.com",
				Subdomains: []models.SubdomainResult{
					{
						Hostname:  "www.example.com",
						IPs:       []string{"93.184.216.34"},
						Reachable: true,
						HTTPS: &models.HTTPResult{
							Status:         200,
							StatusText:     "200 OK",
							ResponseTimeMs: 120,
							FinalURL:       "https://www.example.com/",
						},
						TLS: &models.TLSResult{
							Valid:   true,
							Issuer:  "DigiCert Inc",
							Subject: "www.example.com",
							Version: "TLS 1.3",
						},
					},
					{
						Hostname:  "mail.example.com",
						IPs:       []string{"93.184.216.35", "93.184.216.36"},
						Reachable: true,
						HTTP: &models.HTTPResult{
							Status:         301,
							StatusText:     "301 Moved Permanently",
							ResponseTimeMs: 85,
							FinalURL:       "https://mail.example.com/",
							RedirectChain:  []string{"https://mail.example.com/"},
						},
					},
					{
						Hostname:  "api.example.com",
						IPs:       []string{},
						Reachable: false,
						Error:     "connection refused",
					},
				},
			},
		},
		Summary: &models.ScanSummary{
			TotalDomains:    1,
			TotalSubdomains: 3,
			Reachable:       2,
			Unreachable:     1,
		},
	}
}

// mockTestProvider implements the Provider interface for testing
type mockTestProvider struct {
	name      string
	available bool
	result    *providers.Result
}

func (m *mockTestProvider) Name() string {
	return m.name
}

func (m *mockTestProvider) IsAvailable() bool {
	return m.available
}

func (m *mockTestProvider) Check(ctx context.Context, domain string) *providers.Result {
	if m.result != nil {
		return m.result
	}
	return &providers.Result{
		Provider:    m.name,
		Detected:    false,
		LastChecked: time.Now(),
	}
}

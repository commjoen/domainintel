package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	manager := NewManager()
	if manager == nil {
		t.Fatal("Expected manager to be non-nil")
	}
	if manager.providers == nil {
		t.Error("Expected providers map to be initialized")
	}
	if manager.rateLimiter == nil {
		t.Error("Expected rate limiter to be initialized")
	}
	if manager.cache == nil {
		t.Error("Expected cache to be initialized")
	}
}

func TestManagerRegister(t *testing.T) {
	manager := NewManager()
	provider := &mockProvider{name: "test", available: true}

	manager.Register(provider)

	p, ok := manager.GetProvider("test")
	if !ok {
		t.Error("Expected provider to be registered")
	}
	if p.Name() != "test" {
		t.Errorf("Expected provider name 'test', got %s", p.Name())
	}
}

func TestManagerListProviders(t *testing.T) {
	manager := NewManager()
	manager.Register(&mockProvider{name: "available", available: true})
	manager.Register(&mockProvider{name: "unavailable", available: false})

	providers := manager.ListProviders()

	if len(providers) != 1 {
		t.Errorf("Expected 1 available provider, got %d", len(providers))
	}
	if providers[0] != "available" {
		t.Errorf("Expected 'available' provider, got %s", providers[0])
	}
}

func TestRateLimiter(t *testing.T) {
	limiter := NewRateLimiter()

	// First request should be allowed
	if !limiter.Allow("test") {
		t.Error("First request should be allowed")
	}

	// Exhaust the limit
	for i := 0; i < 100; i++ {
		limiter.Allow("test")
	}

	// Should be rate limited now
	if limiter.Allow("test") {
		t.Error("Should be rate limited after many requests")
	}
}

func TestCache(t *testing.T) {
	cache := NewCache(1 * time.Hour)

	result := &Result{
		Provider: "test",
		Detected: true,
		Score:    "5/10",
	}

	// Set and get
	cache.Set("test", "example.com", result)
	cached := cache.Get("test", "example.com")

	if cached == nil {
		t.Fatal("Expected cached result")
	}
	if cached.Provider != "test" {
		t.Errorf("Expected provider 'test', got %s", cached.Provider)
	}

	// Non-existent key
	notCached := cache.Get("other", "example.com")
	if notCached != nil {
		t.Error("Expected nil for non-cached entry")
	}

	// Clear cache
	cache.Clear()
	cleared := cache.Get("test", "example.com")
	if cleared != nil {
		t.Error("Expected nil after cache clear")
	}
}

func TestCacheTTL(t *testing.T) {
	cache := NewCache(1 * time.Millisecond)

	result := &Result{Provider: "test"}
	cache.Set("test", "example.com", result)

	// Wait for TTL to expire
	time.Sleep(5 * time.Millisecond)

	cached := cache.Get("test", "example.com")
	if cached != nil {
		t.Error("Expected nil for expired cache entry")
	}
}

func TestResultStructure(t *testing.T) {
	result := &Result{
		Provider:    "test",
		Detected:    true,
		Score:       "5/10",
		Categories:  []string{"malware", "phishing"},
		Details:     map[string]string{"key": "value"},
		LastChecked: time.Now(),
	}

	if result.Provider != "test" {
		t.Errorf("Expected provider 'test', got %s", result.Provider)
	}
	if !result.Detected {
		t.Error("Expected Detected to be true")
	}
	if len(result.Categories) != 2 {
		t.Errorf("Expected 2 categories, got %d", len(result.Categories))
	}
}

// Mock provider for testing
type mockProvider struct {
	name      string
	available bool
	result    *Result
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) IsAvailable() bool {
	return m.available
}

func (m *mockProvider) Check(ctx context.Context, domain string) *Result {
	if m.result != nil {
		return m.result
	}
	return &Result{
		Provider:    m.name,
		Detected:    false,
		LastChecked: time.Now(),
	}
}

func TestURLVoidName(t *testing.T) {
	uv := NewURLVoid(URLVoidConfig{})
	if uv.Name() != "urlvoid" {
		t.Errorf("Expected name 'urlvoid', got %s", uv.Name())
	}
}

func TestURLVoidIsAvailable(t *testing.T) {
	// Without API key
	uv := NewURLVoid(URLVoidConfig{})
	if uv.IsAvailable() {
		t.Error("Expected IsAvailable to be false without API key")
	}

	// With API key
	uv = NewURLVoid(URLVoidConfig{APIKey: "test-key"})
	if !uv.IsAvailable() {
		t.Error("Expected IsAvailable to be true with API key")
	}
}

func TestURLVoidCheckNoAPIKey(t *testing.T) {
	uv := NewURLVoid(URLVoidConfig{})
	result := uv.Check(context.Background(), "example.com")

	if result.Error == "" {
		t.Error("Expected error without API key")
	}
}

func TestVirusTotalName(t *testing.T) {
	vt := NewVirusTotal(VirusTotalConfig{})
	if vt.Name() != "vt" {
		t.Errorf("Expected name 'vt', got %s", vt.Name())
	}
}

func TestVirusTotalIsAvailable(t *testing.T) {
	// Without API key
	vt := NewVirusTotal(VirusTotalConfig{})
	if vt.IsAvailable() {
		t.Error("Expected IsAvailable to be false without API key")
	}

	// With API key
	vt = NewVirusTotal(VirusTotalConfig{APIKey: "test-key"})
	if !vt.IsAvailable() {
		t.Error("Expected IsAvailable to be true with API key")
	}
}

func TestVirusTotalCheckNoAPIKey(t *testing.T) {
	vt := NewVirusTotal(VirusTotalConfig{})
	result := vt.Check(context.Background(), "example.com")

	if result.Error == "" {
		t.Error("Expected error without API key")
	}
}

func TestVirusTotalCheckMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers
		if r.Header.Get("x-apikey") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		response := `{
			"data": {
				"attributes": {
					"last_analysis_stats": {
						"malicious": 0,
						"suspicious": 0,
						"harmless": 70,
						"undetected": 5
					},
					"categories": {},
					"registrar": "Example Registrar",
					"reputation": 0
				}
			}
		}`
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	vt := &VirusTotal{
		apiKey:  "test-key",
		baseURL: server.URL,
		client:  &http.Client{Timeout: 5 * time.Second},
	}

	result := vt.Check(context.Background(), "example.com")

	if result.Error != "" {
		t.Errorf("Unexpected error: %s", result.Error)
	}
	if result.Detected {
		t.Error("Expected Detected to be false")
	}
	if result.Score != "0/75" {
		t.Errorf("Expected score '0/75', got %s", result.Score)
	}
}

func TestExtractXMLValue(t *testing.T) {
	tests := []struct {
		name     string
		xml      string
		tag      string
		expected string
	}{
		{"simple value", "<ip>1.2.3.4</ip>", "ip", "1.2.3.4"},
		{"nested", "<root><ip>1.2.3.4</ip></root>", "ip", "1.2.3.4"},
		{"not found", "<other>value</other>", "ip", ""},
		{"empty value", "<ip></ip>", "ip", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractXMLValue(tt.xml, tt.tag)
			if result != tt.expected {
				t.Errorf("extractXMLValue() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestManagerCheck(t *testing.T) {
	manager := NewManager()
	provider := &mockProvider{
		name:      "test",
		available: true,
		result: &Result{
			Provider: "test",
			Detected: false,
			Score:    "0/10",
		},
	}
	manager.Register(provider)

	results := manager.Check(context.Background(), "example.com", []string{"test"})

	if len(results.Results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results.Results))
	}
	if results.Results[0].Provider != "test" {
		t.Errorf("Expected provider 'test', got %s", results.Results[0].Provider)
	}
}

func TestManagerCheckNonExistent(t *testing.T) {
	manager := NewManager()

	results := manager.Check(context.Background(), "example.com", []string{"nonexistent"})

	if len(results.Results) != 0 {
		t.Errorf("Expected 0 results for non-existent provider, got %d", len(results.Results))
	}
}

func TestSecurityHeadersName(t *testing.T) {
	sh := NewSecurityHeaders(SecurityHeadersConfig{})
	if sh.Name() != "securityheaders" {
		t.Errorf("Expected name 'securityheaders', got %s", sh.Name())
	}
}

func TestSecurityHeadersIsAvailable(t *testing.T) {
	// SecurityHeaders does not require an API key
	sh := NewSecurityHeaders(SecurityHeadersConfig{})
	if !sh.IsAvailable() {
		t.Error("Expected IsAvailable to be true (no API key required)")
	}
}

func TestSecurityHeadersCheckMockServerJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify query parameters include hide=on for privacy
		if !strings.Contains(r.URL.RawQuery, "hide=on") {
			t.Error("Expected hide=on parameter for privacy")
		}

		w.Header().Set("Content-Type", "application/json")
		response := `{
			"grade": "A",
			"score": 90,
			"headers": {
				"Content-Security-Policy": true,
				"X-Frame-Options": true,
				"X-Content-Type-Options": true,
				"Strict-Transport-Security": true,
				"Referrer-Policy": false,
				"Permissions-Policy": false
			},
			"url": "https://example.com"
		}`
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	sh := &SecurityHeaders{
		baseURL: server.URL,
		client:  &http.Client{Timeout: 5 * time.Second},
	}

	result := sh.Check(context.Background(), "example.com")

	if result.Error != "" {
		t.Errorf("Unexpected error: %s", result.Error)
	}
	if result.Score != "A" {
		t.Errorf("Expected score 'A', got %s", result.Score)
	}
	if result.Detected {
		t.Error("Expected Detected to be false for grade A")
	}
	if result.Details["Content-Security-Policy"] != "present" {
		t.Errorf("Expected CSP to be present, got %s", result.Details["Content-Security-Policy"])
	}
	if result.Details["Referrer-Policy"] != "missing" {
		t.Errorf("Expected Referrer-Policy to be missing, got %s", result.Details["Referrer-Policy"])
	}
}

func TestSecurityHeadersCheckMockServerGradeF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{
			"grade": "F",
			"score": 10,
			"headers": {
				"Content-Security-Policy": false,
				"X-Frame-Options": false,
				"Strict-Transport-Security": false
			}
		}`
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	sh := &SecurityHeaders{
		baseURL: server.URL,
		client:  &http.Client{Timeout: 5 * time.Second},
	}

	result := sh.Check(context.Background(), "example.com")

	if result.Error != "" {
		t.Errorf("Unexpected error: %s", result.Error)
	}
	if result.Score != "F" {
		t.Errorf("Expected score 'F', got %s", result.Score)
	}
	if !result.Detected {
		t.Error("Expected Detected to be true for grade F (security issues)")
	}
	if len(result.Categories) != 3 {
		t.Errorf("Expected 3 missing header categories, got %d", len(result.Categories))
	}
}

func TestSecurityHeadersCheckHTMLFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		html := `<html><body><div class="grade_b">B</div></body></html>`
		_, _ = w.Write([]byte(html))
	}))
	defer server.Close()

	sh := &SecurityHeaders{
		baseURL: server.URL,
		client:  &http.Client{Timeout: 5 * time.Second},
	}

	result := sh.Check(context.Background(), "example.com")

	if result.Score != "B" {
		t.Errorf("Expected score 'B' from HTML fallback, got %s", result.Score)
	}
	if !result.Detected {
		t.Error("Expected Detected to be true for grade B")
	}
}

func TestSecurityHeadersCheckServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	sh := &SecurityHeaders{
		baseURL: server.URL,
		client:  &http.Client{Timeout: 5 * time.Second},
	}

	result := sh.Check(context.Background(), "example.com")

	if result.Error == "" {
		t.Error("Expected error for server error response")
	}
}

func TestSecurityHeadersDefaultTimeout(t *testing.T) {
	sh := NewSecurityHeaders(SecurityHeadersConfig{})
	// Default timeout should be set
	if sh.client.Timeout != 30*time.Second {
		t.Errorf("Expected default timeout of 30s, got %v", sh.client.Timeout)
	}
}

func TestSecurityHeadersCustomTimeout(t *testing.T) {
	sh := NewSecurityHeaders(SecurityHeadersConfig{Timeout: 60 * time.Second})
	if sh.client.Timeout != 60*time.Second {
		t.Errorf("Expected custom timeout of 60s, got %v", sh.client.Timeout)
	}
}

func TestParseSecurityHeadersHTML(t *testing.T) {
	tests := []struct {
		name           string
		html           string
		expectedGrade  string
		expectedDetect bool
	}{
		{
			name:           "grade A+ class",
			html:           `<div class="grade_a_plus">A+</div>`,
			expectedGrade:  "A+",
			expectedDetect: false,
		},
		{
			name:           "grade A class",
			html:           `<div class="grade_a">A</div>`,
			expectedGrade:  "A",
			expectedDetect: false,
		},
		{
			name:           "grade F class",
			html:           `<div class="grade_f">F</div>`,
			expectedGrade:  "F",
			expectedDetect: true,
		},
		{
			name:           "grade-b style",
			html:           `<span class="grade-b">B</span>`,
			expectedGrade:  "B",
			expectedDetect: true,
		},
		{
			name:           "no grade found",
			html:           `<html><body>No grade here</body></html>`,
			expectedGrade:  "",
			expectedDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &Result{
				Provider:    "securityheaders",
				LastChecked: time.Now(),
				Details:     make(map[string]string),
			}
			result = parseSecurityHeadersHTML(tt.html, result)

			if result.Score != tt.expectedGrade {
				t.Errorf("Expected grade %q, got %q", tt.expectedGrade, result.Score)
			}
			if result.Detected != tt.expectedDetect {
				t.Errorf("Expected Detected=%v, got %v", tt.expectedDetect, result.Detected)
			}
		})
	}
}

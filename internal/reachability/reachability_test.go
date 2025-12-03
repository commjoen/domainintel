package reachability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewChecker(t *testing.T) {
	// Test with zero timeout (should use default)
	checker := NewChecker(0)
	if checker.timeout != defaultTimeout {
		t.Errorf("Expected default timeout %v, got %v", defaultTimeout, checker.timeout)
	}

	// Test with custom timeout
	customTimeout := 60 * time.Second
	checker = NewChecker(customTimeout)
	if checker.timeout != customTimeout {
		t.Errorf("Expected custom timeout %v, got %v", customTimeout, checker.timeout)
	}
}

func TestCheckHTTP(t *testing.T) {
	tests := []struct {
		name           string
		serverHandler  func(w http.ResponseWriter, r *http.Request)
		expectedStatus int
		expectError    bool
	}{
		{
			name: "successful 200 response",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			},
			expectedStatus: 200,
			expectError:    false,
		},
		{
			name: "404 response",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectedStatus: 404,
			expectError:    false,
		},
		{
			name: "500 response",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedStatus: 500,
			expectError:    false,
		},
		{
			name: "redirect response",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					http.Redirect(w, r, "/redirected", http.StatusMovedPermanently)
					return
				}
				w.WriteHeader(http.StatusOK)
			},
			expectedStatus: 200,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.serverHandler))
			defer server.Close()

			checker := NewChecker(10 * time.Second)
			result := checker.CheckHTTP(context.Background(), server.URL)

			if tt.expectError && result.Error == "" {
				t.Error("Expected error, got none")
			}

			if !tt.expectError && result.Error != "" {
				t.Errorf("Unexpected error: %s", result.Error)
			}

			if !tt.expectError && result.Status != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, result.Status)
			}

			// ResponseTimeMs may be 0 for very fast local responses, so we just check it's non-negative
			if result.ResponseTimeMs < 0 {
				t.Error("Expected non-negative response time")
			}
		})
	}
}

func TestCheckHTTPError(t *testing.T) {
	checker := NewChecker(1 * time.Second)

	// Test with invalid URL
	result := checker.CheckHTTP(context.Background(), "http://invalid.local.domain.test:99999")
	if result.Error == "" {
		t.Error("Expected error for invalid URL")
	}
}

func TestCategorizeError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected string
	}{
		{
			name:     "connection refused",
			errMsg:   "dial tcp: connection refused",
			expected: "connection refused",
		},
		{
			name:     "no such host",
			errMsg:   "dial tcp: lookup invalid.domain: no such host",
			expected: "DNS resolution failed",
		},
		{
			name:     "timeout",
			errMsg:   "dial tcp: i/o timeout",
			expected: "connection timeout",
		},
		{
			name:     "context deadline",
			errMsg:   "context deadline exceeded",
			expected: "request timeout",
		},
		{
			name:     "certificate error",
			errMsg:   "certificate has expired",
			expected: "TLS error: certificate has expired",
		},
		{
			name:     "x509 error",
			errMsg:   "x509: certificate signed by unknown authority",
			expected: "certificate error: x509: certificate signed by unknown authority",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := categorizeError(&testError{msg: tt.errMsg})
			if result != tt.expected {
				t.Errorf("categorizeError() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestNewResolver(t *testing.T) {
	// Test with zero timeout (should use default)
	resolver := NewResolver(0)
	if resolver.timeout != resolverTimeout {
		t.Errorf("Expected default timeout %v, got %v", resolverTimeout, resolver.timeout)
	}

	// Test with custom timeout
	customTimeout := 60 * time.Second
	resolver = NewResolver(customTimeout)
	if resolver.timeout != customTimeout {
		t.Errorf("Expected custom timeout %v, got %v", customTimeout, resolver.timeout)
	}
}

// Note: DNS resolution tests are skipped in CI as they require network access
// and may have inconsistent results depending on the DNS resolver configuration.

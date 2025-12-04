// Package providers provides third-party reputation service integrations
package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SecurityHeaders is a provider for SecurityHeaders.com security header checks
type SecurityHeaders struct {
	baseURL string
	client  *http.Client
}

// SecurityHeadersConfig contains configuration for the SecurityHeaders provider
type SecurityHeadersConfig struct {
	Timeout time.Duration
}

// NewSecurityHeaders creates a new SecurityHeaders provider
// This provider does not require an API key
func NewSecurityHeaders(config SecurityHeadersConfig) *SecurityHeaders {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &SecurityHeaders{
		baseURL: "https://securityheaders.com",
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the provider identifier
func (s *SecurityHeaders) Name() string {
	return "securityheaders"
}

// IsAvailable returns true since this provider does not require an API key
func (s *SecurityHeaders) IsAvailable() bool {
	return true
}

// Check queries SecurityHeaders.com for security header analysis of a domain
func (s *SecurityHeaders) Check(ctx context.Context, domain string) *Result {
	result := &Result{
		Provider:    s.Name(),
		LastChecked: time.Now(),
		Details:     make(map[string]string),
	}

	// Build request URL with hide=on to disable tracking and followRedirects=false
	// The hide=on parameter ensures the scan is not tracked publicly
	targetURL := fmt.Sprintf("https://%s", domain)
	reqURL := fmt.Sprintf("%s/?q=%s&followRedirects=false&hide=on",
		s.baseURL, url.QueryEscape(targetURL))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result
	}
	req.Header.Set("User-Agent", "domainintel/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("API error: %s", resp.Status)
		return result
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read response: %v", err)
		return result
	}

	// Parse the JSON response
	var shResponse securityHeadersResponse
	if err := json.Unmarshal(body, &shResponse); err != nil {
		// If JSON parsing fails, try to extract grade from HTML response
		result = parseSecurityHeadersHTML(string(body), result)
		return result
	}

	// Extract grade and header information from JSON response
	result.Score = shResponse.Grade
	result.Detected = shResponse.Grade != "" && shResponse.Grade != "A+" && shResponse.Grade != "A"

	// Add header presence details
	for header, present := range shResponse.Headers {
		if present {
			result.Details[header] = "present"
		} else {
			result.Details[header] = "missing"
		}
	}

	// Add categories for missing headers (potential security issues)
	for header, present := range shResponse.Headers {
		if !present {
			result.Categories = append(result.Categories, fmt.Sprintf("missing: %s", header))
		}
	}

	return result
}

// securityHeadersResponse represents the SecurityHeaders.com API response structure
type securityHeadersResponse struct {
	Grade   string          `json:"grade"`
	Score   int             `json:"score"`
	Headers map[string]bool `json:"headers"`
	URL     string          `json:"url"`
}

// parseSecurityHeadersHTML attempts to parse grade from HTML response
// This is a fallback for when JSON response is not available
func parseSecurityHeadersHTML(html string, result *Result) *Result {
	// Look for grade indicators in the HTML
	gradePatterns := []struct {
		marker string
		grade  string
	}{
		{"class=\"grade_a_plus\"", "A+"},
		{"class=\"grade_a\"", "A"},
		{"class=\"grade_b\"", "B"},
		{"class=\"grade_c\"", "C"},
		{"class=\"grade_d\"", "D"},
		{"class=\"grade_e\"", "E"},
		{"class=\"grade_f\"", "F"},
		{"grade-a-plus", "A+"},
		{"grade-a", "A"},
		{"grade-b", "B"},
		{"grade-c", "C"},
		{"grade-d", "D"},
		{"grade-e", "E"},
		{"grade-f", "F"},
	}

	htmlLower := strings.ToLower(html)
	for _, pattern := range gradePatterns {
		if strings.Contains(htmlLower, strings.ToLower(pattern.marker)) {
			result.Score = pattern.grade
			result.Detected = pattern.grade != "A+" && pattern.grade != "A"
			break
		}
	}

	// Extract security header presence from HTML
	headerNames := []string{
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Strict-Transport-Security",
		"Referrer-Policy",
		"Permissions-Policy",
		"X-XSS-Protection",
	}

	for _, header := range headerNames {
		// Check for presence/absence markers
		if strings.Contains(html, header) {
			if strings.Contains(html, fmt.Sprintf("%s</td><td class=\"present\"", header)) ||
				strings.Contains(html, fmt.Sprintf("%s</span>", header)) {
				result.Details[header] = "present"
			} else if strings.Contains(html, fmt.Sprintf("%s</td><td class=\"missing\"", header)) {
				result.Details[header] = "missing"
				result.Categories = append(result.Categories, fmt.Sprintf("missing: %s", header))
			}
		}
	}

	if result.Score == "" {
		result.Error = "could not parse security headers response"
	}

	return result
}

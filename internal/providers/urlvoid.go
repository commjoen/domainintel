// Package providers provides third-party reputation service integrations
package providers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// URLVoid is a provider for URLVoid reputation checks
type URLVoid struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// URLVoidConfig contains configuration for the URLVoid provider
type URLVoidConfig struct {
	APIKey  string
	Timeout time.Duration
}

// NewURLVoid creates a new URLVoid provider
func NewURLVoid(config URLVoidConfig) *URLVoid {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &URLVoid{
		apiKey:  config.APIKey,
		baseURL: "https://api.urlvoid.com/api1000/",
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the provider identifier
func (u *URLVoid) Name() string {
	return "urlvoid"
}

// IsAvailable returns true if the provider is configured
func (u *URLVoid) IsAvailable() bool {
	return u.apiKey != ""
}

// Check queries URLVoid for reputation information about a domain
func (u *URLVoid) Check(ctx context.Context, domain string) *Result {
	result := &Result{
		Provider:    u.Name(),
		LastChecked: time.Now(),
		Details:     make(map[string]string),
	}

	if !u.IsAvailable() {
		result.Error = "URLVoid API key not configured"
		return result
	}

	// Build request URL
	reqURL := fmt.Sprintf("%s%s/host/%s/", u.baseURL, u.apiKey, url.PathEscape(domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result
	}
	req.Header.Set("User-Agent", "domainintel/1.0")

	resp, err := u.client.Do(req)
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

	// Parse the XML/JSON response
	// URLVoid returns XML by default, but we'll handle the response structure
	// For simplicity, we'll extract key information from the response
	responseStr := string(body)

	// Check for detection
	if strings.Contains(responseStr, "<blacklists>") {
		// Extract blacklist count
		if strings.Contains(responseStr, "<detections>0</detections>") {
			result.Detected = false
			result.Score = "0/0"
		} else {
			result.Detected = true
			// Try to extract detection count
			result.Score = "detected"
		}
	}

	// Extract additional details if available
	if strings.Contains(responseStr, "<ip>") {
		result.Details["resolved_ip"] = extractXMLValue(responseStr, "ip")
	}
	if strings.Contains(responseStr, "<country_code>") {
		result.Details["country"] = extractXMLValue(responseStr, "country_code")
	}

	return result
}

// extractXMLValue is a simple XML value extractor
func extractXMLValue(xml, tag string) string {
	startTag := "<" + tag + ">"
	endTag := "</" + tag + ">"
	startIdx := strings.Index(xml, startTag)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(startTag)
	endIdx := strings.Index(xml[startIdx:], endTag)
	if endIdx == -1 {
		return ""
	}
	return xml[startIdx : startIdx+endIdx]
}

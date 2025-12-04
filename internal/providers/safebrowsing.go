// Package providers provides third-party reputation service integrations
package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SafeBrowsing is a provider for Google Safe Browsing API checks
type SafeBrowsing struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// SafeBrowsingConfig contains configuration for the Safe Browsing provider
type SafeBrowsingConfig struct {
	APIKey  string
	Timeout time.Duration
}

// NewSafeBrowsing creates a new Safe Browsing provider
func NewSafeBrowsing(config SafeBrowsingConfig) *SafeBrowsing {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &SafeBrowsing{
		apiKey:  config.APIKey,
		baseURL: "https://safebrowsing.googleapis.com/v4",
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the provider identifier
func (s *SafeBrowsing) Name() string {
	return "safebrowsing"
}

// IsAvailable returns true if the provider is configured
func (s *SafeBrowsing) IsAvailable() bool {
	return s.apiKey != ""
}

// Check queries Google Safe Browsing API for the domain
func (s *SafeBrowsing) Check(ctx context.Context, domain string) *Result {
	result := &Result{
		Provider:    s.Name(),
		LastChecked: time.Now(),
		Details:     make(map[string]string),
		Categories:  make([]string, 0),
	}

	if !s.IsAvailable() {
		result.Error = "Google Safe Browsing API key not configured"
		return result
	}

	// Build the request
	reqURL := fmt.Sprintf("%s/threatMatches:find?key=%s", s.baseURL, s.apiKey)

	// Create the request body according to Google Safe Browsing API v4
	requestBody := safeBrowsingRequest{
		Client: safeBrowsingClient{
			ClientID:      "domainintel",
			ClientVersion: "1.0.0",
		},
		ThreatInfo: safeBrowsingThreatInfo{
			ThreatTypes: []string{
				"MALWARE",
				"SOCIAL_ENGINEERING",
				"UNWANTED_SOFTWARE",
				"POTENTIALLY_HARMFUL_APPLICATION",
			},
			PlatformTypes: []string{
				"ANY_PLATFORM",
			},
			ThreatEntryTypes: []string{
				"URL",
			},
			ThreatEntries: []safeBrowsingThreatEntry{
				{URL: "http://" + domain + "/"},
				{URL: "https://" + domain + "/"},
			},
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		result.Error = fmt.Sprintf("failed to marshal request: %v", err)
		return result
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(jsonBody))
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		result.Error = "Google Safe Browsing API rate limit exceeded"
		return result
	}

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("API error: %s", resp.Status)
		return result
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read response: %v", err)
		return result
	}

	// Parse response
	var sbResponse safeBrowsingResponse
	if err := json.Unmarshal(body, &sbResponse); err != nil {
		result.Error = fmt.Sprintf("failed to parse response: %v", err)
		return result
	}

	// Check if matches were found
	if len(sbResponse.Matches) == 0 {
		result.Detected = false
		result.Score = "0/1"
		return result
	}

	// Domain has threats
	result.Detected = true
	result.Score = fmt.Sprintf("%d/1", len(sbResponse.Matches))

	// Extract threat types
	seenTypes := make(map[string]bool)
	for _, match := range sbResponse.Matches {
		if !seenTypes[match.ThreatType] {
			result.Categories = append(result.Categories, match.ThreatType)
			seenTypes[match.ThreatType] = true
		}
		result.Details[match.ThreatType] = match.PlatformType
	}

	return result
}

// Request structures for Google Safe Browsing API
type safeBrowsingRequest struct {
	Client     safeBrowsingClient     `json:"client"`
	ThreatInfo safeBrowsingThreatInfo `json:"threatInfo"`
}

type safeBrowsingClient struct {
	ClientID      string `json:"clientId"`
	ClientVersion string `json:"clientVersion"`
}

type safeBrowsingThreatInfo struct {
	ThreatTypes      []string                  `json:"threatTypes"`
	PlatformTypes    []string                  `json:"platformTypes"`
	ThreatEntryTypes []string                  `json:"threatEntryTypes"`
	ThreatEntries    []safeBrowsingThreatEntry `json:"threatEntries"`
}

type safeBrowsingThreatEntry struct {
	URL string `json:"url"`
}

// Response structures for Google Safe Browsing API
type safeBrowsingResponse struct {
	Matches []safeBrowsingMatch `json:"matches"`
}

type safeBrowsingMatch struct {
	ThreatType      string                  `json:"threatType"`
	PlatformType    string                  `json:"platformType"`
	ThreatEntryType string                  `json:"threatEntryType"`
	Threat          safeBrowsingThreatEntry `json:"threat"`
	CacheDuration   string                  `json:"cacheDuration"`
}

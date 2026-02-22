// Package providers provides third-party reputation service integrations
package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// VirusTotal is a provider for VirusTotal reputation checks
type VirusTotal struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// VirusTotalConfig contains configuration for the VirusTotal provider
type VirusTotalConfig struct {
	APIKey  string // #nosec G117
	Timeout time.Duration
}

// NewVirusTotal creates a new VirusTotal provider
func NewVirusTotal(config VirusTotalConfig) *VirusTotal {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &VirusTotal{
		apiKey:  config.APIKey,
		baseURL: "https://www.virustotal.com/api/v3",
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the provider identifier
func (v *VirusTotal) Name() string {
	return "vt"
}

// IsAvailable returns true if the provider is configured
func (v *VirusTotal) IsAvailable() bool {
	return v.apiKey != ""
}

// Check queries VirusTotal for reputation information about a domain
func (v *VirusTotal) Check(ctx context.Context, domain string) *Result {
	result := &Result{
		Provider:    v.Name(),
		LastChecked: time.Now(),
		Details:     make(map[string]string),
	}

	if !v.IsAvailable() {
		result.Error = "VirusTotal API key not configured"
		return result
	}

	// Build request URL
	reqURL := fmt.Sprintf("%s/domains/%s", v.baseURL, url.PathEscape(domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result
	}
	req.Header.Set("x-apikey", v.apiKey)
	req.Header.Set("Accept", "application/json")

	// #nosec G704 - URL is from hardcoded VirusTotal API with validated domain parameter
	resp, err := v.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		result.Error = "domain not found in VirusTotal database"
		return result
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		result.Error = "VirusTotal rate limit exceeded"
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

	// Parse the response
	var vtResponse virusTotalResponse
	if err := json.Unmarshal(body, &vtResponse); err != nil {
		result.Error = fmt.Sprintf("failed to parse response: %v", err)
		return result
	}

	// Extract analysis stats
	stats := vtResponse.Data.Attributes.LastAnalysisStats
	malicious := stats.Malicious
	suspicious := stats.Suspicious
	total := malicious + suspicious + stats.Harmless + stats.Undetected

	result.Detected = malicious > 0 || suspicious > 0
	result.Score = fmt.Sprintf("%d/%d", malicious+suspicious, total)

	// Extract categories
	for engine, category := range vtResponse.Data.Attributes.Categories {
		result.Categories = append(result.Categories, fmt.Sprintf("%s: %s", engine, category))
	}

	// Extract additional details
	if vtResponse.Data.Attributes.Registrar != "" {
		result.Details["registrar"] = vtResponse.Data.Attributes.Registrar
	}
	if vtResponse.Data.Attributes.CreationDate > 0 {
		creationTime := time.Unix(vtResponse.Data.Attributes.CreationDate, 0)
		result.Details["creation_date"] = creationTime.Format(time.RFC3339)
	}
	if vtResponse.Data.Attributes.Reputation != 0 {
		result.Details["reputation"] = fmt.Sprintf("%d", vtResponse.Data.Attributes.Reputation)
	}

	return result
}

// virusTotalResponse represents the VirusTotal API response structure
type virusTotalResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			Categories   map[string]string `json:"categories"`
			Registrar    string            `json:"registrar"`
			CreationDate int64             `json:"creation_date"`
			Reputation   int               `json:"reputation"`
		} `json:"attributes"`
	} `json:"data"`
}

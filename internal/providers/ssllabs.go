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

// SSLLabs is a provider for SSL Labs SSL/TLS analysis
type SSLLabs struct {
	baseURL string
	client  *http.Client
}

// SSLLabsConfig contains configuration for the SSL Labs provider
type SSLLabsConfig struct {
	Timeout time.Duration
}

// NewSSLLabs creates a new SSL Labs provider
func NewSSLLabs(config SSLLabsConfig) *SSLLabs {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &SSLLabs{
		baseURL: "https://api.ssllabs.com/api/v3",
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the provider identifier
func (s *SSLLabs) Name() string {
	return "ssllabs"
}

// IsAvailable returns true if the provider is ready to use
// SSL Labs is a free public API, so it's always available
func (s *SSLLabs) IsAvailable() bool {
	return true
}

// Check queries SSL Labs for SSL/TLS analysis of a domain
func (s *SSLLabs) Check(ctx context.Context, domain string) *Result {
	result := &Result{
		Provider:    s.Name(),
		LastChecked: time.Now(),
		Details:     make(map[string]string),
	}

	// Build request URL for analyze endpoint
	// Use startNew=off to get cached results if available
	// Use fromCache=on to prefer cached results
	// Use all=done to only return when analysis is complete
	reqURL := fmt.Sprintf("%s/analyze?host=%s&startNew=off&fromCache=on&maxAge=24",
		s.baseURL, url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result
	}
	req.Header.Set("User-Agent", "domainintel/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	// Handle rate limiting
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		result.Error = "SSL Labs rate limit exceeded, please try again later"
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
	var sslResponse sslLabsResponse
	if err := json.Unmarshal(body, &sslResponse); err != nil {
		result.Error = fmt.Sprintf("failed to parse response: %v", err)
		return result
	}

	// Handle different status values
	switch sslResponse.Status {
	case "DNS":
		result.Error = "DNS resolution in progress"
		return result
	case "ERROR":
		result.Error = fmt.Sprintf("analysis error: %s", sslResponse.StatusMessage)
		return result
	case "IN_PROGRESS":
		result.Error = "analysis in progress, try again later"
		return result
	case "READY":
		// Analysis complete, parse results
	default:
		result.Error = fmt.Sprintf("unknown status: %s", sslResponse.Status)
		return result
	}

	// Extract information from endpoints
	if len(sslResponse.Endpoints) == 0 {
		result.Error = "no endpoints found"
		return result
	}

	// Get the best (or worst) grade from all endpoints
	var grades []string
	var hasIssues bool
	for _, ep := range sslResponse.Endpoints {
		if ep.Grade != "" {
			grades = append(grades, ep.Grade)
			// Consider anything below A as having issues
			if ep.Grade != "A" && ep.Grade != "A+" {
				hasIssues = true
			}
		}
		if ep.HasWarnings || ep.StatusMessage != "Ready" {
			hasIssues = true
		}
	}

	if len(grades) > 0 {
		result.Score = grades[0]
		if len(grades) > 1 {
			result.Details["all_grades"] = fmt.Sprintf("%v", grades)
		}
	}

	// Mark as detected if there are SSL/TLS issues
	result.Detected = hasIssues

	// Add additional details
	result.Details["host"] = sslResponse.Host
	if sslResponse.Protocol != "" {
		result.Details["protocol"] = sslResponse.Protocol
	}

	// Extract endpoint details
	if len(sslResponse.Endpoints) > 0 {
		ep := sslResponse.Endpoints[0]
		if ep.IPAddress != "" {
			result.Details["ip_address"] = ep.IPAddress
		}
		if ep.ServerName != "" {
			result.Details["server_name"] = ep.ServerName
		}
		if ep.StatusMessage != "" {
			result.Details["status"] = ep.StatusMessage
		}
		if ep.Delegation > 0 {
			result.Details["delegation"] = fmt.Sprintf("%d", ep.Delegation)
		}
	}

	return result
}

// sslLabsResponse represents the SSL Labs API response structure
type sslLabsResponse struct {
	Host          string             `json:"host"`
	Port          int                `json:"port"`
	Protocol      string             `json:"protocol"`
	Status        string             `json:"status"`
	StatusMessage string             `json:"statusMessage"`
	StartTime     int64              `json:"startTime"`
	TestTime      int64              `json:"testTime"`
	EngineVersion string             `json:"engineVersion"`
	Endpoints     []sslLabsEndpoint  `json:"endpoints"`
	CertChains    []sslLabsCertChain `json:"certChains"`
}

// sslLabsEndpoint represents an endpoint in the SSL Labs response
type sslLabsEndpoint struct {
	IPAddress         string `json:"ipAddress"`
	ServerName        string `json:"serverName"`
	StatusMessage     string `json:"statusMessage"`
	Grade             string `json:"grade"`
	GradeTrustIgnored string `json:"gradeTrustIgnored"`
	HasWarnings       bool   `json:"hasWarnings"`
	IsExceptional     bool   `json:"isExceptional"`
	Progress          int    `json:"progress"`
	Duration          int    `json:"duration"`
	Delegation        int    `json:"delegation"`
}

// sslLabsCertChain represents a certificate chain in the SSL Labs response
type sslLabsCertChain struct {
	ID         string             `json:"id"`
	CertIDs    []string           `json:"certIds"`
	TrustPaths []sslLabsTrustPath `json:"trustPaths"`
	Issues     int                `json:"issues"`
	NoSNI      bool               `json:"noSni"`
}

// sslLabsTrustPath represents a trust path in the SSL Labs response
type sslLabsTrustPath struct {
	CertIDs []string       `json:"certIds"`
	Trust   []sslLabsTrust `json:"trust"`
}

// sslLabsTrust represents trust information
type sslLabsTrust struct {
	RootStore         string `json:"rootStore"`
	IsTrusted         bool   `json:"isTrusted"`
	TrustErrorMessage string `json:"trustErrorMessage"`
}

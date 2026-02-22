// Package crt provides Certificate Transparency log query functionality
package crt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/commjoen/domainintel/pkg/models"
)

const (
	crtshBaseURL   = "https://crt.sh"
	defaultTimeout = 30 * time.Second
	maxRetries     = 3
	retryDelay     = 2 * time.Second
)

// domainRegex validates RFC 1035 compliant domain names
var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// wildcardRegex matches wildcard entries like *.example.com
var wildcardRegex = regexp.MustCompile(`^\*\.`)

// inputWildcardRegex matches user input wildcard patterns like *.domain.com or *domain.com
var inputWildcardRegex = regexp.MustCompile(`^\*\.?`)

// Client provides methods to query Certificate Transparency logs
type Client struct {
	httpClient *http.Client
	timeout    time.Duration
}

// NewClient creates a new CRT client with the specified timeout
func NewClient(timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

// ValidateDomain checks if the domain is a valid RFC 1035 compliant domain name
func ValidateDomain(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain name too long (max 253 characters)")
	}
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}
	return nil
}

// NormalizeDomain strips wildcard prefixes (* or *.) from domain input
// and returns the base domain for querying
func NormalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	// Remove wildcard prefix patterns like "*." or "*"
	return inputWildcardRegex.ReplaceAllString(domain, "")
}

// QuerySubdomains queries crt.sh for subdomains of the given domain
func (c *Client) QuerySubdomains(ctx context.Context, domain string) ([]string, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, err
	}

	entries, err := c.queryCRTsh(ctx, domain)
	if err != nil {
		return nil, err
	}

	return extractSubdomains(entries, domain), nil
}

// queryCRTsh makes the actual HTTP request to crt.sh
func (c *Client) queryCRTsh(ctx context.Context, domain string) ([]models.CRTEntry, error) {
	// URL-encode the domain parameter safely
	escapedDomain := url.QueryEscape("%." + domain)
	queryURL := fmt.Sprintf("%s/?q=%s&output=json", crtshBaseURL, escapedDomain)

	var entries []models.CRTEntry
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryDelay * time.Duration(attempt)):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("User-Agent", "domainintel/1.0")
		req.Header.Set("Accept", "application/json")

		// #nosec G704 - URL is safely constructed from hardcoded base URL and properly escaped domain
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("crt.sh HTTP %d: rate limited", resp.StatusCode)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("crt.sh HTTP %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode))
			continue
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			continue
		}

		// Handle empty response (no certificates found)
		if len(body) == 0 || string(body) == "null" {
			return []models.CRTEntry{}, nil
		}

		if err := json.Unmarshal(body, &entries); err != nil {
			lastErr = fmt.Errorf("failed to parse JSON response: %w", err)
			continue
		}

		return entries, nil
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr)
}

// extractSubdomains processes CRT entries and returns unique subdomains
func extractSubdomains(entries []models.CRTEntry, baseDomain string) []string {
	seen := make(map[string]bool)
	var subdomains []string

	baseDomain = strings.ToLower(baseDomain)

	for _, entry := range entries {
		// Process common_name
		processHostname(entry.CommonName, baseDomain, seen, &subdomains)

		// Process name_value (may contain multiple hostnames separated by newlines)
		for _, name := range strings.Split(entry.NameValue, "\n") {
			processHostname(name, baseDomain, seen, &subdomains)
		}
	}

	sort.Strings(subdomains)
	return subdomains
}

// processHostname validates and adds a hostname to the result set
func processHostname(hostname, baseDomain string, seen map[string]bool, subdomains *[]string) {
	hostname = strings.TrimSpace(strings.ToLower(hostname))
	if hostname == "" {
		return
	}

	// Remove wildcard prefix if present
	hostname = wildcardRegex.ReplaceAllString(hostname, "")

	// Skip if already seen
	if seen[hostname] {
		return
	}

	// Ensure hostname is part of the base domain
	if !strings.HasSuffix(hostname, baseDomain) {
		return
	}

	// Validate the hostname format
	if !domainRegex.MatchString(hostname) {
		return
	}

	seen[hostname] = true
	*subdomains = append(*subdomains, hostname)
}

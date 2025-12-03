// Package whois provides WHOIS lookup functionality
package whois

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

const (
	defaultTimeout = 30 * time.Second
)

// WHOISResult contains parsed WHOIS information
type WHOISResult struct {
	Registrar        string     `json:"registrar,omitempty"`
	RegistrantName   string     `json:"registrant_name,omitempty"`
	RegistrantOrg    string     `json:"registrant_org,omitempty"`
	RegistrantEmail  string     `json:"registrant_email,omitempty"`
	CreationDate     *time.Time `json:"creation_date,omitempty"`
	ExpirationDate   *time.Time `json:"expiration_date,omitempty"`
	UpdatedDate      *time.Time `json:"updated_date,omitempty"`
	Nameservers      []string   `json:"nameservers,omitempty"`
	Status           []string   `json:"status,omitempty"`
	DNSSEC           string     `json:"dnssec,omitempty"`
	RawText          string     `json:"raw_text,omitempty"`
	Error            string     `json:"error,omitempty"`
}

// Client provides WHOIS lookup functionality with caching
type Client struct {
	timeout time.Duration
	cache   map[string]*cachedResult
	mu      sync.RWMutex
	ttl     time.Duration
}

type cachedResult struct {
	result    *WHOISResult
	timestamp time.Time
}

// NewClient creates a new WHOIS client with the specified timeout
func NewClient(timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return &Client{
		timeout: timeout,
		cache:   make(map[string]*cachedResult),
		ttl:     24 * time.Hour, // Cache WHOIS results for 24 hours
	}
}

// Lookup performs a WHOIS lookup for the given domain
func (c *Client) Lookup(ctx context.Context, domain string) *WHOISResult {
	// Normalize domain to base domain
	domain = extractBaseDomain(domain)
	if domain == "" {
		return &WHOISResult{Error: "invalid domain"}
	}

	// Check cache
	if result := c.getFromCache(domain); result != nil {
		return result
	}

	// Perform lookup
	result := c.performLookup(ctx, domain)

	// Cache the result
	c.saveToCache(domain, result)

	return result
}

// performLookup executes the actual WHOIS query
func (c *Client) performLookup(ctx context.Context, domain string) *WHOISResult {
	result := &WHOISResult{}

	// Create a channel for the result
	done := make(chan struct{})
	var rawWhois string
	var err error

	go func() {
		rawWhois, err = whois.Whois(domain)
		close(done)
	}()

	// Wait for result or context cancellation
	select {
	case <-ctx.Done():
		result.Error = "WHOIS lookup cancelled"
		return result
	case <-time.After(c.timeout):
		result.Error = "WHOIS lookup timeout"
		return result
	case <-done:
		// Continue processing
	}

	if err != nil {
		result.Error = categorizeError(err)
		return result
	}

	// Store raw text (truncated for storage efficiency)
	if len(rawWhois) > 5000 {
		result.RawText = rawWhois[:5000] + "...[truncated]"
	} else {
		result.RawText = rawWhois
	}

	// Parse the WHOIS response
	parsed, err := whoisparser.Parse(rawWhois)
	if err != nil {
		// Even if parsing fails, we have the raw text
		result.Error = fmt.Sprintf("parse error: %v", err)
		return result
	}

	// Extract domain information
	if parsed.Domain != nil {
		result.Nameservers = parsed.Domain.NameServers
		result.Status = parsed.Domain.Status
		if parsed.Domain.DNSSec {
			result.DNSSEC = "signed"
		} else {
			result.DNSSEC = "unsigned"
		}

		// Parse dates
		if parsed.Domain.CreatedDate != "" {
			if t, err := parseDate(parsed.Domain.CreatedDate); err == nil {
				result.CreationDate = &t
			}
		}
		if parsed.Domain.ExpirationDate != "" {
			if t, err := parseDate(parsed.Domain.ExpirationDate); err == nil {
				result.ExpirationDate = &t
			}
		}
		if parsed.Domain.UpdatedDate != "" {
			if t, err := parseDate(parsed.Domain.UpdatedDate); err == nil {
				result.UpdatedDate = &t
			}
		}
	}

	// Extract registrar information
	if parsed.Registrar != nil {
		result.Registrar = parsed.Registrar.Name
	}

	// Extract registrant information
	if parsed.Registrant != nil {
		result.RegistrantName = parsed.Registrant.Name
		result.RegistrantOrg = parsed.Registrant.Organization
		result.RegistrantEmail = parsed.Registrant.Email
	}

	return result
}

// getFromCache retrieves a cached result if valid
func (c *Client) getFromCache(domain string) *WHOISResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cached, ok := c.cache[domain]
	if !ok {
		return nil
	}

	// Check if cache entry is still valid
	if time.Since(cached.timestamp) > c.ttl {
		return nil
	}

	return cached.result
}

// saveToCache stores a result in the cache
func (c *Client) saveToCache(domain string, result *WHOISResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[domain] = &cachedResult{
		result:    result,
		timestamp: time.Now(),
	}
}

// ClearCache removes all cached entries
func (c *Client) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*cachedResult)
}

// extractBaseDomain returns the base domain from a subdomain
// e.g., "www.example.com" -> "example.com"
func extractBaseDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}

	// Remove protocol if present
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	// Remove path if present
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	// Remove port if present
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}

	// Handle special TLDs like .co.uk, .com.au, etc.
	specialTLDs := map[string]bool{
		"co.uk": true, "org.uk": true, "me.uk": true, "ltd.uk": true,
		"com.au": true, "net.au": true, "org.au": true,
		"co.nz": true, "net.nz": true, "org.nz": true,
		"co.jp": true, "ne.jp": true, "or.jp": true,
		"com.br": true, "net.br": true, "org.br": true,
	}

	if len(parts) >= 3 {
		lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if specialTLDs[lastTwo] {
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}

	// Return last two parts for standard TLDs
	return strings.Join(parts[len(parts)-2:], ".")
}

// parseDate attempts to parse a date string in various formats
func parseDate(dateStr string) (time.Time, error) {
	dateStr = strings.TrimSpace(dateStr)

	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"January 02, 2006",
		"02/01/2006",
		"01/02/2006",
		"2006/01/02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

// categorizeError converts WHOIS errors to user-friendly messages
func categorizeError(err error) string {
	if err == nil {
		return ""
	}

	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "timeout"):
		return "WHOIS server timeout"
	case strings.Contains(errStr, "connection refused"):
		return "WHOIS server connection refused"
	case strings.Contains(errStr, "no whois server"):
		return "no WHOIS server found for this TLD"
	case strings.Contains(errStr, "rate limit"):
		return "rate limited by WHOIS server"
	default:
		return errStr
	}
}

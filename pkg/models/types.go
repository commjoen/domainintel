// Package models contains shared data structures used across the application
package models

import "time"

// SubdomainResult represents the reconnaissance results for a single subdomain
type SubdomainResult struct {
	Hostname    string       `json:"hostname"`
	IPs         []string     `json:"ips"`
	HTTP        *HTTPResult  `json:"http,omitempty"`
	HTTPS       *HTTPResult  `json:"https,omitempty"`
	TLS         *TLSResult   `json:"tls,omitempty"`
	Reachable   bool         `json:"reachable"`
	Error       string       `json:"error,omitempty"`
}

// HTTPResult contains HTTP/HTTPS check results
type HTTPResult struct {
	Status         int      `json:"status"`
	StatusText     string   `json:"status_text"`
	RedirectChain  []string `json:"redirect_chain,omitempty"`
	ResponseTimeMs int64    `json:"response_time_ms"`
	FinalURL       string   `json:"final_url,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// TLSResult contains TLS certificate validation results
type TLSResult struct {
	Valid      bool      `json:"valid"`
	Issuer     string    `json:"issuer,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	Expires    time.Time `json:"expires,omitempty"`
	NotBefore  time.Time `json:"not_before,omitempty"`
	Error      string    `json:"error,omitempty"`
	Version    string    `json:"version,omitempty"`
}

// DomainResult contains all results for a single domain
type DomainResult struct {
	Name       string            `json:"name"`
	Subdomains []SubdomainResult `json:"subdomains"`
}

// ScanResult is the top-level result structure
type ScanResult struct {
	Timestamp time.Time       `json:"timestamp"`
	Domains   []DomainResult  `json:"domains"`
	Summary   *ScanSummary    `json:"summary"`
}

// ScanSummary provides aggregate statistics
type ScanSummary struct {
	TotalDomains    int `json:"total_domains"`
	TotalSubdomains int `json:"total_subdomains"`
	Reachable       int `json:"reachable"`
	Unreachable     int `json:"unreachable"`
}

// CRTEntry represents a single entry from the crt.sh API response
type CRTEntry struct {
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

// Config holds the application configuration
type Config struct {
	Domains    []string
	Timeout    time.Duration
	Concurrent int
	Verbose    bool
	Format     string
	Output     string
	Dig        bool
	Whois      bool
	Providers  []string
}

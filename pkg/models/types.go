// Package models contains shared data structures used across the application
package models

import "time"

// SubdomainResult represents the reconnaissance results for a single subdomain
type SubdomainResult struct {
	Hostname   string                 `json:"hostname"`
	IPs        []string               `json:"ips"`
	ThirdParty map[string]interface{} `json:"third_party,omitempty"`
	HTTP       *HTTPResult            `json:"http,omitempty"`
	HTTPS      *HTTPResult            `json:"https,omitempty"`
	TLS        *TLSResult             `json:"tls,omitempty"`
	DNS        *DNSResult             `json:"dns,omitempty"`
	WHOIS      *WHOISResult           `json:"whois,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Reachable  bool                   `json:"reachable"`
}

// DNSResult contains extended DNS query results
type DNSResult struct {
	A     []string   `json:"a,omitempty"`
	AAAA  []string   `json:"aaaa,omitempty"`
	MX    []MXRecord `json:"mx,omitempty"`
	TXT   []string   `json:"txt,omitempty"`
	NS    []string   `json:"ns,omitempty"`
	SOA   *SOARecord `json:"soa,omitempty"`
	CNAME string     `json:"cname,omitempty"`
	Error string     `json:"error,omitempty"`
}

// MXRecord represents a mail exchanger record
type MXRecord struct {
	Host     string `json:"host"`
	Priority uint16 `json:"priority"`
}

// SOARecord represents a Start of Authority record
type SOARecord struct {
	PrimaryNS  string `json:"primary_ns"`
	AdminEmail string `json:"admin_email"`
	Serial     uint32 `json:"serial"`
	Refresh    uint32 `json:"refresh"`
	Retry      uint32 `json:"retry"`
	Expire     uint32 `json:"expire"`
	MinTTL     uint32 `json:"min_ttl"`
}

// WHOISResult contains parsed WHOIS information
type WHOISResult struct {
	Registrar      string     `json:"registrar,omitempty"`
	RegistrantName string     `json:"registrant_name,omitempty"`
	RegistrantOrg  string     `json:"registrant_org,omitempty"`
	Nameservers    []string   `json:"nameservers,omitempty"`
	Status         []string   `json:"status,omitempty"`
	CreationDate   *time.Time `json:"creation_date,omitempty"`
	ExpirationDate *time.Time `json:"expiration_date,omitempty"`
	UpdatedDate    *time.Time `json:"updated_date,omitempty"`
	Error          string     `json:"error,omitempty"`
}

// HTTPResult contains HTTP/HTTPS check results
type HTTPResult struct {
	StatusText     string   `json:"status_text"`
	RedirectChain  []string `json:"redirect_chain,omitempty"`
	FinalURL       string   `json:"final_url,omitempty"`
	Error          string   `json:"error,omitempty"`
	ResponseTimeMs int64    `json:"response_time_ms"`
	Status         int      `json:"status"`
}

// TLSResult contains TLS certificate validation results
type TLSResult struct {
	Issuer    string    `json:"issuer,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	Error     string    `json:"error,omitempty"`
	Version   string    `json:"version,omitempty"`
	Expires   time.Time `json:"expires,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
	Valid     bool      `json:"valid"`
}

// DomainResult contains all results for a single domain
type DomainResult struct {
	Name       string            `json:"name"`
	Subdomains []SubdomainResult `json:"subdomains"`
}

// ScanResult is the top-level result structure
type ScanResult struct {
	Domains   []DomainResult `json:"domains"`
	Summary   *ScanSummary   `json:"summary"`
	Timestamp time.Time      `json:"timestamp"`
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
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
	ID             int64  `json:"id"`
	IssuerCAID     int    `json:"issuer_ca_id"`
}

// Config holds the application configuration
type Config struct {
	Domains    []string
	Format     string
	Output     string
	Providers  []string
	Timeout    time.Duration
	Concurrent int
	Verbose    bool
	Dig        bool
	Whois      bool
}

// Package models provides tests for shared data structures
package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSubdomainResultJSON(t *testing.T) {
	result := SubdomainResult{
		Hostname:  "www.example.com",
		IPs:       []string{"93.184.216.34", "93.184.216.35"},
		Reachable: true,
		HTTP: &HTTPResult{
			Status:         200,
			StatusText:     "200 OK",
			ResponseTimeMs: 120,
		},
		HTTPS: &HTTPResult{
			Status:         200,
			StatusText:     "200 OK",
			ResponseTimeMs: 100,
		},
		TLS: &TLSResult{
			Valid:   true,
			Issuer:  "DigiCert Inc",
			Subject: "www.example.com",
			Version: "TLS 1.3",
		},
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal SubdomainResult: %v", err)
	}

	// Test JSON unmarshaling
	var parsed SubdomainResult
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal SubdomainResult: %v", err)
	}

	if parsed.Hostname != "www.example.com" {
		t.Errorf("Expected hostname 'www.example.com', got %s", parsed.Hostname)
	}
	if len(parsed.IPs) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(parsed.IPs))
	}
	if !parsed.Reachable {
		t.Error("Expected Reachable to be true")
	}
}

func TestDNSResultJSON(t *testing.T) {
	result := DNSResult{
		A:    []string{"1.2.3.4", "5.6.7.8"},
		AAAA: []string{"2001:db8::1"},
		MX: []MXRecord{
			{Host: "mail1.example.com", Priority: 10},
			{Host: "mail2.example.com", Priority: 20},
		},
		TXT: []string{"v=spf1 include:_spf.example.com ~all"},
		NS:  []string{"ns1.example.com", "ns2.example.com"},
		SOA: &SOARecord{
			PrimaryNS:  "ns1.example.com",
			AdminEmail: "admin@example.com",
			Serial:     2024010101,
			Refresh:    3600,
			Retry:      600,
			Expire:     604800,
			MinTTL:     300,
		},
		CNAME: "www.example.com",
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal DNSResult: %v", err)
	}

	var parsed DNSResult
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal DNSResult: %v", err)
	}

	if len(parsed.A) != 2 {
		t.Errorf("Expected 2 A records, got %d", len(parsed.A))
	}
	if len(parsed.MX) != 2 {
		t.Errorf("Expected 2 MX records, got %d", len(parsed.MX))
	}
	if parsed.SOA == nil {
		t.Error("Expected SOA to be non-nil")
	}
}

func TestWHOISResultJSON(t *testing.T) {
	now := time.Now()
	result := WHOISResult{
		Registrar:      "Example Registrar",
		RegistrantName: "John Doe",
		RegistrantOrg:  "Example Inc",
		Nameservers:    []string{"ns1.example.com", "ns2.example.com"},
		Status:         []string{"clientTransferProhibited"},
		CreationDate:   &now,
		ExpirationDate: &now,
		UpdatedDate:    &now,
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal WHOISResult: %v", err)
	}

	var parsed WHOISResult
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal WHOISResult: %v", err)
	}

	if parsed.Registrar != "Example Registrar" {
		t.Errorf("Expected Registrar 'Example Registrar', got %s", parsed.Registrar)
	}
}

func TestHTTPResultJSON(t *testing.T) {
	result := HTTPResult{
		Status:         200,
		StatusText:     "200 OK",
		ResponseTimeMs: 150,
		FinalURL:       "https://www.example.com/",
		RedirectChain:  []string{"http://example.com/", "https://example.com/"},
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal HTTPResult: %v", err)
	}

	var parsed HTTPResult
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal HTTPResult: %v", err)
	}

	if parsed.Status != 200 {
		t.Errorf("Expected Status 200, got %d", parsed.Status)
	}
	if len(parsed.RedirectChain) != 2 {
		t.Errorf("Expected 2 redirects, got %d", len(parsed.RedirectChain))
	}
}

func TestTLSResultJSON(t *testing.T) {
	now := time.Now()
	result := TLSResult{
		Valid:     true,
		Issuer:    "DigiCert Inc",
		Subject:   "www.example.com",
		Expires:   now.Add(365 * 24 * time.Hour),
		NotBefore: now.Add(-30 * 24 * time.Hour),
		Version:   "TLS 1.3",
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal TLSResult: %v", err)
	}

	var parsed TLSResult
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal TLSResult: %v", err)
	}

	if !parsed.Valid {
		t.Error("Expected Valid to be true")
	}
	if parsed.Version != "TLS 1.3" {
		t.Errorf("Expected Version 'TLS 1.3', got %s", parsed.Version)
	}
}

func TestScanResultJSON(t *testing.T) {
	result := ScanResult{
		Timestamp: time.Now(),
		Domains: []DomainResult{
			{
				Name: "example.com",
				Subdomains: []SubdomainResult{
					{
						Hostname:  "www.example.com",
						IPs:       []string{"93.184.216.34"},
						Reachable: true,
					},
				},
			},
		},
		Summary: &ScanSummary{
			TotalDomains:    1,
			TotalSubdomains: 1,
			Reachable:       1,
			Unreachable:     0,
		},
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal ScanResult: %v", err)
	}

	var parsed ScanResult
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal ScanResult: %v", err)
	}

	if len(parsed.Domains) != 1 {
		t.Errorf("Expected 1 domain, got %d", len(parsed.Domains))
	}
	if parsed.Summary == nil {
		t.Error("Expected Summary to be non-nil")
	}
}

func TestCRTEntryJSON(t *testing.T) {
	entry := CRTEntry{
		ID:             12345,
		IssuerCAID:     100,
		IssuerName:     "DigiCert Inc",
		CommonName:     "www.example.com",
		NameValue:      "www.example.com\nmail.example.com",
		NotBefore:      "2024-01-01T00:00:00",
		NotAfter:       "2025-01-01T00:00:00",
		SerialNumber:   "0A1B2C3D",
		EntryTimestamp: "2024-01-15T10:30:00",
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Failed to marshal CRTEntry: %v", err)
	}

	var parsed CRTEntry
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal CRTEntry: %v", err)
	}

	if parsed.CommonName != "www.example.com" {
		t.Errorf("Expected CommonName 'www.example.com', got %s", parsed.CommonName)
	}
	if parsed.ID != 12345 {
		t.Errorf("Expected ID 12345, got %d", parsed.ID)
	}
}

func TestConfigStruct(t *testing.T) {
	config := Config{
		Domains:    []string{"example.com", "example.org"},
		Format:     "json",
		Output:     "results.json",
		Providers:  []string{"vt", "urlvoid"},
		Timeout:    30 * time.Second,
		Concurrent: 20,
		Verbose:    true,
		Dig:        true,
		Whois:      true,
	}

	if len(config.Domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(config.Domains))
	}
	if config.Format != "json" {
		t.Errorf("Expected format 'json', got %s", config.Format)
	}
	if config.Concurrent != 20 {
		t.Errorf("Expected Concurrent 20, got %d", config.Concurrent)
	}
	if !config.Verbose {
		t.Error("Expected Verbose to be true")
	}
}

func TestMXRecordJSON(t *testing.T) {
	record := MXRecord{
		Host:     "mail.example.com",
		Priority: 10,
	}

	jsonData, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Failed to marshal MXRecord: %v", err)
	}

	var parsed MXRecord
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal MXRecord: %v", err)
	}

	if parsed.Host != "mail.example.com" {
		t.Errorf("Expected Host 'mail.example.com', got %s", parsed.Host)
	}
	if parsed.Priority != 10 {
		t.Errorf("Expected Priority 10, got %d", parsed.Priority)
	}
}

func TestSOARecordJSON(t *testing.T) {
	record := SOARecord{
		PrimaryNS:  "ns1.example.com",
		AdminEmail: "admin@example.com",
		Serial:     2024010101,
		Refresh:    3600,
		Retry:      600,
		Expire:     604800,
		MinTTL:     300,
	}

	jsonData, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Failed to marshal SOARecord: %v", err)
	}

	var parsed SOARecord
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal SOARecord: %v", err)
	}

	if parsed.PrimaryNS != "ns1.example.com" {
		t.Errorf("Expected PrimaryNS 'ns1.example.com', got %s", parsed.PrimaryNS)
	}
	if parsed.Serial != 2024010101 {
		t.Errorf("Expected Serial 2024010101, got %d", parsed.Serial)
	}
}

func TestDomainResultJSON(t *testing.T) {
	result := DomainResult{
		Name: "example.com",
		Subdomains: []SubdomainResult{
			{Hostname: "www.example.com", Reachable: true},
			{Hostname: "mail.example.com", Reachable: true},
		},
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal DomainResult: %v", err)
	}

	var parsed DomainResult
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal DomainResult: %v", err)
	}

	if parsed.Name != "example.com" {
		t.Errorf("Expected Name 'example.com', got %s", parsed.Name)
	}
	if len(parsed.Subdomains) != 2 {
		t.Errorf("Expected 2 subdomains, got %d", len(parsed.Subdomains))
	}
}

func TestScanSummaryJSON(t *testing.T) {
	summary := ScanSummary{
		TotalDomains:    5,
		TotalSubdomains: 100,
		Reachable:       85,
		Unreachable:     15,
	}

	jsonData, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Failed to marshal ScanSummary: %v", err)
	}

	var parsed ScanSummary
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal ScanSummary: %v", err)
	}

	if parsed.TotalDomains != 5 {
		t.Errorf("Expected TotalDomains 5, got %d", parsed.TotalDomains)
	}
	if parsed.Reachable != 85 {
		t.Errorf("Expected Reachable 85, got %d", parsed.Reachable)
	}
}

func TestSubdomainResultWithThirdParty(t *testing.T) {
	result := SubdomainResult{
		Hostname:  "www.example.com",
		Reachable: true,
		ThirdParty: map[string]interface{}{
			"virustotal": map[string]interface{}{
				"detected": false,
				"score":    "0/70",
			},
			"urlvoid": map[string]interface{}{
				"detected": false,
				"engines":  0,
			},
		},
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal SubdomainResult with ThirdParty: %v", err)
	}

	var parsed SubdomainResult
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal SubdomainResult with ThirdParty: %v", err)
	}

	if parsed.ThirdParty == nil {
		t.Error("Expected ThirdParty to be non-nil")
	}
	if len(parsed.ThirdParty) != 2 {
		t.Errorf("Expected 2 third party results, got %d", len(parsed.ThirdParty))
	}
}

func TestOptionalFieldsOmitEmpty(t *testing.T) {
	// Test that optional fields are omitted when empty
	result := SubdomainResult{
		Hostname:  "www.example.com",
		Reachable: false,
		// All optional fields left nil/empty
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal SubdomainResult: %v", err)
	}

	jsonStr := string(jsonData)

	// These fields should be omitted when empty
	omittedFields := []string{"third_party", "http", "https", "tls", "dns", "whois", "error"}
	for _, field := range omittedFields {
		if contains(jsonStr, `"`+field+`"`) {
			t.Errorf("Field %s should be omitted when empty", field)
		}
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

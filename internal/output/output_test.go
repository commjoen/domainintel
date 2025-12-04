package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/commjoen/domainintel/pkg/models"
)

func createTestResult() *models.ScanResult {
	return &models.ScanResult{
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Domains: []models.DomainResult{
			{
				Name: "example.com",
				Subdomains: []models.SubdomainResult{
					{
						Hostname:  "www.example.com",
						IPs:       []string{"93.184.216.34"},
						Reachable: true,
						HTTPS: &models.HTTPResult{
							Status:         200,
							StatusText:     "200 OK",
							ResponseTimeMs: 120,
						},
						TLS: &models.TLSResult{
							Valid:  true,
							Issuer: "DigiCert Inc",
						},
					},
					{
						Hostname:  "mail.example.com",
						IPs:       []string{"93.184.216.35"},
						Reachable: true,
						HTTP: &models.HTTPResult{
							Status:         200,
							StatusText:     "200 OK",
							ResponseTimeMs: 85,
						},
					},
					{
						Hostname:  "api.example.com",
						IPs:       []string{},
						Reachable: false,
						Error:     "connection refused",
					},
				},
			},
		},
		Summary: &models.ScanSummary{
			TotalDomains:    1,
			TotalSubdomains: 3,
			Reachable:       2,
			Unreachable:     1,
		},
	}
}

func TestNewFormatter(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		wantType  string
		wantError bool
	}{
		{"text format", "text", "*output.TextFormatter", false},
		{"empty format", "", "*output.TextFormatter", false},
		{"json format", "json", "*output.JSONFormatter", false},
		{"csv format", "csv", "*output.CSVFormatter", false},
		{"uppercase format", "JSON", "*output.JSONFormatter", false},
		{"invalid format", "xml", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter, err := NewFormatter(tt.format)

			if tt.wantError {
				if err == nil {
					t.Error("Expected error, got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if formatter == nil {
				t.Error("Expected formatter, got nil")
			}
		})
	}
}

func TestTextFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &TextFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check that output contains expected elements
	checks := []string{
		"Domain: example.com",
		"www.example.com",
		"mail.example.com",
		"api.example.com",
		"93.184.216.34",
		"200",
		"120ms",
		"Found 3 subdomains",
		"2 reachable",
		"1 unreachable",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("Output should contain %q", check)
		}
	}
}

func TestTextFormatterWrite(t *testing.T) {
	result := createTestResult()
	formatter := &TextFormatter{}

	var buf bytes.Buffer
	err := formatter.Write(&buf, result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Domain: example.com") {
		t.Error("Output should contain domain name")
	}
}

func TestJSONFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &JSONFormatter{Pretty: true}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check that output is valid JSON with expected structure
	checks := []string{
		`"timestamp"`,
		`"domains"`,
		`"name": "example.com"`,
		`"subdomains"`,
		`"hostname": "www.example.com"`,
		`"ips"`,
		`"summary"`,
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("JSON output should contain %q", check)
		}
	}
}

func TestJSONFormatterCompact(t *testing.T) {
	result := createTestResult()
	formatter := &JSONFormatter{Pretty: false}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Compact JSON should not have newlines in the middle
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 1 {
		t.Errorf("Compact JSON should be on one line, got %d lines", len(lines))
	}
}

func TestCSVFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &CSVFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check header
	if !strings.HasPrefix(output, "domain,subdomain,ip,status,tls_valid,response_time_ms,error") {
		t.Error("CSV output should start with header")
	}

	// Check data rows
	checks := []string{
		"example.com,www.example.com,93.184.216.34,200,true,120",
		"example.com,mail.example.com,93.184.216.35,200,,85",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("CSV output should contain %q", check)
		}
	}

	// Check line count (header + 3 data rows)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 4 {
		t.Errorf("Expected 4 lines (header + 3 data), got %d", len(lines))
	}
}

func TestCSVFormatterEmptyResult(t *testing.T) {
	result := &models.ScanResult{
		Timestamp: time.Now(),
		Domains:   []models.DomainResult{},
	}
	formatter := &CSVFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should only have header
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 1 {
		t.Errorf("Expected 1 line (header only), got %d", len(lines))
	}
}

func TestCSVFormatterWithDomainError(t *testing.T) {
	result := &models.ScanResult{
		Timestamp: time.Now(),
		Domains: []models.DomainResult{
			{
				Name: "example.com",
				Subdomains: []models.SubdomainResult{
					{
						Hostname:  "example.com",
						IPs:       []string{},
						Reachable: false,
						Error:     "DNS resolution failed",
					},
				},
				Error: "crt.sh HTTP 500: Internal Server Error",
			},
		},
	}
	formatter := &CSVFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check that error is included in CSV
	if !strings.Contains(output, "DNS resolution failed") {
		t.Errorf("CSV output should contain subdomain error, got: %s", output)
	}
}

func TestTextFormatterLongSubdomain(t *testing.T) {
	result := &models.ScanResult{
		Timestamp: time.Now(),
		Domains: []models.DomainResult{
			{
				Name: "example.com",
				Subdomains: []models.SubdomainResult{
					{
						Hostname:  "very-long-subdomain-name-that-exceeds-limit.example.com",
						IPs:       []string{"1.2.3.4"},
						Reachable: true,
					},
				},
			},
		},
	}
	formatter := &TextFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Long subdomain should be truncated
	if strings.Contains(output, "very-long-subdomain-name-that-exceeds-limit.example.com") {
		t.Error("Long subdomain should be truncated")
	}
	if !strings.Contains(output, "...") {
		t.Error("Truncated subdomain should contain ellipsis")
	}
}

func TestTextFormatterMultipleIPs(t *testing.T) {
	result := &models.ScanResult{
		Timestamp: time.Now(),
		Domains: []models.DomainResult{
			{
				Name: "example.com",
				Subdomains: []models.SubdomainResult{
					{
						Hostname:  "www.example.com",
						IPs:       []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"},
						Reachable: true,
					},
				},
			},
		},
	}
	formatter := &TextFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should show first IP and count of additional IPs
	if !strings.Contains(output, "1.2.3.4 (+2)") {
		t.Error("Output should show first IP and additional count")
	}
}

func TestTextFormatterWithDNSRecords(t *testing.T) {
	result := &models.ScanResult{
		Timestamp: time.Now(),
		Domains: []models.DomainResult{
			{
				Name: "example.com",
				Subdomains: []models.SubdomainResult{
					{
						Hostname:  "example.com",
						IPs:       []string{"93.184.216.34"},
						Reachable: true,
						DNS: &models.DNSResult{
							A:     []string{"93.184.216.34"},
							AAAA:  []string{"2606:2800:220:1:248:1893:25c8:1946"},
							MX:    []models.MXRecord{{Host: "mail.example.com", Priority: 10}},
							NS:    []string{"ns1.example.com", "ns2.example.com"},
							TXT:   []string{"v=spf1 include:_spf.example.com ~all"},
							CNAME: "",
							SOA: &models.SOARecord{
								PrimaryNS:  "ns1.example.com",
								AdminEmail: "admin@example.com",
								Serial:     2023010101,
							},
						},
					},
				},
			},
		},
	}
	formatter := &TextFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check that DNS records are displayed
	checks := []string{
		"DNS Records:",
		"A:     93.184.216.34",
		"AAAA:  2606:2800:220:1:248:1893:25c8:1946",
		"MX:    mail.example.com (pri: 10)",
		"NS:    ns1.example.com, ns2.example.com",
		"TXT:   v=spf1 include:_spf.example.com ~all",
		"SOA:   ns1.example.com (admin: admin@example.com, serial: 2023010101)",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("Output should contain %q, got:\n%s", check, output)
		}
	}
}

func TestTextFormatterWithWHOIS(t *testing.T) {
	creationDate := time.Date(1995, 8, 14, 0, 0, 0, 0, time.UTC)
	expirationDate := time.Date(2025, 8, 13, 0, 0, 0, 0, time.UTC)
	updatedDate := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)

	result := &models.ScanResult{
		Timestamp: time.Now(),
		Domains: []models.DomainResult{
			{
				Name: "example.com",
				Subdomains: []models.SubdomainResult{
					{
						Hostname:  "example.com",
						IPs:       []string{"93.184.216.34"},
						Reachable: true,
						WHOIS: &models.WHOISResult{
							Registrar:      "Example Registrar, Inc.",
							RegistrantOrg:  "Example Organization",
							RegistrantName: "Domain Admin",
							Nameservers:    []string{"ns1.example.com", "ns2.example.com"},
							Status:         []string{"clientTransferProhibited"},
							CreationDate:   &creationDate,
							ExpirationDate: &expirationDate,
							UpdatedDate:    &updatedDate,
						},
					},
				},
			},
		},
	}
	formatter := &TextFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check that WHOIS information is displayed
	checks := []string{
		"WHOIS Information:",
		"Registrar:   Example Registrar, Inc.",
		"Organization: Example Organization",
		"Registrant:  Domain Admin",
		"Created:     1995-08-14",
		"Expires:     2025-08-13",
		"Updated:     2024-01-15",
		"Nameservers: ns1.example.com, ns2.example.com",
		"Status:      clientTransferProhibited",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("Output should contain %q, got:\n%s", check, output)
		}
	}
}

func TestTextFormatterWithThirdPartyProviders(t *testing.T) {
	result := &models.ScanResult{
		Timestamp: time.Now(),
		Domains: []models.DomainResult{
			{
				Name: "example.com",
				Subdomains: []models.SubdomainResult{
					{
						Hostname:  "example.com",
						IPs:       []string{"93.184.216.34"},
						Reachable: true,
						ThirdParty: map[string]interface{}{
							"vt": map[string]interface{}{
								"detected":   false,
								"score":      "0/87",
								"categories": []interface{}{"harmless"},
							},
						},
					},
				},
			},
		},
	}
	formatter := &TextFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check that third-party provider results are displayed
	checks := []string{
		"Third-Party Providers:",
		"vt:",
		"Detected:   No",
		"Score:      0/87",
		"Categories: harmless",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("Output should contain %q, got:\n%s", check, output)
		}
	}
}

func TestTextFormatterWithAllExtendedInfo(t *testing.T) {
	creationDate := time.Date(1995, 8, 14, 0, 0, 0, 0, time.UTC)

	result := &models.ScanResult{
		Timestamp: time.Now(),
		Domains: []models.DomainResult{
			{
				Name: "example.com",
				Subdomains: []models.SubdomainResult{
					{
						Hostname:  "example.com",
						IPs:       []string{"93.184.216.34"},
						Reachable: true,
						DNS: &models.DNSResult{
							A:  []string{"93.184.216.34"},
							NS: []string{"ns1.example.com"},
						},
						WHOIS: &models.WHOISResult{
							Registrar:    "Example Registrar",
							CreationDate: &creationDate,
						},
						ThirdParty: map[string]interface{}{
							"vt": map[string]interface{}{
								"detected": false,
								"score":    "0/87",
							},
						},
					},
				},
			},
		},
	}
	formatter := &TextFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check that all sections are displayed
	checks := []string{
		"DNS Records:",
		"WHOIS Information:",
		"Third-Party Providers:",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("Output should contain %q, got:\n%s", check, output)
		}
	}
}

func TestTextFormatterWithDNSError(t *testing.T) {
	result := &models.ScanResult{
		Timestamp: time.Now(),
		Domains: []models.DomainResult{
			{
				Name: "example.com",
				Subdomains: []models.SubdomainResult{
					{
						Hostname:  "example.com",
						IPs:       []string{},
						Reachable: false,
						DNS: &models.DNSResult{
							Error: "DNS lookup failed: NXDOMAIN",
						},
					},
				},
			},
		},
	}
	formatter := &TextFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !strings.Contains(output, "Error: DNS lookup failed: NXDOMAIN") {
		t.Errorf("Output should contain DNS error, got:\n%s", output)
	}
}

func TestTextFormatterWithWHOISError(t *testing.T) {
	result := &models.ScanResult{
		Timestamp: time.Now(),
		Domains: []models.DomainResult{
			{
				Name: "example.com",
				Subdomains: []models.SubdomainResult{
					{
						Hostname:  "example.com",
						IPs:       []string{"93.184.216.34"},
						Reachable: true,
						WHOIS: &models.WHOISResult{
							Error: "WHOIS lookup failed: connection timeout",
						},
					},
				},
			},
		},
	}
	formatter := &TextFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !strings.Contains(output, "Error:       WHOIS lookup failed: connection timeout") {
		t.Errorf("Output should contain WHOIS error, got:\n%s", output)
	}
}

func TestTextFormatterWithProviderError(t *testing.T) {
	result := &models.ScanResult{
		Timestamp: time.Now(),
		Domains: []models.DomainResult{
			{
				Name: "example.com",
				Subdomains: []models.SubdomainResult{
					{
						Hostname:  "example.com",
						IPs:       []string{"93.184.216.34"},
						Reachable: true,
						ThirdParty: map[string]interface{}{
							"vt": map[string]interface{}{
								"detected": false,
								"error":    "API rate limit exceeded",
							},
						},
					},
				},
			},
		},
	}
	formatter := &TextFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !strings.Contains(output, "Error:      API rate limit exceeded") {
		t.Errorf("Output should contain provider error, got:\n%s", output)
	}
}

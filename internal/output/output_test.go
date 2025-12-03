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
	if !strings.HasPrefix(output, "domain,subdomain,ip,status,tls_valid,response_time_ms") {
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

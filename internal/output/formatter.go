// Package output provides formatting options for scan results
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/commjoen/domainintel/pkg/models"
)

const (
	// maxSubdomainDisplayLength is the maximum length for subdomain display in text format
	maxSubdomainDisplayLength = 28
	// truncatedSubdomainLength is the length of truncated subdomain (with space for ellipsis)
	truncatedSubdomainLength = 25
	// maxTXTDisplayLength is the maximum length for TXT record display
	maxTXTDisplayLength = 60
	// truncatedTXTLength is the length of truncated TXT record (with space for ellipsis)
	truncatedTXTLength = 57
)

// Formatter defines the interface for output formatters
type Formatter interface {
	Format(result *models.ScanResult) (string, error)
	Write(w io.Writer, result *models.ScanResult) error
}

// TextFormatter formats results as human-readable text tables
type TextFormatter struct{}

// JSONFormatter formats results as JSON
type JSONFormatter struct {
	Pretty bool
}

// CSVFormatter formats results as CSV
type CSVFormatter struct{}

// NewFormatter creates a new formatter based on the format type
func NewFormatter(format string) (Formatter, error) {
	switch strings.ToLower(format) {
	case "text", "":
		return &TextFormatter{}, nil
	case "json":
		return &JSONFormatter{Pretty: true}, nil
	case "csv":
		return &CSVFormatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// Format returns the formatted string
func (f *TextFormatter) Format(result *models.ScanResult) (string, error) {
	var sb strings.Builder
	if err := f.Write(&sb, result); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// Write writes the formatted output to the writer
func (f *TextFormatter) Write(w io.Writer, result *models.ScanResult) error {
	separator := strings.Repeat("=", 80)
	lineSeparator := strings.Repeat("-", 80)

	for _, domain := range result.Domains {
		fmt.Fprintf(w, "Domain: %s\n", domain.Name)
		fmt.Fprintln(w, separator)
		fmt.Fprintf(w, "%-30s %-18s %-8s %-5s %s\n", "Subdomain", "IP Address", "Status", "TLS", "Response Time")
		fmt.Fprintln(w, lineSeparator)

		for _, sub := range domain.Subdomains {
			ip := "-"
			if len(sub.IPs) > 0 {
				ip = sub.IPs[0]
				if len(sub.IPs) > 1 {
					ip = fmt.Sprintf("%s (+%d)", ip, len(sub.IPs)-1)
				}
			}

			status := "-"
			responseTime := "-"
			if sub.HTTPS != nil && sub.HTTPS.Status > 0 {
				status = fmt.Sprintf("%d", sub.HTTPS.Status)
				responseTime = fmt.Sprintf("%dms", sub.HTTPS.ResponseTimeMs)
			} else if sub.HTTP != nil && sub.HTTP.Status > 0 {
				status = fmt.Sprintf("%d", sub.HTTP.Status)
				responseTime = fmt.Sprintf("%dms", sub.HTTP.ResponseTimeMs)
			} else if sub.Error != "" {
				status = "ERR"
			}

			tlsStatus := "-"
			if sub.TLS != nil {
				if sub.TLS.Valid {
					tlsStatus = "✓"
				} else {
					tlsStatus = "✗"
				}
			}

			// Truncate long subdomain names
			subdomain := sub.Hostname
			if len(subdomain) > maxSubdomainDisplayLength {
				subdomain = subdomain[:truncatedSubdomainLength] + "..."
			}

			fmt.Fprintf(w, "%-30s %-18s %-8s %-5s %s\n", subdomain, ip, status, tlsStatus, responseTime)

			// Display DNS records if present (--dig flag was used)
			if sub.DNS != nil {
				formatDNSRecords(w, sub.DNS)
			}

			// Display WHOIS information if present (--whois flag was used)
			if sub.WHOIS != nil {
				formatWHOISInfo(w, sub.WHOIS)
			}

			// Display third-party provider results if present (--providers flag was used)
			if len(sub.ThirdParty) > 0 {
				formatThirdPartyResults(w, sub.ThirdParty)
			}
		}

		fmt.Fprintln(w, separator)
	}

	if result.Summary != nil {
		fmt.Fprintf(w, "Found %d subdomains | %d reachable | %d unreachable\n",
			result.Summary.TotalSubdomains,
			result.Summary.Reachable,
			result.Summary.Unreachable)
	}

	return nil
}

// formatDNSRecords formats DNS records for plaintext output
func formatDNSRecords(w io.Writer, dns *models.DNSResult) {
	fmt.Fprintf(w, "  DNS Records:\n")
	if len(dns.A) > 0 {
		fmt.Fprintf(w, "    A:     %s\n", strings.Join(dns.A, ", "))
	}
	if len(dns.AAAA) > 0 {
		fmt.Fprintf(w, "    AAAA:  %s\n", strings.Join(dns.AAAA, ", "))
	}
	if len(dns.MX) > 0 {
		mxRecords := make([]string, len(dns.MX))
		for i, mx := range dns.MX {
			mxRecords[i] = fmt.Sprintf("%s (pri: %d)", mx.Host, mx.Priority)
		}
		fmt.Fprintf(w, "    MX:    %s\n", strings.Join(mxRecords, ", "))
	}
	if len(dns.NS) > 0 {
		fmt.Fprintf(w, "    NS:    %s\n", strings.Join(dns.NS, ", "))
	}
	if len(dns.TXT) > 0 {
		for i, txt := range dns.TXT {
			// Truncate long TXT records for display
			displayTxt := txt
			if len(displayTxt) > maxTXTDisplayLength {
				displayTxt = displayTxt[:truncatedTXTLength] + "..."
			}
			if i == 0 {
				fmt.Fprintf(w, "    TXT:   %s\n", displayTxt)
			} else {
				fmt.Fprintf(w, "           %s\n", displayTxt)
			}
		}
	}
	if dns.CNAME != "" {
		fmt.Fprintf(w, "    CNAME: %s\n", dns.CNAME)
	}
	if dns.SOA != nil {
		fmt.Fprintf(w, "    SOA:   %s (admin: %s, serial: %d)\n",
			dns.SOA.PrimaryNS, dns.SOA.AdminEmail, dns.SOA.Serial)
	}
	if dns.Error != "" {
		fmt.Fprintf(w, "    Error: %s\n", dns.Error)
	}
}

// formatWHOISInfo formats WHOIS information for plaintext output
func formatWHOISInfo(w io.Writer, whois *models.WHOISResult) {
	fmt.Fprintf(w, "  WHOIS Information:\n")
	if whois.Registrar != "" {
		fmt.Fprintf(w, "    Registrar:   %s\n", whois.Registrar)
	}
	if whois.RegistrantOrg != "" {
		fmt.Fprintf(w, "    Organization: %s\n", whois.RegistrantOrg)
	}
	if whois.RegistrantName != "" {
		fmt.Fprintf(w, "    Registrant:  %s\n", whois.RegistrantName)
	}
	if whois.CreationDate != nil {
		fmt.Fprintf(w, "    Created:     %s\n", whois.CreationDate.Format("2006-01-02"))
	}
	if whois.ExpirationDate != nil {
		fmt.Fprintf(w, "    Expires:     %s\n", whois.ExpirationDate.Format("2006-01-02"))
	}
	if whois.UpdatedDate != nil {
		fmt.Fprintf(w, "    Updated:     %s\n", whois.UpdatedDate.Format("2006-01-02"))
	}
	if len(whois.Nameservers) > 0 {
		fmt.Fprintf(w, "    Nameservers: %s\n", strings.Join(whois.Nameservers, ", "))
	}
	if len(whois.Status) > 0 {
		fmt.Fprintf(w, "    Status:      %s\n", strings.Join(whois.Status, ", "))
	}
	if whois.Error != "" {
		fmt.Fprintf(w, "    Error:       %s\n", whois.Error)
	}
}

// formatThirdPartyResults formats third-party provider results for plaintext output
func formatThirdPartyResults(w io.Writer, thirdParty map[string]interface{}) {
	fmt.Fprintf(w, "  Third-Party Providers:\n")
	for provider, data := range thirdParty {
		fmt.Fprintf(w, "    %s:\n", provider)
		if dataMap, ok := data.(map[string]interface{}); ok {
			if detected, ok := dataMap["detected"].(bool); ok {
				if detected {
					fmt.Fprintf(w, "      Detected:   Yes\n")
				} else {
					fmt.Fprintf(w, "      Detected:   No\n")
				}
			}
			if score, ok := dataMap["score"].(string); ok && score != "" {
				fmt.Fprintf(w, "      Score:      %s\n", score)
			}
			if categories := extractStringSlice(dataMap["categories"]); len(categories) > 0 {
				fmt.Fprintf(w, "      Categories: %s\n", strings.Join(categories, ", "))
			}
			if details := extractStringMap(dataMap["details"]); len(details) > 0 {
				for key, value := range details {
					fmt.Fprintf(w, "      %s: %s\n", key, value)
				}
			}
			if errStr, ok := dataMap["error"].(string); ok && errStr != "" {
				fmt.Fprintf(w, "      Error:      %s\n", errStr)
			}
		}
	}
}

// extractStringSlice extracts a string slice from interface{} that could be []string or []interface{}
func extractStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	// Handle []string directly
	if strs, ok := v.([]string); ok {
		return strs
	}
	// Handle []interface{} (common when unmarshaling JSON)
	if ifaces, ok := v.([]interface{}); ok {
		result := make([]string, 0, len(ifaces))
		for _, item := range ifaces {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// extractStringMap extracts a string map from interface{} that could be map[string]string or map[string]interface{}
func extractStringMap(v interface{}) map[string]string {
	if v == nil {
		return nil
	}
	// Handle map[string]string directly
	if m, ok := v.(map[string]string); ok {
		return m
	}
	// Handle map[string]interface{} (common when unmarshaling JSON)
	if m, ok := v.(map[string]interface{}); ok {
		result := make(map[string]string, len(m))
		for key, value := range m {
			result[key] = fmt.Sprintf("%v", value)
		}
		return result
	}
	return nil
}

// Format returns the formatted string
func (f *JSONFormatter) Format(result *models.ScanResult) (string, error) {
	var sb strings.Builder
	if err := f.Write(&sb, result); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// Write writes the formatted output to the writer
func (f *JSONFormatter) Write(w io.Writer, result *models.ScanResult) error {
	encoder := json.NewEncoder(w)
	if f.Pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(result)
}

// Format returns the formatted string
func (f *CSVFormatter) Format(result *models.ScanResult) (string, error) {
	var sb strings.Builder
	if err := f.Write(&sb, result); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// Write writes the formatted output to the writer
func (f *CSVFormatter) Write(w io.Writer, result *models.ScanResult) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header
	header := []string{"domain", "subdomain", "ip", "status", "tls_valid", "response_time_ms"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data
	for _, domain := range result.Domains {
		for _, sub := range domain.Subdomains {
			ip := ""
			if len(sub.IPs) > 0 {
				ip = sub.IPs[0]
			}

			status := ""
			responseTime := ""
			if sub.HTTPS != nil && sub.HTTPS.Status > 0 {
				status = fmt.Sprintf("%d", sub.HTTPS.Status)
				responseTime = fmt.Sprintf("%d", sub.HTTPS.ResponseTimeMs)
			} else if sub.HTTP != nil && sub.HTTP.Status > 0 {
				status = fmt.Sprintf("%d", sub.HTTP.Status)
				responseTime = fmt.Sprintf("%d", sub.HTTP.ResponseTimeMs)
			}

			tlsValid := ""
			if sub.TLS != nil {
				if sub.TLS.Valid {
					tlsValid = "true"
				} else {
					tlsValid = "false"
				}
			}

			row := []string{domain.Name, sub.Hostname, ip, status, tlsValid, responseTime}
			if err := writer.Write(row); err != nil {
				return err
			}
		}
	}

	return nil
}

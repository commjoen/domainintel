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
			if len(subdomain) > 28 {
				subdomain = subdomain[:25] + "..."
			}

			fmt.Fprintf(w, "%-30s %-18s %-8s %-5s %s\n", subdomain, ip, status, tlsStatus, responseTime)
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

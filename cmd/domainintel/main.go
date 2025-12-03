// domainintel is a command-line reconnaissance tool for gathering intelligence about domains
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/commjoen/domainintel/internal/crt"
	"github.com/commjoen/domainintel/internal/output"
	"github.com/commjoen/domainintel/internal/reachability"
	"github.com/commjoen/domainintel/pkg/models"
)

var (
	// CLI flags
	domains    string
	format     string
	outputFile string
	timeout    time.Duration
	concurrent int
	verbose    bool
	progress   bool

	// Version information (set during build)
	version = "dev"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:     "domainintel",
	Short:   "Domain intelligence and reconnaissance tool",
	Version: version,
	Long: `domainintel is a command-line reconnaissance tool designed to gather
comprehensive intelligence about domains. It automates the process of
discovering subdomains, checking their availability, resolving IP addresses,
and validating TLS certificates.`,
	Example: `  # Basic subdomain enumeration
  domainintel --domains example.com

  # Multiple domains with JSON output
  domainintel --domains example.com,example.org --format json

  # Save results to file
  domainintel --domains example.com --format csv --out results.csv`,
	RunE: run,
}

func init() {
	rootCmd.Flags().StringVarP(&domains, "domains", "d", "", "Comma-separated list of target domains (required)")
	rootCmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text, json, or csv")
	rootCmd.Flags().StringVarP(&outputFile, "out", "o", "", "Write output to file (default: stdout)")
	rootCmd.Flags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "HTTP request timeout")
	rootCmd.Flags().IntVarP(&concurrent, "concurrent", "c", 10, "Maximum concurrent requests")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.Flags().BoolVarP(&progress, "progress", "p", false, "Show progress bar during scan")

	// MarkFlagRequired only returns an error if the flag doesn't exist.
	// Since we just registered the flag above, this error should never occur in practice.
	if err := rootCmd.MarkFlagRequired("domains"); err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: failed to mark 'domains' flag as required: %v\n", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Parse domains
	domainList := parseDomains(domains)
	if len(domainList) == 0 {
		return fmt.Errorf("no valid domains provided")
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Parsed domains: %v\n", domainList)
	}

	// Validate domains
	for _, domain := range domainList {
		if err := crt.ValidateDomain(domain); err != nil {
			return fmt.Errorf("invalid domain %q: %w", domain, err)
		}
	}

	// Create output formatter
	formatter, err := output.NewFormatter(format)
	if err != nil {
		return err
	}

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		if verbose {
			fmt.Fprintln(os.Stderr, "\nReceived interrupt, shutting down...")
		}
		cancel()
	}()

	// Create clients
	crtClient := crt.NewClient(timeout)
	checker := reachability.NewChecker(timeout)

	// Process each domain
	result := &models.ScanResult{
		Timestamp: time.Now().UTC(),
		Domains:   make([]models.DomainResult, 0, len(domainList)),
		Summary: &models.ScanSummary{
			TotalDomains: len(domainList),
		},
	}

	for _, domain := range domainList {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		domainResult, err := processDomain(ctx, domain, crtClient, checker)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", domain, err)
			}
			continue
		}

		result.Domains = append(result.Domains, *domainResult)

		// Update summary
		for _, sub := range domainResult.Subdomains {
			result.Summary.TotalSubdomains++
			if sub.Reachable {
				result.Summary.Reachable++
			} else {
				result.Summary.Unreachable++
			}
		}
	}

	// Output results
	return outputResults(formatter, result)
}

func parseDomains(input string) []string {
	var result []string
	for _, domain := range strings.Split(input, ",") {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			// Normalize wildcards (*.domain.com or *domain.com -> domain.com)
			domain = crt.NormalizeDomain(domain)
			result = append(result, strings.ToLower(domain))
		}
	}
	return result
}

func processDomain(ctx context.Context, domain string, crtClient *crt.Client, checker *reachability.Checker) (*models.DomainResult, error) {
	if verbose {
		fmt.Fprintf(os.Stderr, "Processing domain: %s\n", domain)
	}

	// Query Certificate Transparency logs
	subdomains, err := crtClient.QuerySubdomains(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to query CT logs: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Found %d subdomains for %s\n", len(subdomains), domain)
	}

	// If no subdomains found, add the base domain
	if len(subdomains) == 0 {
		subdomains = []string{domain}
	}

	total := len(subdomains)
	var completed int64

	// Check reachability for each subdomain concurrently
	results := make([]models.SubdomainResult, len(subdomains))
	var wg sync.WaitGroup

	// Create a semaphore to limit concurrency
	sem := make(chan struct{}, concurrent)

	for i, subdomain := range subdomains {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		wg.Add(1)
		go func(idx int, hostname string) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			if verbose {
				fmt.Fprintf(os.Stderr, "Checking: %s\n", hostname)
			}

			results[idx] = checker.CheckHost(ctx, hostname)

			// Update progress
			if progress {
				current := atomic.AddInt64(&completed, 1)
				printProgress(domain, int(current), total)
			}
		}(i, subdomain)
	}

	wg.Wait()

	// Clear progress bar line
	if progress {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 80))
	}

	return &models.DomainResult{
		Name:       domain,
		Subdomains: results,
	}, nil
}

// printProgress displays a progress bar
func printProgress(domain string, current, total int) {
	percentage := float64(current) / float64(total) * 100
	barWidth := 40
	filled := int(float64(barWidth) * float64(current) / float64(total))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Fprintf(os.Stderr, "\r[%s] %3.0f%% (%d/%d) %s", bar, percentage, current, total, domain)
}

func outputResults(formatter output.Formatter, result *models.ScanResult) error {
	var writer *os.File
	var err error

	if outputFile != "" {
		// Sanitize the file path to prevent directory traversal
		cleanPath := filepath.Clean(outputFile)
		// #nosec G304 -- User-provided output file path is intentional for CLI tool
		writer, err = os.Create(cleanPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer writer.Close()
	} else {
		writer = os.Stdout
	}

	return formatter.Write(writer, result)
}

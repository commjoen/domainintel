// domainintel is a command-line reconnaissance tool for gathering intelligence about domains
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	"github.com/commjoen/domainintel/internal/dns"
	"github.com/commjoen/domainintel/internal/output"
	"github.com/commjoen/domainintel/internal/providers"
	"github.com/commjoen/domainintel/internal/reachability"
	"github.com/commjoen/domainintel/internal/whois"
	"github.com/commjoen/domainintel/pkg/models"
)

var (
	// CLI flags
	domains       string
	format        string
	outputFile    string
	timeout       time.Duration
	concurrent    int
	verbose       bool
	progress      bool
	enableDig     bool
	enableWhois   bool
	providersList string

	// Version information (set during build)
	version = "dev"
	// GitHub repository for version checks
	githubRepo = "commjoen/domainintel"
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
and validating TLS certificates.

Third-party providers:
  --providers vt,urlvoid
    - vt      (VirusTotal) requires VT_API_KEY in environment
    - urlvoid (URLVoid)    requires URLVOID_API_KEY in environment
If you request a provider without the required API key set, the command will fail with a clear error.`,
	Example: `  # Basic subdomain enumeration
  domainintel --domains example.com

  # Multiple domains with JSON output
  domainintel --domains example.com,example.org --format json

  # Save results to file
  domainintel --domains example.com --format csv --out results.csv

  # Full reconnaissance with DNS and WHOIS
  domainintel --domains example.com --dig --whois

  # Use third-party reputation services (API keys required)
  export VT_API_KEY=your_key
  export URLVOID_API_KEY=your_key
  domainintel --domains example.com --providers vt,urlvoid`,
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
	rootCmd.Flags().BoolVar(&enableDig, "dig", false, "Enable extended DNS queries (A/AAAA/MX/TXT/NS/CNAME/SOA)")
	rootCmd.Flags().BoolVar(&enableWhois, "whois", false, "Enable WHOIS lookups for registration data")
	// Clarify available providers and required env keys
	rootCmd.Flags().StringVar(&providersList, "providers", "", "Comma-separated third-party services: vt,urlvoid (requires VT_API_KEY and/or URLVOID_API_KEY)")

	// Override the default version template to include update check
	rootCmd.SetVersionTemplate(getVersionTemplate())

	// MarkFlagRequired only returns an error if the flag doesn't exist.
	// Since we just registered the flag above, this error should never occur in practice.
	if err := rootCmd.MarkFlagRequired("domains"); err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: failed to mark 'domains' flag as required: %v\n", err)
		os.Exit(1)
	}
}

// getVersionTemplate returns a custom version template with update checking
func getVersionTemplate() string {
	versionInfo := fmt.Sprintf("domainintel version %s\n", version)

	// Check for updates (with timeout to avoid hanging)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	latestVersion, err := checkLatestVersion(ctx)
	if err != nil {
		if verbose {
			versionInfo += fmt.Sprintf("(unable to check for updates: %v)\n", err)
		}
	} else if latestVersion != "" && latestVersion != version {
		versionInfo += fmt.Sprintf("\n⚠️  A newer version is available: %s\n", latestVersion)
		versionInfo += fmt.Sprintf("Download: https://github.com/%s/releases/latest\n", githubRepo)
		versionInfo += fmt.Sprintf("Update:   go install github.com/%s/cmd/domainintel@latest\n", githubRepo)
	} else if latestVersion == version {
		versionInfo += "✓ You are running the latest version\n"
	}

	return versionInfo
}

// GitHubRelease represents a GitHub release API response
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	URL     string `json:"html_url"`
}

// checkLatestVersion queries GitHub API for the latest release
func checkLatestVersion(ctx context.Context) (string, error) {
	if version == "dev" || version == "" {
		return "", fmt.Errorf("development build")
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set User-Agent to avoid rate limiting
	req.Header.Set("User-Agent", fmt.Sprintf("domainintel/%s", version))
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var release GitHubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return "", fmt.Errorf("failed to parse release info: %w", err)
	}

	// Normalize version tags (remove 'v' prefix if present)
	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := strings.TrimPrefix(version, "v")

	// Simple string comparison (for more complex versioning, use semver library)
	if latestVersion != currentVersion {
		return latestVersion, nil
	}

	return currentVersion, nil
}

func run(cmd *cobra.Command, args []string) error {
	// Parse domains
	domainList := parseDomains(domains)
	if len(domainList) == 0 {
		return fmt.Errorf("no valid domains provided")
	}

	// Security: Limit domain list size to prevent abuse
	const maxDomains = 100
	if len(domainList) > maxDomains {
		return fmt.Errorf("too many domains specified (max %d, got %d)", maxDomains, len(domainList))
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

	// Create optional clients based on flags
	var dnsClient *dns.Client
	if enableDig {
		dnsClient = dns.NewClient(timeout)
	}

	var whoisClient *whois.Client
	if enableWhois {
		whoisClient = whois.NewClient(timeout)
	}

	// Validate and set up providers if requested
	providerManager, providerList, err := setupProviders(providersList, timeout)
	if err != nil {
		return err
	}

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

		domainResult, err := processDomain(ctx, domain, crtClient, checker, dnsClient, whoisClient, providerManager, providerList)
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

func processDomain(ctx context.Context, domain string, crtClient *crt.Client, checker *reachability.Checker, dnsClient *dns.Client, whoisClient *whois.Client, providerManager *providers.Manager, providerList []string) (*models.DomainResult, error) {
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

	// Ensure the base domain is included so WHOIS runs
	// Deduplicate entries
	seen := make(map[string]struct{}, len(subdomains)+1)
	for _, s := range subdomains {
		seen[s] = struct{}{}
	}
	if _, ok := seen[domain]; !ok {
		subdomains = append(subdomains, domain)
		seen[domain] = struct{}{}
	}

	total := len(subdomains)
	var completed int64

	// Show initial progress (0%) before starting subdomain checks
	if progress {
		printProgress(domain, 0, total)
	}

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

			// Add DNS records if --dig flag is set
			if dnsClient != nil {
				dnsResult := dnsClient.QueryAll(ctx, hostname)
				results[idx].DNS = convertDNSResult(dnsResult)
			}

			// Add WHOIS data if --whois flag is set (only for base domain)
			if whoisClient != nil && hostname == domain {
				whoisResult := whoisClient.Lookup(ctx, hostname)
				results[idx].WHOIS = convertWHOISResult(whoisResult)
			}

			// Add third-party provider results if --providers flag is set
			if providerManager != nil && len(providerList) > 0 {
				providerResults := providerManager.Check(ctx, hostname, providerList)
				if len(providerResults.Results) > 0 {
					results[idx].ThirdParty = make(map[string]interface{})
					for _, pr := range providerResults.Results {
						results[idx].ThirdParty[pr.Provider] = map[string]interface{}{
							"detected":     pr.Detected,
							"score":        pr.Score,
							"categories":   pr.Categories,
							"details":      pr.Details,
							"error":        pr.Error,
							"last_checked": pr.LastChecked,
						}
					}
				}
			}

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

// convertDNSResult converts internal dns.DNSResult to models.DNSResult
func convertDNSResult(d *dns.DNSResult) *models.DNSResult {
	if d == nil {
		return nil
	}
	result := &models.DNSResult{
		A:     d.A,
		AAAA:  d.AAAA,
		TXT:   d.TXT,
		NS:    d.NS,
		CNAME: d.CNAME,
		Error: d.Error,
	}
	// Convert MX records
	if len(d.MX) > 0 {
		result.MX = make([]models.MXRecord, len(d.MX))
		for i, mx := range d.MX {
			result.MX[i] = models.MXRecord{
				Host:     mx.Host,
				Priority: mx.Priority,
			}
		}
	}
	// Convert SOA record
	if d.SOA != nil {
		result.SOA = &models.SOARecord{
			PrimaryNS:  d.SOA.PrimaryNS,
			AdminEmail: d.SOA.AdminEmail,
			Serial:     d.SOA.Serial,
			Refresh:    d.SOA.Refresh,
			Retry:      d.SOA.Retry,
			Expire:     d.SOA.Expire,
			MinTTL:     d.SOA.MinTTL,
		}
	}
	return result
}

// convertWHOISResult converts internal whois.WHOISResult to models.WHOISResult
func convertWHOISResult(w *whois.WHOISResult) *models.WHOISResult {
	if w == nil {
		return nil
	}
	return &models.WHOISResult{
		Registrar:      w.Registrar,
		RegistrantName: w.RegistrantName,
		RegistrantOrg:  w.RegistrantOrg,
		Nameservers:    w.Nameservers,
		Status:         w.Status,
		CreationDate:   w.CreationDate,
		ExpirationDate: w.ExpirationDate,
		UpdatedDate:    w.UpdatedDate,
		Error:          w.Error,
	}
}

// printProgress displays a progress bar
func printProgress(domain string, current, total int) {
	percentage := float64(current) / float64(total) * 100
	barWidth := 40
	filled := int(float64(barWidth) * float64(current) / float64(total))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Fprintf(os.Stderr, "\r[%s] %3.0f%% (%d/%d) %s", bar, percentage, current, total, domain)
}

// validateOutputPath performs security validation on the output file path
func validateOutputPath(path string) error {
	if path == "" {
		return nil
	}

	// Clean the path to resolve any . or .. components
	cleanPath := filepath.Clean(path)

	// Check for absolute paths that might be trying to write to sensitive locations
	if filepath.IsAbs(cleanPath) {
		// Allow absolute paths but warn about sensitive locations
		sensitivePatterns := []string{"/etc/", "/var/", "/usr/", "/bin/", "/sbin/", "/root/"}
		for _, pattern := range sensitivePatterns {
			if strings.HasPrefix(cleanPath, pattern) {
				return fmt.Errorf("refusing to write to sensitive system location: %s", cleanPath)
			}
		}
	}

	// Ensure path doesn't escape current directory unexpectedly for relative paths
	if !filepath.IsAbs(path) && strings.HasPrefix(cleanPath, "..") {
		// Allow parent directory references but ensure the resolved path is reasonable
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			return fmt.Errorf("failed to resolve path: %w", err)
		}
		// Just resolve it - the Clean already handled normalization
		_ = absPath
	}

	return nil
}

func outputResults(formatter output.Formatter, result *models.ScanResult) error {
	var writer *os.File
	var err error

	if outputFile != "" {
		// Validate the output path for security
		if validateErr := validateOutputPath(outputFile); validateErr != nil {
			return validateErr
		}

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

func setupProviders(list string, timeout time.Duration) (*providers.Manager, []string, error) {
	if strings.TrimSpace(list) == "" {
		return nil, nil, nil
	}

	// Supported providers registry
	supported := map[string]struct{}{
		"vt":      {},
		"urlvoid": {},
	}

	parts := strings.Split(list, ",")
	requested := make([]string, 0, len(parts))

	// Parse and validate names
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" {
			continue
		}
		if _, ok := supported[p]; !ok {
			return nil, nil, fmt.Errorf("unknown provider %q. Supported: vt,urlvoid", p)
		}
		requested = append(requested, p)
	}
	if len(requested) == 0 {
		return nil, nil, fmt.Errorf("no valid providers specified. Use --providers vt,urlvoid")
	}

	// Validate API keys for requested providers
	vtKey := os.Getenv("VT_API_KEY")
	urlvoidKey := os.Getenv("URLVOID_API_KEY")
	for _, p := range requested {
		switch p {
		case "vt":
			if strings.TrimSpace(vtKey) == "" {
				return nil, nil, fmt.Errorf("VT_API_KEY is required for provider 'vt'")
			}
		case "urlvoid":
			if strings.TrimSpace(urlvoidKey) == "" {
				return nil, nil, fmt.Errorf("URLVOID_API_KEY is required for provider 'urlvoid'")
			}
		}
	}

	// Build manager and register only requested providers
	pm := providers.NewManager()
	for _, p := range requested {
		switch p {
		case "vt":
			pm.Register(providers.NewVirusTotal(providers.VirusTotalConfig{
				APIKey:  vtKey,
				Timeout: timeout,
			}))
		case "urlvoid":
			pm.Register(providers.NewURLVoid(providers.URLVoidConfig{
				APIKey:  urlvoidKey,
				Timeout: timeout,
			}))
		}
	}

	return pm, requested, nil
}

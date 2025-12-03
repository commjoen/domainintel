// Package reachability provides HTTP/HTTPS connectivity checks and IP resolution
package reachability

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/commjoen/domainintel/pkg/models"
)

const (
	defaultTimeout      = 10 * time.Second
	maxRedirects        = 10
	defaultDNSTimeout   = 5 * time.Second
)

// Checker provides methods to check host reachability
type Checker struct {
	httpClient  *http.Client
	dnsResolver *net.Resolver
	timeout     time.Duration
}

// NewChecker creates a new reachability checker with the specified timeout
func NewChecker(timeout time.Duration) *Checker {
	if timeout == 0 {
		timeout = defaultTimeout
	}

	// Create HTTP client with redirect tracking
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
		// Skip TLS verification for testing reachability (we capture errors separately)
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
			},
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
		},
	}

	return &Checker{
		httpClient: client,
		dnsResolver: &net.Resolver{
			PreferGo: true,
		},
		timeout: timeout,
	}
}

// CheckHost performs all reachability checks for a single hostname
func (c *Checker) CheckHost(ctx context.Context, hostname string) models.SubdomainResult {
	result := models.SubdomainResult{
		Hostname:  hostname,
		Reachable: false,
	}

	// Resolve IP addresses first
	ips, err := c.ResolveIPs(ctx, hostname)
	if err != nil {
		result.Error = fmt.Sprintf("DNS resolution failed: %v", err)
		return result
	}
	result.IPs = ips

	// Check HTTPS first (preferred)
	httpsResult := c.CheckHTTP(ctx, "https://"+hostname)
	result.HTTPS = httpsResult

	// Check HTTP as fallback
	httpResult := c.CheckHTTP(ctx, "http://"+hostname)
	result.HTTP = httpResult

	// Extract TLS info if HTTPS was successful
	if httpsResult.Error == "" {
		result.TLS = c.CheckTLS(ctx, hostname)
		result.Reachable = true
	} else if httpResult.Error == "" {
		result.Reachable = true
	}

	return result
}

// ResolveIPs resolves both A and AAAA records for a hostname
func (c *Checker) ResolveIPs(ctx context.Context, hostname string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultDNSTimeout)
	defer cancel()

	ips, err := c.dnsResolver.LookupHost(ctx, hostname)
	if err != nil {
		return nil, err
	}

	return ips, nil
}

// CheckHTTP performs an HTTP/HTTPS request and returns the result
func (c *Checker) CheckHTTP(ctx context.Context, url string) *models.HTTPResult {
	result := &models.HTTPResult{}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result
	}
	req.Header.Set("User-Agent", "domainintel/1.0")

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	result.ResponseTimeMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = categorizeError(err)
		return result
	}
	defer resp.Body.Close()

	result.Status = resp.StatusCode
	result.StatusText = resp.Status
	result.FinalURL = resp.Request.URL.String()

	// Track redirect chain
	if resp.Request.URL.String() != url {
		result.RedirectChain = []string{resp.Request.URL.String()}
	}

	return result
}

// CheckTLS performs TLS certificate validation for a hostname
func (c *Checker) CheckTLS(ctx context.Context, hostname string) *models.TLSResult {
	result := &models.TLSResult{}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: c.timeout}, "tcp", hostname+":443", &tls.Config{
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		result.Valid = false
		result.Error = categorizeError(err)
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Valid = true
		result.Issuer = cert.Issuer.CommonName
		result.Subject = cert.Subject.CommonName
		result.Expires = cert.NotAfter
		result.NotBefore = cert.NotBefore

		// Check if certificate is expired or not yet valid
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			result.Valid = false
			result.Error = "certificate expired or not yet valid"
		}
	}

	// Get TLS version
	switch state.Version {
	case tls.VersionTLS10:
		result.Version = "TLS 1.0"
	case tls.VersionTLS11:
		result.Version = "TLS 1.1"
	case tls.VersionTLS12:
		result.Version = "TLS 1.2"
	case tls.VersionTLS13:
		result.Version = "TLS 1.3"
	default:
		result.Version = "Unknown"
	}

	return result
}

// categorizeError converts various network errors into user-friendly messages
func categorizeError(err error) string {
	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "connection refused"):
		return "connection refused"
	case strings.Contains(errStr, "no such host"):
		return "DNS resolution failed"
	case strings.Contains(errStr, "i/o timeout"):
		return "connection timeout"
	case strings.Contains(errStr, "context deadline exceeded"):
		return "request timeout"
	case strings.Contains(errStr, "x509"):
		return fmt.Sprintf("certificate error: %s", errStr)
	case strings.Contains(errStr, "certificate"):
		return fmt.Sprintf("TLS error: %s", errStr)
	default:
		return errStr
	}
}

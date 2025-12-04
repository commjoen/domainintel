// Package providers provides third-party reputation service integrations
package providers

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSBL is a provider for DNS-based Blackhole List checks
type DNSBL struct {
	resolver *net.Resolver
	timeout  time.Duration
	lists    []string
}

// DNSBLConfig contains configuration for the DNSBL provider
type DNSBLConfig struct {
	Timeout time.Duration
	Lists   []string // Custom DNSBL lists (optional, defaults provided)
}

// DefaultDNSBLLists contains commonly used DNSBL services
var DefaultDNSBLLists = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"dnsbl.sorbs.net",
	"b.barracudacentral.org",
	"cbl.abuseat.org",
}

// NewDNSBL creates a new DNSBL provider
func NewDNSBL(config DNSBLConfig) *DNSBL {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	lists := config.Lists
	if len(lists) == 0 {
		lists = DefaultDNSBLLists
	}

	return &DNSBL{
		resolver: net.DefaultResolver,
		timeout:  timeout,
		lists:    lists,
	}
}

// Name returns the provider identifier
func (d *DNSBL) Name() string {
	return "dnsbl"
}

// IsAvailable returns true if the provider is configured
// DNSBL is always available as it doesn't require API keys
func (d *DNSBL) IsAvailable() bool {
	return true
}

// Check queries DNSBL lists for the domain
func (d *DNSBL) Check(ctx context.Context, domain string) *Result {
	result := &Result{
		Provider:    d.Name(),
		LastChecked: time.Now(),
		Details:     make(map[string]string),
		Categories:  make([]string, 0),
	}

	// For domain-based checks, we check the domain directly against DNSBL
	// Some DNSBLs support domain lookups (like dbl.spamhaus.org)
	listed := 0
	checked := 0

	for _, bl := range d.lists {
		select {
		case <-ctx.Done():
			result.Error = "context canceled"
			return result
		default:
		}

		// Construct the DNSBL lookup query
		query := domain + "." + bl

		timeoutCtx, cancel := context.WithTimeout(ctx, d.timeout)
		addrs, err := d.resolver.LookupHost(timeoutCtx, query)
		cancel()

		checked++

		if err != nil {
			// DNS lookup errors are expected for non-listed domains
			continue
		}

		// If we get an A record response, the domain is listed
		if len(addrs) > 0 {
			listed++
			result.Categories = append(result.Categories, bl)
			// Record the return code (different codes indicate different threats)
			result.Details[bl] = strings.Join(addrs, ",")
		}
	}

	result.Detected = listed > 0
	result.Score = fmt.Sprintf("%d/%d", listed, checked)

	return result
}

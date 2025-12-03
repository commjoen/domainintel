// Package dns provides extended DNS record query functionality
package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultTimeout     = 10 * time.Second
	defaultRetries     = 3
	defaultConcurrency = 4
)

// DNSResult contains all DNS query results for a hostname
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

// Client provides DNS query functionality
type Client struct {
	dnsServers []string
	timeout    time.Duration
	retries    int
}

// NewClient creates a new DNS client with the specified timeout
func NewClient(timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return &Client{
		timeout:    timeout,
		retries:    defaultRetries,
		dnsServers: getSystemDNSServers(),
	}
}

// getSystemDNSServers returns the system's DNS servers or defaults
func getSystemDNSServers() []string {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(config.Servers) == 0 {
		// Fall back to well-known public DNS servers
		return []string{"8.8.8.8:53", "1.1.1.1:53"}
	}

	servers := make([]string, 0, len(config.Servers))
	for _, server := range config.Servers {
		if !strings.Contains(server, ":") {
			server = server + ":53"
		}
		servers = append(servers, server)
	}
	return servers
}

// QueryAll performs all DNS record queries for a hostname
func (c *Client) QueryAll(ctx context.Context, hostname string) *DNSResult {
	result := &DNSResult{}

	// Create a wait group for concurrent queries
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Query types to fetch concurrently
	type queryFunc func(context.Context, string) (interface{}, error)
	type queryResult struct {
		name   string
		result interface{}
		err    error
	}

	queries := []struct {
		name string
		fn   queryFunc
	}{
		{"A", func(ctx context.Context, h string) (interface{}, error) {
			return c.QueryA(ctx, h)
		}},
		{"AAAA", func(ctx context.Context, h string) (interface{}, error) {
			return c.QueryAAAA(ctx, h)
		}},
		{"MX", func(ctx context.Context, h string) (interface{}, error) {
			return c.QueryMX(ctx, h)
		}},
		{"TXT", func(ctx context.Context, h string) (interface{}, error) {
			return c.QueryTXT(ctx, h)
		}},
		{"NS", func(ctx context.Context, h string) (interface{}, error) {
			return c.QueryNS(ctx, h)
		}},
		{"CNAME", func(ctx context.Context, h string) (interface{}, error) {
			return c.QueryCNAME(ctx, h)
		}},
		{"SOA", func(ctx context.Context, h string) (interface{}, error) {
			return c.QuerySOA(ctx, h)
		}},
	}

	results := make(chan queryResult, len(queries))

	for _, q := range queries {
		wg.Add(1)
		go func(name string, fn queryFunc) {
			defer wg.Done()
			r, err := fn(ctx, hostname)
			results <- queryResult{name: name, result: r, err: err}
		}(q.name, q.fn)
	}

	// Wait for all queries and close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var errors []string
	for qr := range results {
		mu.Lock()
		if qr.err != nil {
			// Only record errors that aren't NXDOMAIN for partial results
			if !isNotFoundError(qr.err) {
				errors = append(errors, fmt.Sprintf("%s: %v", qr.name, qr.err))
			}
		} else {
			switch qr.name {
			case "A":
				if v, ok := qr.result.([]string); ok {
					result.A = v
				}
			case "AAAA":
				if v, ok := qr.result.([]string); ok {
					result.AAAA = v
				}
			case "MX":
				if v, ok := qr.result.([]MXRecord); ok {
					result.MX = v
				}
			case "TXT":
				if v, ok := qr.result.([]string); ok {
					result.TXT = v
				}
			case "NS":
				if v, ok := qr.result.([]string); ok {
					result.NS = v
				}
			case "CNAME":
				if v, ok := qr.result.(string); ok {
					result.CNAME = v
				}
			case "SOA":
				if v, ok := qr.result.(*SOARecord); ok {
					result.SOA = v
				}
			}
		}
		mu.Unlock()
	}

	if len(errors) > 0 {
		result.Error = strings.Join(errors, "; ")
	}

	return result
}

// QueryA returns A records (IPv4 addresses) for a hostname
func (c *Client) QueryA(ctx context.Context, hostname string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

	resp, err := c.query(ctx, msg)
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}

	sort.Strings(ips)
	return ips, nil
}

// QueryAAAA returns AAAA records (IPv6 addresses) for a hostname
func (c *Client) QueryAAAA(ctx context.Context, hostname string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)

	resp, err := c.query(ctx, msg)
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, ans := range resp.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			ips = append(ips, aaaa.AAAA.String())
		}
	}

	sort.Strings(ips)
	return ips, nil
}

// QueryMX returns MX records for a hostname
func (c *Client) QueryMX(ctx context.Context, hostname string) ([]MXRecord, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeMX)

	resp, err := c.query(ctx, msg)
	if err != nil {
		return nil, err
	}

	var records []MXRecord
	for _, ans := range resp.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			records = append(records, MXRecord{
				Priority: mx.Preference,
				Host:     strings.TrimSuffix(mx.Mx, "."),
			})
		}
	}

	// Sort by priority
	sort.Slice(records, func(i, j int) bool {
		return records[i].Priority < records[j].Priority
	})

	return records, nil
}

// QueryTXT returns TXT records for a hostname
func (c *Client) QueryTXT(ctx context.Context, hostname string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeTXT)

	resp, err := c.query(ctx, msg)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			// Join multi-part TXT records
			records = append(records, strings.Join(txt.Txt, ""))
		}
	}

	sort.Strings(records)
	return records, nil
}

// QueryNS returns NS records for a hostname
func (c *Client) QueryNS(ctx context.Context, hostname string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeNS)

	resp, err := c.query(ctx, msg)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ans := range resp.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			records = append(records, strings.TrimSuffix(ns.Ns, "."))
		}
	}

	sort.Strings(records)
	return records, nil
}

// QueryCNAME returns the CNAME record for a hostname
func (c *Client) QueryCNAME(ctx context.Context, hostname string) (string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeCNAME)

	resp, err := c.query(ctx, msg)
	if err != nil {
		return "", err
	}

	for _, ans := range resp.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			return strings.TrimSuffix(cname.Target, "."), nil
		}
	}

	return "", nil
}

// QuerySOA returns the SOA record for a hostname
func (c *Client) QuerySOA(ctx context.Context, hostname string) (*SOARecord, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeSOA)

	resp, err := c.query(ctx, msg)
	if err != nil {
		return nil, err
	}

	// Check Answer section first, then Authority section
	for _, ans := range append(resp.Answer, resp.Ns...) {
		if soa, ok := ans.(*dns.SOA); ok {
			// Convert admin email format (e.g., admin.example.com -> admin@example.com)
			adminEmail := strings.TrimSuffix(soa.Mbox, ".")
			adminEmail = strings.Replace(adminEmail, ".", "@", 1)

			return &SOARecord{
				PrimaryNS:  strings.TrimSuffix(soa.Ns, "."),
				AdminEmail: adminEmail,
				Serial:     soa.Serial,
				Refresh:    soa.Refresh,
				Retry:      soa.Retry,
				Expire:     soa.Expire,
				MinTTL:     soa.Minttl,
			}, nil
		}
	}

	return nil, nil
}

// query performs a DNS query with retry logic
func (c *Client) query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{
		Timeout: c.timeout,
		Net:     "udp",
	}

	var lastErr error
	for attempt := 0; attempt < c.retries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		for _, server := range c.dnsServers {
			resp, _, err := client.ExchangeContext(ctx, msg, server)
			if err != nil {
				lastErr = err
				continue
			}

			// Check for DNS errors
			if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
				lastErr = fmt.Errorf("DNS error: %s", dns.RcodeToString[resp.Rcode])
				continue
			}

			return resp, nil
		}

		// Wait before retry (except for last attempt)
		if attempt < c.retries-1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
			}
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("DNS query failed after %d attempts: %w", c.retries, lastErr)
	}
	return nil, fmt.Errorf("DNS query failed after %d attempts", c.retries)
}

// isNotFoundError checks if the error indicates no records were found
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "NXDOMAIN") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "Name Error")
}

// categorizeError converts DNS errors to user-friendly messages
func categorizeError(err error) string {
	if err == nil {
		return ""
	}

	errStr := err.Error()

	// Check for common error patterns
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "DNS query timeout"
	}

	switch {
	case strings.Contains(errStr, "NXDOMAIN"):
		return "domain not found (NXDOMAIN)"
	case strings.Contains(errStr, "SERVFAIL"):
		return "server failure (SERVFAIL)"
	case strings.Contains(errStr, "REFUSED"):
		return "query refused"
	case strings.Contains(errStr, "no such host"):
		return "host not found"
	case strings.Contains(errStr, "i/o timeout"):
		return "DNS query timeout"
	case strings.Contains(errStr, "connection refused"):
		return "DNS server connection refused"
	default:
		return errStr
	}
}

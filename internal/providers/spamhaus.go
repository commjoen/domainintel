// Package providers provides third-party reputation service integrations
package providers

import (
	"context"
	"net"
	"time"
)

// Spamhaus is a provider for Spamhaus reputation checks
type Spamhaus struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// SpamhausConfig contains configuration for the Spamhaus provider
type SpamhausConfig struct {
	Timeout time.Duration
}

// Spamhaus return codes for ZEN combined list
var spamhausReturnCodes = map[string]string{
	"127.0.0.2":  "SBL - Spamhaus Block List",
	"127.0.0.3":  "SBL CSS - Spamhaus Block List CSS",
	"127.0.0.4":  "XBL - Exploits Block List (CBL)",
	"127.0.0.9":  "SBL DROP - Spamhaus DROP/EDROP",
	"127.0.0.10": "PBL - Policy Block List (ISP range)",
	"127.0.0.11": "PBL - Policy Block List (ISP range)",
	"127.0.1.2":  "DBL - Spamhaus Domain Block List (spam domain)",
	"127.0.1.4":  "DBL - Spamhaus Domain Block List (phishing domain)",
	"127.0.1.5":  "DBL - Spamhaus Domain Block List (malware domain)",
	"127.0.1.6":  "DBL - Spamhaus Domain Block List (botnet C&C domain)",
	"127.0.1.102": "DBL - Spamhaus Domain Block List (abused legit spam)",
	"127.0.1.103": "DBL - Spamhaus Domain Block List (abused redirector)",
	"127.0.1.104": "DBL - Spamhaus Domain Block List (abused legit phish)",
	"127.0.1.105": "DBL - Spamhaus Domain Block List (abused legit malware)",
	"127.0.1.106": "DBL - Spamhaus Domain Block List (abused legit botnet)",
}

// NewSpamhaus creates a new Spamhaus provider
func NewSpamhaus(config SpamhausConfig) *Spamhaus {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &Spamhaus{
		resolver: net.DefaultResolver,
		timeout:  timeout,
	}
}

// Name returns the provider identifier
func (s *Spamhaus) Name() string {
	return "spamhaus"
}

// IsAvailable returns true if the provider is configured
// Spamhaus DNS queries are free for non-commercial use and don't require API keys
func (s *Spamhaus) IsAvailable() bool {
	return true
}

// Check queries Spamhaus DBL (Domain Block List) for the domain
func (s *Spamhaus) Check(ctx context.Context, domain string) *Result {
	result := &Result{
		Provider:    s.Name(),
		LastChecked: time.Now(),
		Details:     make(map[string]string),
		Categories:  make([]string, 0),
	}

	// Query Spamhaus DBL (Domain Block List)
	dblQuery := domain + ".dbl.spamhaus.org"

	timeoutCtx, cancel := context.WithTimeout(ctx, s.timeout)
	addrs, err := s.resolver.LookupHost(timeoutCtx, dblQuery)
	cancel()

	if err != nil {
		// DNS lookup error means domain is not listed
		result.Detected = false
		result.Score = "0/1"
		return result
	}

	if len(addrs) == 0 {
		result.Detected = false
		result.Score = "0/1"
		return result
	}

	// Domain is listed in Spamhaus DBL
	result.Detected = true
	result.Score = "1/1"

	// Parse return codes
	for _, addr := range addrs {
		if description, ok := spamhausReturnCodes[addr]; ok {
			result.Categories = append(result.Categories, description)
		} else {
			result.Categories = append(result.Categories, "Listed (code: "+addr+")")
		}
		result.Details["dbl_return_code"] = addr
	}

	return result
}

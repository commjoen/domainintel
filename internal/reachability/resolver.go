// Package reachability provides IP address resolution functionality
package reachability

import (
	"context"
	"net"
	"time"
)

const resolverTimeout = 10 * time.Second

// Resolver provides DNS resolution capabilities
type Resolver struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// NewResolver creates a new IP resolver with the specified timeout
func NewResolver(timeout time.Duration) *Resolver {
	if timeout == 0 {
		timeout = resolverTimeout
	}
	return &Resolver{
		resolver: &net.Resolver{
			PreferGo: true,
		},
		timeout: timeout,
	}
}

// LookupA returns A records (IPv4 addresses) for a hostname
func (r *Resolver) LookupA(ctx context.Context, hostname string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	ips, err := r.resolver.LookupIP(ctx, "ip4", hostname)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		result = append(result, ip.String())
	}
	return result, nil
}

// LookupAAAA returns AAAA records (IPv6 addresses) for a hostname
func (r *Resolver) LookupAAAA(ctx context.Context, hostname string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	ips, err := r.resolver.LookupIP(ctx, "ip6", hostname)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		result = append(result, ip.String())
	}
	return result, nil
}

// LookupAll returns both A and AAAA records for a hostname
func (r *Resolver) LookupAll(ctx context.Context, hostname string) (ipv4 []string, ipv6 []string, err error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Lookup IPv4
	ipv4, _ = r.LookupA(ctx, hostname)

	// Lookup IPv6
	ipv6, _ = r.LookupAAAA(ctx, hostname)

	// Return error only if both lookups failed
	if len(ipv4) == 0 && len(ipv6) == 0 {
		_, err = r.resolver.LookupHost(ctx, hostname)
		return nil, nil, err
	}

	return ipv4, ipv6, nil
}

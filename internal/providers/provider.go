// Package providers provides third-party reputation service integrations
package providers

import (
	"context"
	"sync"
	"time"
)

// Provider defines the interface for third-party reputation providers
type Provider interface {
	// Name returns the provider identifier
	Name() string

	// Check queries the provider for reputation information about a domain
	Check(ctx context.Context, domain string) *Result

	// IsAvailable returns true if the provider is configured and ready to use
	IsAvailable() bool
}

// Result contains the reputation check result from a provider
type Result struct {
	Provider    string            `json:"provider"`
	Score       string            `json:"score,omitempty"`
	Categories  []string          `json:"categories,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	Error       string            `json:"error,omitempty"`
	LastChecked time.Time         `json:"last_checked"`
	Detected    bool              `json:"detected"`
}

// ProviderResults contains results from all providers
type ProviderResults struct {
	Results []Result `json:"results"`
}

// Manager manages multiple providers and orchestrates reputation checks
type Manager struct {
	providers   map[string]Provider
	rateLimiter *RateLimiter
	cache       *Cache
	mu          sync.RWMutex
}

// NewManager creates a new provider manager
func NewManager() *Manager {
	return &Manager{
		providers:   make(map[string]Provider),
		rateLimiter: NewRateLimiter(),
		cache:       NewCache(1 * time.Hour),
	}
}

// Register adds a provider to the manager
func (m *Manager) Register(p Provider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[p.Name()] = p
}

// GetProvider returns a provider by name
func (m *Manager) GetProvider(name string) (Provider, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.providers[name]
	return p, ok
}

// ListProviders returns a list of available provider names
func (m *Manager) ListProviders() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.providers))
	for name, p := range m.providers {
		if p.IsAvailable() {
			names = append(names, name)
		}
	}
	return names
}

// Check runs reputation checks against specified providers
func (m *Manager) Check(ctx context.Context, domain string, providerNames []string) *ProviderResults {
	m.mu.RLock()
	providers := make([]Provider, 0, len(providerNames))
	for _, name := range providerNames {
		if p, ok := m.providers[name]; ok && p.IsAvailable() {
			providers = append(providers, p)
		}
	}
	m.mu.RUnlock()

	results := &ProviderResults{
		Results: make([]Result, 0, len(providers)),
	}

	// Check cache first, then query providers concurrently
	var wg sync.WaitGroup
	resultChan := make(chan Result, len(providers))

	for _, p := range providers {
		// Check cache
		if cached := m.cache.Get(p.Name(), domain); cached != nil {
			resultChan <- *cached
			continue
		}

		// Rate limit check
		if !m.rateLimiter.Allow(p.Name()) {
			resultChan <- Result{
				Provider:    p.Name(),
				Error:       "rate limit exceeded",
				LastChecked: time.Now(),
			}
			continue
		}

		wg.Add(1)
		go func(provider Provider) {
			defer wg.Done()
			result := provider.Check(ctx, domain)
			if result.Error == "" {
				m.cache.Set(provider.Name(), domain, result)
			}
			resultChan <- *result
		}(p)
	}

	// Close channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		results.Results = append(results.Results, result)
	}

	return results
}

// RateLimiter controls the rate of requests to each provider
type RateLimiter struct {
	limits   map[string]*providerLimit
	defaults map[string]int // requests per minute
	mu       sync.Mutex
}

type providerLimit struct {
	lastReset time.Time
	tokens    int
	maxTokens int
}

// NewRateLimiter creates a new rate limiter with default limits
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limits: make(map[string]*providerLimit),
		defaults: map[string]int{
			"urlvoid": 10, // 10 requests per minute
			"vt":      4,  // VirusTotal free tier: 4 requests per minute
			"gsafe":   10,
			"norton":  10,
			"scanurl": 10,
			"ssllabs": 1, // SSL Labs: conservative limit due to slow analysis
		},
	}
}

// Allow checks if a request to the provider is allowed
func (r *RateLimiter) Allow(provider string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	limit, ok := r.limits[provider]
	if !ok {
		maxTokens := r.defaults[provider]
		if maxTokens == 0 {
			maxTokens = 10 // default limit
		}
		limit = &providerLimit{
			tokens:    maxTokens,
			lastReset: time.Now(),
			maxTokens: maxTokens,
		}
		r.limits[provider] = limit
	}

	// Reset tokens if a minute has passed
	if time.Since(limit.lastReset) >= time.Minute {
		limit.tokens = limit.maxTokens
		limit.lastReset = time.Now()
	}

	if limit.tokens > 0 {
		limit.tokens--
		return true
	}
	return false
}

// Cache stores provider results temporarily
type Cache struct {
	entries map[string]*cacheEntry
	ttl     time.Duration
	mu      sync.RWMutex
}

type cacheEntry struct {
	result    *Result
	timestamp time.Time
}

// NewCache creates a new cache with the specified TTL
func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
}

// Get retrieves a cached result
func (c *Cache) Get(provider, domain string) *Result {
	key := provider + ":" + domain
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || time.Since(entry.timestamp) > c.ttl {
		return nil
	}
	return entry.result
}

// Set stores a result in the cache
func (c *Cache) Set(provider, domain string, result *Result) {
	key := provider + ":" + domain
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		result:    result,
		timestamp: time.Now(),
	}
}

// Clear removes all cached entries
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheEntry)
}

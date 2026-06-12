package detector

import (
	"sync"
	"time"
)

// DefaultCacheTTL is how long a detection result stays valid before it is
// re-checked. PLANNED.md specifies a 24h refresh window.
const DefaultCacheTTL = 24 * time.Hour

// cacheEntry is a stored detection result with its expiry time.
type cacheEntry struct {
	result    Result
	expiresAt time.Time
}

// Cache stores detection results per domain with a TTL. It is safe for
// concurrent use.
type Cache struct {
	ttl time.Duration

	mu      sync.RWMutex
	entries map[string]cacheEntry

	// now is injectable for testing; defaults to time.Now.
	now func() time.Time
}

// NewCache returns a Cache with the given TTL. A non-positive ttl falls back
// to DefaultCacheTTL.
func NewCache(ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Cache{
		ttl:     ttl,
		entries: make(map[string]cacheEntry),
		now:     time.Now,
	}
}

// Get returns the cached result for domain and true if a non-expired entry
// exists. Expired entries are treated as misses.
func (c *Cache) Get(domain string) (Result, bool) {
	c.mu.RLock()
	e, ok := c.entries[domain]
	c.mu.RUnlock()

	if !ok || c.now().After(e.expiresAt) {
		return Result{}, false
	}
	return e.result, true
}

// Set stores a detection result for domain, expiring after the cache TTL.
func (c *Cache) Set(domain string, result Result) {
	c.mu.Lock()
	c.entries[domain] = cacheEntry{
		result:    result,
		expiresAt: c.now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// Invalidate drops the cached entry for domain, forcing a fresh check on the
// next lookup. Used to honour "refresh on user request".
func (c *Cache) Invalidate(domain string) {
	c.mu.Lock()
	delete(c.entries, domain)
	c.mu.Unlock()
}

// Clear removes all cached entries.
func (c *Cache) Clear() {
	c.mu.Lock()
	c.entries = make(map[string]cacheEntry)
	c.mu.Unlock()
}

package jwtverify

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"log"
)

// jwksCacheEntry holds a fetched JWKS for one URL.
type jwksCacheEntry struct {
	// keys maps kid → parsed crypto public key.
	keys map[string]interface{}
	// fetchedAt is when this entry was last populated from the network.
	fetchedAt time.Time
	// ttl is the duration to wait before re-fetching when a kid is missing.
	// Derived from Cache-Control: max-age in the JWKS response; falls back to
	// defaultJWKSTTL when the header is absent or unparseable.
	ttl time.Duration
}

// jwksCache is the package-level in-memory JWKS cache, safe for concurrent use.
type jwksCache struct {
	mu      sync.RWMutex
	entries map[string]*jwksCacheEntry // keyed by JWKS URL
}

var globalJWKSCache = &jwksCache{
	entries: make(map[string]*jwksCacheEntry),
}

// defaultJWKSTTL is used when the JWKS response carries no Cache-Control header.
const defaultJWKSTTL = 300 * time.Second

// getKey returns the public key for (url, kid).
//
// Cache behaviour:
//   - kid found in cache              → return immediately (no TTL applied).
//   - URL never fetched               → fetch now.
//   - URL fetched, kid absent, TTL elapsed   → re-fetch.
//   - URL fetched, kid absent, TTL not elapsed → return ErrJWKSKeyNotFound without
//     hitting the network.
func (c *jwksCache) getKey(url, kid string) (interface{}, error) {
	// ── fast path: read lock ─────────────────────────────────────────────────
	c.mu.RLock()
	entry, exists := c.entries[url]
	c.mu.RUnlock()

	if exists {
		if key, ok := entry.keys[kid]; ok {
			return key, nil
		}
		if time.Since(entry.fetchedAt) < entry.ttl {
			return nil, fmt.Errorf("%w: kid=%q url=%s (cache still fresh, expires in %s)",
				ErrJWKSKeyNotFound, kid, url,
				(entry.ttl - time.Since(entry.fetchedAt)).Round(time.Second))
		}
	}

	// ── slow path: write lock + fetch ────────────────────────────────────────
	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check under write lock — another goroutine may have fetched already.
	entry, exists = c.entries[url]
	if exists {
		if key, ok := entry.keys[kid]; ok {
			return key, nil
		}
		if time.Since(entry.fetchedAt) < entry.ttl {
			return nil, fmt.Errorf("%w: kid=%q url=%s (cache still fresh, expires in %s)",
				ErrJWKSKeyNotFound, kid, url,
				(entry.ttl - time.Since(entry.fetchedAt)).Round(time.Second))
		}
	}

	// Fetch from the network.
	keys, ttl, err := fetchAndParseJWKS(url)
	if err != nil {
		return nil, err
	}

	c.entries[url] = &jwksCacheEntry{
		keys:      keys,
		fetchedAt: time.Now(),
		ttl:       ttl,
	}

	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: kid=%q url=%s", ErrJWKSKeyNotFound, kid, url)
	}
	return key, nil
}

// fetchAndParseJWKS downloads a JWKS, parses all keys, and returns:
//   - map[kid]→publicKey
//   - TTL derived from Cache-Control: max-age (or defaultJWKSTTL as fallback)
// jwksHTTPClient has a bounded timeout so a slow or malicious JWKS endpoint
// cannot hang verification indefinitely.
var jwksHTTPClient = &http.Client{Timeout: 10 * time.Second}

// maxJWKSBodySize caps the JWKS response body to prevent memory exhaustion
// from a malicious endpoint returning an enormous payload.
const maxJWKSBodySize = 1 << 20 // 1 MiB

func fetchAndParseJWKS(url string) (map[string]interface{}, time.Duration, error) {
	log.Printf("Fetching JWKS from %s", url)
	resp, err := jwksHTTPClient.Get(url) //nolint:gosec
	if err != nil {
		return nil, 0, fmt.Errorf("fetching JWKS from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("fetching JWKS from %s: unexpected status %d", url, resp.StatusCode)
	}

	ttl := parseCacheControlMaxAge(resp.Header.Get("Cache-Control"))

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBodySize))
	if err != nil {
		return nil, 0, fmt.Errorf("reading JWKS response from %s: %w", url, err)
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, 0, fmt.Errorf("parsing JWKS from %s: %w", url, err)
	}

	keys := make(map[string]interface{}, len(jwks.Keys))
	for _, k := range jwks.Keys {
		pub, err := jwkToPublicKey(k)
		if err != nil {
			// Skip keys using algorithms we don't support.
			continue
		}
		keys[k.Kid] = pub
	}
	return keys, ttl, nil
}

// parseCacheControlMaxAge extracts max-age from a Cache-Control header value.
// Returns defaultJWKSTTL when the header is absent, malformed, or has no max-age.
// A value of 0 is valid and means "always re-fetch for missing kids".
//
// Examples handled:
//
//	"public, max-age=21478"   → 21478s
//	"public, max-age=0"       → 0s  (re-fetch on every missing-kid miss)
//	"no-cache"                → defaultJWKSTTL
//	""                        → defaultJWKSTTL
func parseCacheControlMaxAge(header string) time.Duration {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(strings.ToLower(part), "max-age=") {
			continue
		}
		valStr := strings.TrimPrefix(strings.ToLower(part), "max-age=")
		secs, err := strconv.ParseInt(strings.TrimSpace(valStr), 10, 64)
		if err != nil || secs < 0 {
			break
		}
		return time.Duration(secs) * time.Second
	}
	return defaultJWKSTTL
}
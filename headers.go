package main

import (
	"net/http"
	"path"
	"strings"
)

// hasWildcard returns true if any entry in the list contains a '*' character.
// Called once at config load / CLI parse time — never on the hot path.
func hasWildcard(names []string) bool {
	for _, n := range names {
		if strings.Contains(n, "*") {
			return true
		}
	}
	return false
}

// matchesDelete reports whether headerName should be deleted given a single
// pattern. Patterns without '*' are matched case-insensitively by exact name.
// Patterns with '*' are matched using path.Match semantics (case-insensitive).
func matchesDelete(pattern, headerName string) bool {
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(pattern, headerName)
	}
	matched, _ := path.Match(strings.ToLower(pattern), strings.ToLower(headerName))
	return matched
}

// applyDeleteHeaders deletes headers from h according to the delete list.
//
// Fast path (no wildcards): one direct Del call per pattern — O(n) in the
// number of delete patterns, with no iteration over existing headers.
//
// Slow path (wildcards present): iterates over the current header map once,
// checking each key against every pattern. Only taken when at least one
// pattern in the list contains '*'.
//
// Host is never in http.Header (Go keeps it in req.Host), so neither the
// fast-path Del nor the slow-path key loop will ever touch it.
func applyDeleteHeaders(h http.Header, deleteList []string, hasWild bool) {
	if !hasWild {
		// Fast path — one direct Del call per pattern, no header map iteration.
		// h.Del("Host") is a no-op anyway since Host is never in http.Header.
		for _, name := range deleteList {
			h.Del(name)
		}
		return
	}

	// Slow path — iterate the header map once and match each key against patterns.
	// Collect keys first to avoid mutating the map while ranging it.
	// Host never appears as a key in http.Header so no special-casing needed.
	var toDelete []string
	for key := range h {
		for _, pattern := range deleteList {
			if matchesDelete(pattern, key) {
				toDelete = append(toDelete, key)
				break
			}
		}
	}
	for _, key := range toDelete {
		delete(h, key)
	}
}

// xffRoundTripper wraps an http.RoundTripper to fix X-Forwarded-For handling.
//
// Go's ReverseProxy always appends the client IP after the Director returns,
// causing duplication. By the time RoundTrip is called, the fix is simple:
//
//   - 2+ IPs: Director built the chain, ReverseProxy appended one extra.
//             Strip the last entry.
//   - 1 IP:  Director deleted XFF (delete-header config), ReverseProxy
//             re-added just the client IP. Delete it entirely.
type xffRoundTripper struct {
	base http.RoundTripper
}

func (t *xffRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if vals, ok := req.Header["X-Forwarded-For"]; ok && len(vals) == 1 {
		combined := vals[0]
		if idx := strings.LastIndex(combined, ", "); idx >= 0 {
			// 2+ IPs: strip the duplicate last entry ReverseProxy appended.
			req.Header.Set("X-Forwarded-For", combined[:idx])
		} else {
			// 1 IP: Director deleted XFF, ReverseProxy re-added it. Delete it.
			req.Header.Del("X-Forwarded-For")
		}
	}
	return t.base.RoundTrip(req)
}
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

// hasVarValues returns true if any value in the map starts with '$' or '\$',
// indicating a variable reference or escape sequence that needs processing.
// Called once at config load time.
func hasVarValues(headers map[string]string) bool {
	for _, v := range headers {
		if strings.HasPrefix(v, "$") || strings.HasPrefix(v, `\$`) {
			return true
		}
	}
	return false
}

// resolveHeaderValue resolves a single add-header value against the request.
//
// Rules:
//   - Plain value (no leading '$')  → returned as-is
//   - '\$...'                        → escaped, returns the literal '$...' string
//   - '$remote_addr'                 → client IP (no port)
//   - '$remote_port'                 → client port
//   - '$scheme'                      → "http" or "https"
//   - '$request_uri'                 → full request URI including query string
//   - '$header.Name'                 → value of Name from the original (pre-modification)
//                                      client headers; empty string if absent
//   - Unknown '$...' variable        → passed through as a literal string
//
// original must be a snapshot of req.Header taken before any modifications
// (auth strip, delete-header, etc.) so that $header.X always reflects what
// the client actually sent, regardless of delete-header config.
func resolveHeaderValue(val string, clientIP, clientPort, scheme, requestURI string, original http.Header) string {
	// Escaped dollar must be checked before the plain-value early exit,
	// since \$foo starts with '\' not '$'.
	if strings.HasPrefix(val, `\$`) {
		return val[1:] // strip the backslash, return literal $foo
	}
	if !strings.HasPrefix(val, "$") {
		return val
	}
	switch val {
	case "$remote_addr":
		return clientIP
	case "$remote_port":
		return clientPort
	case "$scheme":
		return scheme
	case "$request_uri":
		return requestURI
	}
	if strings.HasPrefix(val, "$header.") {
		name := val[len("$header."):]
		return original.Get(name) // empty string if header absent
	}
	// Unknown variable — pass through as literal so config errors are visible.
	return val
}
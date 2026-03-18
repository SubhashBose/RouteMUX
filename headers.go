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
// The Host header is always protected: it is never deleted here because it is
// managed separately via req.Host / outHost.
func applyDeleteHeaders(h http.Header, deleteList []string, hasWild bool) {
	if !hasWild {
		// Fast path — direct lookup, no iteration over header map.
		for _, name := range deleteList {
			if strings.EqualFold(name, "host") {
				continue // Host handled separately
			}
			h.Del(name)
		}
		return
	}

	// Slow path — must iterate over current headers to find wildcard matches.
	// Collect keys to delete first to avoid mutating the map while ranging it.
	var toDelete []string
	for key := range h {
		if strings.EqualFold(key, "host") {
			continue
		}
		for _, pattern := range deleteList {
			if strings.EqualFold(pattern, "host") {
				continue
			}
			if matchesDelete(pattern, key) {
				toDelete = append(toDelete, key)
				break
			}
		}
	}
	for _, key := range toDelete {
		delete(h, key) // use direct map delete (faster than h.Del for known canonical keys)
	}
}

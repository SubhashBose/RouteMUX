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

// ---- Parsed header value system ----
//
// add-header values are compiled once at config load time into a slice of
// segments. At request time, evaluation is a simple linear scan with no
// string parsing — just concatenation of literals and resolved variables.
//
// Syntax:  ${variable}       variable reference
//          \${...}           escaped — emits a literal ${...}
//          anything else     literal text (no quoting needed in YAML)
//
// Supported variables:
//   ${remote_addr}    client IP (no port)
//   ${remote_port}    client port
//   ${scheme}         http or https
//   ${request_uri}    full URI including query string
//   ${header.Name}    value of Name from original client headers
//
// Unknown ${variables} pass through as the literal text "${variable}".
// Unmatched ${ (no closing }) is treated as literal text.

type segKind int

const (
	segLiteral    segKind = iota
	segRemoteAddr         // ${remote_addr}
	segRemotePort         // ${remote_port}
	segScheme             // ${scheme}
	segRequestURI         // ${request_uri}
	segHeaderName         // ${header.Name} — carries the header name in seg.value
)

type segment struct {
	kind  segKind
	value string // literal text or header name for segHeaderName
}

// parsedHeaderValue is the compiled form of a single add-header value.
// If isConst is true, the value is a plain string in segments[0].value
// and eval returns it directly with no allocation.
type parsedHeaderValue struct {
	segments []segment
	isConst  bool
}

// compileHeaderValue parses a raw add-header value string into a
// parsedHeaderValue. Called once per header at config load / CLI parse time.
func compileHeaderValue(raw string) parsedHeaderValue {
	var segs []segment

	appendLit := func(lit string) {
		if lit == "" {
			return
		}
		if len(segs) > 0 && segs[len(segs)-1].kind == segLiteral {
			segs[len(segs)-1].value += lit
		} else {
			segs = append(segs, segment{kind: segLiteral, value: lit})
		}
	}

	s := raw
	for len(s) > 0 {
		// Find next ${ marker
		idx := strings.Index(s, "${")
		if idx < 0 {
			// No more variable markers — rest is literal
			appendLit(s)
			break
		}
		// Check for escape \${
		if idx > 0 && s[idx-1] == '\\' {
			// Everything before the backslash + literal ${ 
			appendLit(s[:idx-1] + "${")
			s = s[idx+2:] // skip past ${
			continue
		}
		// Emit literal text before ${
		appendLit(s[:idx])
		s = s[idx+2:] // skip past ${
		// Find matching }
		close := strings.IndexByte(s, '}')
		if close < 0 {
			// Unmatched ${ — treat as literal
			appendLit("${")
			continue
		}
		varName := s[:close]
		s = s[close+1:] // skip past }
		seg := resolveVarName(varName)
		if len(segs) > 0 && seg.kind == segLiteral && segs[len(segs)-1].kind == segLiteral {
			segs[len(segs)-1].value += seg.value
		} else {
			segs = append(segs, seg)
		}
	}
	if len(segs) == 0 {
		segs = []segment{{kind: segLiteral, value: ""}}
	}
	isConst := len(segs) == 1 && segs[0].kind == segLiteral
	return parsedHeaderValue{segments: segs, isConst: isConst}
}

// resolveVarName maps a variable name (inside {}) to a segment.
// Unknown names become literal text "{name}".
func resolveVarName(name string) segment {
	switch name {
	case "remote_addr":
		return segment{kind: segRemoteAddr}
	case "remote_port":
		return segment{kind: segRemotePort}
	case "scheme":
		return segment{kind: segScheme}
	case "request_uri":
		return segment{kind: segRequestURI}
	}
	if strings.HasPrefix(name, "header.") {
		return segment{kind: segHeaderName, value: name[len("header."):]}
	}
	// Unknown variable — pass through as literal ${name}
	return segment{kind: segLiteral, value: "${" + name + "}"}
}

// eval resolves a parsedHeaderValue against the current request context.
// For constant values (isConst == true) this is a single field read — no
// allocation, no iteration.
func (ph parsedHeaderValue) eval(clientIP, clientPort, scheme, requestURI string, original http.Header) string {
	if ph.isConst {
		return ph.segments[0].value
	}
	var b strings.Builder
	for _, seg := range ph.segments {
		switch seg.kind {
		case segLiteral:
			b.WriteString(seg.value)
		case segRemoteAddr:
			b.WriteString(clientIP)
		case segRemotePort:
			b.WriteString(clientPort)
		case segScheme:
			b.WriteString(scheme)
		case segRequestURI:
			b.WriteString(requestURI)
		case segHeaderName:
			b.WriteString(original.Get(seg.value))
		}
	}
	return b.String()
}

// compiledHeaders compiles a map of raw add-header strings into
// parsedHeaderValues. Called once at config load / CLI parse time.
func compiledHeaders(raw map[string]string) map[string]parsedHeaderValue {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]parsedHeaderValue, len(raw))
	for k, v := range raw {
		out[k] = compileHeaderValue(v)
	}
	return out
}

// hasNonConstHeader returns true if any header value contains any variable
// reference. Used to decide whether to compute scheme/URI at request time.
func hasNonConstHeader(headers map[string]parsedHeaderValue) bool {
	for _, ph := range headers {
		if !ph.isConst {
			return true
		}
	}
	return false
}

// hasHeaderNameVar returns true if any header value references ${header.X},
// which requires a snapshot of the original client headers at request time.
func hasHeaderNameVar(headers map[string]parsedHeaderValue) bool {
	for _, ph := range headers {
		for _, seg := range ph.segments {
			if seg.kind == segHeaderName {
				return true
			}
		}
	}
	return false
}
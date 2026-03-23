package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ---- Data types ----

// filterListKind distinguishes the two filter lists.
type filterListKind int

const (
	filterBlocked filterListKind = iota
	filterAllowed
)

// sourceKind distinguishes how a filter source is loaded.
type sourceKind int

const (
	sourceCIDR sourceKind = iota // inline CIDR — static, never refreshed
	sourceFile                   // local file path — polled by mtime
	sourceURL                    // remote URL — fetched periodically
)

// filterSource describes one entry in an allowed/blocked list.
type filterSource struct {
	kind    sourceKind
	list    filterListKind
	cidr    net.IPNet     // sourceCIDR only
	path    string        // sourceFile / sourceURL
	url     string        // sourceURL only
	cache   string        // sourceURL only — optional persistent cache file path
	refresh time.Duration // 0 = no refresh / no polling
}

// IPFilter holds the compiled allowed/blocked CIDR lists and all sources.
// It is safe for concurrent use — a sync.RWMutex protects the lists.
type IPFilter struct {
	mu      sync.RWMutex
	allowed []net.IPNet
	blocked []net.IPNet

	sources      []filterSource          // all sources (inline + dynamic)
	dynamicCIDRs map[int]dynamicEntry    // idx → current loaded CIDRs for file/URL sources

	hasAllowed bool // true if at least one allowed CIDR is configured
	hasBlocked bool // true if at least one blocked CIDR is configured
}

// ---- Filter logic ----

// Allow reports whether the given IP address is permitted to connect.
//
// Rules:
//
//	only blocked  → allow all except blocked IPs
//	only allowed  → block all except allowed IPs
//	both          → allow only (allowed ∩ ¬blocked)
//	neither       → allow all (no filter configured)
func (f *IPFilter) Allow(remoteAddr string) bool {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If we can't parse the address, parse it directly (no port case).
		ip = remoteAddr
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// Unparseable address — deny to be safe.
		return false
	}

	f.mu.RLock()
	inAllowed := cidrContains(f.allowed, parsed)
	inBlocked := cidrContains(f.blocked, parsed)
	hasAllowed := f.hasAllowed
	hasBlocked := f.hasBlocked
	f.mu.RUnlock()

	switch {
	case hasAllowed && hasBlocked:
		return inAllowed && !inBlocked
	case hasAllowed:
		return inAllowed
	case hasBlocked:
		return !inBlocked
	default:
		return true
	}
}

// cidrContains reports whether ip is contained in any of the given networks.
func cidrContains(nets []net.IPNet, ip net.IP) bool {
	for i := range nets {
		if nets[i].Contains(ip) {
			return true
		}
	}
	return false
}

// ---- List merging ----

// rebuildLocked rebuilds f.allowed and f.blocked from all sources.
// Must be called with f.mu held for writing.
func (f *IPFilter) rebuildLocked() {
	var allowed, blocked []net.IPNet
	for _, src := range f.sources {
		if src.kind == sourceCIDR {
			if src.list == filterAllowed {
				allowed = append(allowed, src.cidr)
			} else {
				blocked = append(blocked, src.cidr)
			}
		}
	}
	// dynamic sources store their current CIDRs in dynamicCIDRs map
	for _, dc := range f.dynamicCIDRs {
		if dc.list == filterAllowed {
			allowed = append(allowed, dc.cidrs...)
		} else {
			blocked = append(blocked, dc.cidrs...)
		}
	}
	f.allowed = allowed
	f.blocked = blocked
	f.hasAllowed = len(allowed) > 0
	f.hasBlocked = len(blocked) > 0
}

// dynamicEntry holds the currently-loaded CIDRs for one dynamic source (file/URL).
type dynamicEntry struct {
	list  filterListKind
	cidrs []net.IPNet
}

// dynamicCIDRs maps source index → current loaded CIDRs.
// Allocated lazily when the first dynamic source is added.
// Protected by f.mu.
func (f *IPFilter) setDynamic(idx int, list filterListKind, cidrs []net.IPNet) {
	f.mu.Lock()
	if f.dynamicCIDRs == nil {
		f.dynamicCIDRs = map[int]dynamicEntry{}
	}
	f.dynamicCIDRs[idx] = dynamicEntry{list: list, cidrs: cidrs}
	f.rebuildLocked()
	f.mu.Unlock()
}

// ---- Startup loading ----

// Load performs the initial load of all sources.
// Called once at startup before the server begins accepting connections.
func (f *IPFilter) Load() error {
	// First pass: collect inline CIDRs and validate them.
	// Dynamic sources are loaded below.
	for i, src := range f.sources {
		if src.kind != sourceCIDR {
			// Load dynamic source now.
			cidrs, err := loadSource(&f.sources[i])
			if err != nil {
				log.Printf("ip-filter: warning: failed to load source %q: %v", sourceDesc(&f.sources[i]), err)
				cidrs = nil
			}
			f.setDynamic(i, src.list, cidrs)
		}
	}
	// Rebuild once at the end to pick up inline CIDRs too.
	f.mu.Lock()
	f.rebuildLocked()
	f.mu.Unlock()

	// Log effective mode.
	f.mu.RLock()
	na, nb := len(f.allowed), len(f.blocked)
	f.mu.RUnlock()
	switch {
	case na > 0 && nb > 0:
		log.Printf("ip-filter: allow-list + block-list mode (%d allowed, %d blocked CIDRs)", na, nb)
	case na > 0:
		log.Printf("ip-filter: allow-list mode (%d CIDRs — all others blocked)", na)
	case nb > 0:
		log.Printf("ip-filter: block-list mode (%d CIDRs — all others allowed)", nb)
	}
	return nil
}

// StartRefresh launches background goroutines for all sources that have a
// non-zero refresh interval. Safe to call after Load().
func (f *IPFilter) StartRefresh() {
	for i := range f.sources {
		src := &f.sources[i]
		if src.kind == sourceCIDR || src.refresh == 0 {
			continue
		}
		idx := i
		go func() {
			ticker := time.NewTicker(src.refresh)
			defer ticker.Stop()
			lastMtime := time.Time{} // for file sources
			for range ticker.C {
				if src.kind == sourceFile {
					// Only reload if mtime changed.
					info, err := os.Stat(src.path)
					if err != nil {
						log.Printf("ip-filter: refresh: cannot stat %q: %v", src.path, err)
						continue
					}
					if !info.ModTime().After(lastMtime) {
						continue // unchanged
					}
					lastMtime = info.ModTime()
				}
				cidrs, err := loadSource(src)
				if err != nil {
					log.Printf("ip-filter: refresh: failed to reload %q: %v (keeping previous list)", sourceDesc(src), err)
					continue
				}
				f.setDynamic(idx, src.list, cidrs)
				log.Printf("ip-filter: refreshed %q (%d CIDRs)", sourceDesc(src), len(cidrs))
			}
		}()
	}
}

// ---- Source loading ----

// loadSource fetches and parses CIDRs from a file or URL source.
func loadSource(src *filterSource) ([]net.IPNet, error) {
	switch src.kind {
	case sourceFile:
		return loadCIDRsFromFile(src.path)
	case sourceURL:
		cidrs, err := loadCIDRsFromURL(src.url)
		if err != nil {
			// Try cache file if available.
			if src.cache != "" {
				cached, cerr := loadCIDRsFromFile(src.cache)
				if cerr == nil {
					log.Printf("ip-filter: URL fetch failed (%v), using cache %q", err, src.cache)
					return cached, nil
				}
			}
			return nil, err
		}
		// Persist to cache file on successful fetch.
		if src.cache != "" {
			if werr := writeCacheFile(src.cache, cidrs); werr != nil {
				log.Printf("ip-filter: warning: could not write cache %q: %v", src.cache, werr)
			}
		}
		return cidrs, nil
	}
	return nil, fmt.Errorf("unexpected source kind %d", src.kind)
}

// loadCIDRsFromFile reads a newline-delimited list of CIDR strings from a file.
func loadCIDRsFromFile(path string) ([]net.IPNet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseCIDRLines(f, path)
}

// loadCIDRsFromURL fetches a newline-delimited CIDR list from a URL.
func loadCIDRsFromURL(rawURL string) ([]net.IPNet, error) {
	resp, err := http.Get(rawURL) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}
	return parseCIDRLines(resp.Body, rawURL)
}

// parseCIDRLines reads CIDR entries from r, one per line.
// Lines starting with '#' and blank lines are ignored.
// Invalid entries are logged and skipped.
func parseCIDRLines(r io.Reader, origin string) ([]net.IPNet, error) {
	var nets []net.IPNet
	sc := bufio.NewScanner(r)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cidrStr := line
		if !strings.Contains(line, "/") {
			// Bare IP — auto-expand to host CIDR.
			ip := net.ParseIP(line)
			if ip == nil {
				log.Printf("ip-filter: %s line %d: invalid CIDR or IP %q (skipped)", origin, lineNum, line)
				continue
			}
			if ip.To4() != nil {
				cidrStr = line + "/32"
			} else {
				cidrStr = line + "/128"
			}
		}
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			log.Printf("ip-filter: %s line %d: invalid CIDR or IP %q (skipped)", origin, lineNum, line)
			continue
		}
		nets = append(nets, *ipNet)
	}
	if err := sc.Err(); err != nil {
		return nets, fmt.Errorf("reading %s: %w", origin, err)
	}
	return nets, nil
}

// writeCacheFile writes a list of CIDRs to a file, one per line.
func writeCacheFile(path string, nets []net.IPNet) error {
	f, err := os.CreateTemp("", "routemux-ipfilter-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	for _, n := range nets {
		fmt.Fprintln(f, n.String())
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

// sourceDesc returns a short human-readable description of a source for logging.
func sourceDesc(src *filterSource) string {
	switch src.kind {
	case sourceFile:
		return src.path
	case sourceURL:
		return src.url
	default:
		return src.cidr.String()
	}
}

// ---- Config parsing ----

// IPFilterConfig is the parsed ip-filter block from the YAML global section.
type IPFilterConfig struct {
	Blocked []string `yaml:"blocked"`
	Allowed []string `yaml:"allowed"`
}

// buildIPFilter constructs an IPFilter from the config's ip-filter block.
// Returns nil if no ip-filter is configured.
func buildIPFilter(cfg *IPFilterConfig) (*IPFilter, error) {
	if cfg == nil {
		return nil, nil
	}
	f := &IPFilter{}
	if err := addSources(f, cfg.Blocked, filterBlocked); err != nil {
		return nil, fmt.Errorf("ip-filter blocked: %w", err)
	}
	if err := addSources(f, cfg.Allowed, filterAllowed); err != nil {
		return nil, fmt.Errorf("ip-filter allowed: %w", err)
	}
	if len(f.sources) == 0 {
		return nil, nil
	}
	// Inline CIDRs are always available immediately — do an initial rebuild so
	// the filter is usable right after buildIPFilter returns (before Load() is
	// called by newServer for dynamic sources).
	f.mu.Lock()
	f.rebuildLocked()
	f.mu.Unlock()
	return f, nil
}

// addSources parses a list of raw entry strings and appends filterSources to f.
func addSources(f *IPFilter, entries []string, list filterListKind) error {
	for _, raw := range entries {
		src, err := parseFilterEntry(raw, list)
		if err != nil {
			return fmt.Errorf("entry %q: %w", raw, err)
		}
		f.sources = append(f.sources, src)
	}
	return nil
}

// parseFilterEntry parses a single ip-filter entry string.
//
// Formats:
//
//	10.0.0.0/8                                         inline CIDR
//	/path/to/file.txt                                  local file (no refresh)
//	/path/to/file.txt  refresh=6h                      local file with polling
//	https://example.com/list                           URL (no refresh)
//	https://example.com/list  refresh=12h              URL with refresh
//	https://example.com/list  refresh=12h  cache=/p    URL with refresh + cache
func parseFilterEntry(raw string, list filterListKind) (filterSource, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return filterSource{}, fmt.Errorf("empty entry")
	}
	value := fields[0]
	opts := fields[1:]

	src := filterSource{list: list}

	// Parse options (key=value pairs).
	var refreshStr, cacheFile string
	for _, opt := range opts {
		k, v, ok := strings.Cut(opt, "=")
		if !ok {
			return filterSource{}, fmt.Errorf("invalid option %q (expected key=value)", opt)
		}
		switch k {
		case "refresh":
			refreshStr = v
		case "cache":
			cacheFile = v
		default:
			return filterSource{}, fmt.Errorf("unknown option %q", k)
		}
	}

	// Parse refresh duration.
	if refreshStr != "" {
		d, err := time.ParseDuration(refreshStr)
		if err != nil || d <= 0 {
			return filterSource{}, fmt.Errorf("invalid refresh=%q: %w", refreshStr, err)
		}
		src.refresh = d
	}

	// Determine source kind.
	switch {
	case strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://"):
		src.kind = sourceURL
		src.url = value
		src.cache = cacheFile
		src.path = value // for sourceDesc
	default:
		// Try to parse as a CIDR or bare IP address.
		cidrStr := value
		if !strings.Contains(value, "/") {
			// Bare IP — auto-expand to host CIDR (/32 for IPv4, /128 for IPv6).
			ip := net.ParseIP(value)
			if ip == nil {
				// Not an IP — treat as a file path.
				src.kind = sourceFile
				src.path = value
				if cacheFile != "" {
					return filterSource{}, fmt.Errorf("file source %q does not support cache= option", value)
				}
				return src, nil
			}
			if ip.To4() != nil {
				cidrStr = value + "/32"
			} else {
				cidrStr = value + "/128"
			}
		}
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err == nil {
			if refreshStr != "" || cacheFile != "" {
				return filterSource{}, fmt.Errorf("inline CIDR/IP %q does not support refresh= or cache= options", value)
			}
			src.kind = sourceCIDR
			src.cidr = *ipNet
		} else {
			// Treat as a file path.
			src.kind = sourceFile
			src.path = value
			if cacheFile != "" {
				return filterSource{}, fmt.Errorf("file source %q does not support cache= option", value)
			}
		}
	}

	return src, nil
}
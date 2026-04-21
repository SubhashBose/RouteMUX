package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"os"
	"strings"
	"sync"
	"time"
)

// ---- Source kinds ----

type sourceKind int

const (
	sourceCIDR sourceKind = iota // inline CIDR or bare IP — static, never refreshed
	sourceFile                   // local file path — polled by mtime
	sourceURL                    // remote URL — fetched periodically
)

// filterSource describes one entry in a CIDR list.
type filterSource struct {
	kind    sourceKind
	cidr    net.IPNet     // sourceCIDR only
	path    string        // sourceFile; also used as display name for sourceURL
	url     string        // sourceURL only
	cache   string        // sourceURL only — optional persistent cache file path
	refresh time.Duration // 0 = no refresh / no polling
}

// ---- CIDRList — shared primitive ----

// CIDRList is a refreshable, concurrency-safe list of IP networks.
// It is the shared building block for IPFilter and TrustedProxies.
type CIDRList struct {
	mu      sync.RWMutex
	nets    []net.IPNet
	sources []filterSource
	dynamic map[int][]net.IPNet // idx → current loaded CIDRs for file/URL sources

	cancel context.CancelFunc // stops background refresh
}

// Contains reports whether ip is in any of the list's networks.
// Safe for concurrent use.
func (cl *CIDRList) Contains(ip net.IP) bool {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	return cidrContains(cl.nets, ip)
}

// rebuild recomputes cl.nets from inline CIDRs + dynamic sources.
// Must be called with cl.mu held for writing.
func (cl *CIDRList) rebuild() {
	var nets []net.IPNet
	for _, src := range cl.sources {
		if src.kind == sourceCIDR {
			nets = append(nets, src.cidr)
		}
	}
	for _, cidrs := range cl.dynamic {
		nets = append(nets, cidrs...)
	}
	cl.nets = nets
}

// setDynamic updates the CIDRs for one dynamic source and rebuilds the list.
func (cl *CIDRList) setDynamic(idx int, cidrs []net.IPNet) {
	cl.mu.Lock()
	if cl.dynamic == nil {
		cl.dynamic = map[int][]net.IPNet{}
	}
	cl.dynamic[idx] = cidrs
	cl.rebuild()
	cl.mu.Unlock()
}

// Load performs the initial fetch of all file/URL sources.
// Called once at startup. Safe to call multiple times (idempotent).
func (cl *CIDRList) Load() error {
	cl.mu.Lock()
	if cl.cancel != nil {
		cl.cancel()
	}
	var ctx context.Context
	ctx, cl.cancel = context.WithCancel(context.Background())
	cl.mu.Unlock()

	for i, src := range cl.sources {
		if src.kind == sourceCIDR {
			continue
		}
		cidrs, cached, err := loadSource(&cl.sources[i])
		if err != nil {
			log.Printf("ip: warning: failed to load %q: %v", sourceDesc(&cl.sources[i]), err)
			cidrs = nil
		}
		cl.setDynamic(i, cidrs)
		if cached {
			cl.AsyncRefresh(ctx, i, true)
		}
	}
	// Final rebuild picks up inline CIDRs (already in sources).
	cl.mu.Lock()
	cl.rebuild()
	cl.mu.Unlock()
	return nil
}

// AsyncRefresh starts a background goroutine to periodic or 
// onetime refresh the CIDRs for one source.
func (cl *CIDRList) AsyncRefresh(ctx context.Context, idx int, onetime bool) {
	src := &cl.sources[idx]
	if src.kind == sourceCIDR || src.refresh == 0 {
		return
	}
	go func() {
		// refreshFromSource fetches the latest CIDRs for this source.
		// For URL sources: always fetches directly from the URL (never uses cache).
		// For file sources: reads the file (mtime already checked by caller).
		refreshFromSource := func() ([]net.IPNet, error) {
			if src.kind == sourceURL {
				cidrs, err := loadCIDRsFromURL(src.url)
				if err != nil {
					return nil, err
				}
				if src.cache != "" {
					if werr := writeCacheFile(src.cache, cidrs); werr != nil {
						log.Printf("ip: warning: could not update cache %q: %v", src.cache, werr)
					}
				}
				return cidrs, nil
			}
			return loadCIDRsFromFile(src.path)
		}

		// For URL sources that loaded from cache at startup, do one immediate
		// background fetch so the list is current without blocking startup.
		// This fires before the first ticker tick (which may be hours away).
		if onetime {
			if src.kind == sourceURL && src.cache != "" {
				if cidrs, err := refreshFromSource(); err == nil {
					cl.setDynamic(idx, cidrs)
					log.Printf("ip: refreshed %q (%d CIDRs)", sourceDesc(src), len(cidrs))
				} else {
					log.Printf("ip: background refresh: %q failed (%v), keeping cached list", sourceDesc(src), err)
				}
			}
			return
		}
		ticker := time.NewTicker(src.refresh)
		defer ticker.Stop()
		lastMtime := time.Time{}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if src.kind == sourceFile {
					info, err := os.Stat(src.path)
					if err != nil {
						log.Printf("ip: refresh: cannot stat %q: %v", src.path, err)
						continue
					}
					if !info.ModTime().After(lastMtime) {
						continue
					}
					lastMtime = info.ModTime()
				}
				cidrs, err := refreshFromSource()
				if err != nil {
					log.Printf("ip: refresh: failed to reload %q: %v (keeping previous list)", sourceDesc(src), err)
					continue
				}
				cl.setDynamic(idx, cidrs)
				log.Printf("ip: refreshed %q (%d CIDRs)", sourceDesc(src), len(cidrs))
			}
		}
	}()
}

// StartRefresh launches background goroutines for all sources with a non-zero
// refresh interval. Safe to call after Load().
func (cl *CIDRList) StartRefresh() {
	cl.mu.Lock()
	if cl.cancel != nil {
		cl.cancel()
	}
	var ctx context.Context
	ctx, cl.cancel = context.WithCancel(context.Background())
	cl.mu.Unlock()

	for i := range cl.sources {
		cl.AsyncRefresh(ctx, i, false)
	}
}

// Stop stops all background refresh goroutines.
func (cl *CIDRList) Stop() {
	cl.mu.Lock()
	if cl.cancel != nil {
		cl.cancel()
		cl.cancel = nil
	}
	cl.mu.Unlock()
}

// Len returns the number of networks currently in the list.
func (cl *CIDRList) Len() int {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	return len(cl.nets)
}

// ---- IPFilter ----

// IPFilter holds allowed and blocked CIDRLists and enforces connection policy.
// All methods are safe for concurrent use.
type IPFilter struct {
	blocked *CIDRList
	allowed *CIDRList
}

// Allow reports whether the given remote address is permitted to connect.
//
//	only blocked  → allow all except blocked IPs
//	only allowed  → block all except allowed IPs
//	both          → allow only (allowed ∩ ¬blocked)
//	neither       → allow all
func (f *IPFilter) Allow(remoteAddr string) bool {
	ip := parseRemoteIP(remoteAddr)
	if ip == nil {
		return false
	}
	hasAllowed := f.allowed != nil && f.allowed.Len() > 0
	hasBlocked := f.blocked != nil && f.blocked.Len() > 0
	switch {
	case hasAllowed && hasBlocked:
		return f.allowed.Contains(ip) && !f.blocked.Contains(ip)
	case hasAllowed:
		return f.allowed.Contains(ip)
	case hasBlocked:
		return !f.blocked.Contains(ip)
	default:
		return true
	}
}

// Load initialises all dynamic sources. Called once by newServer.
func (f *IPFilter) Load() error {
	if f.blocked != nil {
		if err := f.blocked.Load(); err != nil {
			return err
		}
	}
	if f.allowed != nil {
		if err := f.allowed.Load(); err != nil {
			return err
		}
	}
	nb, na := 0, 0
	if f.blocked != nil {
		nb = f.blocked.Len()
	}
	if f.allowed != nil {
		na = f.allowed.Len()
	}
	switch {
	case na > 0 && nb > 0:
		log.Printf("ip-filter: allow+block mode (%d allowed, %d blocked CIDRs)", na, nb)
	case na > 0:
		log.Printf("ip-filter: allow-list mode (%d CIDRs — all others blocked)", na)
	case nb > 0:
		log.Printf("ip-filter: block-list mode (%d CIDRs — all others allowed)", nb)
	}
	return nil
}

// StartRefresh launches background refresh goroutines for all dynamic sources.
func (f *IPFilter) StartRefresh() {
	if f.blocked != nil {
		f.blocked.StartRefresh()
	}
	if f.allowed != nil {
		f.allowed.StartRefresh()
	}
}

// Stop stops all background refresh goroutines.
func (f *IPFilter) Stop() {
	if f.blocked != nil {
		f.blocked.Stop()
	}
	if f.allowed != nil {
		f.allowed.Stop()
	}
}

// ---- TrustedProxies ----

// TrustedProxies holds a CIDRList of proxy addresses whose X-Forwarded-*
// headers should be trusted. Connections from these IPs are treated as if
// trust-client-headers were enabled for that request only.
type TrustedProxies struct {
	list *CIDRList
}

// IsTrusted reports whether the connecting address is a trusted proxy.
func (tp *TrustedProxies) IsTrusted(remoteAddr string) bool {
	ip := parseRemoteIP(remoteAddr)
	if ip == nil {
		return false
	}
	return tp.list.Contains(ip)
}

// Load initialises all dynamic sources.
func (tp *TrustedProxies) Load() error {
	if err := tp.list.Load(); err != nil {
		return err
	}
	log.Printf("trusted-proxies: %d CIDRs", tp.list.Len())
	return nil
}

// StartRefresh launches background refresh goroutines.
func (tp *TrustedProxies) StartRefresh() {
	tp.list.StartRefresh()
}

// Stop stops background refresh.
func (tp *TrustedProxies) Stop() {
	tp.list.Stop()
}

// ---- Shared source loading ----

// loadSource fetches CIDRs for a dynamic source.
//
// For URL sources with a cache file:
//   - If the cache file exists and is readable, it is returned immediately
//     so startup is never delayed by a network round-trip.
//   - A background goroutine then fetches the URL and, on success, updates
//     the cache file for next time.
//   - If the cache file does not exist yet (first run), the URL is fetched
//     synchronously so the list is populated before the server starts.
//
// For URL sources without a cache file, the URL is always fetched synchronously.
func loadSource(src *filterSource) ([]net.IPNet, bool, error) {
	switch src.kind {
	case sourceFile:
		cidrs, err := loadCIDRsFromFile(src.path)
		return cidrs, false, err
	case sourceURL:
		// If a cache file exists and is readable, use it immediately.
		if src.cache != "" {
			if cached, cerr := loadCIDRsFromFile(src.cache); cerr == nil {
				log.Printf("ip: startup: loaded %d CIDRs from cache %q (URL refresh in progress)", len(cached), src.cache)
				return cached, true, nil
			}
			// Cache missing or unreadable — fall through to synchronous fetch below.
			log.Printf("ip: startup: no cache at %q, fetching %s synchronously", src.cache, src.url)
		}
		// No cache or cache unavailable — fetch synchronously.
		cidrs, err := loadCIDRsFromURL(src.url)
		if err != nil {
			return nil, false, err
		}
		log.Printf("ip: startup: fetched %d CIDRs", len(cidrs))
		if src.cache != "" {
			if werr := writeCacheFile(src.cache, cidrs); werr != nil {
				log.Printf("ip: warning: could not write cache %q: %v", src.cache, werr)
			}
		}
		return cidrs, false, nil
	}
	return nil, false, fmt.Errorf("unexpected source kind %d", src.kind)
}

func loadCIDRsFromFile(path string) ([]net.IPNet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseCIDRLines(f, path)
}

func loadCIDRsFromURL(rawURL string) ([]net.IPNet, error) {
	client := http.Client{
		Timeout: 12 * time.Second,
	}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "RouteMUX")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}
	return parseCIDRLines(resp.Body, rawURL)
}

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
			ip := net.ParseIP(line)
			if ip == nil {
				log.Printf("ip: %s line %d: invalid CIDR or IP %q (skipped)", origin, lineNum, line)
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
			log.Printf("ip: %s line %d: invalid CIDR or IP %q (skipped)", origin, lineNum, line)
			continue
		}
		nets = append(nets, *ipNet)
	}
	if err := sc.Err(); err != nil {
		return nets, fmt.Errorf("reading %s: %w", origin, err)
	}
	return nets, nil
}

func writeCacheFile(path string, nets []net.IPNet) error {
	// Create the temp file in the same directory as the cache file so that
	// os.Rename is always an atomic same-filesystem move (never EXDEV).
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".routemux-ip-*.tmp")
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
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

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

// ---- Shared helpers ----

// parseRemoteIP extracts and parses the IP from a host:port remoteAddr string.
func parseRemoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}

func cidrContains(nets []net.IPNet, ip net.IP) bool {
	for i := range nets {
		if nets[i].Contains(ip) {
			return true
		}
	}
	return false
}

// ---- Config parsing ----

// IPFilterConfig is the YAML structure for the ip-filter global block.
type IPFilterConfig struct {
	Blocked []string `yaml:"blocked"`
	Allowed []string `yaml:"allowed"`
}

// TrustedProxiesConfig is the YAML structure for the trusted-proxies global block.
// It accepts the same entry formats as ip-filter: inline CIDRs/IPs, file paths, URLs.
type TrustedProxiesConfig []string

// buildCIDRList parses a list of raw entry strings into a CIDRList.
func buildCIDRList(entries []string) (*CIDRList, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	cl := &CIDRList{}
	for _, raw := range entries {
		src, err := parseFilterEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", raw, err)
		}
		cl.sources = append(cl.sources, src)
		if src.kind == sourceCIDR {
			cl.nets = append(cl.nets, src.cidr)
		}
	}
	return cl, nil
}

// buildIPFilter constructs an IPFilter from the config block.
// Returns nil if no ip-filter is configured.
func buildIPFilter(cfg *IPFilterConfig) (*IPFilter, error) {
	if cfg == nil {
		return nil, nil
	}
	blocked, err := buildCIDRList(cfg.Blocked)
	if err != nil {
		return nil, fmt.Errorf("blocked: %w", err)
	}
	allowed, err := buildCIDRList(cfg.Allowed)
	if err != nil {
		return nil, fmt.Errorf("allowed: %w", err)
	}
	if blocked == nil && allowed == nil {
		return nil, nil
	}
	return &IPFilter{blocked: blocked, allowed: allowed}, nil
}

// buildTrustedProxies constructs a TrustedProxies from the config block.
// Returns nil if no trusted-proxies is configured.
func buildTrustedProxies(entries TrustedProxiesConfig) (*TrustedProxies, error) {
	cl, err := buildCIDRList([]string(entries))
	if err != nil {
		return nil, err
	}
	if cl == nil {
		return nil, nil
	}
	return &TrustedProxies{list: cl}, nil
}

// parseFilterEntry parses a single CIDR list entry string.
// Format: "<value> [refresh=<duration>] [cache=<path>]"
// Value may be: bare IP, CIDR, file path, http/https URL.
//
//	10.0.0.0/8                                         inline CIDR
//	/path/to/file.txt                                  local file (no refresh)
//	/path/to/file.txt  refresh=6h                      local file with polling
//	https://example.com/list                           URL (no refresh)
//	https://example.com/list  refresh=12h              URL with refresh
//	https://example.com/list  refresh=12h  cache=/p    URL with refresh + cache
func parseFilterEntry(raw string) (filterSource, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return filterSource{}, fmt.Errorf("empty entry")
	}
	value := fields[0]
	var refreshStr, cacheFile string
	for _, opt := range fields[1:] {
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
	src := filterSource{}
	if refreshStr != "" {
		d, err := time.ParseDuration(refreshStr)
		if err != nil || d <= 0 {
			return filterSource{}, fmt.Errorf("invalid refresh=%q: %w", refreshStr, err)
		}
		src.refresh = d
	}
	switch {
	case strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://"):
		src.kind = sourceURL
		src.url = value
		src.path = value
		src.cache = cacheFile
	default:
		cidrStr := value
		if !strings.Contains(value, "/") {
			ip := net.ParseIP(value)
			if ip == nil {
				// File path
				src.kind = sourceFile
				src.path = value
				if cacheFile != "" {
					return filterSource{}, fmt.Errorf("file source %q does not support cache=", value)
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
				return filterSource{}, fmt.Errorf("inline CIDR/IP %q does not support refresh= or cache=", value)
			}
			src.kind = sourceCIDR
			src.cidr = *ipNet
		} else {
			src.kind = sourceFile
			src.path = value
			if cacheFile != "" {
				return filterSource{}, fmt.Errorf("file source %q does not support cache=", value)
			}
		}
	}
	return src, nil
}

// addToCIDRList adds a parsed filterSource to a lazily-initialised *CIDRList.
// Inline CIDRs are immediately appended to cl.nets; dynamic sources (file/URL)
// are loaded later via CIDRList.Load(). If *clp is nil it is allocated.
func addToCIDRList(clp **CIDRList, src filterSource) {
	if *clp == nil {
		*clp = &CIDRList{}
	}
	cl := *clp
	cl.sources = append(cl.sources, src)
	if src.kind == sourceCIDR {
		cl.nets = append(cl.nets, src.cidr)
	}
}
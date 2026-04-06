package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ---- helpers ----

func mustNet(cidr string) net.IPNet {
	// Accept both CIDR notation and bare IPs (auto-expand to /32 or /128).
	if !strings.Contains(cidr, "/") {
		ip := net.ParseIP(cidr)
		if ip == nil {
			panic("invalid IP: " + cidr)
		}
		if ip.To4() != nil {
			cidr = cidr + "/32"
		} else {
			cidr = cidr + "/128"
		}
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return *n
}

func filterWithNets(allowed, blocked []string) *IPFilter {
	f := &IPFilter{}
	if len(allowed) > 0 {
		cl := &CIDRList{}
		for _, s := range allowed {
			n := mustNet(s)
			cl.sources = append(cl.sources, filterSource{kind: sourceCIDR, cidr: n})
			cl.nets = append(cl.nets, n)
		}
		f.allowed = cl
	}
	if len(blocked) > 0 {
		cl := &CIDRList{}
		for _, s := range blocked {
			n := mustNet(s)
			cl.sources = append(cl.sources, filterSource{kind: sourceCIDR, cidr: n})
			cl.nets = append(cl.nets, n)
		}
		f.blocked = cl
	}
	return f
}

// ---- Allow() logic tests ----

func TestIPFilter_NoFilter_AllowsAll(t *testing.T) {
	f := &IPFilter{}
	for _, ip := range []string{"1.2.3.4:1234", "10.0.0.1:80", "192.168.1.1:443"} {
		if !f.Allow(ip) {
			t.Errorf("no filter: expected Allow(%q) = true", ip)
		}
	}
}

func TestIPFilter_BlockedOnly_BlocksMatched(t *testing.T) {
	f := filterWithNets(nil, []string{"10.0.0.0/8"})
	tests := []struct {
		addr string
		want bool
	}{
		{"10.1.2.3:80", false},   // inside blocked range
		{"10.0.0.1:80", false},   // inside blocked range
		{"192.168.1.1:80", true}, // outside blocked range
		{"8.8.8.8:80", true},     // outside blocked range
	}
	for _, tt := range tests {
		if got := f.Allow(tt.addr); got != tt.want {
			t.Errorf("blocked-only Allow(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestIPFilter_AllowedOnly_BlocksAll(t *testing.T) {
	f := filterWithNets([]string{"192.168.1.0/24"}, nil)
	tests := []struct {
		addr string
		want bool
	}{
		{"192.168.1.50:80", true},  // inside allowed range
		{"192.168.1.254:80", true}, // inside allowed range
		{"192.168.2.1:80", false},  // outside allowed range
		{"10.0.0.1:80", false},     // outside allowed range
	}
	for _, tt := range tests {
		if got := f.Allow(tt.addr); got != tt.want {
			t.Errorf("allowed-only Allow(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestIPFilter_BothLists_BlockedWinsOverAllowed(t *testing.T) {
	// allowed: 192.168.0.0/16, blocked: 192.168.1.0/24
	// → 192.168.1.x is in allowed but also in blocked → denied
	f := filterWithNets([]string{"192.168.0.0/16"}, []string{"192.168.1.0/24"})
	tests := []struct {
		addr string
		want bool
	}{
		{"192.168.0.1:80", true},  // allowed, not blocked
		{"192.168.2.1:80", true},  // allowed, not blocked
		{"192.168.1.1:80", false}, // allowed but also blocked → denied
		{"10.0.0.1:80", false},    // not in allowed range → denied
	}
	for _, tt := range tests {
		if got := f.Allow(tt.addr); got != tt.want {
			t.Errorf("both-lists Allow(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestIPFilter_IPv6(t *testing.T) {
	f := filterWithNets(nil, []string{"2001:db8::/32"})
	if f.Allow("[2001:db8::1]:80") {
		t.Error("IPv6 address in blocked range should be denied")
	}
	if !f.Allow("[2001:db9::1]:80") {
		t.Error("IPv6 address outside blocked range should be allowed")
	}
}

// ---- parseFilterEntry tests ----

func TestParseFilterEntry_InlineCIDR(t *testing.T) {
	src, err := parseFilterEntry("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if src.kind != sourceCIDR {
		t.Errorf("kind = %v, want sourceCIDR", src.kind)
	}
	if src.cidr.String() != "10.0.0.0/8" {
		t.Errorf("cidr = %q, want 10.0.0.0/8", src.cidr.String())
	}
}

func TestParseFilterEntry_FilePath(t *testing.T) {
	src, err := parseFilterEntry("/etc/blocklist.txt refresh=6h")
	if err != nil {
		t.Fatal(err)
	}
	if src.kind != sourceFile {
		t.Errorf("kind = %v, want sourceFile", src.kind)
	}
	if src.path != "/etc/blocklist.txt" {
		t.Errorf("path = %q", src.path)
	}
	if src.refresh != 6*time.Hour {
		t.Errorf("refresh = %v, want 6h", src.refresh)
	}
}

func TestParseFilterEntry_URL(t *testing.T) {
	src, err := parseFilterEntry("https://example.com/list refresh=12h cache=/tmp/cache.txt")
	if err != nil {
		t.Fatal(err)
	}
	if src.kind != sourceURL {
		t.Errorf("kind = %v, want sourceURL", src.kind)
	}
	if src.url != "https://example.com/list" {
		t.Errorf("url = %q", src.url)
	}
	if src.refresh != 12*time.Hour {
		t.Errorf("refresh = %v, want 12h", src.refresh)
	}
	if src.cache != "/tmp/cache.txt" {
		t.Errorf("cache = %q, want /tmp/cache.txt", src.cache)
	}
}

func TestParseFilterEntry_URLNoRefresh(t *testing.T) {
	src, err := parseFilterEntry("https://example.com/list")
	if err != nil {
		t.Fatal(err)
	}
	if src.refresh != 0 {
		t.Errorf("refresh should be 0 when not specified, got %v", src.refresh)
	}
	if src.cache != "" {
		t.Errorf("cache should be empty when not specified")
	}
}

func TestParseFilterEntry_InvalidRefresh(t *testing.T) {
	_, err := parseFilterEntry("10.0.0.0/8 refresh=notaduration")
	if err == nil {
		t.Error("expected error for invalid refresh duration")
	}
}

func TestParseFilterEntry_CIDRWithRefresh_Error(t *testing.T) {
	_, err := parseFilterEntry("10.0.0.0/8 refresh=1h")
	if err == nil {
		t.Error("expected error: inline CIDR does not support refresh=")
	}
}

func TestParseFilterEntry_FileWithCache_Error(t *testing.T) {
	_, err := parseFilterEntry("/etc/list.txt cache=/tmp/cache.txt")
	if err == nil {
		t.Error("expected error: file source does not support cache=")
	}
}

func TestParseFilterEntry_UnknownOption(t *testing.T) {
	_, err := parseFilterEntry("https://example.com/list unknown=val")
	if err == nil {
		t.Error("expected error for unknown option")
	}
}

// ---- parseCIDRLines tests ----

func TestParseCIDRLines(t *testing.T) {
	input := `# comment
10.0.0.0/8
192.168.0.0/16

# another comment
172.16.0.0/12
invalid-line
`
	nets, err := parseCIDRLines(strings.NewReader(input), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 3 {
		t.Errorf("got %d nets, want 3", len(nets))
	}
}

// ---- File source loading test ----

func TestLoadCIDRsFromFile(t *testing.T) {
	f, err := os.CreateTemp("", "routemux-ipfilter-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	fmt.Fprintln(f, "10.0.0.0/8")
	fmt.Fprintln(f, "192.168.0.0/16")
	f.Close()

	nets, err := loadCIDRsFromFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 2 {
		t.Errorf("got %d nets, want 2", len(nets))
	}
}

// ---- URL source loading test ----

func TestLoadCIDRsFromURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "10.0.0.0/8")
		fmt.Fprintln(w, "172.16.0.0/12")
	}))
	defer srv.Close()

	nets, err := loadCIDRsFromURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 2 {
		t.Errorf("got %d nets, want 2", len(nets))
	}
}

// ---- URL cache fallback test ----

func TestURLSource_CacheFallback(t *testing.T) {
	// Write a cache file with known CIDRs
	cf, err := os.CreateTemp("", "routemux-cache-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cf.Name())
	fmt.Fprintln(cf, "10.0.0.0/8")
	cf.Close()

	// Use a URL that will fail
	src := &filterSource{
		kind:  sourceURL,
		url:   "http://127.0.0.1:1", // nothing listening here
		cache: cf.Name(),
	}
	nets, err := loadSource(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 1 {
		t.Errorf("expected 1 net from cache fallback, got %d", len(nets))
	}
}

// ---- Cache persistence test ----

func TestURLSource_CacheWrite(t *testing.T) {
	cachePath := os.TempDir() + "/routemux-test-cache-write.txt"
	defer os.Remove(cachePath)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "192.168.0.0/16")
	}))
	defer srv.Close()

	src := &filterSource{
		kind:  sourceURL,
		url:   srv.URL,
		cache: cachePath,
	}
	nets, err := loadSource(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 1 {
		t.Errorf("got %d nets, want 1", len(nets))
	}

	// Cache file should have been written
	cached, err := loadCIDRsFromFile(cachePath)
	if err != nil {
		t.Fatalf("cache file not written: %v", err)
	}
	if len(cached) != 1 {
		t.Errorf("cache file has %d nets, want 1", len(cached))
	}
}

// ---- File refresh by mtime test ----

func TestFileSource_MtimeRefresh(t *testing.T) {
	f, err := os.CreateTemp("", "routemux-mtime-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	fmt.Fprintln(f, "10.0.0.0/8")
	f.Close()

	// Use CIDRList directly for the blocked source
	cl := &CIDRList{}
	src := filterSource{
		kind:    sourceFile,
		path:    f.Name(),
		refresh: 50 * time.Millisecond,
	}
	cl.sources = append(cl.sources, src)
	filter := &IPFilter{blocked: cl}

	// Initial load
	cidrs, _ := loadSource(&cl.sources[0])
	cl.setDynamic(0, cidrs)

	if filter.Allow("10.1.2.3:80") {
		t.Error("10.1.2.3 should be blocked after initial load")
	}

	// Update the file with a different CIDR — change mtime
	time.Sleep(10 * time.Millisecond) // ensure mtime differs
	f2, _ := os.OpenFile(f.Name(), os.O_WRONLY|os.O_TRUNC, 0644)
	fmt.Fprintln(f2, "192.168.0.0/16")
	f2.Close()

	// Manually trigger a reload (simulating the ticker)
	cidrs2, _ := loadSource(&cl.sources[0])
	cl.setDynamic(0, cidrs2)

	if !filter.Allow("10.1.2.3:80") {
		t.Error("10.1.2.3 should be allowed after file update")
	}
	if filter.Allow("192.168.1.1:80") {
		t.Error("192.168.1.1 should be blocked after file update")
	}
}

// ---- buildIPFilter / YAML config tests ----

func TestBuildIPFilter_Nil(t *testing.T) {
	f, err := buildIPFilter(nil)
	if err != nil {
		t.Fatal(err)
	}
	if f != nil {
		t.Error("nil config should return nil IPFilter")
	}
}

func TestBuildIPFilter_InlineCIDRs(t *testing.T) {
	cfg := &IPFilterConfig{
		Blocked: []string{"10.0.0.0/8", "172.16.0.0/12"},
		Allowed: []string{"192.168.0.0/16"},
	}
	f, err := buildIPFilter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if f == nil {
		t.Fatal("expected non-nil IPFilter")
	}
	// 192.168.1.1 is in allowed, not in blocked → allowed
	if !f.Allow("192.168.1.1:80") {
		t.Error("192.168.1.1 should be allowed")
	}
	// 10.1.2.3 is in blocked (even if not in allowed) → denied
	if f.Allow("10.1.2.3:80") {
		t.Error("10.1.2.3 should be blocked")
	}
}

// ---- Integration: HTTP handler with IP filter ----

func TestIPFilter_HTTPHandler_BlocksIP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}},
	})

	// Block 127.0.0.0/8 (loopback — where test requests come from)
	cfg.IPFilter = filterWithNets(nil, []string{"127.0.0.0/8"})

	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	// Should get connection closed (err) or a non-2xx response
	if err == nil && resp.StatusCode == http.StatusOK {
		t.Error("blocked IP should not get 200 OK")
	}
}

func TestIPFilter_HTTPHandler_AllowsIP(t *testing.T) {
	var reached bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}},
	})

	// Allow loopback explicitly (127.0.0.0/8)
	cfg.IPFilter = filterWithNets([]string{"127.0.0.0/8"}, nil)

	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("allowed IP should get 200, got %d", resp.StatusCode)
	}
	if !reached {
		t.Error("request should have reached backend")
	}
}

// ---- YAML config loading with ip-filter ----

func TestLoadConfigFile_IPFilter(t *testing.T) {
	yml := `
global:
  port: 8080
  ip-filter:
    blocked:
      - 10.0.0.0/8
      - 172.16.0.0/12
    allowed:
      - 192.168.0.0/16
routes:
  /:
    dest: http://localhost:3000/
`
	f, _ := os.CreateTemp("", "routemux-*.yml")
	f.WriteString(yml)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := loadConfigFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IPFilter == nil {
		t.Fatal("IPFilter should be set")
	}
	// Verify filter is functional
	if cfg.IPFilter.Allow("10.0.0.1:80") {
		t.Error("10.0.0.1 should be blocked")
	}
	if !cfg.IPFilter.Allow("192.168.1.1:80") {
		t.Error("192.168.1.1 should be allowed")
	}
}

// ---- Bare IP auto-expansion tests ----

func TestParseFilterEntry_BareIPv4(t *testing.T) {
	src, err := parseFilterEntry("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if src.kind != sourceCIDR {
		t.Errorf("kind = %v, want sourceCIDR", src.kind)
	}
	if src.cidr.String() != "127.0.0.1/32" {
		t.Errorf("cidr = %q, want 127.0.0.1/32", src.cidr.String())
	}
}

func TestParseFilterEntry_BareIPv6(t *testing.T) {
	src, err := parseFilterEntry("::1")
	if err != nil {
		t.Fatal(err)
	}
	if src.kind != sourceCIDR {
		t.Errorf("kind = %v, want sourceCIDR", src.kind)
	}
	if src.cidr.String() != "::1/128" {
		t.Errorf("cidr = %q, want ::1/128", src.cidr.String())
	}
}

func TestIPFilter_BareIP_Allow(t *testing.T) {
	// Use bare IP notation — should behave identically to /32
	f := filterWithNets([]string{"127.0.0.1"}, nil)
	if !f.Allow("127.0.0.1:80") {
		t.Error("127.0.0.1 should be allowed")
	}
	if f.Allow("127.0.0.2:80") {
		t.Error("127.0.0.2 should not be allowed (only 127.0.0.1/32)")
	}
}

func TestIPFilter_BareIPv6_Allow(t *testing.T) {
	f := filterWithNets([]string{"::1"}, nil)
	if !f.Allow("[::1]:80") {
		t.Error("::1 should be allowed")
	}
	if f.Allow("[::2]:80") {
		t.Error("::2 should not be allowed")
	}
}

func TestParseCIDRLines_BareIP(t *testing.T) {
	input := "10.0.0.1\n::1\n192.168.1.0/24\n"
	nets, err := parseCIDRLines(strings.NewReader(input), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 3 {
		t.Errorf("got %d nets, want 3", len(nets))
	}
}

// ---- CLI ip-filter flag tests ----

func TestCLI_IPFilterAllow(t *testing.T) {
	cfg, err := parseAll([]string{
		"--ip-filter-allow", "192.168.0.0/16",
		"--ip-filter-allow", "127.0.0.1",
		"--route", "/",
		"--dest", "http://localhost:3000/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IPFilter == nil {
		t.Fatal("IPFilter should be set")
	}
	if !cfg.IPFilter.Allow("192.168.1.1:80") {
		t.Error("192.168.1.1 should be allowed")
	}
	if !cfg.IPFilter.Allow("127.0.0.1:80") {
		t.Error("127.0.0.1 should be allowed")
	}
	if cfg.IPFilter.Allow("10.0.0.1:80") {
		t.Error("10.0.0.1 should be blocked (not in allow list)")
	}
}

func TestCLI_IPFilterBlock(t *testing.T) {
	cfg, err := parseAll([]string{
		"--ip-filter-block", "10.0.0.0/8",
		"--ip-filter-block", "172.16.0.1",
		"--route", "/",
		"--dest", "http://localhost:3000/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IPFilter == nil {
		t.Fatal("IPFilter should be set")
	}
	if cfg.IPFilter.Allow("10.1.2.3:80") {
		t.Error("10.1.2.3 should be blocked")
	}
	if cfg.IPFilter.Allow("172.16.0.1:80") {
		t.Error("172.16.0.1 should be blocked (bare IP)")
	}
	if !cfg.IPFilter.Allow("192.168.1.1:80") {
		t.Error("192.168.1.1 should be allowed (not in block list)")
	}
}

func TestCLI_IPFilterBothLists(t *testing.T) {
	cfg, err := parseAll([]string{
		"--ip-filter-allow", "192.168.0.0/16",
		"--ip-filter-block", "192.168.1.0/24",
		"--route", "/",
		"--dest", "http://localhost:3000/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IPFilter.Allow("192.168.2.1:80") {
		t.Error("192.168.2.1 should be allowed (in allowed, not blocked)")
	}
	if cfg.IPFilter.Allow("192.168.1.1:80") {
		t.Error("192.168.1.1 should be blocked (in both lists — blocked wins)")
	}
	if cfg.IPFilter.Allow("10.0.0.1:80") {
		t.Error("10.0.0.1 should be blocked (not in allowed list)")
	}
}

func TestCLI_IPFilterFile(t *testing.T) {
	f, _ := os.CreateTemp("", "routemux-ipfilter-*.txt")
	fmt.Fprintln(f, "10.0.0.0/8")
	fmt.Fprintln(f, "172.16.0.1")
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := parseAll([]string{
		"--ip-filter-block", f.Name(),
		"--route", "/",
		"--dest", "http://localhost:3000/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IPFilter == nil {
		t.Fatal("IPFilter should be set")
	}
	// File sources load at server start via Load() — verify source registered in blocked list
	if cfg.IPFilter.blocked == nil {
		t.Fatal("blocked CIDRList should be set")
	}
	if len(cfg.IPFilter.blocked.sources) != 1 {
		t.Errorf("expected 1 source, got %d", len(cfg.IPFilter.blocked.sources))
	}
	if cfg.IPFilter.blocked.sources[0].kind != sourceFile {
		t.Errorf("source kind = %v, want sourceFile", cfg.IPFilter.blocked.sources[0].kind)
	}
}

func TestCLI_IPFilterInvalidEntry(t *testing.T) {
	_, err := parseAll([]string{
		"--ip-filter-allow", "notanip refresh=badval",
		"--route", "/", "--dest", "http://localhost:3000/",
	})
	if err == nil {
		t.Error("expected error for invalid refresh duration")
	}
}

// ---- TrustedProxies tests ----

func TestTrustedProxies_IsTrusted(t *testing.T) {
	cl := &CIDRList{}
	for _, cidr := range []string{"10.0.0.0/8", "192.168.0.0/16"} {
		n := mustNet(cidr)
		cl.sources = append(cl.sources, filterSource{kind: sourceCIDR, cidr: n})
		cl.nets = append(cl.nets, n)
	}
	tp := &TrustedProxies{list: cl}

	tests := []struct {
		addr    string
		trusted bool
	}{
		{"10.1.2.3:54321", true},
		{"192.168.1.1:54321", true},
		{"172.16.0.1:54321", false},
		{"1.2.3.4:54321", false},
	}
	for _, tt := range tests {
		if got := tp.IsTrusted(tt.addr); got != tt.trusted {
			t.Errorf("IsTrusted(%q) = %v, want %v", tt.addr, got, tt.trusted)
		}
	}
}

func TestTrustedProxies_XFFBehaviour(t *testing.T) {
	// When connecting from a trusted proxy, X-Forwarded-For should be appended
	// (not overwritten) and X-Forwarded-Host/Proto should be left untouched.
	var gotXFF, gotXFH, gotXFP string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotXFH = r.Header.Get("X-Forwarded-Host")
		gotXFP = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}},
	})
	// Trust loopback — test server connects via 127.0.0.1
	cl := &CIDRList{}
	n := mustNet("127.0.0.0/8")
	cl.sources = append(cl.sources, filterSource{kind: sourceCIDR, cidr: n})
	cl.nets = append(cl.nets, n)
	cfg.TrustedProxies = &TrustedProxies{list: cl}

	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Host", "original.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	http.DefaultClient.Do(req)

	// Trusted proxy: existing XFF should be preserved/appended, not overwritten
	if gotXFF == "127.0.0.1" {
		t.Error("trusted proxy: XFF should append, not overwrite")
	}
	if !strings.Contains(gotXFF, "1.2.3.4") {
		t.Errorf("trusted proxy: XFF should contain original chain, got %q", gotXFF)
	}
	// XFH and XFP should be left untouched
	if gotXFH != "original.example.com" {
		t.Errorf("trusted proxy: X-Forwarded-Host should be untouched, got %q", gotXFH)
	}
	if gotXFP != "https" {
		t.Errorf("trusted proxy: X-Forwarded-Proto should be untouched, got %q", gotXFP)
	}
}

func TestTrustedProxies_UntrustedOverwrites(t *testing.T) {
	// When NOT from a trusted proxy, XFF should be overwritten with connecting IP
	var gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}},
	})
	// Trust only 10.0.0.0/8 — test client is 127.0.0.1, so untrusted
	cl := &CIDRList{}
	n := mustNet("10.0.0.0/8")
	cl.sources = append(cl.sources, filterSource{kind: sourceCIDR, cidr: n})
	cl.nets = append(cl.nets, n)
	cfg.TrustedProxies = &TrustedProxies{list: cl}

	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("X-Forwarded-For", "evil-spoofed-ip")
	http.DefaultClient.Do(req)

	// Untrusted: spoofed XFF should be discarded, only real IP kept
	if gotXFF == "evil-spoofed-ip" {
		t.Error("untrusted client: spoofed XFF should be overwritten")
	}
	if strings.Contains(gotXFF, "evil") {
		t.Errorf("untrusted: XFF should not contain spoofed value, got %q", gotXFF)
	}
}

func TestBuildTrustedProxies_Nil(t *testing.T) {
	tp, err := buildTrustedProxies(nil)
	if err != nil {
		t.Fatal(err)
	}
	if tp != nil {
		t.Error("nil config should return nil TrustedProxies")
	}
}

func TestLoadConfigFile_TrustedProxies(t *testing.T) {
	yml := `
global:
  port: 8080
  trusted-proxies:
    - 10.0.0.0/8
    - 172.16.0.0/12
routes:
  /:
    dest: http://localhost:3000/
`
	f, _ := os.CreateTemp("", "routemux-*.yml")
	f.WriteString(yml)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := loadConfigFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TrustedProxies == nil {
		t.Fatal("TrustedProxies should be set")
	}
	if !cfg.TrustedProxies.IsTrusted("10.1.2.3:80") {
		t.Error("10.1.2.3 should be trusted")
	}
	if cfg.TrustedProxies.IsTrusted("1.2.3.4:80") {
		t.Error("1.2.3.4 should not be trusted")
	}
}

func TestCLI_TrustedProxy(t *testing.T) {
	cfg, err := parseAll([]string{
		"--trusted-proxy", "10.0.0.0/8",
		"--trusted-proxy", "192.168.0.0/16",
		"--route", "/", "--dest", "http://localhost:3000/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TrustedProxies == nil {
		t.Fatal("TrustedProxies should be set")
	}
	if !cfg.TrustedProxies.IsTrusted("10.1.2.3:80") {
		t.Error("10.1.2.3 should be trusted")
	}
	if !cfg.TrustedProxies.IsTrusted("192.168.1.1:80") {
		t.Error("192.168.1.1 should be trusted")
	}
	if cfg.TrustedProxies.IsTrusted("172.16.0.1:80") {
		t.Error("172.16.0.1 should not be trusted")
	}
}

func TestCIDRList_Contains(t *testing.T) {
	cl := &CIDRList{}
	for _, cidr := range []string{"10.0.0.0/8"} {
		n := mustNet(cidr)
		cl.nets = append(cl.nets, n)
	}
	if !cl.Contains(net.ParseIP("10.1.2.3")) {
		t.Error("10.1.2.3 should be in 10.0.0.0/8")
	}
	if cl.Contains(net.ParseIP("192.168.1.1")) {
		t.Error("192.168.1.1 should not be in 10.0.0.0/8")
	}
}
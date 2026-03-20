package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)


// mustUpstream parses a URL at test time and returns a ready Upstream.
func mustUpstream(rawURL string, weight int) Upstream {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		panic("invalid test URL: " + rawURL)
	}
	return Upstream{URL: rawURL, ParsedURL: parsed, Weight: weight}
}

// ---- Config file loading (yaml.v3) ----

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "routemux-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(content)
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestLoadConfigFile_Full(t *testing.T) {
	path := writeTempConfig(t, `
global:
  listen: 127.0.0.1
  port: 9000
  tls-cert: /tmp/cert.pem
  tls-key: /tmp/key.pem
  global-auth: ["admin", "pass"]

routes:
  /api/:
    dest: http://localhost:3000/v1/
    noTLSverify: true
    timeout: 60s
    auth: ["user", "pw"]
  /static/:
    dest: http://localhost:8000/
`)
	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.Port != 9000 {
		t.Errorf("port = %d", cfg.Port)
	}
	if cfg.TLSCert != "/tmp/cert.pem" {
		t.Errorf("tls-cert = %q", cfg.TLSCert)
	}
	if cfg.GlobalAuth == nil || cfg.GlobalAuth.User != "admin" || cfg.GlobalAuth.Password != "pass" {
		t.Errorf("global-auth = %+v", cfg.GlobalAuth)
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("want 2 routes, got %d", len(cfg.Routes))
	}

	api := cfg.Routes["/api/"]
	if api == nil {
		t.Fatal("/api/ route missing")
	}
	if api.Upstreams[0].URL != "http://localhost:3000/v1/" {
		t.Errorf("dest = %q", api.Upstreams[0].URL)
	}
	if !api.NoTLSVerify {
		t.Error("noTLSverify should be true")
	}
	if api.Timeout != "60s" {
		t.Errorf("timeout = %q", api.Timeout)
	}
	if !api.AuthExplicit || api.Auth == nil || api.Auth.User != "user" {
		t.Errorf("auth = %+v", api.Auth)
	}
}

func TestLoadConfigFile_Defaults(t *testing.T) {
	path := writeTempConfig(t, `
routes:
  /x/:
    dest: http://localhost/
`)
	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 8080 {
		t.Errorf("default port = %d, want 8080", cfg.Port)
	}
	if cfg.GlobalAuth != nil {
		t.Errorf("unexpected global-auth: %+v", cfg.GlobalAuth)
	}
}

func TestLoadConfigFile_ExplicitNoAuth(t *testing.T) {
	path := writeTempConfig(t, `
global:
  global-auth: ["admin", "secret"]
routes:
  /public/:
    dest: http://localhost/
    auth: []
`)
	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Routes["/public/"]
	if r == nil {
		t.Fatal("/public/ route missing")
	}
	if !r.AuthExplicit {
		t.Error("AuthExplicit should be true")
	}
	if r.Auth != nil {
		t.Errorf("Auth should be nil for empty auth list, got %+v", r.Auth)
	}
}

func TestLoadConfigFile_BadGlobalAuth(t *testing.T) {
	path := writeTempConfig(t, `
global:
  global-auth: ["onlyone"]
routes:
  /x/:
    dest: http://localhost/
`)
	_, err := loadConfigFile(path)
	if err == nil {
		t.Error("expected error for malformed global-auth")
	}
}

func TestLoadConfigFile_InvalidYAML(t *testing.T) {
	path := writeTempConfig(t, `{bad yaml:::`)
	_, err := loadConfigFile(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

// ---- CLI parser tests ----

func TestCLI_GlobalFlags(t *testing.T) {
	cfg := &Config{Port: 8080, Routes: map[string]*RouteConfig{}}
	err := applyCLI(cfg, []string{
		"--listen", "127.0.0.1",
		"--port", "9999",
		"--tls-cert", "/c.pem",
		"--tls-key", "/k.pem",
		"--global-auth", "admin:secret",
		"--route", "/api/",
		"--dest", "http://backend/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.Port != 9999 {
		t.Errorf("port = %d", cfg.Port)
	}
	if cfg.TLSCert != "/c.pem" || cfg.TLSKey != "/k.pem" {
		t.Errorf("tls = %q %q", cfg.TLSCert, cfg.TLSKey)
	}
	if cfg.GlobalAuth == nil || cfg.GlobalAuth.User != "admin" || cfg.GlobalAuth.Password != "secret" {
		t.Errorf("global-auth = %+v", cfg.GlobalAuth)
	}
}

func TestCLI_MultipleRoutes(t *testing.T) {
	cfg := &Config{Port: 8080, Routes: map[string]*RouteConfig{}}
	err := applyCLI(cfg, []string{
		"--route", "/a/",
		"--dest", "http://a/",
		"--timeout", "30s",
		"--noTLSverify",
		"--route", "/b/",
		"--dest", "http://b/",
		"--auth", "u:p",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("want 2 routes, got %d", len(cfg.Routes))
	}
	a := cfg.Routes["/a/"]
	if a == nil || a.Upstreams[0].URL != "http://a/" || a.Timeout != "30s" || !a.NoTLSVerify {
		t.Errorf("route /a/ = %+v", a)
	}
	b := cfg.Routes["/b/"]
	if b == nil || !b.AuthExplicit || b.Auth == nil || b.Auth.User != "u" || b.Auth.Password != "p" {
		t.Errorf("route /b/ = %+v", b)
	}
}

func TestCLI_ExplicitNoAuth(t *testing.T) {
	cfg := &Config{Port: 8080, Routes: map[string]*RouteConfig{}}
	err := applyCLI(cfg, []string{
		"--route", "/pub/",
		"--dest", "http://pub/",
		"--auth", "",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Routes["/pub/"]
	if !r.AuthExplicit {
		t.Error("AuthExplicit should be true")
	}
	if r.Auth != nil {
		t.Error("Auth should be nil for empty --auth")
	}
}

func TestCLI_KeyValueSyntax(t *testing.T) {
	cfg := &Config{Port: 8080, Routes: map[string]*RouteConfig{}}
	err := applyCLI(cfg, []string{
		"--port=7777",
		"--route=/x/",
		"--dest=http://x/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 7777 {
		t.Errorf("port = %d", cfg.Port)
	}
	if cfg.Routes["/x/"] == nil {
		t.Error("route /x/ missing")
	}
}

func TestCLI_UnknownFlag(t *testing.T) {
	cfg := &Config{Port: 8080, Routes: map[string]*RouteConfig{}}
	err := applyCLI(cfg, []string{"--bogus", "val"})
	if err == nil {
		t.Error("expected error for unknown flag")
	}
}

func TestCLI_DestWithoutRoute(t *testing.T) {
	cfg := &Config{Port: 8080, Routes: map[string]*RouteConfig{}}
	err := applyCLI(cfg, []string{"--dest", "http://x/"})
	if err == nil {
		t.Error("expected error: --dest without --route")
	}
}

// ---- Config file + CLI merge ----

func TestParseAll_CLIOverridesFile(t *testing.T) {
	path := writeTempConfig(t, `
global:
  port: 1111
  listen: 0.0.0.0
routes:
  /old/:
    dest: http://old/
`)
	cfg, err := parseAll([]string{
		"--config", path,
		"--port", "2222",
		"--route", "/new/",
		"--dest", "http://new/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 2222 {
		t.Errorf("port = %d, want CLI value 2222", cfg.Port)
	}
	// Both file route and CLI route should be present
	if cfg.Routes["/old/"] == nil {
		t.Error("/old/ from file should be present")
	}
	if cfg.Routes["/new/"] == nil {
		t.Error("/new/ from CLI should be present")
	}
}

func TestParseAll_MissingExplicitConfig(t *testing.T) {
	_, err := parseAll([]string{"--config", "/nonexistent/config.yml"})
	if err == nil {
		t.Error("expected error for missing explicit --config file")
	}
}

// ---- Default config search ----

func TestFindDefaultConfig_BinaryDir(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	os.WriteFile(cfgPath, []byte("global:\n  port: 1234\nroutes:\n  /x/:\n    dest: http://x/\n"), 0644)
	cfg, err := loadConfigFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 1234 {
		t.Errorf("port = %d", cfg.Port)
	}
}

// ---- Server / proxy handler tests ----

func TestRouteHandler_BasicProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:   8080,
		Routes: map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/v1/", 1)}}},
	}
	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/users")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if v := resp.Header.Get("X-Backend-Path"); !strings.HasPrefix(v, "/v1/") {
		t.Errorf("backend path = %q, want /v1/...", v)
	}
}

func TestRouteHandler_GlobalAuth(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:       8080,
		GlobalAuth: &Auth{"admin", "secret"},
		Routes:     map[string]*RouteConfig{"/secure/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	// No credentials → 401
	resp, _ := http.Get(ts.URL + "/secure/")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	// Wrong password → 401
	req, _ := http.NewRequest("GET", ts.URL+"/secure/", nil)
	req.SetBasicAuth("admin", "wrong")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong password, got %d", resp.StatusCode)
	}

	// Correct credentials → 200
	req, _ = http.NewRequest("GET", ts.URL+"/secure/", nil)
	req.SetBasicAuth("admin", "secret")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestRouteHandler_RouteAuthOverridesGlobal(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:       8080,
		GlobalAuth: &Auth{"admin", "secret"},
		Routes: map[string]*RouteConfig{
			"/public/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				AuthExplicit: true,
				Auth:         nil, // explicit no-auth overrides global
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/public/")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for public route, got %d", resp.StatusCode)
	}
}

func TestRouteHandler_PerRouteAuth(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:       8080,
		GlobalAuth: &Auth{"admin", "global"},
		Routes: map[string]*RouteConfig{
			"/special/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				AuthExplicit: true,
				Auth:         &Auth{"special", "pass"},
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	// Global creds should NOT work
	req, _ := http.NewRequest("GET", ts.URL+"/special/", nil)
	req.SetBasicAuth("admin", "global")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("global creds should be rejected, got %d", resp.StatusCode)
	}

	// Route-specific creds should work
	req, _ = http.NewRequest("GET", ts.URL+"/special/", nil)
	req.SetBasicAuth("special", "pass")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("route creds should be accepted, got %d", resp.StatusCode)
	}
}

func TestRouteHandler_PathStripping(t *testing.T) {
	var receivedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:   8080,
		Routes: map[string]*RouteConfig{"/prefix/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/base/", 1)}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	http.Get(ts.URL + "/prefix/foo/bar")
	if receivedPath != "/base/foo/bar" {
		t.Errorf("backend received %q, want /base/foo/bar", receivedPath)
	}
}

func TestRouteHandler_XForwardedHeaders(t *testing.T) {
	var gotXFH, gotXFP string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFH = r.Header.Get("X-Forwarded-Host")
		gotXFP = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:   8080,
		Routes: map[string]*RouteConfig{"/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	http.Get(ts.URL + "/")
	if gotXFH == "" {
		t.Error("X-Forwarded-Host not set")
	}
	if gotXFP == "" {
		t.Error("X-Forwarded-Proto not set")
	}
}

// ---- Validation tests ----

func TestValidate_NoRoutes(t *testing.T) {
	cfg := &Config{Port: 8080, Routes: map[string]*RouteConfig{}}
	if err := cfg.validate(); err == nil {
		t.Error("expected error for no routes")
	}
}

func TestValidate_MissingDest(t *testing.T) {
	cfg := &Config{Port: 8080, Routes: map[string]*RouteConfig{"/x/": {}}}
	if err := cfg.validate(); err == nil {
		t.Error("expected error for missing dest")
	}
}

func TestValidate_TLSPartial(t *testing.T) {
	cfg := &Config{
		Port:    8080,
		TLSCert: "/c.pem",
		Routes:  map[string]*RouteConfig{"/x/": {Upstreams: []Upstream{mustUpstream("http://x/", 1)}}},
	}
	if err := cfg.validate(); err == nil {
		t.Error("expected error for tls-cert without tls-key")
	}
}

// ---- Header manipulation tests ----

func TestRouteHandler_AddHeader(t *testing.T) {
	var gotUA, gotCustom string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotCustom = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				AddHeaders: map[string]string{"User-Agent": "RouteMUX", "X-Custom": "hello"},
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("User-Agent", "OriginalAgent")
	http.DefaultClient.Do(req)

	if gotUA != "RouteMUX" {
		t.Errorf("User-Agent = %q, want RouteMUX", gotUA)
	}
	if gotCustom != "hello" {
		t.Errorf("X-Custom = %q, want hello", gotCustom)
	}
}

func TestRouteHandler_DeleteHeader(t *testing.T) {
	var gotUA, gotCookie string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders: []string{"User-Agent", "Cookie"},
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("User-Agent", "ShouldBeGone")
	req.Header.Set("Cookie", "session=abc")
	http.DefaultClient.Do(req)

	if gotUA != "" {
		t.Errorf("User-Agent should be deleted, got %q", gotUA)
	}
	if gotCookie != "" {
		t.Errorf("Cookie should be deleted, got %q", gotCookie)
	}
}

func TestRouteHandler_DeleteHostIgnored(t *testing.T) {
	var gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders: []string{"Host"}, // should be silently ignored
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	http.Get(ts.URL + "/api/")

	if gotHost == "" {
		t.Error("Host should always be present even when listed in delete-header")
	}
}

func TestRouteHandler_AddAndDeleteOrder(t *testing.T) {
	// delete runs before add, so add-header always wins even for same key
	var gotUA string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders: []string{"User-Agent"},
				AddHeaders:    map[string]string{"User-Agent": "RouteMUX"},
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("User-Agent", "OriginalAgent")
	http.DefaultClient.Do(req)

	if gotUA != "RouteMUX" {
		t.Errorf("User-Agent = %q, want RouteMUX (add should win over delete)", gotUA)
	}
}

func TestCLI_AddDeleteHeaders(t *testing.T) {
	cfg := &Config{Port: 8080, Routes: map[string]*RouteConfig{}}
	err := applyCLI(cfg, []string{
		"--route", "/api/",
		"--dest", "http://backend/",
		"--add-header", "User-Agent: RouteMUX",
		"--add-header", "X-Env: production",
		"--delete-header", "Cookie",
		"--delete-header", "Authorization",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Routes["/api/"]
	if r == nil {
		t.Fatal("route missing")
	}
	if r.AddHeaders["User-Agent"] != "RouteMUX" {
		t.Errorf("User-Agent = %q", r.AddHeaders["User-Agent"])
	}
	if r.AddHeaders["X-Env"] != "production" {
		t.Errorf("X-Env = %q", r.AddHeaders["X-Env"])
	}
	if len(r.DeleteHeaders) != 2 {
		t.Errorf("DeleteHeaders = %v", r.DeleteHeaders)
	}
}

func TestCLI_AddHeaderBadFormat(t *testing.T) {
	cfg := &Config{Port: 8080, Routes: map[string]*RouteConfig{}}
	err := applyCLI(cfg, []string{
		"--route", "/api/",
		"--dest", "http://backend/",
		"--add-header", "NoColonHere",
	})
	if err == nil {
		t.Error("expected error for missing colon in --add-header value")
	}
}

func TestLoadConfigFile_HeaderOptions(t *testing.T) {
	path := writeTempConfig(t, `
routes:
  /api/:
    dest: http://localhost:3000/
    add-header:
      User-Agent: RouteMUX
      X-Env: production
    delete-header:
      - Cookie
      - Authorization
`)
	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Routes["/api/"]
	if r == nil {
		t.Fatal("/api/ route missing")
	}
	if r.AddHeaders["User-Agent"] != "RouteMUX" {
		t.Errorf("User-Agent = %q", r.AddHeaders["User-Agent"])
	}
	if r.AddHeaders["X-Env"] != "production" {
		t.Errorf("X-Env = %q", r.AddHeaders["X-Env"])
	}
	if len(r.DeleteHeaders) != 2 {
		t.Errorf("DeleteHeaders = %v", r.DeleteHeaders)
	}
}

// ---- Host header manipulation tests ----

func TestRouteHandler_AddHostHeader(t *testing.T) {
	var gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				AddHeaders: map[string]string{"Host": "custom.example.com"},
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	http.Get(ts.URL + "/api/")

	if gotHost != "custom.example.com" {
		t.Errorf("Host = %q, want custom.example.com", gotHost)
	}
}

func TestRouteHandler_DeleteHostHeader_FallsBackToUpstream(t *testing.T) {
	var gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Parse the backend URL to get just the host:port
	backendURL, _ := url.Parse(backend.URL)

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders: []string{"Host"},
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	http.Get(ts.URL + "/api/")

	// When Host is deleted, Go uses req.URL.Host — the upstream address.
	if gotHost != backendURL.Host {
		t.Errorf("Host = %q, want upstream host %q", gotHost, backendURL.Host)
	}
}

func TestRouteHandler_ClientHostPassedThrough(t *testing.T) {
	// Without any host manipulation, the client's Host header passes through
	// to the upstream unchanged.
	var gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:   8080,
		Routes: map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	// The client sends Host: myapp.example.com
	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Host = "myapp.example.com"
	http.DefaultClient.Do(req)

	if gotHost != "myapp.example.com" {
		t.Errorf("Host = %q, want client host myapp.example.com", gotHost)
	}
}

// ---- Authorization header passthrough tests ----

func TestRouteHandler_ProxyAuthStripsAuthorization(t *testing.T) {
	// When proxy auth is active, the client's Authorization header must NOT
	// reach the upstream (it contained the proxy credentials).
	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:       8080,
		GlobalAuth: &Auth{"admin", "secret"},
		Routes:     map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.SetBasicAuth("admin", "secret")
	http.DefaultClient.Do(req)

	if gotAuth != "" {
		t.Errorf("Authorization should be stripped by proxy, but upstream got: %q", gotAuth)
	}
}

func TestRouteHandler_NoProxyAuthPassesAuthorization(t *testing.T) {
	// When no proxy auth is active, the client's Authorization header must
	// pass through to upstream untouched.
	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:   8080,
		Routes: map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("Authorization", "Bearer mytoken123")
	http.DefaultClient.Do(req)

	if gotAuth != "Bearer mytoken123" {
		t.Errorf("Authorization should pass through, got: %q", gotAuth)
	}
}

func TestRouteHandler_ProxyAuthWithAddHeaderAuthOverride(t *testing.T) {
	// When proxy auth is active but user also sets add-header: Authorization,
	// the user-supplied value should be sent (not stripped, not the proxy creds).
	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:       8080,
		GlobalAuth: &Auth{"admin", "secret"},
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				AddHeaders: map[string]string{"Authorization": "Bearer upstream-token"},
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.SetBasicAuth("admin", "secret")
	http.DefaultClient.Do(req)

	if gotAuth != "Bearer upstream-token" {
		t.Errorf("Authorization should be user-supplied value, got: %q", gotAuth)
	}
}

func TestRouteHandler_NoProxyAuthDeleteAuthorization(t *testing.T) {
	// No proxy auth, but user explicitly deletes Authorization — it should be gone.
	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders: []string{"Authorization"},
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("Authorization", "Bearer mytoken123")
	http.DefaultClient.Do(req)

	if gotAuth != "" {
		t.Errorf("Authorization should be deleted, got: %q", gotAuth)
	}
}

// ---- Wildcard delete-header tests ----

func TestDeleteHeader_WildcardPrefix(t *testing.T) {
	var gotHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders:    []string{"CF-*"},
				DeleteHasWildcard: true,
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("CF-Ray", "abc123")
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")
	req.Header.Set("X-Keep-Me", "yes")
	http.DefaultClient.Do(req)

	if gotHeaders.Get("Cf-Ray") != "" {
		t.Error("CF-Ray should be deleted")
	}
	if gotHeaders.Get("Cf-Connecting-Ip") != "" {
		t.Error("CF-Connecting-IP should be deleted")
	}
	if gotHeaders.Get("X-Keep-Me") != "yes" {
		t.Error("X-Keep-Me should be untouched")
	}
}

func TestDeleteHeader_WildcardSuffix(t *testing.T) {
	var gotHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders:    []string{"*-Secret"},
				DeleteHasWildcard: true,
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("X-Secret", "gone")
	req.Header.Set("Api-Secret", "gone")
	req.Header.Set("X-Public", "kept")
	http.DefaultClient.Do(req)

	if gotHeaders.Get("X-Secret") != "" {
		t.Error("X-Secret should be deleted")
	}
	if gotHeaders.Get("Api-Secret") != "" {
		t.Error("Api-Secret should be deleted")
	}
	if gotHeaders.Get("X-Public") != "kept" {
		t.Error("X-Public should be untouched")
	}
}

func TestDeleteHeader_NoWildcard_FastPath(t *testing.T) {
	// Verify that exact-match delete still works and the wildcard flag is false.
	rc := &RouteConfig{
		Upstreams: []Upstream{mustUpstream("http://x/", 1)},
		DeleteHeaders:    []string{"Cookie", "Authorization"},
		DeleteHasWildcard: false,
	}
	if rc.DeleteHasWildcard {
		t.Error("DeleteHasWildcard should be false for exact patterns")
	}

	h := http.Header{
		"Cookie":        []string{"session=abc"},
		"Authorization": []string{"Bearer tok"},
		"X-Keep":        []string{"yes"},
	}
	applyDeleteHeaders(h, rc.DeleteHeaders, rc.DeleteHasWildcard)

	if h.Get("Cookie") != "" {
		t.Error("Cookie should be deleted")
	}
	if h.Get("Authorization") != "" {
		t.Error("Authorization should be deleted")
	}
	if h.Get("X-Keep") != "yes" {
		t.Error("X-Keep should be untouched")
	}
}

func TestDeleteHeader_WildcardHostPattern(t *testing.T) {
	// "Host" pattern is skipped in applyDeleteHeaders — Host is managed via
	// req.Host and is never present in http.Header in real requests.
	// A wildcard like "*" will match any key that IS in the header map,
	// but since Host is never there, it is naturally unaffected.
	h := http.Header{
		"X-Misc":  []string{"val"},
		"X-Other": []string{"other"},
	}
	applyDeleteHeaders(h, []string{"host"}, false) // exact "host" pattern — no-op
	if h.Get("X-Misc") != "val" || h.Get("X-Other") != "other" {
		t.Error("other headers should be untouched when only host pattern is given")
	}

	// Wildcard "*" deletes everything in the map (Host isn't in the map anyway).
	applyDeleteHeaders(h, []string{"*"}, true)
	if len(h) != 0 {
		t.Errorf("wildcard * should delete all headers in map, got: %v", h)
	}
}

func TestHasWildcard(t *testing.T) {
	if hasWildcard([]string{"Cookie", "Authorization"}) {
		t.Error("no wildcard expected")
	}
	if !hasWildcard([]string{"Cookie", "CF-*"}) {
		t.Error("wildcard expected")
	}
}
// ---- Variable resolution tests ----

func TestResolveHeaderValue_PlainValue(t *testing.T) {
	orig := http.Header{"User-Agent": []string{"TestBrowser"}}
	got := resolveHeaderValue("plain-value", "1.2.3.4", "54321", "https", "/path?q=1", orig)
	if got != "plain-value" {
		t.Errorf("got %q, want plain-value", got)
	}
}

func TestResolveHeaderValue_EscapedDollar(t *testing.T) {
	orig := http.Header{}
	got := resolveHeaderValue(`\$remote_addr`, "1.2.3.4", "54321", "https", "/", orig)
	if got != "$remote_addr" {
		t.Errorf("got %q, want literal $remote_addr", got)
	}
}

func TestResolveHeaderValue_RemoteAddr(t *testing.T) {
	orig := http.Header{}
	got := resolveHeaderValue("$remote_addr", "1.2.3.4", "54321", "https", "/", orig)
	if got != "1.2.3.4" {
		t.Errorf("got %q, want 1.2.3.4", got)
	}
}

func TestResolveHeaderValue_RemotePort(t *testing.T) {
	orig := http.Header{}
	got := resolveHeaderValue("$remote_port", "1.2.3.4", "54321", "https", "/", orig)
	if got != "54321" {
		t.Errorf("got %q, want 54321", got)
	}
}

func TestResolveHeaderValue_Scheme(t *testing.T) {
	orig := http.Header{}
	got := resolveHeaderValue("$scheme", "1.2.3.4", "54321", "https", "/", orig)
	if got != "https" {
		t.Errorf("got %q, want https", got)
	}
}

func TestResolveHeaderValue_RequestURI(t *testing.T) {
	orig := http.Header{}
	got := resolveHeaderValue("$request_uri", "1.2.3.4", "54321", "http", "/path?foo=bar", orig)
	if got != "/path?foo=bar" {
		t.Errorf("got %q, want /path?foo=bar", got)
	}
}

func TestResolveHeaderValue_HeaderVar(t *testing.T) {
	orig := http.Header{"User-Agent": []string{"TestBrowser/1.0"}}
	got := resolveHeaderValue("$header.User-Agent", "1.2.3.4", "54321", "http", "/", orig)
	if got != "TestBrowser/1.0" {
		t.Errorf("got %q, want TestBrowser/1.0", got)
	}
}

func TestResolveHeaderValue_HeaderVarMissing(t *testing.T) {
	orig := http.Header{}
	got := resolveHeaderValue("$header.X-Missing", "1.2.3.4", "54321", "http", "/", orig)
	if got != "" {
		t.Errorf("got %q, want empty string for missing header", got)
	}
}

func TestResolveHeaderValue_UnknownVar(t *testing.T) {
	orig := http.Header{}
	got := resolveHeaderValue("$unknown_var", "1.2.3.4", "54321", "http", "/", orig)
	if got != "$unknown_var" {
		t.Errorf("got %q, want literal $unknown_var", got)
	}
}

func TestRouteHandler_VarRemoteAddr(t *testing.T) {
	var gotHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Real-IP")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				AddHeaders: map[string]string{"X-Real-IP": "$remote_addr"},
				AddHasVars: true,
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	http.Get(ts.URL + "/api/")

	if gotHeader == "" {
		t.Error("X-Real-IP should be set to client IP")
	}
	// Should be a valid IP (no port)
	if strings.Contains(gotHeader, ":") {
		t.Errorf("X-Real-IP should be IP only (no port), got %q", gotHeader)
	}
}

func TestRouteHandler_VarHeaderCopiedAfterDelete(t *testing.T) {
	// Even if User-Agent is deleted, $header.User-Agent should still pass
	// the original value because we snapshot headers before modification.
	var gotUA, gotUACopy string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotUACopy = r.Header.Get("X-Original-UA")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders: []string{"User-Agent"},
				AddHeaders:    map[string]string{"X-Original-UA": "$header.User-Agent"},
				AddHasVars:    true,
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("User-Agent", "MyTestClient/2.0")
	http.DefaultClient.Do(req)

	if gotUA != "" {
		t.Errorf("User-Agent should be deleted, got %q", gotUA)
	}
	if gotUACopy != "MyTestClient/2.0" {
		t.Errorf("X-Original-UA should contain original UA, got %q", gotUACopy)
	}
}

func TestRouteHandler_VarScheme(t *testing.T) {
	var gotScheme string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotScheme = r.Header.Get("X-Scheme")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				AddHeaders: map[string]string{"X-Scheme": "$scheme"},
				AddHasVars: true,
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	http.Get(ts.URL + "/api/")

	if gotScheme != "http" {
		t.Errorf("X-Scheme = %q, want http", gotScheme)
	}
}

func TestRouteHandler_EscapedDollar(t *testing.T) {
	var gotHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Literal")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				AddHeaders: map[string]string{"X-Literal": `\$remote_addr`},
				AddHasVars: true,
			},
		},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	http.Get(ts.URL + "/api/")

	if gotHeader != "$remote_addr" {
		t.Errorf("X-Literal = %q, want literal $remote_addr", gotHeader)
	}
}

func TestHasVarValues(t *testing.T) {
	if hasVarValues(map[string]string{"X-Foo": "bar", "X-Baz": "qux"}) {
		t.Error("expected false for no variables")
	}
	if !hasVarValues(map[string]string{"X-Foo": "bar", "X-IP": "$remote_addr"}) {
		t.Error("expected true when variable present")
	}
}
// ---- trust-client-headers tests ----

func TestTrustClientHeaders_False_DiscardXFF(t *testing.T) {
	var gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:               8080,
		TrustClientHeaders: false,
		Routes:             map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("X-Forwarded-For", "185.255.129.29, 10.0.0.1") // forged chain
	http.DefaultClient.Do(req)

	// Client chain should be discarded — only the connecting IP
	parts := strings.Split(gotXFF, ", ")
	if len(parts) != 1 {
		t.Errorf("trust=false: expected 1 IP, got %d in %q (client chain not discarded)", len(parts), gotXFF)
	}
}

func TestTrustClientHeaders_True_AppendXFF(t *testing.T) {
	var gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:               8080,
		TrustClientHeaders: true,
		Routes:             map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("X-Forwarded-For", "185.255.129.29") // upstream proxy set this
	http.DefaultClient.Do(req)

	// Chain should be preserved and connecting IP appended
	if !strings.HasPrefix(gotXFF, "185.255.129.29") {
		t.Errorf("trust=true: client chain should be preserved, got %q", gotXFF)
	}
	parts := strings.Split(gotXFF, ", ")
	if len(parts) != 2 {
		t.Errorf("trust=true: expected 2 IPs (original + connecting), got %d in %q", len(parts), gotXFF)
	}
}

func TestTrustClientHeaders_False_SetsXForwardedHeaders(t *testing.T) {
	var gotHost, gotProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Header.Get("X-Forwarded-Host")
		gotProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:               8080,
		TrustClientHeaders: false,
		Routes:             map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Host = "myapp.example.com"
	// Client tries to forge these
	req.Header.Set("X-Forwarded-Host", "evil.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	http.DefaultClient.Do(req)

	if gotHost != "myapp.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want myapp.example.com", gotHost)
	}
	if gotProto != "http" { // plain HTTP test server
		t.Errorf("X-Forwarded-Proto = %q, want http", gotProto)
	}
}

func TestTrustClientHeaders_True_LeavesXForwardedHeadersUntouched(t *testing.T) {
	var gotHost, gotProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Header.Get("X-Forwarded-Host")
		gotProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port:               8080,
		TrustClientHeaders: true,
		Routes:             map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("X-Forwarded-Host", "original.example.com") // set by upstream proxy
	req.Header.Set("X-Forwarded-Proto", "https")               // set by upstream proxy
	http.DefaultClient.Do(req)

	// Both should pass through untouched
	if gotHost != "original.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want original.example.com", gotHost)
	}
	if gotProto != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https", gotProto)
	}
}
// ---- Upstream / STATUS route tests ----

func TestParseDestField_Status(t *testing.T) {
	cases := []struct {
		dest     string
		wantCode int
		wantText string
		wantIs   bool
	}{
		{"STATUS 200 OK", 200, "OK", true},
		{"STATUS 404 Not Found", 404, "Not Found", true},
		{"STATUS 204", 204, "", true},
		{"STATUS 200 Hello world", 200, "Hello world", true},
		{"status 200 lowercase", 200, "lowercase", true},
		{"http://localhost:3000/", 0, "", false},
		{"STATUS 99 too low", 0, "", false},
		{"STATUS 600 too high", 0, "", false},
	}
	for _, tc := range cases {
		code, text, isStatus := parseDestField(tc.dest)
		if isStatus != tc.wantIs || code != tc.wantCode || text != tc.wantText {
			t.Errorf("parseDestField(%q) = (%d, %q, %v), want (%d, %q, %v)",
				tc.dest, code, text, isStatus, tc.wantCode, tc.wantText, tc.wantIs)
		}
	}
}

func TestParseUpstreamString(t *testing.T) {
	cases := []struct {
		in         string
		wantURL    string
		wantWeight int
		wantErr    bool
	}{
		{"http://localhost:3000/", "http://localhost:3000/", 1, false},
		{"http://localhost:3000/  weight=2", "http://localhost:3000/", 2, false},
		{"http://localhost:4000/ weight=0", "http://localhost:4000/", 1, false}, // weight<1 → 1
		{"STATUS 200 OK", "", 0, true}, // STATUS not allowed in list
	}
	for _, tc := range cases {
		u, err := parseUpstreamString(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseUpstreamString(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseUpstreamString(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if u.URL != tc.wantURL || u.Weight != tc.wantWeight {
			t.Errorf("parseUpstreamString(%q) = {%q, %d}, want {%q, %d}",
				tc.in, u.URL, u.Weight, tc.wantURL, tc.wantWeight)
		}
	}
}

func TestApplyDestEntries_Single(t *testing.T) {
	rc := &RouteConfig{}
	if err := applyDestEntries(rc, []string{"http://localhost:3000/"}, "/api/"); err != nil {
		t.Fatal(err)
	}
	if len(rc.Upstreams) != 1 || rc.Upstreams[0].URL != "http://localhost:3000/" {
		t.Errorf("unexpected upstreams: %v", rc.Upstreams)
	}
	if rc.StatusCode != 0 {
		t.Errorf("StatusCode should be 0, got %d", rc.StatusCode)
	}
}

func TestApplyDestEntries_Multi(t *testing.T) {
	rc := &RouteConfig{}
	entries := []string{"http://localhost:3000/ weight=2", "http://localhost:3001/ weight=1"}
	if err := applyDestEntries(rc, entries, "/api/"); err != nil {
		t.Fatal(err)
	}
	if len(rc.Upstreams) != 2 {
		t.Fatalf("expected 2 upstreams, got %d", len(rc.Upstreams))
	}
	if rc.Upstreams[0].Weight != 2 || rc.Upstreams[1].Weight != 1 {
		t.Errorf("unexpected weights: %+v", rc.Upstreams)
	}
}

func TestApplyDestEntries_Status(t *testing.T) {
	rc := &RouteConfig{}
	if err := applyDestEntries(rc, []string{"STATUS 200 healthy"}, "/health/"); err != nil {
		t.Fatal(err)
	}
	if rc.StatusCode != 200 || rc.StatusText != "healthy" {
		t.Errorf("got StatusCode=%d StatusText=%q", rc.StatusCode, rc.StatusText)
	}
	if len(rc.Upstreams) != 0 {
		t.Errorf("STATUS route should have no upstreams")
	}
}

func TestApplyDestEntries_StatusInList_Error(t *testing.T) {
	rc := &RouteConfig{}
	entries := []string{"http://localhost:3000/", "STATUS 200 OK"}
	if err := applyDestEntries(rc, entries, "/api/"); err == nil {
		t.Error("expected error when STATUS appears in a multi-dest list")
	}
}

func TestStatusRoute_200(t *testing.T) {
	cfg := &Config{
		Port:   8080,
		Routes: map[string]*RouteConfig{"/health/": {StatusCode: 200, StatusText: "OK"}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "OK" {
		t.Errorf("body = %q, want OK", string(body))
	}
}

func TestStatusRoute_EmptyBody(t *testing.T) {
	cfg := &Config{
		Port:   8080,
		Routes: map[string]*RouteConfig{"/ping/": {StatusCode: 204, StatusText: ""}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/ping/")
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("body should be empty, got %q", string(body))
	}
}

func TestStatusRoute_WithAuth(t *testing.T) {
	cfg := &Config{
		Port:       8080,
		GlobalAuth: &Auth{User: "admin", Password: "secret"},
		Routes:     map[string]*RouteConfig{"/health/": {StatusCode: 200, StatusText: "healthy"}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/health/")
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("without auth: status = %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/health/", nil)
	req.SetBasicAuth("admin", "secret")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("with auth: status = %d, want 200", resp.StatusCode)
	}
}

// ---- Load balancer tests ----

func TestUpstreamPicker_SingleUpstream(t *testing.T) {
	upstreams := []Upstream{{URL: "http://a/", Weight: 1}}
	p := newUpstreamPicker(upstreams, "random")
	for i := 0; i < 10; i++ {
		u := p.pick("random")
		if u.URL != "http://a/" {
			t.Errorf("pick() = %q, want http://a/", u.URL)
		}
	}
}

func TestUpstreamPicker_RoundRobin_Equal(t *testing.T) {
	upstreams := []Upstream{
		{URL: "http://a/", Weight: 1},
		{URL: "http://b/", Weight: 1},
	}
	p := newUpstreamPicker(upstreams, "round-robin")
	got := make([]string, 6)
	for i := range got {
		got[i] = p.pick("round-robin").URL
	}
	want := []string{"http://a/", "http://b/", "http://a/", "http://b/", "http://a/", "http://b/"}
	for i, g := range got {
		if g != want[i] {
			t.Errorf("pick[%d] = %q, want %q", i, g, want[i])
		}
	}
}

func TestUpstreamPicker_RoundRobin_Weighted(t *testing.T) {
	upstreams := []Upstream{
		{URL: "http://a/", Weight: 2},
		{URL: "http://b/", Weight: 1},
	}
	p := newUpstreamPicker(upstreams, "round-robin")
	counts := map[string]int{}
	for i := 0; i < 300; i++ {
		counts[p.pick("round-robin").URL]++
	}
	// a should get ~2x the requests of b
	if counts["http://a/"] < counts["http://b/"]*15/10 {
		t.Errorf("weighted round-robin: a=%d b=%d, expected a ~2x b", counts["http://a/"], counts["http://b/"])
	}
}

func TestUpstreamPicker_Random_Weighted(t *testing.T) {
	upstreams := []Upstream{
		{URL: "http://a/", Weight: 3},
		{URL: "http://b/", Weight: 1},
	}
	p := newUpstreamPicker(upstreams, "random")
	counts := map[string]int{}
	for i := 0; i < 4000; i++ {
		counts[p.pick("random").URL]++
	}
	// a should get ~3x the requests of b (allow 20% variance)
	ratio := float64(counts["http://a/"]) / float64(counts["http://b/"])
	if ratio < 2.0 || ratio > 4.5 {
		t.Errorf("weighted random ratio a/b = %.2f, want ~3.0", ratio)
	}
}

func TestNormalizeLBMode(t *testing.T) {
	cases := map[string]string{
		"random":      "random",
		"round-robin": "round-robin",
		"roundrobin":  "round-robin",
		"RANDOM":      "random",
		"":            "random",
		"unknown":     "random",
	}
	for in, want := range cases {
		if got := normalizeLBMode(in); got != want {
			t.Errorf("normalizeLBMode(%q) = %q, want %q", in, got, want)
		}
	}
}
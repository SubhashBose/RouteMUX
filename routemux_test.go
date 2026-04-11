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



// evalConst returns the constant value of a parsedHeaderValue for testing.
// Panics if the value contains variables (use in tests that only test plain values).
func evalConst(ph parsedHeaderValue) string {
	if !ph.isConst {
		panic("evalConst called on non-const parsedHeaderValue")
	}
	return ph.segments[0].value
}


// makeConfig creates a Config with a single catch-all vhost — shorthand for tests.
// Use makeConfigVHosts for multi-vhost tests.
func makeConfig(port int, routes map[string]*RouteConfig) *Config {
	return &Config{
		Port:   port,
		VHosts: []VHost{{Domains: []string{"*"}, Routes: routes}},
	}
}

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
	if len(cfg.VHosts[0].Routes) != 2 {
		t.Fatalf("want 2 routes, got %d", len(cfg.VHosts[0].Routes))
	}

	api := cfg.VHosts[0].Routes["/api/"]
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
	r := cfg.VHosts[0].Routes["/public/"]
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
	cfg := &Config{Port: 8080, VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{}}}}
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
	cfg := &Config{Port: 8080, VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{}}}}
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
	// CLI routes go into the last VHost appended by applyCLI
	cliVH := cfg.VHosts[len(cfg.VHosts)-1]
	if len(cliVH.Routes) != 2 {
		t.Fatalf("want 2 routes, got %d", len(cliVH.Routes))
	}
	a := cliVH.Routes["/a/"]
	if a == nil || a.Upstreams[0].URL != "http://a/" || a.Timeout != "30s" || !a.NoTLSVerify {
		t.Errorf("route /a/ = %+v", a)
	}
	b := cliVH.Routes["/b/"]
	if b == nil || !b.AuthExplicit || b.Auth == nil || b.Auth.User != "u" || b.Auth.Password != "p" {
		t.Errorf("route /b/ = %+v", b)
	}
}

func TestCLI_ExplicitNoAuth(t *testing.T) {
	cfg := &Config{Port: 8080, VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{}}}}
	err := applyCLI(cfg, []string{
		"--route", "/pub/",
		"--dest", "http://pub/",
		"--auth", "",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.VHosts[len(cfg.VHosts)-1].Routes["/pub/"]
	if !r.AuthExplicit {
		t.Error("AuthExplicit should be true")
	}
	if r.Auth != nil {
		t.Error("Auth should be nil for empty --auth")
	}
}

func TestCLI_KeyValueSyntax(t *testing.T) {
	cfg := &Config{Port: 8080, VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{}}}}
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
	if cfg.VHosts[0].Routes["/x/"] == nil {
		t.Error("route /x/ missing")
	}
}

func TestCLI_UnknownFlag(t *testing.T) {
	cfg := &Config{Port: 8080, VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{}}}}
	err := applyCLI(cfg, []string{"--bogus", "val"})
	if err == nil {
		t.Error("expected error for unknown flag")
	}
}

func TestCLI_DestWithoutRoute(t *testing.T) {
	cfg := &Config{Port: 8080, VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{}}}}
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
	if cfg.VHosts[0].Routes["/old/"] == nil {
		t.Error("/old/ from file should be present")
	}
	if cfg.VHosts[0].Routes["/new/"] == nil {
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/v1/", 1)}}}}},
	}
	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/secure/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/public/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				AuthExplicit: true,
				Auth:         nil, // explicit no-auth overrides global
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/special/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				AuthExplicit: true,
				Auth:         &Auth{"special", "pass"},
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/prefix/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/base/", 1)}}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
	cfg := &Config{Port: 8080, VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{}}}}
	if err := cfg.validate(); err == nil {
		t.Error("expected error for no routes")
	}
}

func TestValidate_MissingDest(t *testing.T) {
	cfg := &Config{Port: 8080, VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/x/": {}}}}}
	if err := cfg.validate(); err == nil {
		t.Error("expected error for missing dest")
	}
}

func TestValidate_TLSPartial(t *testing.T) {
	cfg := &Config{
		Port:    8080,
		TLSCert: "/c.pem",
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/x/": {Upstreams: []Upstream{mustUpstream("http://x/", 1)}}}}},
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				ParsedAddHeaders: map[string]parsedHeaderValue{"User-Agent": compileHeaderValue("RouteMUX"), "X-Custom": compileHeaderValue("hello")},
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders: []string{"User-Agent", "Cookie"},
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders: []string{"Host"}, // should be silently ignored
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders: []string{"User-Agent"},
				ParsedAddHeaders: map[string]parsedHeaderValue{"User-Agent": compileHeaderValue("RouteMUX")},
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("User-Agent", "OriginalAgent")
	http.DefaultClient.Do(req)

	if gotUA != "RouteMUX" {
		t.Errorf("User-Agent = %q, want RouteMUX (add should win over delete)", gotUA)
	}
}

func TestCLI_AddDeleteHeaders(t *testing.T) {
	cfg := &Config{Port: 8080, VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{}}}}
	err := applyCLI(cfg, []string{
		"--route", "/api/",
		"--dest", "http://backend/",
		"--dest-add-header", "User-Agent: RouteMUX",
		"--dest-add-header", "X-Env: production",
		"--dest-del-header", "Cookie",
		"--dest-del-header", "Authorization",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.VHosts[0].Routes["/api/"]
	if r == nil {
		t.Fatal("route missing")
	}
	if evalConst(r.ParsedAddHeaders["User-Agent"]) != "RouteMUX" {
		t.Errorf("User-Agent = %q", evalConst(r.ParsedAddHeaders["User-Agent"]))
	}
	if evalConst(r.ParsedAddHeaders["X-Env"]) != "production" {
		t.Errorf("X-Env = %q", evalConst(r.ParsedAddHeaders["X-Env"]))
	}
	if len(r.DeleteHeaders) != 2 {
		t.Errorf("DeleteHeaders = %v", r.DeleteHeaders)
	}
}

func TestCLI_AddHeaderBadFormat(t *testing.T) {
	cfg := &Config{Port: 8080, VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{}}}}
	err := applyCLI(cfg, []string{
		"--route", "/api/",
		"--dest", "http://backend/",
		"--dest-add-header", "NoColonHere",
	})
	if err == nil {
		t.Error("expected error for missing colon in --dest-add-header value")
	}
}

func TestLoadConfigFile_HeaderOptions(t *testing.T) {
	path := writeTempConfig(t, `
routes:
  /api/:
    dest: http://localhost:3000/
    dest-add-header:
      User-Agent: RouteMUX
      X-Env: production
    dest-del-header:
      - Cookie
      - Authorization
`)
	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.VHosts[0].Routes["/api/"]
	if r == nil {
		t.Fatal("/api/ route missing")
	}
	if evalConst(r.ParsedAddHeaders["User-Agent"]) != "RouteMUX" {
		t.Errorf("User-Agent = %q", evalConst(r.ParsedAddHeaders["User-Agent"]))
	}
	if evalConst(r.ParsedAddHeaders["X-Env"]) != "production" {
		t.Errorf("X-Env = %q", evalConst(r.ParsedAddHeaders["X-Env"]))
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				ParsedAddHeaders: map[string]parsedHeaderValue{"Host": compileHeaderValue("custom.example.com")},
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders: []string{"Host"},
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("Authorization", "Bearer mytoken123")
	http.DefaultClient.Do(req)

	if gotAuth != "Bearer mytoken123" {
		t.Errorf("Authorization should pass through, got: %q", gotAuth)
	}
}

func TestRouteHandler_ProxyAuthWithAddHeaderAuthOverride(t *testing.T) {
	// When proxy auth is active but user also sets dest-add-header: Authorization,
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				ParsedAddHeaders: map[string]parsedHeaderValue{"Authorization": compileHeaderValue("Bearer upstream-token")},
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders: []string{"Authorization"},
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders:    []string{"CF-*"},
				DeleteHasWildcard: true,
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)},
				DeleteHeaders:    []string{"*-Secret"},
				DeleteHasWildcard: true,
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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


// ---- Variable (compiled header value) tests ----

func evalHeader(raw, clientIP, clientPort, scheme, requestURI string, orig http.Header) string {
	ph := compileHeaderValue(raw)
	return ph.eval("example.com", clientIP, clientPort, scheme, requestURI, nil, nil, orig)
}

func TestCompile_PlainValue(t *testing.T) {
	ph := compileHeaderValue("plain-value")
	if !ph.isConst {
		t.Error("plain value should be const")
	}
	if got := evalHeader("plain-value", "1.2.3.4", "54321", "https", "/", nil); got != "plain-value" {
		t.Errorf("got %q, want plain-value", got)
	}
}

func TestCompile_EscapedBrace(t *testing.T) {
	// \${ should produce a literal ${
	got := evalHeader(`\${scheme}`, "1.2.3.4", "54321", "https", "/", nil)
	if got != "${scheme}" {
		t.Errorf("got %q, want ${scheme}", got)
	}
}

func TestCompile_RemoteAddr(t *testing.T) {
	got := evalHeader("${remote_addr}", "1.2.3.4", "54321", "https", "/", nil)
	if got != "1.2.3.4" {
		t.Errorf("got %q, want 1.2.3.4", got)
	}
}

func TestCompile_RemotePort(t *testing.T) {
	got := evalHeader("${remote_port}", "1.2.3.4", "54321", "https", "/", nil)
	if got != "54321" {
		t.Errorf("got %q, want 54321", got)
	}
}

func TestCompile_Scheme(t *testing.T) {
	got := evalHeader("${scheme}", "1.2.3.4", "54321", "https", "/", nil)
	if got != "https" {
		t.Errorf("got %q, want https", got)
	}
}

func TestCompile_RequestURI(t *testing.T) {
	got := evalHeader("${request_uri}", "1.2.3.4", "54321", "http", "/path?foo=bar", nil)
	if got != "/path?foo=bar" {
		t.Errorf("got %q, want /path?foo=bar", got)
	}
}

func TestCompile_HeaderVar(t *testing.T) {
	orig := http.Header{"User-Agent": []string{"TestBrowser/1.0"}}
	got := evalHeader("${header.User-Agent}", "1.2.3.4", "54321", "http", "/", orig)
	if got != "TestBrowser/1.0" {
		t.Errorf("got %q, want TestBrowser/1.0", got)
	}
}

func TestCompile_HeaderVarMissing(t *testing.T) {
	orig := http.Header{}
	got := evalHeader("${header.X-Missing}", "1.2.3.4", "54321", "http", "/", orig)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestCompile_HeaderHost(t *testing.T) {
	// {header.Host} works because Host is injected into the snapshot.
	orig := http.Header{}
	orig.Set("Host", "myapp.example.com")
	got := evalHeader("${header.Host}", "1.2.3.4", "54321", "http", "/", orig)
	if got != "myapp.example.com" {
		t.Errorf("got %q, want myapp.example.com", got)
	}
}

func TestCompile_UnknownVar(t *testing.T) {
	// Unknown variable passes through as literal ${unknown_var}
	got := evalHeader("${unknown_var}", "1.2.3.4", "54321", "http", "/", nil)
	if got != "${unknown_var}" {
		t.Errorf("got %q, want ${unknown_var}", got)
	}
}

func TestCompile_UnmatchedBrace(t *testing.T) {
	// Unmatched ${ treated as literal
	got := evalHeader("prefix${no-close", "1.2.3.4", "54321", "http", "/", nil)
	if got != "prefix${no-close" {
		t.Errorf("got %q, want prefix${no-close", got)
	}
}

func TestCompile_Concatenation(t *testing.T) {
	// "{scheme}://{header.Host}:{remote_port}" — the key new feature
	orig := http.Header{}
	orig.Set("Host", "example.com")
	got := evalHeader("${scheme}://${header.Host}:${remote_port}", "1.2.3.4", "8080", "https", "/", orig)
	if got != "https://example.com:8080" {
		t.Errorf("got %q, want https://example.com:8080", got)
	}
}

func TestCompile_IsConst(t *testing.T) {
	if !compileHeaderValue("plain").isConst {
		t.Error("plain string should be const")
	}
	if compileHeaderValue("${scheme}").isConst {
		t.Error("{scheme} should not be const")
	}
	if compileHeaderValue("prefix-${scheme}").isConst {
		t.Error("mixed should not be const")
	}
}

func TestHasNonConstHeader(t *testing.T) {
	if hasNonConstHeader(compiledHeaders(map[string]string{"X-Foo": "bar", "X-Baz": "qux"})) {
		t.Error("expected false for no variables")
	}
	if !hasNonConstHeader(compiledHeaders(map[string]string{"X-Foo": "bar", "X-IP": "${remote_addr}"})) {
		t.Error("expected true when variable present")
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams:        []Upstream{mustUpstream(backend.URL+"/", 1)},
				ParsedAddHeaders: map[string]parsedHeaderValue{"X-Real-IP": compileHeaderValue("${remote_addr}")},
				AddHasVars:       true,
				NeedsOriginal:    false,
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
	defer ts.Close()
	http.Get(ts.URL + "/api/")
	if gotHeader == "" {
		t.Error("X-Real-IP should be set to client IP")
	}
	if strings.Contains(gotHeader, ":") {
		t.Errorf("X-Real-IP should be IP only (no port), got %q", gotHeader)
	}
}

func TestRouteHandler_VarHeaderCopiedAfterDelete(t *testing.T) {
	// Even if User-Agent is deleted, ${header.User-Agent} captures the original.
	var gotUA, gotUACopy string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotUACopy = r.Header.Get("X-Original-UA")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams:        []Upstream{mustUpstream(backend.URL+"/", 1)},
				DeleteHeaders:    []string{"User-Agent"},
				ParsedAddHeaders: map[string]parsedHeaderValue{"X-Original-UA": compileHeaderValue("${header.User-Agent}")},
				AddHasVars:       true,
				NeedsOriginal:    true,
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams:        []Upstream{mustUpstream(backend.URL+"/", 1)},
				ParsedAddHeaders: map[string]parsedHeaderValue{"X-Scheme": compileHeaderValue("${scheme}")},
				AddHasVars:       true,
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
	defer ts.Close()
	http.Get(ts.URL + "/api/")
	if gotScheme != "http" {
		t.Errorf("X-Scheme = %q, want http", gotScheme)
	}
}

func TestRouteHandler_VarConcatenation(t *testing.T) {
	var gotHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Origin")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{
			"/api/": {
				Upstreams:        []Upstream{mustUpstream(backend.URL+"/", 1)},
				ParsedAddHeaders: map[string]parsedHeaderValue{"X-Origin": compileHeaderValue("${scheme}://${header.Host}")},
				AddHasVars:       true,
				NeedsOriginal:    true,
			},
		}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Host = "myapp.example.com"
	http.DefaultClient.Do(req)

	if gotHeader != "http://myapp.example.com" {
		t.Errorf("X-Origin = %q, want http://myapp.example.com", gotHeader)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL + "/", 1)}}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/health/": {StatusCode: 200, StatusText: "OK"}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/ping/": {StatusCode: 204, StatusText: ""}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
		VHosts: []VHost{{Domains: []string{"*"}, Routes: map[string]*RouteConfig{"/health/": {StatusCode: 200, StatusText: "healthy"}}}},
	}
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.vhosts[0].mux)
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
func TestCLI_RepeatedDest(t *testing.T) {
	cfg, err := parseAll([]string{
		"--route", "/api/",
		"--dest", "http://localhost:3000/ weight=2",
		"--dest", "http://localhost:3001/ weight=1",
		"--load-balancer-mode", "round-robin",
	})
	if err != nil {
		t.Fatal(err)
	}
	rc := cfg.VHosts[0].Routes["/api/"]
	if rc == nil {
		t.Fatal("route /api/ not found")
	}
	if len(rc.Upstreams) != 2 {
		t.Fatalf("expected 2 upstreams, got %d", len(rc.Upstreams))
	}
	if rc.Upstreams[0].URL != "http://localhost:3000/" || rc.Upstreams[0].Weight != 2 {
		t.Errorf("upstream[0] = %+v", rc.Upstreams[0])
	}
	if rc.Upstreams[1].URL != "http://localhost:3001/" || rc.Upstreams[1].Weight != 1 {
		t.Errorf("upstream[1] = %+v", rc.Upstreams[1])
	}
	if rc.LBMode != "round-robin" {
		t.Errorf("LBMode = %q, want round-robin", rc.LBMode)
	}
}

func TestCLI_SingleDest(t *testing.T) {
	cfg, err := parseAll([]string{
		"--route", "/api/",
		"--dest", "http://localhost:3000/",
	})
	if err != nil {
		t.Fatal(err)
	}
	rc := cfg.VHosts[0].Routes["/api/"]
	if len(rc.Upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(rc.Upstreams))
	}
	if rc.Upstreams[0].URL != "http://localhost:3000/" {
		t.Errorf("upstream URL = %q", rc.Upstreams[0].URL)
	}
	if rc.Upstreams[0].ParsedURL == nil {
		t.Error("ParsedURL should not be nil")
	}
}

func TestCLI_StatusDest(t *testing.T) {
	cfg, err := parseAll([]string{
		"--route", "/health/",
		"--dest", "STATUS 200 healthy",
	})
	if err != nil {
		t.Fatal(err)
	}
	rc := cfg.VHosts[0].Routes["/health/"]
	if rc.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", rc.StatusCode)
	}
	if rc.StatusText != "healthy" {
		t.Errorf("StatusText = %q, want healthy", rc.StatusText)
	}
	if len(rc.Upstreams) != 0 {
		t.Error("STATUS route should have no upstreams")
	}
}
func TestParseAll_InvalidYAML_ShowsRealError(t *testing.T) {
	// Write a config file with invalid YAML structure
	f, err := os.CreateTemp("", "routemux-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("global:\n  port: notanumber\nroutes:\n  /api/:\n    dest: [\n") // invalid YAML
	f.Close()

	_, err = parseAll([]string{"--config", f.Name()})
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
	// Should mention the config file, not just "no routes configured"
	if err.Error() == "no routes configured" {
		t.Error("error should describe the YAML problem, not 'no routes configured'")
	}
	if !strings.Contains(err.Error(), f.Name()) {
		t.Errorf("error should mention the config file path, got: %v", err)
	}
}

func TestParseAll_AutoDiscovered_InvalidYAML_ShowsRealError(t *testing.T) {
	// Create a temp dir with an invalid config.yml — simulates auto-discovery finding a bad file
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	os.WriteFile(cfgPath, []byte("global:\n  port: [bad\nroutes: {invalid\n"), 0644)

	// We can't easily test auto-discovery without changing cwd,
	// but we can test that --config with an invalid file gives a real error
	_, err := parseAll([]string{"--config", cfgPath})
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if strings.Contains(err.Error(), "no routes configured") {
		t.Errorf("should show real YAML error, not 'no routes configured': %v", err)
	}
}
// ---- VHost tests ----

func TestVHost_ExactMatch(t *testing.T) {
	var gotHost string
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = "backend1"
		w.WriteHeader(http.StatusOK)
	}))
	defer backend1.Close()
	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = "backend2"
		w.WriteHeader(http.StatusOK)
	}))
	defer backend2.Close()

	cfg := &Config{
		Port: 8080,
		VHosts: []VHost{
			{
				Domains: []string{"app.example.com"},
				Routes:  map[string]*RouteConfig{"/": {Upstreams: []Upstream{mustUpstream(backend1.URL+"/", 1)}}},
			},
			{
				Domains: []string{"api.example.com"},
				Routes:  map[string]*RouteConfig{"/": {Upstreams: []Upstream{mustUpstream(backend2.URL+"/", 1)}}},
			},
		},
	}
	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	// Request to app.example.com → backend1
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = "app.example.com"
	http.DefaultClient.Do(req)
	if gotHost != "backend1" {
		t.Errorf("app.example.com → got %q, want backend1", gotHost)
	}

	// Request to api.example.com → backend2
	req, _ = http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = "api.example.com"
	http.DefaultClient.Do(req)
	if gotHost != "backend2" {
		t.Errorf("api.example.com → got %q, want backend2", gotHost)
	}
}

func TestVHost_CatchAll(t *testing.T) {
	var gotBackend string
	specific := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBackend = "specific"
		w.WriteHeader(http.StatusOK)
	}))
	defer specific.Close()
	catchAll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBackend = "catchall"
		w.WriteHeader(http.StatusOK)
	}))
	defer catchAll.Close()

	cfg := &Config{
		Port: 8080,
		VHosts: []VHost{
			{
				Domains: []string{"specific.example.com"},
				Routes:  map[string]*RouteConfig{"/": {Upstreams: []Upstream{mustUpstream(specific.URL+"/", 1)}}},
			},
			{
				Domains: []string{"*"},
				Routes:  map[string]*RouteConfig{"/": {Upstreams: []Upstream{mustUpstream(catchAll.URL+"/", 1)}}},
			},
		},
	}
	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	// Specific domain → specific backend
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = "specific.example.com"
	http.DefaultClient.Do(req)
	if gotBackend != "specific" {
		t.Errorf("specific domain → got %q, want specific", gotBackend)
	}

	// Unknown domain → catch-all backend
	req, _ = http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = "unknown.example.com"
	http.DefaultClient.Do(req)
	if gotBackend != "catchall" {
		t.Errorf("unknown domain → got %q, want catchall", gotBackend)
	}
}

func TestVHost_MultiDomain(t *testing.T) {
	var hit bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		VHosts: []VHost{
			{
				Domains: []string{"example.com", "www.example.com"},
				Routes:  map[string]*RouteConfig{"/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}}},
			},
		},
	}
	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	for _, host := range []string{"example.com", "www.example.com"} {
		hit = false
		req, _ := http.NewRequest("GET", ts.URL+"/", nil)
		req.Host = host
		http.DefaultClient.Do(req)
		if !hit {
			t.Errorf("host %q should have matched vhost", host)
		}
	}
}

func TestVHost_NoMatch_ClosesConnection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		VHosts: []VHost{
			{
				Domains: []string{"only.example.com"},
				Routes:  map[string]*RouteConfig{"/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}}},
			},
			{
				Domains: []string{"other.example.com"},
				Routes:  map[string]*RouteConfig{"/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}}},
			},
		},
	}
	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	// Unmatched host — connection should be closed with no usable response.
	// The HTTP client will either get an EOF/connection-reset error or a 400
	// (HTTP/2 fallback). Either way, no 2xx/4xx route-level response.
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = "nomatch.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		t.Error("unmatched host should not return 200")
	}
	// Should not reach a backend route (no 200 from backend)
	if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 400 {
		t.Errorf("unmatched host should close connection, got status %d", resp.StatusCode)
	}
}

func TestVHost_CaseInsensitiveMatch(t *testing.T) {
	var hit bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Port: 8080,
		VHosts: []VHost{
			{
				Domains: []string{"Example.COM"},
				Routes:  map[string]*RouteConfig{"/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}}},
			},
		},
	}
	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = "example.com" // lowercase should match "Example.COM"
	http.DefaultClient.Do(req)
	if !hit {
		t.Error("domain matching should be case-insensitive")
	}
}

func TestVHost_SingleMuxShortCircuit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Single catch-all vhost → singleMux=true, no host matching needed
	cfg := &Config{
		Port: 8080,
		VHosts: []VHost{{
			Domains: []string{"*"},
			Routes:  map[string]*RouteConfig{"/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}}},
		}},
	}
	srv, _ := newServer(cfg)
	if !srv.singleMux {
		t.Error("single catch-all vhost should set singleMux=true")
	}

	// Single specific-domain vhost → singleMux=false, host matching must be enforced
	cfg2 := &Config{
		Port: 8080,
		VHosts: []VHost{{
			Domains: []string{"host.com"},
			Routes:  map[string]*RouteConfig{"/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}}},
		}},
	}
	srv2, _ := newServer(cfg2)
	if srv2.singleMux {
		t.Error("single specific-domain vhost should NOT set singleMux — host matching must be enforced")
	}

	// Verify unmatched host gets 404 even with a single vhost
	ts := httptest.NewServer(srv2.handler())
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = "other.com"
	resp, err2 := http.DefaultClient.Do(req)
	// Unmatched host should close connection — client gets error or non-2xx
	if err2 == nil && resp.StatusCode >= 200 && resp.StatusCode < 400 {
		t.Errorf("unmatched host should close connection, got status %d", resp.StatusCode)
	}

	// Matched host should succeed
	req2, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req2.Host = "host.com"
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("matched host should get 200, got %d", resp2.StatusCode)
	}
}

func TestVHost_YAML_MultiVHost(t *testing.T) {
	yml := `
global:
  port: 9090
vhosts:
  - domains: [app.example.com, www.app.example.com]
    routes:
      /api/:
        dest: http://localhost:3000/
  - domains: ["*"]
    routes:
      /:
        dest: http://localhost:8080/
`
	f, _ := os.CreateTemp("", "routemux-*.yml")
	f.WriteString(yml)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := loadConfigFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.VHosts) != 2 {
		t.Fatalf("want 2 vhosts, got %d", len(cfg.VHosts))
	}
	if cfg.VHosts[0].Domains[0] != "app.example.com" {
		t.Errorf("vhost[0] domain = %q", cfg.VHosts[0].Domains[0])
	}
	if cfg.VHosts[0].Domains[1] != "www.app.example.com" {
		t.Errorf("vhost[0] domain[1] = %q", cfg.VHosts[0].Domains[1])
	}
	if cfg.VHosts[1].Domains[0] != "*" {
		t.Errorf("vhost[1] domain = %q", cfg.VHosts[1].Domains[0])
	}
	if cfg.Port != 9090 {
		t.Errorf("port = %d, want 9090", cfg.Port)
	}
}

func TestVHost_YAML_BackwardCompat(t *testing.T) {
	// Old-style top-level routes: should become a single catch-all vhost
	yml := `
global:
  port: 8080
routes:
  /api/:
    dest: http://localhost:3000/
  /:
    dest: http://localhost:8080/
`
	f, _ := os.CreateTemp("", "routemux-*.yml")
	f.WriteString(yml)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := loadConfigFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.VHosts) != 1 {
		t.Fatalf("want 1 vhost (catch-all), got %d", len(cfg.VHosts))
	}
	if cfg.VHosts[0].Domains[0] != "*" {
		t.Errorf("backward compat vhost domain = %q, want *", cfg.VHosts[0].Domains[0])
	}
	if len(cfg.VHosts[0].Routes) != 2 {
		t.Errorf("want 2 routes, got %d", len(cfg.VHosts[0].Routes))
	}
}

func TestVHost_CLI_VHostFlag(t *testing.T) {
	cfg, err := parseAll([]string{
		"--vhost", "app.example.com|www.app.example.com",
		"--route", "/api/",
		"--dest", "http://localhost:3000/",
		"--vhost", "*",
		"--route", "/",
		"--dest", "http://localhost:8080/",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Find vhosts by domain rather than index (order may vary)
	var appVH, starVH *VHost
	for i := range cfg.VHosts {
		for _, d := range cfg.VHosts[i].Domains {
			if d == "app.example.com" {
				appVH = &cfg.VHosts[i]
			}
			if d == "*" {
				starVH = &cfg.VHosts[i]
			}
		}
	}
	if appVH == nil {
		t.Fatal("vhost app.example.com not found")
	}
	if starVH == nil {
		t.Fatal("vhost * not found")
	}
	if len(appVH.Domains) != 2 {
		t.Errorf("app vhost domains = %v", appVH.Domains)
	}
	if appVH.Routes["/api/"] == nil {
		t.Error("app vhost missing /api/ route")
	}
	if starVH.Routes["/"] == nil {
		t.Error("catch-all vhost missing / route")
	}
}

func TestVHost_CLI_BackwardCompat(t *testing.T) {
	// Routes without --vhost → single catch-all vhost
	cfg, err := parseAll([]string{
		"--route", "/api/",
		"--dest", "http://localhost:3000/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.VHosts) != 1 {
		t.Fatalf("want 1 vhost, got %d", len(cfg.VHosts))
	}
	if cfg.VHosts[0].Domains[0] != "*" {
		t.Errorf("want catch-all, got %q", cfg.VHosts[0].Domains[0])
	}
	if cfg.VHosts[0].Routes["/api/"] == nil {
		t.Error("route /api/ missing")
	}
}
// ---- client-add-header / client-del-header tests ----

func TestClientHeader_AddPlain(t *testing.T) {
	var gotHeader string
	// The backend (upstream) does NOT set X-Served-By — we add it in the response to client
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {
			Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)},
			ParsedClientAddHeaders: map[string]parsedHeaderValue{
				"X-Served-By": compileHeaderValue("RouteMUX"),
			},
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/")
	if err != nil {
		t.Fatal(err)
	}
	gotHeader = resp.Header.Get("X-Served-By")
	if gotHeader != "RouteMUX" {
		t.Errorf("X-Served-By = %q, want RouteMUX", gotHeader)
	}
}

func TestClientHeader_DelHeader(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Go")
		w.Header().Set("Server", "go-httpd")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {
			Upstreams:       []Upstream{mustUpstream(backend.URL+"/", 1)},
			ClientDelHeaders: []string{"X-Powered-By", "Server"},
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/api/")
	if resp.Header.Get("X-Powered-By") != "" {
		t.Error("X-Powered-By should be deleted from response")
	}
	if resp.Header.Get("Server") != "" {
		t.Error("Server should be deleted from response")
	}
}

func TestClientHeader_DelWildcard(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Internal-Trace", "abc123")
		w.Header().Set("X-Internal-Id", "42")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {
			Upstreams:            []Upstream{mustUpstream(backend.URL+"/", 1)},
			ClientDelHeaders:     []string{"X-Internal-*"},
			ClientDelHasWildcard: true,
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/api/")
	if resp.Header.Get("X-Internal-Trace") != "" {
		t.Error("X-Internal-Trace should be deleted")
	}
	if resp.Header.Get("X-Internal-Id") != "" {
		t.Error("X-Internal-Id should be deleted")
	}
	if resp.Header.Get("Content-Type") == "" {
		t.Error("Content-Type should NOT be deleted")
	}
}

func TestClientHeader_VarRemoteAddr(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {
			Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)},
			ParsedClientAddHeaders: map[string]parsedHeaderValue{
				"X-Client-IP": compileHeaderValue("${remote_addr}"),
			},
			ClientAddHasVars: true,
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/api/")
	got := resp.Header.Get("X-Client-IP")
	if got == "" {
		t.Error("X-Client-IP should be set to client IP")
	}
	if strings.Contains(got, ":") {
		t.Errorf("X-Client-IP should be IP only (no port), got %q", got)
	}
}

func TestClientHeader_VarRespHeader(t *testing.T) {
	// ${header.X-Upstream-Id} should resolve from the upstream RESPONSE headers
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Id", "node-42")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {
			Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)},
			ParsedClientAddHeaders: map[string]parsedHeaderValue{
				"X-Node": compileHeaderValue("served-by-${header.X-Upstream-Id}"),
			},
			ClientAddHasVars:       true,
			ClientNeedsRespHeaders: true,
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/api/")
	got := resp.Header.Get("X-Node")
	if got != "served-by-node-42" {
		t.Errorf("X-Node = %q, want served-by-node-42", got)
	}
}

func TestClientHeader_DelThenAdd(t *testing.T) {
	// Delete runs before add — add always wins
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Version", "upstream-v1")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {
			Upstreams:        []Upstream{mustUpstream(backend.URL+"/", 1)},
			ClientDelHeaders: []string{"X-Version"},
			ParsedClientAddHeaders: map[string]parsedHeaderValue{
				"X-Version": compileHeaderValue("proxy-v2"),
			},
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/api/")
	got := resp.Header.Get("X-Version")
	if got != "proxy-v2" {
		t.Errorf("X-Version = %q, want proxy-v2 (add should win over del)", got)
	}
}

func TestCLI_ClientAddDelHeader(t *testing.T) {
	cfg, err := parseAll([]string{
		"--route", "/api/",
		"--dest", "http://localhost:3000/",
		"--client-add-header", "X-Served-By: RouteMUX",
		"--client-del-header", "Server",
		"--client-del-header", "X-Powered-*",
	})
	if err != nil {
		t.Fatal(err)
	}
	rc := cfg.VHosts[0].Routes["/api/"]
	if rc == nil {
		t.Fatal("route /api/ not found")
	}
	if evalConst(rc.ParsedClientAddHeaders["X-Served-By"]) != "RouteMUX" {
		t.Errorf("X-Served-By = %q", evalConst(rc.ParsedClientAddHeaders["X-Served-By"]))
	}
	if len(rc.ClientDelHeaders) != 2 {
		t.Errorf("ClientDelHeaders = %v, want 2 entries", rc.ClientDelHeaders)
	}
	if !rc.ClientDelHasWildcard {
		t.Error("ClientDelHasWildcard should be true (X-Powered-*)")
	}
}

func TestLoadConfigFile_ClientHeaders(t *testing.T) {
	yml := `
global:
  port: 8080
routes:
  /api/:
    dest: http://localhost:3000/
    client-add-header:
      X-Served-By: RouteMUX
      X-Node: node-${remote_addr}
    client-del-header:
      - Server
      - X-Powered-*
`
	f, _ := os.CreateTemp("", "routemux-*.yml")
	f.WriteString(yml)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := loadConfigFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	rc := cfg.VHosts[0].Routes["/api/"]
	if rc == nil {
		t.Fatal("route /api/ not found")
	}
	if evalConst(rc.ParsedClientAddHeaders["X-Served-By"]) != "RouteMUX" {
		t.Errorf("X-Served-By = %q", evalConst(rc.ParsedClientAddHeaders["X-Served-By"]))
	}
	if rc.ParsedClientAddHeaders["X-Node"].isConst {
		t.Error("X-Node should not be const (has variable)")
	}
	if !rc.ClientAddHasVars {
		t.Error("ClientAddHasVars should be true")
	}
	if len(rc.ClientDelHeaders) != 2 {
		t.Errorf("ClientDelHeaders = %v, want 2", rc.ClientDelHeaders)
	}
	if !rc.ClientDelHasWildcard {
		t.Error("ClientDelHasWildcard should be true")
	}
}
func TestManipulateClientHeaders_ViaAlwaysSet(t *testing.T) {
	// Via: RouteMUX is unconditionally added to all responses
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/api/")
	if resp.Header.Get("Via") != "RouteMUX" {
		t.Errorf("Via header should always be RouteMUX, got %q", resp.Header.Get("Via"))
	}
}

func TestManipulateClientHeaders_ViaCanBeDeleted(t *testing.T) {
	// User can suppress Via: RouteMUX via client-del-header: Via
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {
			Upstreams:        []Upstream{mustUpstream(backend.URL+"/", 1)},
			ClientDelHeaders: []string{"Via"},
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/api/")
	if resp.Header.Get("Via") != "" {
		t.Errorf("Via should be deletable via client-del-header, got %q", resp.Header.Get("Via"))
	}
}

func TestManipulateClientHeaders_ViaOnStatus(t *testing.T) {
	// Via: RouteMUX is also set on STATUS routes
	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/health/": {StatusCode: 200, StatusText: "ok"},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/health/")
	if resp.Header.Get("Via") != "RouteMUX" {
		t.Errorf("Via header should be RouteMUX on STATUS route, got %q", resp.Header.Get("Via"))
	}
}

// ---- evalTrustedXFF tests ----











// ---- expandEnvVars tests ----

func TestExpandEnvVars_Basic(t *testing.T) {
	os.Setenv("ROUTEMUX_TEST_HOST", "backend.example.com")
	defer os.Unsetenv("ROUTEMUX_TEST_HOST")
	result := expandEnvVars([]byte("dest: http://${env.ROUTEMUX_TEST_HOST}/"))
	if string(result) != "dest: http://backend.example.com/" {
		t.Errorf("got %q", result)
	}
}

func TestExpandEnvVars_Multiple(t *testing.T) {
	os.Setenv("ROUTEMUX_TEST_H", "api.example.com")
	os.Setenv("ROUTEMUX_TEST_P", "9000")
	defer os.Unsetenv("ROUTEMUX_TEST_H")
	defer os.Unsetenv("ROUTEMUX_TEST_P")
	result := expandEnvVars([]byte("dest: http://${env.ROUTEMUX_TEST_H}:${env.ROUTEMUX_TEST_P}/"))
	if string(result) != "dest: http://api.example.com:9000/" {
		t.Errorf("got %q", result)
	}
}

func TestExpandEnvVars_DefaultUsedWhenMissing(t *testing.T) {
	os.Unsetenv("ROUTEMUX_DEFINITELY_UNSET")
	result := expandEnvVars([]byte("port: ${env.ROUTEMUX_DEFINITELY_UNSET:8080}"))
	if string(result) != "port: 8080" {
		t.Errorf("got %q, want port: 8080", result)
	}
}

func TestExpandEnvVars_DefaultNotUsedWhenSet(t *testing.T) {
	os.Setenv("ROUTEMUX_TEST_PORT", "9090")
	defer os.Unsetenv("ROUTEMUX_TEST_PORT")
	result := expandEnvVars([]byte("port: ${env.ROUTEMUX_TEST_PORT:8080}"))
	if string(result) != "port: 9090" {
		t.Errorf("got %q, want port: 9090 (set value, not default)", result)
	}
}

func TestExpandEnvVars_BlankNotTreatedAsUnset(t *testing.T) {
	// Variable explicitly set to "" should not trigger the default
	os.Setenv("ROUTEMUX_TEST_BLANK", "")
	defer os.Unsetenv("ROUTEMUX_TEST_BLANK")
	result := expandEnvVars([]byte("x: ${env.ROUTEMUX_TEST_BLANK:fallback}"))
	if string(result) != "x: " {
		t.Errorf("got %q, want blank (explicitly set empty should not use default)", result)
	}
}

func TestExpandEnvVars_Escape(t *testing.T) {
	// \${env. should produce literal ${env.
	result := expandEnvVars([]byte(`dest: \${env.NOT_EXPANDED}`))
	if string(result) != "dest: ${env.NOT_EXPANDED}" {
		t.Errorf("got %q, want literal ${env.NOT_EXPANDED}", result)
	}
}

func TestExpandEnvVars_NoVars(t *testing.T) {
	input := []byte("dest: http://localhost:3000/")
	result := expandEnvVars(input)
	if string(result) != string(input) {
		t.Errorf("no vars: input should be unchanged")
	}
}

func TestExpandEnvVars_UnmatchedBrace(t *testing.T) {
	input := []byte("dest: ${env.NOCLOSE")
	result := expandEnvVars(input)
	if string(result) != string(input) {
		t.Errorf("unmatched brace: got %q, want input unchanged", result)
	}
}

func TestExpandEnvVars_EscapeBeforeReal(t *testing.T) {
	// \${env. followed by real ${env.VAR} — escape first, then expand
	os.Setenv("ROUTEMUX_TEST_EBR", "real")
	defer os.Unsetenv("ROUTEMUX_TEST_EBR")
	result := expandEnvVars([]byte(`\${env.ESCAPED} and ${env.ROUTEMUX_TEST_EBR}`))
	if string(result) != "${env.ESCAPED} and real" {
		t.Errorf("got %q", result)
	}
}

func TestLoadConfigFile_EnvVarSubstitution(t *testing.T) {
	os.Setenv("ROUTEMUX_TEST_UPSTREAM", "backend.internal")
	os.Setenv("ROUTEMUX_TEST_UPSTREAM_PORT", "8181")
	defer os.Unsetenv("ROUTEMUX_TEST_UPSTREAM")
	defer os.Unsetenv("ROUTEMUX_TEST_UPSTREAM_PORT")

	f, err := os.CreateTemp("", "routemux-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`
global:
  port: ${env.ROUTEMUX_TEST_UPSTREAM_PORT}
routes:
  /api/:
    dest: http://${env.ROUTEMUX_TEST_UPSTREAM}:${env.ROUTEMUX_TEST_UPSTREAM_PORT}/v1/
`)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := loadConfigFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 8181 {
		t.Errorf("port = %d, want 8181", cfg.Port)
	}
	rc := cfg.VHosts[0].Routes["/api/"]
	if rc == nil {
		t.Fatal("route /api/ not found")
	}
	if rc.Upstreams[0].URL != "http://backend.internal:8181/v1/" {
		t.Errorf("upstream URL = %q", rc.Upstreams[0].URL)
	}
}

func TestLoadConfigFile_EnvVarDefault(t *testing.T) {
	os.Unsetenv("ROUTEMUX_TEST_MISSING_PORT")
	f, err := os.CreateTemp("", "routemux-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`
global:
  port: ${env.ROUTEMUX_TEST_MISSING_PORT:7777}
routes:
  /:
    dest: http://localhost:3000/
`)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := loadConfigFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 7777 {
		t.Errorf("port = %d, want 7777 (default value)", cfg.Port)
	}
}

// ---- ${host} variable compile test ----

func TestCompile_Host(t *testing.T) {
	got := evalHeader("${host}", "1.2.3.4", "54321", "https", "/path", nil)
	// evalHeader passes "example.com" as host
	if got != "example.com" {
		t.Errorf("${host}: got %q, want example.com", got)
	}
}

func TestRouteHandler_VarHost(t *testing.T) {
	var gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Header.Get("X-Original-Host")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {
			Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)},
			ParsedAddHeaders: map[string]parsedHeaderValue{
				"X-Original-Host": compileHeaderValue("${host}"),
			},
			AddHasVars: true,
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Host = "myapp.example.com"
	http.DefaultClient.Do(req)

	if gotHost != "myapp.example.com" {
		t.Errorf("${host}: got %q, want myapp.example.com", gotHost)
	}
}

// ---- ${trusted_xff} compile & NeedsTrustedXFF tests ----

func TestCompile_TrustedXFF(t *testing.T) {
	ph := compileHeaderValue("${trusted_xff}")
	if ph.isConst {
		t.Error("${trusted_xff} should not be const")
	}
	if len(ph.segments) != 1 || ph.segments[0].kind != segTrustedXFF {
		t.Errorf("expected single segTrustedXFF segment, got %+v", ph.segments)
	}
}

func TestNeedsTrustedXFF_SetInConfig(t *testing.T) {
	f, err := os.CreateTemp("", "routemux-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`
global:
  port: 8080
routes:
  /api/:
    dest: http://localhost:3000/
    dest-add-header:
      X-Real-Client: ${trusted_xff}
`)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := loadConfigFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	rc := cfg.VHosts[0].Routes["/api/"]
	if rc == nil {
		t.Fatal("route /api/ not found")
	}
	if !rc.NeedsTrustedXFF {
		t.Error("NeedsTrustedXFF should be true when ${trusted_xff} is in dest-add-header")
	}
}

func TestNeedsTrustedXFF_SetInClientHeader(t *testing.T) {
	f, err := os.CreateTemp("", "routemux-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`
global:
  port: 8080
routes:
  /api/:
    dest: http://localhost:3000/
    client-add-header:
      X-Real-Client: ${trusted_xff}
`)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := loadConfigFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	rc := cfg.VHosts[0].Routes["/api/"]
	if rc == nil {
		t.Fatal("route /api/ not found")
	}
	if !rc.NeedsTrustedXFF {
		t.Error("NeedsTrustedXFF should be true when ${trusted_xff} is in client-add-header")
	}
}

func TestNeedsTrustedXFF_NotSetWhenUnused(t *testing.T) {
	f, err := os.CreateTemp("", "routemux-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`
global:
  port: 8080
routes:
  /api/:
    dest: http://localhost:3000/
    dest-add-header:
      X-Real-IP: ${remote_addr}
`)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := loadConfigFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	rc := cfg.VHosts[0].Routes["/api/"]
	if rc.NeedsTrustedXFF {
		t.Error("NeedsTrustedXFF should be false when ${trusted_xff} is not used")
	}
}

// ---- client-add-header on STATUS routes ----

func TestClientHeader_StatusRoute_Add(t *testing.T) {
	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/health/": {
			StatusCode: 200,
			StatusText: "healthy",
			ParsedClientAddHeaders: map[string]parsedHeaderValue{
				"X-Served-By":   compileHeaderValue("RouteMUX"),
				"Cache-Control": compileHeaderValue("no-store"),
			},
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("X-Served-By") != "RouteMUX" {
		t.Errorf("X-Served-By = %q, want RouteMUX", resp.Header.Get("X-Served-By"))
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", resp.Header.Get("Cache-Control"))
	}
}

func TestClientHeader_StatusRoute_VarHost(t *testing.T) {
	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/health/": {
			StatusCode: 200,
			StatusText: "ok",
			ParsedClientAddHeaders: map[string]parsedHeaderValue{
				"X-Request-Host": compileHeaderValue("${host}"),
			},
			ClientAddHasVars: true,
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/health/", nil)
	req.Host = "example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("X-Request-Host") != "example.com" {
		t.Errorf("X-Request-Host = %q, want example.com", resp.Header.Get("X-Request-Host"))
	}
}

func TestClientHeader_StatusRoute_NilRespHeaderVar(t *testing.T) {
	// ${header.X} on STATUS route has no upstream response → empty string, no panic
	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/health/": {
			StatusCode: 200,
			StatusText: "ok",
			ParsedClientAddHeaders: map[string]parsedHeaderValue{
				"X-Echo": compileHeaderValue("${header.X-Upstream-Id}"),
			},
			ClientAddHasVars:       true,
			ClientNeedsRespHeaders: true,
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("X-Echo") != "" {
		t.Errorf("X-Echo should be empty on STATUS route, got %q", resp.Header.Get("X-Echo"))
	}
}

// ---- trusted-proxies HTTP integration tests ----

func TestTrustedProxies_HTTPHandler_TrustAppends(t *testing.T) {
	// When connecting IP is in trusted-proxies, XFF should be appended not overwritten
	var gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}},
	})
	// Trust loopback — the test httptest server connects via 127.0.0.1
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
	http.DefaultClient.Do(req)

	if gotXFF == "127.0.0.1" {
		t.Error("trusted proxy: XFF should append, not overwrite")
	}
	if !strings.Contains(gotXFF, "1.2.3.4") {
		t.Errorf("trusted proxy: XFF should contain original chain, got %q", gotXFF)
	}
}

func TestTrustedProxies_HTTPHandler_UntrustedDiscards(t *testing.T) {
	// When connecting IP is NOT in trusted-proxies, spoofed XFF is discarded
	var gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)}},
	})
	// Trust only 10.0.0.0/8 — test client connects from 127.0.0.1 (untrusted)
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

	if strings.Contains(gotXFF, "evil") {
		t.Errorf("untrusted: spoofed XFF should be discarded, got %q", gotXFF)
	}
}

// ---- ${trusted_xff} end-to-end HTTP test ----

func TestRouteHandler_VarTrustedXFF_NoTrust(t *testing.T) {
	// No trusted-proxies → ${trusted_xff} = connecting IP
	var gotHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Client")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	ph := compileHeaderValue("${trusted_xff}")
	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {
			Upstreams:       []Upstream{mustUpstream(backend.URL+"/", 1)},
			ParsedAddHeaders: map[string]parsedHeaderValue{"X-Client": ph},
			AddHasVars:      true,
			NeedsTrustedXFF: true,
		},
	})

	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	http.Get(ts.URL + "/api/")

	if gotHeader == "" {
		t.Error("X-Client should be set from ${trusted_xff}")
	}
	// Without trust config, should be the connecting IP
	if strings.Contains(gotHeader, ",") {
		t.Errorf("no trust config: expected single IP, got %q", gotHeader)
	}
}

func TestRouteHandler_VarTrustedXFF_TrustAll(t *testing.T) {
	// trust-client-headers: true → ${trusted_xff} = leftmost in chain
	var gotHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Client")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	ph := compileHeaderValue("${trusted_xff}")
	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/api/": {
			Upstreams:       []Upstream{mustUpstream(backend.URL+"/", 1)},
			ParsedAddHeaders: map[string]parsedHeaderValue{"X-Client": ph},
			AddHasVars:      true,
			NeedsTrustedXFF: true,
		},
	})
	cfg.TrustClientHeaders = true

	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/", nil)
	req.Header.Set("X-Forwarded-For", "5.6.7.8, 10.0.0.1")
	http.DefaultClient.Do(req)

	// trust-client-headers: leftmost valid IP in chain
	if gotHeader != "5.6.7.8" {
		t.Errorf("trust all: ${trusted_xff} = %q, want 5.6.7.8 (leftmost)", gotHeader)
	}
}

// ---- Route timeout test ----

func TestRouteHandler_Timeout(t *testing.T) {
	// A slow backend with a short route timeout should return 504
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep longer than the configured timeout
		select {
		case <-r.Context().Done():
		case <-func() chan struct{} {
			ch := make(chan struct{})
			go func() { strings.Repeat("x", 1000); close(ch) }()
			return ch
		}():
		}
		// Simulate slow response - just block
		done := make(chan struct{})
		select {
		case <-r.Context().Done():
		case <-done:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/slow/": {
			Upstreams: []Upstream{mustUpstream(backend.URL+"/", 1)},
			Timeout:   "50ms",
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/slow/")
	if err != nil {
		t.Fatal(err)
	}
	// http.TimeoutHandler returns 503 Service Unavailable
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("timeout: status = %d, want 503", resp.StatusCode)
	}
}

// ---- WebSocket header/path tests ----

// wsUpgradeServer returns a test server that accepts WebSocket upgrades
// and calls handler(headers) with the upgrade request headers it received.
func wsUpgradeServer(handler func(path string, headers http.Header)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(r.URL.RequestURI(), r.Header)
		// Respond with 101 Switching Protocols so the client gets a valid response
		hj := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		conn.Close()
	}))
}

// wsUpgradeRequest sends a WebSocket upgrade request and returns the response.
func wsUpgradeRequest(t *testing.T, url string, extraHeaders map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	// Use a transport that doesn't follow redirects and doesn't complain about 101
	client := &http.Client{
		Transport: &http.Transport{},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil && resp == nil {
		t.Fatalf("ws request failed: %v", err)
	}
	return resp
}

func TestWebSocket_DestAddHeader(t *testing.T) {
	var gotHeaders http.Header
	upstream := wsUpgradeServer(func(_ string, h http.Header) { gotHeaders = h })
	defer upstream.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/ws/": {
			Upstreams: []Upstream{mustUpstream(upstream.URL+"/", 1)},
			ParsedAddHeaders: map[string]parsedHeaderValue{
				"X-Custom": compileHeaderValue("hello"),
			},
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	wsUpgradeRequest(t, ts.URL+"/ws/", nil)
	if gotHeaders.Get("X-Custom") != "hello" {
		t.Errorf("X-Custom = %q, want hello", gotHeaders.Get("X-Custom"))
	}
}

func TestWebSocket_DestDelHeader(t *testing.T) {
	var gotHeaders http.Header
	upstream := wsUpgradeServer(func(_ string, h http.Header) { gotHeaders = h })
	defer upstream.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/ws/": {
			Upstreams:    []Upstream{mustUpstream(upstream.URL+"/", 1)},
			DeleteHeaders: []string{"Sec-WebSocket-Key"},
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	wsUpgradeRequest(t, ts.URL+"/ws/", nil)
	if gotHeaders.Get("Sec-WebSocket-Key") != "" {
		t.Error("Sec-WebSocket-Key should be deleted")
	}
}

func TestWebSocket_XForwardedHeaders_Untrusted(t *testing.T) {
	var gotHeaders http.Header
	upstream := wsUpgradeServer(func(_ string, h http.Header) { gotHeaders = h })
	defer upstream.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/ws/": {Upstreams: []Upstream{mustUpstream(upstream.URL+"/", 1)}},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	wsUpgradeRequest(t, ts.URL+"/ws/", map[string]string{
		"X-Forwarded-For":   "spoofed-ip",
		"X-Forwarded-Proto": "spoofed-proto",
	})
	// Untrusted: XFF set to connecting IP, spoofed headers discarded
	if gotHeaders.Get("X-Forwarded-For") == "spoofed-ip" {
		t.Error("untrusted WS: spoofed X-Forwarded-For should be overwritten")
	}
	if gotHeaders.Get("X-Forwarded-Proto") == "spoofed-proto" {
		t.Error("untrusted WS: spoofed X-Forwarded-Proto should be overwritten")
	}
}

func TestWebSocket_XForwardedHeaders_TrustClientHeaders(t *testing.T) {
	var gotHeaders http.Header
	upstream := wsUpgradeServer(func(_ string, h http.Header) { gotHeaders = h })
	defer upstream.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/ws/": {Upstreams: []Upstream{mustUpstream(upstream.URL+"/", 1)}},
	})
	cfg.TrustClientHeaders = true
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	wsUpgradeRequest(t, ts.URL+"/ws/", map[string]string{
		"X-Forwarded-For":  "1.2.3.4",
		"X-Forwarded-Host": "original.example.com",
	})
	// Trusted: XFF should be appended, XFH left untouched
	if !strings.Contains(gotHeaders.Get("X-Forwarded-For"), "1.2.3.4") {
		t.Errorf("trusted WS: XFF should contain original chain, got %q", gotHeaders.Get("X-Forwarded-For"))
	}
	if gotHeaders.Get("X-Forwarded-Host") != "original.example.com" {
		t.Errorf("trusted WS: X-Forwarded-Host should be untouched, got %q", gotHeaders.Get("X-Forwarded-Host"))
	}
}

func TestWebSocket_VarRemoteAddr(t *testing.T) {
	var gotHeaders http.Header
	upstream := wsUpgradeServer(func(_ string, h http.Header) { gotHeaders = h })
	defer upstream.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/ws/": {
			Upstreams: []Upstream{mustUpstream(upstream.URL+"/", 1)},
			ParsedAddHeaders: map[string]parsedHeaderValue{
				"X-Client-IP": compileHeaderValue("${remote_addr}"),
			},
			AddHasVars: true,
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	wsUpgradeRequest(t, ts.URL+"/ws/", nil)
	got := gotHeaders.Get("X-Client-IP")
	if got == "" {
		t.Error("X-Client-IP should be set from ${remote_addr}")
	}
	if strings.Contains(got, ":") {
		t.Errorf("X-Client-IP should be IP only (no port), got %q", got)
	}
}

func TestWebSocket_QueryStringMerge(t *testing.T) {
	var gotPath string
	upstream := wsUpgradeServer(func(path string, _ http.Header) { gotPath = path })
	defer upstream.Close()

	// dest has a base query string; client also sends one — both should appear
	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/ws/": {Upstreams: []Upstream{mustUpstream(upstream.URL+"/?token=abc", 1)}},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	wsUpgradeRequest(t, ts.URL+"/ws/?room=42", nil)
	if !strings.Contains(gotPath, "token=abc") {
		t.Errorf("dest query string missing from upstream path: %q", gotPath)
	}
	if !strings.Contains(gotPath, "room=42") {
		t.Errorf("client query string missing from upstream path: %q", gotPath)
	}
}

func TestWebSocket_QueryStringDestOnly(t *testing.T) {
	var gotPath string
	upstream := wsUpgradeServer(func(path string, _ http.Header) { gotPath = path })
	defer upstream.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/ws/": {Upstreams: []Upstream{mustUpstream(upstream.URL+"/?token=abc", 1)}},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	wsUpgradeRequest(t, ts.URL+"/ws/", nil) // no client query string
	if !strings.Contains(gotPath, "token=abc") {
		t.Errorf("dest query string missing: %q", gotPath)
	}
}

func TestWebSocket_PathStripping(t *testing.T) {
	var gotPath string
	upstream := wsUpgradeServer(func(path string, _ http.Header) { gotPath = path })
	defer upstream.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/ws/": {Upstreams: []Upstream{mustUpstream(upstream.URL+"/upstream/", 1)}},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	wsUpgradeRequest(t, ts.URL+"/ws/room/chat", nil)
	if !strings.HasPrefix(gotPath, "/upstream/room/chat") {
		t.Errorf("path stripping: got %q, want /upstream/room/chat...", gotPath)
	}
}

func TestWebSocket_Auth(t *testing.T) {
	upstream := wsUpgradeServer(func(_ string, _ http.Header) {})
	defer upstream.Close()

	cfg := makeConfig(8080, map[string]*RouteConfig{
		"/ws/": {
			Upstreams:    []Upstream{mustUpstream(upstream.URL+"/", 1)},
			Auth:         &Auth{User: "user", Password: "pass"},
			AuthExplicit: true,
		},
	})
	srv, _ := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	// No credentials — should get 401
	resp := wsUpgradeRequest(t, ts.URL+"/ws/", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no auth: status = %d, want 401", resp.StatusCode)
	}

	// With correct credentials — should get 101
	req, _ := http.NewRequest("GET", ts.URL+"/ws/", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.SetBasicAuth("user", "pass")
	client := &http.Client{Transport: &http.Transport{}}
	resp2, err := client.Do(req)
	if err != nil && resp2 == nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("with auth: status = %d, want 101", resp2.StatusCode)
	}
}
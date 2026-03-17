package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	if api.Dest != "http://localhost:3000/v1/" {
		t.Errorf("dest = %q", api.Dest)
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
	if a == nil || a.Dest != "http://a/" || a.Timeout != "30s" || !a.NoTLSVerify {
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
		Routes: map[string]*RouteConfig{"/api/": {Dest: backend.URL + "/v1/"}},
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
		Routes:     map[string]*RouteConfig{"/secure/": {Dest: backend.URL + "/"}},
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
				Dest:         backend.URL + "/",
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
				Dest:         backend.URL + "/",
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
		Routes: map[string]*RouteConfig{"/prefix/": {Dest: backend.URL + "/base/"}},
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
		Routes: map[string]*RouteConfig{"/": {Dest: backend.URL + "/"}},
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
		Routes:  map[string]*RouteConfig{"/x/": {Dest: "http://x/"}},
	}
	if err := cfg.validate(); err == nil {
		t.Error("expected error for tls-cert without tls-key")
	}
}

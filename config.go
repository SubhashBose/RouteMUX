package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"gopkg.in/yaml.v3"
)

// Config is the top-level runtime configuration structure.
type Config struct {
	Listen             string
	Port               int
	TLSCert            string
	TLSKey             string
	GlobalAuth         *Auth
	TrustClientHeaders bool
	VHosts             []VHost // ordered list; matched top-to-bottom per request
}

// VHost groups a set of routes under one or more domain names.
// Domains is a list of hostnames (e.g. ["example.com", "www.example.com"]).
// Use ["*"] or [""] to match all hosts (catch-all / backward-compat mode).
type VHost struct {
	Domains []string
	Routes  map[string]*RouteConfig
}

// Auth holds HTTP Basic Auth credentials.
type Auth struct {
	User     string
	Password string
}

// Upstream holds the destination URL and per-upstream options for a route.
type Upstream struct {
	URL       string
	ParsedURL *url.URL // parsed once at startup, never nil for valid routes
	Weight    int      // default 1; used for weighted load balancing (future)
}

// RouteConfig describes a single reverse-proxy route.
type RouteConfig struct {
	Upstreams          []Upstream        // upstream destinations (nil for STATUS routes)
	LBMode             string            // "random" (default) or "round-robin"
	StatusCode         int               // non-zero: static response route
	StatusText         string            // body text for static response
	NoTLSVerify        bool              // skip TLS verification for all upstreams
	Auth               *Auth             // nil = inherit global-auth; explicitly cleared = no auth
	AuthExplicit       bool              // true when auth was set explicitly (even as empty)
	Timeout            string            // e.g. "30s", "2m"
	ParsedAddHeaders   map[string]parsedHeaderValue // compiled add-header values (parsed at startup)
	NeedsOriginal      bool              // true if any header value references ${header.X}
	AddHasVars         bool              // true if any header value contains a variable (non-const)
	DeleteHeaders      []string          // headers to remove from upstream request
	DeleteHasWildcard  bool              // true if any DeleteHeaders entry contains '*'
	destEntries        []string          // temporary: accumulates --dest CLI args before parsing
}

func (c *Config) validate() error {
	if len(c.VHosts) == 0 {
		return fmt.Errorf("no routes configured")
	}
	for _, vh := range c.VHosts {
		if len(vh.Routes) == 0 {
			return fmt.Errorf("vhost %v has no routes", vh.Domains)
		}
		for path, r := range vh.Routes {
			if r.StatusCode == 0 && len(r.Upstreams) == 0 {
				return fmt.Errorf("%v route %q has no dest", vh.Domains, path)
			}
		}
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("both tls-cert and tls-key must be provided together")
	}
	return nil
}

// ---- YAML file types ----
// These mirror the config.yml structure exactly and are only used during loading.

type fileConfig struct {
	Global fileGlobal           `yaml:"global"`
	Routes map[string]fileRoute `yaml:"routes"` // backward-compat: top-level routes → single catch-all vhost
	VHosts []fileVHost          `yaml:"vhosts"`
}

type fileVHost struct {
	Domains []string             `yaml:"domains"`
	Routes  map[string]fileRoute `yaml:"routes"`
}

type fileGlobal struct {
	Listen     string   `yaml:"listen"`
	Port       int      `yaml:"port"`
	TLSCert    string   `yaml:"tls-cert"`
	TLSKey     string   `yaml:"tls-key"`
	GlobalAuth          []string `yaml:"global-auth"`   // ["USER", "PASSWORD"]
	TrustClientHeaders  bool     `yaml:"trust-client-headers"`
}

type fileRoute struct {
	Dest        destValue         `yaml:"dest"` // string or []string — custom unmarshaler
	NoTLSVerify bool              `yaml:"noTLSverify"`
	Auth        []string          `yaml:"auth"` // ["USER", "PASSWORD"] or absent
	Timeout     string            `yaml:"timeout"`
	LBMode      string            `yaml:"load-balancer-mode"`
	AddHeaders  map[string]string `yaml:"add-header"`
	DeleteHeaders []string        `yaml:"delete-header"`

	// authPresent records whether the "auth" key existed in the YAML at all.
	authPresent bool
}

// destValue holds the raw dest strings before they are parsed into Upstreams.
// It accepts both a single string and a YAML sequence of strings.
type destValue struct {
	entries []string
}

func (d *destValue) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		d.entries = []string{value.Value}
	case yaml.SequenceNode:
		for _, item := range value.Content {
			if item.Kind != yaml.ScalarNode {
				return fmt.Errorf("dest list entries must be strings")
			}
			d.entries = append(d.entries, item.Value)
		}
	default:
		return fmt.Errorf("dest must be a string or a list of strings")
	}
	return nil
}

// UnmarshalYAML implements yaml.Unmarshaler so we can detect whether the
// "auth" key was present in the document (even when its value is empty/null).
func (r *fileRoute) UnmarshalYAML(value *yaml.Node) error {
	// Alias type prevents infinite recursion when calling Decode.
	type plain fileRoute
	var tmp plain
	if err := value.Decode(&tmp); err != nil {
		return err
	}
	*r = fileRoute(tmp)

	// Walk the mapping node's key-value pairs to detect "auth" key presence.
	if value.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(value.Content); i += 2 {
			if value.Content[i].Value == "auth" {
				r.authPresent = true
				break
			}
		}
	}
	return nil
}

// loadConfigFile reads a config.yml file and returns a Config.
func loadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	log.Printf("Loading config from %q", path)

	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parsing %q: %w", path, err)
	}

	cfg := &Config{
		Listen:             fc.Global.Listen,
		Port:               fc.Global.Port,
		TLSCert:            fc.Global.TLSCert,
		TLSKey:             fc.Global.TLSKey,
		TrustClientHeaders: fc.Global.TrustClientHeaders,
	}
	if cfg.Port == 0 {
		cfg.Port = 8080
	}

	if len(fc.Global.GlobalAuth) == 2 {
		cfg.GlobalAuth = &Auth{
			User:     fc.Global.GlobalAuth[0],
			Password: fc.Global.GlobalAuth[1],
		}
	} else if len(fc.Global.GlobalAuth) != 0 {
		return nil, fmt.Errorf("global-auth must be a two-element list [USER, PASSWORD]")
	}

	// Backward compat: top-level routes: → single catch-all vhost.
	if len(fc.Routes) > 0 {
		if len(fc.VHosts) > 0 {
			return nil, fmt.Errorf("cannot use both top-level \"routes\" and \"vhosts\" in the same config")
		}
		vh, err := parseFileVHost(fc.Routes, []string{"*"})
		if err != nil {
			return nil, err
		}
		cfg.VHosts = []VHost{vh}
		return cfg, nil
	}

	// New vhosts: format.
	for i, fvh := range fc.VHosts {
		if len(fvh.Domains) == 0 {
			return nil, fmt.Errorf("vhosts[%d]: domains list must not be empty", i)
		}
		vh, err := parseFileVHost(fvh.Routes, fvh.Domains)
		if err != nil {
			return nil, err
		}
		cfg.VHosts = append(cfg.VHosts, vh)
	}

	return cfg, nil
}

// parseFileVHost converts a map of fileRoutes into a VHost.
func parseFileVHost(fileRoutes map[string]fileRoute, domains []string) (VHost, error) {
	routes := make(map[string]*RouteConfig, len(fileRoutes))
	for path, fr := range fileRoutes {
		rc := &RouteConfig{
			NoTLSVerify:       fr.NoTLSVerify,
			Timeout:           fr.Timeout,
			LBMode:            normalizeLBMode(fr.LBMode),
			AuthExplicit:      fr.authPresent,
			ParsedAddHeaders:  compiledHeaders(fr.AddHeaders),
			DeleteHeaders:     fr.DeleteHeaders,
			DeleteHasWildcard: hasWildcard(fr.DeleteHeaders),
		}
		rc.AddHasVars = hasNonConstHeader(rc.ParsedAddHeaders)
		rc.NeedsOriginal = hasHeaderNameVar(rc.ParsedAddHeaders)
		if err := applyDestEntries(rc, fr.Dest.entries, path); err != nil {
			return VHost{}, err
		}
		if fr.authPresent {
			if len(fr.Auth) == 2 {
				rc.Auth = &Auth{User: fr.Auth[0], Password: fr.Auth[1]}
			} else if len(fr.Auth) != 0 {
				return VHost{}, fmt.Errorf("route %q: auth must be a two-element list [USER, PASSWORD]", path)
			}
		}
		routes[path] = rc
	}
	return VHost{Domains: domains, Routes: routes}, nil
}

// parseDestField checks if a dest value is a STATUS directive.
// Format: "STATUS <code> [text]" (case-insensitive).
// Returns (statusCode, statusText, isStatus).
func parseDestField(dest string) (code int, text string, isStatus bool) {
	if !strings.HasPrefix(strings.ToUpper(dest), "STATUS ") {
		return 0, "", false
	}
	rest := strings.TrimSpace(dest[7:]) // strip "STATUS "
	spaceIdx := strings.IndexByte(rest, ' ')
	var codeStr string
	if spaceIdx < 0 {
		codeStr = rest
		text = ""
	} else {
		codeStr = rest[:spaceIdx]
		text = rest[spaceIdx+1:]
	}
	var n int
	if _, err := fmt.Sscanf(codeStr, "%d", &n); err != nil || n < 100 || n > 599 {
		return 0, "", false
	}
	return n, text, true
}


// parseUpstreamString parses a single upstream entry from a dest list.
// Format: "URL [weight=N]"
// Returns an error if the entry looks like a STATUS directive (not valid in a list).
func parseUpstreamString(s string) (Upstream, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToUpper(s), "STATUS") {
		return Upstream{}, fmt.Errorf("STATUS is not valid in a multi-dest list; use a single dest: STATUS <code> <text>")
	}
	// Split off optional weight= suffix
	weight := 1
	rawURL := s
	if idx := strings.Index(s, " "); idx >= 0 {
		rawURL = s[:idx]
		rest := strings.TrimSpace(s[idx+1:])
		if strings.HasPrefix(rest, "weight=") {
			fmt.Sscanf(rest[7:], "%d", &weight)
			if weight < 1 {
				weight = 1
			}
		}
	}
	return Upstream{URL: rawURL, Weight: weight}, nil
}

// applyDestEntries parses the raw dest entries (from YAML or CLI) and populates
// rc.Upstreams or rc.StatusCode/StatusText accordingly.
// Each upstream URL is parsed once here so the Director closure pays zero
// allocation cost per request.
// routePath is used only for error messages.
func applyDestEntries(rc *RouteConfig, entries []string, routePath string) error {
	if len(entries) == 0 {
		return nil // no dest — validate() will catch this
	}
	if len(entries) == 1 {
		// Single entry: may be a URL or a STATUS directive.
		code, text, isStatus := parseDestField(entries[0])
		if isStatus {
			rc.StatusCode = code
			rc.StatusText = text
			return nil
		}
		parsed, err := url.Parse(entries[0])
		if err != nil {
			return fmt.Errorf("route %q: invalid dest URL: %w", routePath, err)
		}
		rc.Upstreams = []Upstream{{URL: entries[0], ParsedURL: parsed, Weight: 1}}
		return nil
	}
	// Multiple entries: all must be URLs (STATUS not allowed in a list).
	upstreams := make([]Upstream, 0, len(entries))
	for _, entry := range entries {
		u, err := parseUpstreamString(entry)
		if err != nil {
			return fmt.Errorf("route %q: %w", routePath, err)
		}
		u.ParsedURL, err = url.Parse(u.URL)
		if err != nil {
			return fmt.Errorf("route %q: invalid dest URL %q: %w", routePath, u.URL, err)
		}
		upstreams = append(upstreams, u)
	}
	rc.Upstreams = upstreams
	return nil
}

// normalizeLBMode returns a canonical LB mode string.
// Empty or unrecognised values default to "random".
func normalizeLBMode(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "round-robin", "roundrobin":
		return "round-robin"
	default:
		return "random"
	}
}
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// parseAll merges config file + CLI args into a final Config.
// CLI args take precedence over config file.
func parseAll(args []string) (*Config, error) {
	// --- 1. Find config file path from args (first pass) ---
	configPath := ""
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--config" {
			configPath = args[i+1]
			break
		}
	}
	if configPath == "" {
		configPath = findDefaultConfig()
	}

	// --- 2. Load config file base ---
	base := &Config{Port: 8080, Routes: map[string]*RouteConfig{}}
	if configPath != "" {
		var err error
		base, err = loadConfigFile(configPath)
		if err != nil && configPath != "" {
			// Only error if user explicitly specified --config
			explicitConfig := false
			for i := 0; i < len(args)-1; i++ {
				if args[i] == "--config" {
					explicitConfig = true
					break
				}
			}
			if explicitConfig {
				return nil, fmt.Errorf("reading config file %q: %w", configPath, err)
			}
			// Default path not found — start fresh
			base = &Config{Port: 8080, Routes: map[string]*RouteConfig{}}
		}
	}

	// --- 3. Apply CLI overrides ---
	if err := applyCLI(base, args); err != nil {
		return nil, err
	}

	return base, nil
}

// findDefaultConfig returns the first existing default config path.
func findDefaultConfig() string {
	// Same directory as the binary
	exe, err := os.Executable()
	if err == nil {
		p := filepath.Join(filepath.Dir(exe), "config.yml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// ~/.config/routemux/config.yml
	home, err := os.UserHomeDir()
	if err == nil {
		p := filepath.Join(home, ".config", "routemux", "config.yml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// resolveListenAddress turns an interface name or IP into a bind IP string.
// Returns "" (all interfaces) for empty input.
func resolveListenAddress(listen string) (string, error) {
	if listen == "" {
		return "", nil
	}
	// Is it already an IP?
	if ip := net.ParseIP(listen); ip != nil {
		return ip.String(), nil
	}
	// Treat as interface name
	iface, err := net.InterfaceByName(listen)
	if err != nil {
		return "", fmt.Errorf("unknown interface %q: %w", listen, err)
	}
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("no addresses on interface %q", listen)
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
	}
	// Fall back to first address
	switch v := addrs[0].(type) {
	case *net.IPNet:
		return v.IP.String(), nil
	case *net.IPAddr:
		return v.IP.String(), nil
	}
	return "", fmt.Errorf("could not determine IP for interface %q", listen)
}

// applyCLI parses os.Args-style slice and overwrites fields in cfg.
// Routes are accumulated: --route PATH starts a new route context;
// subsequent --dest/--noTLSverify/--auth/--timeout belong to it.
// expandArgs converts --key=value tokens into ["--key", "value"] pairs.
func expandArgs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		if strings.HasPrefix(a, "--") && strings.Contains(a, "=") {
			parts := strings.SplitN(a[2:], "=", 2)
			out = append(out, "--"+parts[0], parts[1])
		} else {
			out = append(out, a)
		}
	}
	return out
}

func applyCLI(cfg *Config, rawArgs []string) error {
	args := expandArgs(rawArgs)
	// current route being built from CLI (nil if not inside --route block)
	var curPath string
	var curRoute *RouteConfig

	flush := func() {
		if curPath != "" && curRoute != nil {
			cfg.Routes[curPath] = curRoute
		}
	}

	i := 0
	for i < len(args) {
		arg := args[i]

		switch arg {
		case "--config":
			i += 2
			continue
		case "--listen":
			if i+1 >= len(args) {
				return fmt.Errorf("--listen requires a value")
			}
			cfg.Listen = args[i+1]
			i += 2
		case "--port":
			if i+1 >= len(args) {
				return fmt.Errorf("--port requires a value")
			}
			if _, err := fmt.Sscanf(args[i+1], "%d", &cfg.Port); err != nil {
				return fmt.Errorf("invalid --port: %v", err)
			}
			i += 2
		case "--tls-cert":
			if i+1 >= len(args) {
				return fmt.Errorf("--tls-cert requires a value")
			}
			cfg.TLSCert = args[i+1]
			i += 2
		case "--tls-key":
			if i+1 >= len(args) {
				return fmt.Errorf("--tls-key requires a value")
			}
			cfg.TLSKey = args[i+1]
			i += 2
		case "--global-auth":
			if i+1 >= len(args) {
				return fmt.Errorf("--global-auth requires a value")
			}
			a, err := parseAuthString(args[i+1])
			if err != nil {
				return fmt.Errorf("--global-auth: %w", err)
			}
			cfg.GlobalAuth = a
			i += 2
		case "--route":
			flush() // save previous route
			if i+1 >= len(args) {
				return fmt.Errorf("--route requires a value")
			}
			curPath = args[i+1]
			// inherit existing route if present, else create new
			if existing, ok := cfg.Routes[curPath]; ok {
				curRoute = existing
			} else {
				curRoute = &RouteConfig{}
			}
			i += 2
		case "--dest":
			if curRoute == nil {
				return fmt.Errorf("--dest must follow --route")
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--dest requires a value")
			}
			curRoute.Dest = args[i+1]
			i += 2
		case "--noTLSverify":
			if curRoute == nil {
				return fmt.Errorf("--noTLSverify must follow --route")
			}
			curRoute.NoTLSVerify = true
			i++
		case "--auth":
			if curRoute == nil {
				return fmt.Errorf("--auth must follow --route")
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--auth requires a value")
			}
			curRoute.AuthExplicit = true
			val := args[i+1]
			if val == "" {
				curRoute.Auth = nil // explicit no-auth
			} else {
				a, err := parseAuthString(val)
				if err != nil {
					return fmt.Errorf("--auth: %w", err)
				}
				curRoute.Auth = a
			}
			i += 2
		case "--add-header":
			if curRoute == nil {
				return fmt.Errorf("--add-header must follow --route")
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--add-header requires a value (format: 'Name: Value')")
			}
			name, val, err := parseHeaderString(args[i+1])
			if err != nil {
				return fmt.Errorf("--add-header: %w", err)
			}
			if curRoute.AddHeaders == nil {
				curRoute.AddHeaders = map[string]string{}
			}
			curRoute.AddHeaders[name] = val
			i += 2
		case "--delete-header":
			if curRoute == nil {
				return fmt.Errorf("--delete-header must follow --route")
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--delete-header requires a value")
			}
			curRoute.DeleteHeaders = append(curRoute.DeleteHeaders, args[i+1])
			i += 2
		case "--timeout":
			if curRoute == nil {
				return fmt.Errorf("--timeout must follow --route")
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--timeout requires a value")
			}
			curRoute.Timeout = args[i+1]
			i += 2
		case "--help", "-h":
			printHelp()
			os.Exit(0)
		default:
			return fmt.Errorf("unknown argument: %q", arg)
		}
	}
	flush()
	return nil
}

func parseHeaderString(s string) (name, value string, err error) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("expected 'Name: Value', got %q", s)
	}
	return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+1:]), nil
}

func parseAuthString(s string) (*Auth, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("expected USER:PASSWORD, got %q", s)
	}
	return &Auth{User: parts[0], Password: parts[1]}, nil
}

func printHelp() {
	fmt.Print(`routemux — a flexible reverse proxy

Usage:
  routemux [global options] [--route PATH --dest URL [route options]] ...

Global options:
  --config PATH       Config file (default: ./config.yml or ~/.config/routemux/config.yml)
  --listen ADDR       IP address or interface name to listen on (default: all interfaces)
  --port PORT         Port to listen on (default: 8080)
  --tls-cert FILE     TLS certificate file (enables HTTPS)
  --tls-key  FILE     TLS key file (enables HTTPS)
  --global-auth U:P   HTTP Basic Auth applied to all routes (format: USER:PASSWORD)

Route options (must follow --route PATH):
  --route PATH        Define a route (e.g. /api/)
  --dest URL          Upstream destination URL
  --noTLSverify       Skip TLS verification for upstream
  --auth U:P          Per-route Basic Auth (overrides global-auth; "" disables auth)
  --timeout DURATION  Upstream timeout (e.g. 30s, 2m)
  --add-header K:V    Add/overwrite a header on upstream request (repeatable)
  --delete-header K   Delete a header from the upstream request (repeatable)

Config file (config.yml):
  global:
    listen: ""
    port: 8080
    tls-cert: ""
    tls-key: ""
    global-auth: ["USER", "PASSWORD"]

  routes:
    "/path/":
      dest: http://localhost:3000/
      noTLSverify: false
      auth: ["USER", "PASSWORD"]
      timeout: 30s
`)
}

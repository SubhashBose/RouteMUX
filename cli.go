package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"routemux/daemon"

	"github.com/SubhashBose/GoPkg-selfupdater"
)

var version = "0.4"

// parseAll merges config file + CLI args into a final Config.
// CLI args take precedence over config file.
func parseAll(args []string) (*Config, error) {
	// --- 1. Find config file path from args (first pass) ---
	// Scan args once to find --config and detect --help early.
	explicitConfig := false
	configPath := ""
	skipConfig := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h", "--upgrade":
			skipConfig = true
		case "--config":
			if i+1 < len(args) {
				configPath = args[i+1]
				explicitConfig = true
				i++
			}
		}
	}
	if !skipConfig && !explicitConfig {
		configPath = findDefaultConfig()
	}

	// --- 2. Load config file base ---
	base := &Config{Port: 8080}
	if configPath != "" {
		var err error
		base, err = loadConfigFile(configPath)
		if err != nil {
			// Always report config file errors — whether the path was given via
			// --config or auto-discovered. findDefaultConfig() already verified
			// the file exists, so any error here is a real problem (YAML syntax,
			// bad values, permission denied) not a missing file.
			return nil, fmt.Errorf("config file %q: %w", configPath, err)
		}
	}

	// Store metadata for hot reload
	base.ConfigPath = configPath
	base.OriginalArgs = args

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
	// Current directory
	{
		p := "config.yml"
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
	// Current vhost being built. Routes without --vhost go into the implicit catch-all.
	var curVHostDomains []string // nil = implicit catch-all (backward compat)
	var curRoutes map[string]*RouteConfig
	getCurrentRoutes := func() map[string]*RouteConfig {
		if curRoutes == nil {
			curRoutes = map[string]*RouteConfig{}
		}
		return curRoutes
	}

	// current route being built from CLI (nil if not inside --route block)
	var curPath string
	var curRoute *RouteConfig

	var flushErr error
	flushRoute := func() {
		if curPath != "" && curRoute != nil {
			if len(curRoute.destEntries) > 0 {
				if err := applyDestEntries(curRoute, curRoute.destEntries, curPath); err != nil {
					flushErr = fmt.Errorf("--dest: %w", err)
					return
				}
			}
			getCurrentRoutes()[curPath] = curRoute
			curPath = ""
			curRoute = nil
		}
	}
	flushVHost := func() {
		flushRoute()
		if flushErr != nil {
			return
		}
		if curRoutes == nil {
			return
		}
		if curVHostDomains == nil {
			// No --vhost flag: implicit catch-all.
			// Merge into an existing catch-all VHost if present (e.g. loaded from config file),
			// so CLI routes and file routes share the same vhost rather than creating a second one.
			for i := range cfg.VHosts {
				for _, d := range cfg.VHosts[i].Domains {
					if d == "*" {
						if cfg.VHosts[i].Routes == nil {
							cfg.VHosts[i].Routes = map[string]*RouteConfig{}
						}
						for k, v := range curRoutes {
							cfg.VHosts[i].Routes[k] = v
						}
						curRoutes = nil
						return
					}
				}
			}
			// No existing catch-all — create one.
			cfg.VHosts = append(cfg.VHosts, VHost{Domains: []string{"*"}, Routes: curRoutes})
		} else {
			cfg.VHosts = append(cfg.VHosts, VHost{Domains: curVHostDomains, Routes: curRoutes})
		}
		curRoutes = nil
		curVHostDomains = nil
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
		case "--trust-client-headers":
			cfg.TrustClientHeaders = true
			i++
		case "--trusted-proxy":
			if i+1 >= len(args) {
				return fmt.Errorf("--trusted-proxy requires a value")
			}
			src, err := parseFilterEntry(args[i+1])
			if err != nil {
				return fmt.Errorf("--trusted-proxy: %w", err)
			}
			if cfg.TrustedProxies == nil {
				cfg.TrustedProxies = &TrustedProxies{list: &CIDRList{}}
			}
			addToCIDRList(&cfg.TrustedProxies.list, src)
			i += 2
		case "--ip-filter-allow", "--ip-filter-block":
			if i+1 >= len(args) {
				return fmt.Errorf("%s requires a value", arg)
			}
			if cfg.IPFilter == nil {
				cfg.IPFilter = &IPFilter{}
			}
			src, err := parseFilterEntry(args[i+1])
			if err != nil {
				return fmt.Errorf("%s: %w", arg, err)
			}
			if arg == "--ip-filter-allow" {
				addToCIDRList(&cfg.IPFilter.allowed, src)
			} else {
				addToCIDRList(&cfg.IPFilter.blocked, src)
			}
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
		case "--vhost":
			flushVHost() // save previous vhost
			if flushErr != nil {
				return flushErr
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--vhost requires a value (domain or domain1|domain2)")
			}
			// Split pipe-separated domains: domain.com|www.domain.com
			curVHostDomains = strings.Split(args[i+1], "|")
			for j, d := range curVHostDomains {
				curVHostDomains[j] = strings.TrimSpace(d)
			}
			i += 2
		case "--route":
			flushRoute() // save previous route
			if flushErr != nil {
				return flushErr
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--route requires a value")
			}
			curPath = args[i+1]
			// inherit existing route if present, else create new
			if existing, ok := getCurrentRoutes()[curPath]; ok {
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
			// Accumulate entries — repeated --dest builds the upstream list.
			curRoute.destEntries = append(curRoute.destEntries, args[i+1])
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
		case "--dest-add-header":
			if curRoute == nil {
				return fmt.Errorf("--dest-add-header must follow --route")
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--dest-add-header requires a value (format: 'Name: Value')")
			}
			name, val, err := parseHeaderString(args[i+1])
			if err != nil {
				return fmt.Errorf("--dest-add-header: %w", err)
			}
			if curRoute.ParsedAddHeaders == nil {
				curRoute.ParsedAddHeaders = map[string]parsedHeaderValue{}
			}
			ph := compileHeaderValue(val)
			curRoute.ParsedAddHeaders[name] = ph
			if !ph.isConst {
				curRoute.AddHasVars = true
			}
			for _, seg := range ph.segments {
				if seg.kind == segHeaderName {
					curRoute.NeedsOriginal = true
				}
				if seg.kind == segTrustedXFF {
					curRoute.NeedsTrustedXFF = true
				}
			}
			i += 2
		case "--dest-del-header":
			if curRoute == nil {
				return fmt.Errorf("--dest-del-header must follow --route")
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--dest-del-header requires a value")
			}
			curRoute.DeleteHeaders = append(curRoute.DeleteHeaders, args[i+1])
			if strings.Contains(args[i+1], "*") {
				curRoute.DeleteHasWildcard = true
			}
			i += 2
		case "--client-add-header":
			if curRoute == nil {
				return fmt.Errorf("--client-add-header must follow --route")
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--client-add-header requires a value (format: 'Name: Value')")
			}
			name, val, err := parseHeaderString(args[i+1])
			if err != nil {
				return fmt.Errorf("--client-add-header: %w", err)
			}
			if curRoute.ParsedClientAddHeaders == nil {
				curRoute.ParsedClientAddHeaders = map[string]parsedHeaderValue{}
			}
			ph := compileHeaderValue(val)
			curRoute.ParsedClientAddHeaders[name] = ph
			if !ph.isConst {
				curRoute.ClientAddHasVars = true
			}
			for _, seg := range ph.segments {
				if seg.kind == segHeaderName {
					curRoute.ClientNeedsRespHeaders = true
				}
				if seg.kind == segTrustedXFF {
					curRoute.NeedsTrustedXFF = true
				}
			}
			i += 2
		case "--client-del-header":
			if curRoute == nil {
				return fmt.Errorf("--client-del-header must follow --route")
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--client-del-header requires a value")
			}
			curRoute.ClientDelHeaders = append(curRoute.ClientDelHeaders, args[i+1])
			if strings.Contains(args[i+1], "*") {
				curRoute.ClientDelHasWildcard = true
			}
			i += 2
		case "--load-balancer-mode":
			if curRoute == nil {
				return fmt.Errorf("--load-balancer-mode must follow --route")
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--load-balancer-mode requires a value (random or round-robin)")
			}
			curRoute.LBMode = normalizeLBMode(args[i+1])
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
		case "--upgrade":
			runUpgrade()
			os.Exit(0)
		case "--help", "-h":
			printHelp()
			os.Exit(0)
		default:
			return fmt.Errorf("unknown argument: %q", arg)
		}
	}
	flushVHost()
	if flushErr != nil {
		return flushErr
	}
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

func runUpgrade(){
	cfg := selfupdate.Config{
		RepoURL:        "https://github.com/SubhashBose/RouteMUX",
		BinaryPrefix:   "routemux-",
		OSSep:          "-",
		CurrentVersion: version, // your build-time var
	}

	fmt.Printf("Current version: %s\nChecking for updates…", version)
 
	res, err := selfupdate.Update(cfg)

	if res.LatestVersion != "" {
		fmt.Printf(" Latest version: %s\n", res.LatestVersion)
	} else {
		fmt.Printf("\n")
	}
	
	if err != nil {
		fmt.Fprintln(os.Stderr, "Update failed:", err)
		os.Exit(1)
	}
 
	if !res.Updated {
		fmt.Printf("Already up to date (latest: %s)\n", res.LatestVersion)
		return
	}
 
	fmt.Printf("Successfully updated to v%s (asset: %s)\nPlease restart any running instances of the program.\n",
		res.LatestVersion, res.AssetName)
}

func printHelp() {
	bindir := "BinaryDirectory/config.yml"
	exe, err := os.Executable()
	if err == nil {
		bindir = filepath.Join(filepath.Dir(exe), "config.yml")
	}

	fmt.Print(`RouteMUX v` + version + ` — a flexible reverse proxy

Usage:
  routemux [global options] \
            --route PATH --dest URL [route options] \
           [--route PATH2 --dest URL [route options]] ...

Global options:
  --config PATH            Config file (default: `+bindir+` or
                           ./config.yml or ~/.config/routemux/config.yml)
  --listen ADDR            IP address or interface name to listen on (default: all interfaces)
  --port PORT              Port to listen on (default: 8080)
  --tls-cert FILE          TLS certificate file (enables HTTPS)
  --tls-key  FILE          TLS key file (enables HTTPS)
  --trust-client-headers   Trust X-Forwarded-* headers from client (default: false)
  --trusted-proxy ENTRY    Trust X-Forwarded-* headers from specific proxy IPs (repeatable)
                           ENTRY: IP, CIDR, file path, or URL — same format as --ip-filter-allow
  --ip-filter-allow ENTRY  Allow an IP, CIDR, file, or URL (repeatable)
  --ip-filter-block ENTRY  Block an IP, CIDR, file, or URL (repeatable)
                           ENTRY formats:
                             10.0.0.1              bare IP (→ /32 or /128)
                             10.0.0.0/8            CIDR range
                             /path/to/list.txt     local file
                             /path/to/list.txt refresh=6h
                             https://example.com/list
                             https://example.com/list refresh=12h cache=/path
  --global-auth U:P        HTTP Basic Auth applied to all routes (format: USER:PASSWORD)

Vhost and Route:
  --vhost DOMAINS          Specify list of hostnames (e.g. "domain.com|www.domain.com") to
                           group routes under it (repeatable). Default is '*'
  --route PATH             Define a route (e.g. /api/) (repeatable under a vhost)
                           If no preceding --vhost specified, then the routes are applied to 
                           '*', i.e., all hosts

Route options (must follow --route PATH):
  --dest URL               Upstream destination URL (repeatable).
                           Repeated --dest <URL> [weight=<N>] per route forms load-balancer,
                           where weight is optional, default is 1.
                           --dest STATUS <code> [text] is also supported, where a HTTP
                           response code is returned with optional static text body.
  --load-balancer-mode     Load balancer mode, "round-robin" or "random", (default: random) 
  --noTLSverify            Skip TLS verification for upstream(s)
  --auth U:P               Per-route Basic Auth (overrides global-auth; "" disables auth)
  --timeout DURATION       Upstream timeout (e.g. 30s, 2m)
  --dest-add-header K:V    Add/overwrite a header on upstream request (repeatable)
                           Can be combination of variables and text
  --dest-del-header K      Delete a header from the upstream request (repeatable)
                           Can take wildcards (e.g. --dest-del-header *cookie*)
  --client-add-header K:V  Add/overwrite a header on upstream response sent to client
                           (repeatable) Can be combination of variables and text
  --client-del-header K    Delete a header from the upstream response (repeatable)
                           Can take wildcards (e.g. --client-del-header *cookie*)
`)
if daemon.DAEMONIZE_SUPPORTED {
	fmt.Print(`
Daemon options:
  start                    Start RouteMUX as a background daemon process.
  watch-start              Start RouteMUX as a background daemon process with watchdog,
                           which monitors the process and restarts it if it fails. It
                           and also creates a log-file to monitor for output and errors.
                           'watch-start' is recommended over 'start' to run as daemon.
  stop                     Stop RouteMUX daemon
  restart                  Restart RouteMUX daemon
  reload                   Sends signal to RouteMUX daemon process to gracefully reload
                           configuration from file. Note, by default RouteMUX always watches
                           config file for changes and gracefully reloads automatically. 
  status                   Show RouteMUX daemon status
`)
}
	fmt.Print(`
General flags:
  --help, -h               Show this help
  --upgrade                Self-upgrade RouteMUX to the latest version

Sets of --route followed by route options can be repeated to define multiple routes.
Options in command line and config.yml file are combined, where command line options takes precedence.
To disable reading any config.yml file, use --config "". 

Config file (config.yml) example:
  global:
    listen: ""
    port: 8080
    tls-cert: ""
    tls-key: ""
    global-auth: ["USER", "PASSWORD"]
    trust-client-headers: false
    trusted-proxy:
	  - 192.168.0.0/16
    ip-filter:
      blocked:
        - 10.0.0.0/8
      allowed:
        - 172.16.0.0/12

  vhosts:
    - domains: ["example.com", "www.example.com"]
      routes:
        "/api/":
           dest: http://localhost:3000/
           noTLSverify: false
           auth: ["USER", "PASSWORD"]
           timeout: 30s
           dest-add-header:
             User-Agent: RouteMUX
             X-Built-URL: ${scheme}://${header.host}${request_uri}
           dest-del-header:
             - *cookie*
             - Authorization
           client-add-header:
             Served-By: RouteMUX
           client-del-header:
             - Server

        "/load-balancer/":
           dest:
             - http://localhost:3000/
             - http://localhost:3001/ weight=5
           load-balancer-mode: round-robin

        "/health/":
           dest: STATUS 200 Health is ok

The 'domains' and set of 'route' under it is repeatable for different hosts.
The 'vhost' and 'domains' can be omitted if there is no host/domain configuration needed. 
All routes are applied to all incoming requests, i.e., ['*'] domains.

Config file can have environment variables substitution globally as ${env.VARIABLE:default}

The 'dest-add-header' or 'client-add-header' values can be a combination of text and following supported variables:
  ${host}: client host header
  ${remote_addr}: client IP (no port)
  ${remote_port}: client port
  ${scheme}:      "http" or "https" client scheme
  ${request_uri}: full request URI including query string
  ${trusted_xff}: Remote IP after evaluating trusted proxies on the 'X-Forwarded-For' chained with connecting IP
  ${header.Name}: value of 'Name' header from the original client headers (in case of 'dest-add-header')
                  or upstream response headers (in case of 'client-add-header')

Full documentation: https://github.com/SubhashBose/RouteMUX
`)
}
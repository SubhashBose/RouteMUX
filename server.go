package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)


// perRequestKeys are unexported context key types to avoid collisions.
type ctxKeyRequestHost struct{}
type ctxKeyXFFCopy struct{}

type server struct {
	state    atomic.Pointer[serverState]
	bindIP   string // resolved from cfg.Listen (does not change on reload)

	// Hot reload coordination.
	// reloadMu ensures only one Reload() runs at a time — concurrent triggers
	// (simultaneous SIGHUP + file change) are dropped rather than queued.
	// timerMu protects reloadTimer for the debounce logic.
	reloadMu    sync.Mutex
	timerMu     sync.Mutex
	reloadTimer *time.Timer
}

type serverState struct {
	cfg       *Config
	vhosts    []vhostEntry
	singleMux bool // true when only one vhost AND it is a catch-all (*) — skip host matching
}

// vhostEntry holds a compiled vhost: its domain list and ready-to-use ServeMux.
type vhostEntry struct {
	domains []string        // lower-cased; "*" matches any host
	mux     *http.ServeMux
}

// matchHost returns true if host matches this vhost entry.
func (ve *vhostEntry) matchHost(host string) bool {
	for _, d := range ve.domains {
		if d == "*" || d == host {
			return true
		}
	}
	return false
}

func newServer(cfg *Config) (*server, error) {
	bindIP, err := resolveListenAddress(cfg.Listen)
	if err != nil {
		return nil, err
	}

	s := &server{bindIP: bindIP}
	vhosts, singleMux, err := s.compileVHosts(cfg)
	if err != nil {
		return nil, err
	}

	s.state.Store(&serverState{
		cfg:       cfg,
		vhosts:    vhosts,
		singleMux: singleMux,
	})

	if cfg.IPFilter != nil {
		if err := cfg.IPFilter.Load(); err != nil {
			return nil, fmt.Errorf("ip-filter: %w", err)
		}
		cfg.IPFilter.StartRefresh()
	}
	if cfg.TrustedProxies != nil {
		if err := cfg.TrustedProxies.Load(); err != nil {
			return nil, fmt.Errorf("trusted-proxies: %w", err)
		}
		cfg.TrustedProxies.StartRefresh()
	}
	return s, nil
}

func (s *server) listenAddr() string {
	return fmt.Sprintf("%s:%d", s.bindIP, s.state.Load().cfg.Port)
}

// compileVHosts compiles all vhosts into vhostEntry values, each with its own ServeMux.
func (s *server) compileVHosts(cfg *Config) ([]vhostEntry, bool, error) {
	var vhosts []vhostEntry
	for _, vh := range cfg.VHosts {
		domains := make([]string, len(vh.Domains))
		for i, d := range vh.Domains {
			domains[i] = strings.ToLower(d)
		}
		log.Printf("vhost [%s]:", strings.Join(domains, ", "))
		mux, err := s.buildMux(vh.Routes, cfg)
		if err != nil {
			return nil, false, err
		}
		vhosts = append(vhosts, vhostEntry{domains: domains, mux: mux})
	}
	// Sort vhosts: specific-domain entries before catch-alls ("*" or empty).
	// This ensures a request for domain.com always matches ["domain.com"]
	// before ["*"], regardless of the order they appear in the config.
	sort.SliceStable(vhosts, func(i, j int) bool {
		return !isCatchAll(vhosts[i].domains) && isCatchAll(vhosts[j].domains)
	})
	singleMux := len(vhosts) == 1 && isCatchAll(vhosts[0].domains)
	return vhosts, singleMux, nil
}

// buildMux builds a ServeMux for a single vhost's route map.
func (s *server) buildMux(routes map[string]*RouteConfig, cfg *Config) (*http.ServeMux, error) {
	mux := http.NewServeMux()

	// Sort routes longest-first so more specific paths win.
	paths := make([]string, 0, len(routes))
	for p := range routes {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		return len(paths[i]) > len(paths[j])
	})

	for _, path := range paths {
		rc := routes[path]
		var picker *upstreamPicker
		if rc.StatusCode == 0 {
			picker = newUpstreamPicker(rc.Upstreams, rc.LBMode)
		}

		handler, err := s.buildRouteHandler(path, picker, rc, cfg)
		if err != nil {
			return nil, err
		}

		pattern := path
		if !strings.HasSuffix(pattern, "/") {
			pattern += "/"
		}
		mux.Handle(pattern, handler)
		if rc.StatusCode != 0 {
			log.Printf("  route %s  →  STATUS %d", pattern, rc.StatusCode)
		} else {
			urls := make([]string, len(rc.Upstreams))
			for i, u := range rc.Upstreams {
				urls[i] = u.URL
			}
			log.Printf("  route %s  →  %s", pattern, strings.Join(urls, ", "))
		}
	}
	return mux, nil
}

// buildRouteHandler creates the http.Handler for one route.
func (s *server) buildRouteHandler(routePath string, picker *upstreamPicker, rc *RouteConfig, cfg *Config) (http.Handler, error) {
	// -- Static STATUS response route --
	if rc.StatusCode != 0 {
		var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			manipulateClientHeaders(w.Header(), nil, r, rc)

			w.WriteHeader(rc.StatusCode)
			if rc.StatusText != "" {
				fmt.Fprint(w, rc.StatusText)
			}
		})
		effectiveAuth := cfg.GlobalAuth
		if rc.AuthExplicit {
			effectiveAuth = rc.Auth
		}
		return requireBasicAuth(effectiveAuth, h), nil
	}

	// -- TLS transport wrapped in a RoundTripper that fixes X-Forwarded-For --
	// The Director always sets X-Forwarded-For, but Go's ReverseProxy appends
	// the client IP again after the Director returns, causing duplication.
	// The xffRoundTripper strips that extra append before the request hits the wire.
	baseTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: rc.NoTLSVerify, //nolint:gosec
		},
	}
	transport := &xffRoundTripper{base: baseTransport}
	lbMode := rc.LBMode

	// -- Timeout --
	var clientTimeout time.Duration
	if rc.Timeout != "" {
		d, err := time.ParseDuration(rc.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout %q for route %q: %w", rc.Timeout, routePath, err)
		}
		clientTimeout = d
	}

	// -- Effective auth for this route (used in Director closure and WS handler) --
	effectiveAuth := cfg.GlobalAuth
	if rc.AuthExplicit {
		effectiveAuth = rc.Auth // may be nil (no auth)
	}

	// -- Reverse proxy --
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			// Pick an upstream for this request — ParsedURL computed once at startup.
			upstream := picker.pick(lbMode)
			destURL := upstream.ParsedURL

			// Strip the route prefix from the path, then prepend the dest path.
			stripped := strings.TrimPrefix(req.URL.Path, routePath)
			// Join dest base path + stripped remainder
			destPath := destURL.Path
			if !strings.HasSuffix(destPath, "/") {
				destPath += "/"
			}

			req.URL.Scheme = destURL.Scheme
			req.URL.Host = destURL.Host
			req.URL.Path = destPath + stripped
			// Keep client Host by default (req.Host stays as-is).
			// dest-del-header:Host → use upstream host (req.Host = "")
			// dest-add-header:Host   → use user-supplied value (req.Host = val)
			// Both are handled in the add/delete loop below.
			// Preserve raw query
			if destURL.RawQuery != "" && req.URL.RawQuery != "" {
				req.URL.RawQuery = destURL.RawQuery + "&" + req.URL.RawQuery
			} else if destURL.RawQuery != "" {
				req.URL.RawQuery = destURL.RawQuery
			}

			// Snapshot original client headers before any modification when variables
			// are in use — {header.X} must reflect what the client sent, not the
			// post-modification state. Host is injected explicitly since Go never
			// puts it in req.Header.
			var originalHeaders http.Header
			if rc.NeedsOriginal {
				originalHeaders = req.Header.Clone()
				originalHeaders.Set("Host", req.Host)
			}
			// Store per-request values in context so ModifyResponse can read them
			// safely under concurrent requests without a data race.
			requestHost := req.Host
			*req = *req.WithContext(
				context.WithValue(
					req.Context(), ctxKeyRequestHost{}, requestHost))

			// Parse client address once — reused for XFF and {remote_addr}/{remote_port} variables.
			clientIP, clientPort, _ := net.SplitHostPort(req.RemoteAddr)

			// X-Forwarded-* handling depends on trust-client-headers setting
			// or whether the connecting IP is in trusted-proxies.
			//
			// trust mode (TrustClientHeaders=true OR connecting IP in TrustedProxies):
			//   X-Forwarded-For   → append connecting IP to existing chain
			//   X-Forwarded-Host  → leave untouched (upstream proxy already set it)
			//   X-Forwarded-Proto → leave untouched (upstream proxy already set it)
			//
			// default (secure, routemux is the entry point):
			//   X-Forwarded-For   → discard client chain, set to connecting IP only
			//   X-Forwarded-Host  → set to original client Host
			//   X-Forwarded-Proto → set from actual TLS state (never trust client)
			// trusted: global flag OR connecting IP is in trusted-proxies list.
			// clientIP is already parsed above — reuse it to avoid double SplitHostPort.
			var clientNetIP net.IP
			if cfg.TrustedProxies != nil {
				clientNetIP = net.ParseIP(clientIP)
			}
			trusted := cfg.TrustClientHeaders ||
				(clientNetIP != nil && cfg.TrustedProxies.list.Contains(clientNetIP))
			if clientIP != "" {
				if trusted {
					if prior, ok := req.Header["X-Forwarded-For"]; ok {
						req.Header.Set("X-Forwarded-For", strings.Join(prior, ", ")+", "+clientIP)
					} else {
						req.Header.Set("X-Forwarded-For", clientIP)
					}
					// Leave X-Forwarded-Host and X-Forwarded-Proto untouched.
				} else {
					req.Header.Set("X-Forwarded-For", clientIP)
				}
			}
			// X-Forwarded-Host and X-Forwarded-Proto don't depend on clientIP —
			// set them unconditionally when not in trust mode.
			if !trusted {
				req.Header.Set("X-Forwarded-Host", req.Host)
				req.Header.Set("X-Forwarded-Proto", schemeOf(req))
			}

			// Snapshot XFF chain for ${trusted_xff} variable — only when needed.
			var xffCopy []string
			if rc.NeedsTrustedXFF {
				xffCopy = req.Header["X-Forwarded-For"]
				*req = *req.WithContext(
					context.WithValue(req.Context(), ctxKeyXFFCopy{}, xffCopy))
			}

			// If proxy auth is active, strip Authorization so the proxy credentials
			// never reach the upstream. The user-defined add/delete loop below runs
			// afterwards, so dest-add-header:Authorization or dest-del-header:Authorization
			// in the config still work as normal — no special casing needed.
			if effectiveAuth != nil {
				req.Header.Del("Authorization")
			}

			// --- User-defined header manipulation ---
			// Delete first, then add/overwrite, so add always wins.
			// Host is special: Go ignores req.Header["Host"] — it reads req.Host.
			for _, name := range rc.DeleteHeaders {
				if strings.EqualFold(name, "host") {
					req.Host = "" // fall back to req.URL.Host (upstream address)
				}
			}
			applyDeleteHeaders(req.Header, rc.DeleteHeaders, rc.DeleteHasWildcard)

			// Apply add-headers. Each parsedHeaderValue was compiled at startup;
			// eval() is a simple segment walk — no string parsing at request time.
			// Constant values (no variables) return directly with no allocation.
			// scheme and requestURI are only computed when at least one header
			// value contains a variable (AddHasVars), avoiding unnecessary work
			// for routes with all plain-string add-headers.
			if len(rc.ParsedAddHeaders) > 0 {
				var scheme, requestURI string
				if rc.AddHasVars {
					scheme = schemeOf(req)
					requestURI = req.RequestURI
				}
				for name, ph := range rc.ParsedAddHeaders {
					resolved := ph.eval(requestHost, clientIP, clientPort, scheme, requestURI, xffCopy, cfg, originalHeaders)
					if strings.EqualFold(name, "host") {
						req.Host = resolved
						continue
					}
					req.Header.Set(name, resolved)
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			// Read per-request values stored by Director in the request context.
			reqHost, _ := resp.Request.Context().Value(ctxKeyRequestHost{}).(string)
			//var xffCopy []string
			//if rc.NeedsTrustedXFF {
			//	xffCopy, _ = resp.Request.Context().Value(ctxKeyXFFCopy{}).([]string)
			//}
			//_ = xffCopy // available for future client-add-header ${trusted_xff} support
			// ${header.X} in client-add-header resolves from the upstream response headers.
			// Snapshot before we modify so add-header can reference headers we're about to delete.
			var originalRespHeaders http.Header
			if rc.ClientNeedsRespHeaders {
				originalRespHeaders = resp.Header.Clone()
			}
			resp.Request.Host = reqHost

			manipulateClientHeaders(resp.Header, originalRespHeaders, resp.Request, rc)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error [%s → %s]: %v", r.URL.Path, r.URL.Host, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// handleWS uses effectiveAuth which is declared above.
	handleWS := func(w http.ResponseWriter, r *http.Request) {
		upstream := picker.pick(lbMode)
		serveWebSocket(w, r, upstream.ParsedURL, routePath, rc, effectiveAuth, cfg)
	}

	var h http.Handler = proxy

	// Wrap with timeout if needed.
	if clientTimeout > 0 {
		h = http.TimeoutHandler(h, clientTimeout, "Gateway Timeout")
	}

	// Wrap with basic auth if needed.
	h = requireBasicAuth(effectiveAuth, h)

	// Wrap: intercept WebSocket upgrades before auth/timeout middleware.
	finalHandler := h
	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketUpgrade(r) {
			// Apply auth check for WebSocket too, then tunnel.
			if effectiveAuth != nil && !checkBasicAuth(r, effectiveAuth) {
				w.Header().Set("WWW-Authenticate", `Basic realm="routemux"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			handleWS(w, r)
			return
		}
		finalHandler.ServeHTTP(w, r)
	})

	return h, nil
}

// manipulateClientHeaders applies client-side response header manipulation
// (client-del-header and client-add-header) to respHeaders.
//
//   - delete runs first, then add/overwrite — add always wins
//   - originalHeaders is a snapshot of the upstream response headers taken
//     before deletion, so ${header.X} in add values sees the original values;
//     pass nil for STATUS routes (no upstream response headers)
//   - returns error to satisfy http.ReverseProxy.ModifyResponse signature;
//     always returns nil
func manipulateClientHeaders(respHeaders http.Header, originalHeaders http.Header, req *http.Request, rc *RouteConfig) {
	respHeaders.Set("Via", "RouteMUX")
	// Apply client-side response header manipulation.
	// Delete first, then add (add always wins).
	if len(rc.ClientDelHeaders) > 0 {
		applyDeleteHeaders(respHeaders, rc.ClientDelHeaders, rc.ClientDelHasWildcard)
	}
	if len(rc.ParsedClientAddHeaders) > 0 {
		// clientIP/clientPort only parsed when needed — eval() for const headers
		// returns segments[0].value immediately without using them, but we still
		// avoid the SplitHostPort call entirely when all headers are constant.
		var clientIP, clientPort, scheme, requestURI string
		if rc.ClientAddHasVars {
			clientIP, clientPort, _ = net.SplitHostPort(req.RemoteAddr)
			scheme = schemeOf(req)
			requestURI = req.RequestURI
		}
		for name, ph := range rc.ParsedClientAddHeaders {
			respHeaders.Set(name, ph.eval(req.Host, clientIP, clientPort, scheme, requestURI, nil, nil, originalHeaders))
		}
	}
}

func (s *server) run() error {
	state := s.state.Load()
	addr := s.listenAddr()
	srv := &http.Server{
		Addr:    addr,
		Handler: s.handler(),
	}

	// 1. Setup platform-specific signal handling (SIGHUP for reload, SIGINT/SIGTERM for shutdown)
	s.setupSignals(srv)

	// 2. Setup config file watcher (polling)
	if state.cfg.ConfigPath != "" {
		// ConfigPath is set from CLI and never changes across reloads —
		// capture it once so the ticker doesn't load the atomic pointer each tick.
		configPath := state.cfg.ConfigPath
		go func() {
			lastStat, err := os.Stat(configPath)
			if err != nil {
				log.Printf("Watcher: could not stat config file: %v", err)
			}
			lastMtime := time.Time{}
			if lastStat != nil {
				lastMtime = lastStat.ModTime()
			}

			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				stat, err := os.Stat(configPath)
				if err != nil {
					continue
				}
				if stat.ModTime().After(lastMtime) {
					lastMtime = stat.ModTime()
					s.scheduledReload(true)
				}
			}
		}()
	}

	// Bind the TCP listener first so we can log only after the socket is
	// actually ready to accept connections.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	if state.cfg.TLSCert != "" {
		// Load the certificate and wrap the listener in TLS before logging,
		// so the message appears only when TLS is also ready.
		cert, cerr := tls.LoadX509KeyPair(state.cfg.TLSCert, state.cfg.TLSKey)
		if cerr != nil {
			ln.Close()
			return fmt.Errorf("TLS: %w", cerr)
		}
		log.Printf("TLS enabled (cert: %s)", state.cfg.TLSCert)
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		ln = tls.NewListener(ln, tlsCfg)
		log.Printf("RouteMUX listening on %s (TLS)", ln.Addr())
	} else {
		log.Printf("RouteMUX listening on %s", ln.Addr())
	}
	if configValidateOnly {
		log.Printf("Config validation (only) successful, not serving.")
		return nil
	}
	err = srv.Serve(ln)

	// ErrServerClosed is the normal return after Shutdown() — not an error.
	if errors.Is(err, http.ErrServerClosed) {
		log.Printf("RouteMUX stopped.")
		return nil
	}
	return err
}

// isCatchAll returns true if the domain list contains "*" or is empty,
// meaning the vhost matches any host.
func isCatchAll(domains []string) bool {
	for _, d := range domains {
		if d == "*" || d == "" {
			return true
		}
	}
	return false
}

// handler returns the top-level HTTP handler.
// IP filter (if configured) is checked first, before vhost dispatch.
// When there is only one catch-all vhost (singleMux), vhost dispatch is skipped.
// handler returns the top-level HTTP handler.
// IP filter and vhost dispatch are inlined — no closure allocation per request.
func (s *server) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := s.state.Load()

		if state.cfg.IPFilter != nil && !state.cfg.IPFilter.Allow(r.RemoteAddr) {
			closeConnection(w)
			return
		}

		if state.singleMux {
			state.vhosts[0].mux.ServeHTTP(w, r)
			return
		}

		// Strip port from Host header for matching.
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		for i := range state.vhosts {
			if state.vhosts[i].matchHost(host) {
				state.vhosts[i].mux.ServeHTTP(w, r)
				return
			}
		}
		// No vhost matched — close the connection immediately without sending
		// any response body (equivalent to nginx's 444). This leaks no
		// information about what vhosts exist on this server.
		closeConnection(w)
	})
}

// closeConnection terminates the connection without sending an HTTP response.
// Used when no vhost matches — equivalent to nginx's 444 status.
// For HTTP/1.x, hijacks and closes the TCP connection directly.
// For HTTP/2 (which does not support hijacking), falls back to 400 Bad Request
// with an empty body — the closest valid HTTP response to "go away".
func closeConnection(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			conn.Close()
			return
		}
	}
	// Fallback for HTTP/2 or hijack failure.
	w.WriteHeader(http.StatusBadRequest)
}


// requireBasicAuth wraps handler h with HTTP Basic Auth enforcement.
// If auth is nil, h is returned unchanged.
func requireBasicAuth(auth *Auth, h http.Handler) http.Handler {
	if auth == nil {
		return h
	}
	inner := h
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !checkBasicAuth(r, auth) {
			w.Header().Set("WWW-Authenticate", `Basic realm="routemux"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// checkBasicAuth returns true if the request carries valid Basic Auth credentials.
func checkBasicAuth(r *http.Request, auth *Auth) bool {
	user, pass, ok := r.BasicAuth()
	return ok && user == auth.User && pass == auth.Password
}
// schemeOf returns the actual scheme of the incoming connection.
// Used only for $scheme variable resolution in dest-dest-add-header values.
// Does NOT trust X-Forwarded-Proto from the client — use trust-client-headers
// if routemux is behind a trusted upstream proxy.
func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
// upstreamPicker selects an upstream for each request according to the
// configured load-balancing mode and weights.
//
// Weighted random: each request draws a random number in [0, totalWeight)
// and walks the upstream list until the cumulative weight exceeds it.
//
// Weighted round-robin: the upstream list is expanded into a flat pool at
// construction time (e.g. weight=2 → two slots), then a mutex-protected
// counter cycles through it. No per-request weight arithmetic.
type upstreamPicker struct {
	upstreams []Upstream

	// random mode
	totalWeight int

	// round-robin mode
	mu   sync.Mutex
	pool []int // indices into upstreams, expanded by weight
	next int
}

func newUpstreamPicker(upstreams []Upstream, mode string) *upstreamPicker {
	p := &upstreamPicker{upstreams: upstreams}
	for _, u := range upstreams {
		w := u.Weight
		if w < 1 {
			w = 1
		}
		p.totalWeight += w
		for i := 0; i < w; i++ {
			p.pool = append(p.pool, len(p.pool)) // will be rebuilt below
		}
	}
	// Rebuild pool with correct upstream indices
	p.pool = p.pool[:0]
	for idx, u := range upstreams {
		w := u.Weight
		if w < 1 {
			w = 1
		}
		for i := 0; i < w; i++ {
			p.pool = append(p.pool, idx)
		}
	}
	return p
}

func (p *upstreamPicker) pick(mode string) *Upstream {
	if len(p.upstreams) == 1 {
		return &p.upstreams[0]
	}
	if mode == "round-robin" {
		p.mu.Lock()
		idx := p.pool[p.next%len(p.pool)]
		p.next++
		p.mu.Unlock()
		return &p.upstreams[idx]
	}
	// Weighted random (default)
	r := rand.Intn(p.totalWeight)
	cumulative := 0
	for i, u := range p.upstreams {
		w := u.Weight
		if w < 1 {
			w = 1
		}
		cumulative += w
		if r < cumulative {
			return &p.upstreams[i]
		}
	}
	return &p.upstreams[0] // unreachable, but safe fallback
}

// scheduledReload debounces rapid reload triggers (e.g. editor writing a
// config file in multiple steps) by coalescing calls within 200ms into a
// single Reload(). Both the file watcher and the SIGHUP handler call this
// instead of Reload() directly. fileMod indicates whether the reload was
// triggered by a file modification, this is for proper logging message.
func (s *server) scheduledReload(fileMod bool) {
	s.timerMu.Lock()
	if s.reloadTimer != nil {
		s.reloadTimer.Reset(200 * time.Millisecond)
		s.timerMu.Unlock()
		return
	}
	s.reloadTimer = time.AfterFunc(200*time.Millisecond, func() {
		s.timerMu.Lock()
		s.reloadTimer = nil
		s.timerMu.Unlock()
		s.Reload(fileMod)
	})
	s.timerMu.Unlock()
}

func (s *server) Reload(fileMod bool) {
	// Prevent concurrent reloads — if one is already running, drop this trigger.
	if !s.reloadMu.TryLock() {
		log.Printf("Reload already in progress, skipping concurrent trigger.")
		return
	}
	defer s.reloadMu.Unlock()


	oldState := s.state.Load()
	if oldState.cfg.ConfigPath == "" {
		log.Printf("Reload: no config file to reload")
		return
	}

	if(fileMod) {
		log.Printf("Config file changed, reloading...")
	} else {
		log.Printf("Received signal to reload config, reloading...")
	}

	// 1. Re-parse everything (config file + CLI overrides)
	newCfg, err := parseAll(oldState.cfg.OriginalArgs)
	if err != nil {
		log.Printf("Reload failed: %v (keeping old config)", err)
		return
	}

	if err := newCfg.validate(); err != nil {
		log.Printf("Reload failed (validation): %v (keeping old config)", err)
		return
	}

	// 2. Check for non-reloadable changes (Port, Listen, TLS).
	// These are fixed at server start and require a full restart to change.
	if newCfg.Port != oldState.cfg.Port || newCfg.Listen != oldState.cfg.Listen {
		log.Printf("Reload: Port or Listen address changes require a full restart. Reverting to current values: %s:%d", oldState.cfg.Listen, oldState.cfg.Port)
		newCfg.Port = oldState.cfg.Port
		newCfg.Listen = oldState.cfg.Listen
	}
	if newCfg.TLSCert != oldState.cfg.TLSCert || newCfg.TLSKey != oldState.cfg.TLSKey {
		log.Printf("Reload: TLS cert/key changes require a full restart. Reverting to current values.")
		newCfg.TLSCert = oldState.cfg.TLSCert
		newCfg.TLSKey = oldState.cfg.TLSKey
	}

	// 3. Compile new vhosts
	vhosts, singleMux, err := s.compileVHosts(newCfg)
	if err != nil {
		log.Printf("Reload failed (compile): %v (keeping old config)", err)
		return
	}

	// 4. Initialize new IP filters and trusted proxies
	if newCfg.IPFilter != nil {
		if err := newCfg.IPFilter.Load(); err != nil {
			log.Printf("Reload failed (ip-filter): %v (keeping old config)", err)
			return
		}
	}
	if newCfg.TrustedProxies != nil {
		if err := newCfg.TrustedProxies.Load(); err != nil {
			log.Printf("Reload failed (trusted-proxies): %v (keeping old config)", err)
			return
		}
	}

	// 5. Swap state
	newState := &serverState{
		cfg:       newCfg,
		vhosts:    vhosts,
		singleMux: singleMux,
	}
	s.state.Store(newState)

	// 6. Stop old background tasks and start new ones
	if oldState.cfg.IPFilter != nil {
		oldState.cfg.IPFilter.Stop()
	}
	if oldState.cfg.TrustedProxies != nil {
		oldState.cfg.TrustedProxies.Stop()
	}

	if newCfg.IPFilter != nil {
		newCfg.IPFilter.StartRefresh()
	}
	if newCfg.TrustedProxies != nil {
		newCfg.TrustedProxies.StartRefresh()
	}

	log.Printf("Reload successful.")
}
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"sort"
	"strings"
	"sync"
	"time"
)

type server struct {
	cfg      *Config
	bindIP   string // resolved from cfg.Listen
	mux      *http.ServeMux
}

func newServer(cfg *Config) (*server, error) {
	bindIP, err := resolveListenAddress(cfg.Listen)
	if err != nil {
		return nil, err
	}

	s := &server{cfg: cfg, bindIP: bindIP}
	if err := s.buildMux(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *server) listenAddr() string {
	return fmt.Sprintf("%s:%d", s.bindIP, s.cfg.Port)
}

func (s *server) buildMux() error {
	s.mux = http.NewServeMux()

	// Sort routes longest-first so more specific paths win.
	paths := make([]string, 0, len(s.cfg.Routes))
	for p := range s.cfg.Routes {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		return len(paths[i]) > len(paths[j])
	})

	for _, path := range paths {
		rc := s.cfg.Routes[path]
		// Build the upstream picker (URLs already validated and parsed in applyDestEntries).
		var picker *upstreamPicker
		if rc.StatusCode == 0 {
			picker = newUpstreamPicker(rc.Upstreams, rc.LBMode)
		}

		handler, err := s.buildRouteHandler(path, picker, rc)
		if err != nil {
			return err
		}

		pattern := path
		// Go's ServeMux needs a trailing slash to match all sub-paths.
		if !strings.HasSuffix(pattern, "/") {
			pattern += "/"
		}
		s.mux.Handle(pattern, handler)
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
	return nil
}

// buildRouteHandler creates the http.Handler for one route.
func (s *server) buildRouteHandler(routePath string, picker *upstreamPicker, rc *RouteConfig) (http.Handler, error) {
	// -- Static STATUS response route --
	if rc.StatusCode != 0 {
		var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(rc.StatusCode)
			if rc.StatusText != "" {
				fmt.Fprint(w, rc.StatusText)
			}
		})
		effectiveAuth := s.cfg.GlobalAuth
		if rc.AuthExplicit {
			effectiveAuth = rc.Auth
		}
		if effectiveAuth != nil {
			inner := h
			auth := effectiveAuth
			h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, pass, ok := r.BasicAuth()
				if !ok || user != auth.User || pass != auth.Password {
					w.Header().Set("WWW-Authenticate", `Basic realm="routemux"`)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				inner.ServeHTTP(w, r)
			})
		}
		return h, nil
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
	effectiveAuth := s.cfg.GlobalAuth
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
			// delete-header:Host → use upstream host (req.Host = "")
			// add-header:Host   → use user-supplied value (req.Host = val)
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

			// Parse client address once — reused for XFF and {remote_addr}/{remote_port} variables.
			clientIP, clientPort, _ := net.SplitHostPort(req.RemoteAddr)

			// X-Forwarded-* handling depends on trust-client-headers setting.
			//
			// false (default — secure, routemux is the entry point):
			//   X-Forwarded-For   → discard client chain, set to connecting IP only
			//   X-Forwarded-Host  → set to original client Host
			//   X-Forwarded-Proto → set from actual TLS state (never trust client)
			//
			// true (routemux sits behind a trusted upstream proxy):
			//   X-Forwarded-For   → append connecting IP to existing chain
			//   X-Forwarded-Host  → leave untouched (upstream proxy already set it)
			//   X-Forwarded-Proto → leave untouched (upstream proxy already set it)
			if clientIP != "" {
				if s.cfg.TrustClientHeaders {
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
			// set them unconditionally when not trusting client headers.
			if !s.cfg.TrustClientHeaders {
				req.Header.Set("X-Forwarded-Host", req.Host)
				req.Header.Set("X-Forwarded-Proto", schemeOf(req))
			}

			// If proxy auth is active, strip Authorization so the proxy credentials
			// never reach the upstream. The user-defined add/delete loop below runs
			// afterwards, so add-header:Authorization or delete-header:Authorization
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
					resolved := ph.eval(clientIP, clientPort, scheme, requestURI, originalHeaders)
					if strings.EqualFold(name, "host") {
						req.Host = resolved
						continue
					}
					req.Header.Set(name, resolved)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error [%s → %s]: %v", r.URL.Path, r.URL.Host, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// handleWS uses effectiveAuth which is declared above.
	handleWS := func(w http.ResponseWriter, r *http.Request) {
		upstream := picker.pick(lbMode)
		serveWebSocket(w, r, upstream.ParsedURL, routePath, rc, effectiveAuth, s.cfg.TrustClientHeaders)
	}

	var h http.Handler = proxy

	// Wrap with timeout if needed.
	if clientTimeout > 0 {
		inner := h
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.TimeoutHandler(inner, clientTimeout, "Gateway Timeout").ServeHTTP(w, r)
		})
	}

	// Wrap with basic auth if needed.
	if effectiveAuth != nil {
		inner := h
		auth := effectiveAuth
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok || user != auth.User || pass != auth.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="routemux"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			inner.ServeHTTP(w, r)
		})
	}

	// Wrap: intercept WebSocket upgrades before auth/timeout middleware.
	finalHandler := h
	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketUpgrade(r) {
			// Apply auth check for WebSocket too, then tunnel.
			if effectiveAuth != nil {
				user, pass, ok := r.BasicAuth()
				if !ok || user != effectiveAuth.User || pass != effectiveAuth.Password {
					w.Header().Set("WWW-Authenticate", `Basic realm="routemux"`)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
			handleWS(w, r)
			return
		}
		finalHandler.ServeHTTP(w, r)
	})

	return h, nil
}

func (s *server) run() error {
	addr := s.listenAddr()
	srv := &http.Server{
		Addr:    addr,
		Handler: s.mux,
	}

	if s.cfg.TLSCert != "" {
		log.Printf("TLS enabled (cert: %s)", s.cfg.TLSCert)
		return srv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	}
	return srv.ListenAndServe()
}

// schemeOf returns the actual scheme of the incoming connection.
// Used only for $scheme variable resolution in add-header values.
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
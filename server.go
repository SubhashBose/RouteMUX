package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
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
		destURL, err := url.Parse(rc.Dest)
		if err != nil {
			return fmt.Errorf("invalid dest for route %q: %w", path, err)
		}

		handler, err := s.buildRouteHandler(path, destURL, rc)
		if err != nil {
			return err
		}

		pattern := path
		// Go's ServeMux needs a trailing slash to match all sub-paths.
		if !strings.HasSuffix(pattern, "/") {
			pattern += "/"
		}
		s.mux.Handle(pattern, handler)
		log.Printf("  route %s  →  %s", pattern, rc.Dest)
	}
	return nil
}

// buildRouteHandler creates the http.Handler for one route.
func (s *server) buildRouteHandler(routePath string, destURL *url.URL, rc *RouteConfig) (http.Handler, error) {
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
			// Strip the route prefix from the path, then prepend the dest path.
			stripped := strings.TrimPrefix(req.URL.Path, routePath)
			// Join dest base path + stripped remainder
			destPath := destURL.Path
			if !strings.HasSuffix(destPath, "/") {
				destPath += "/"
			}
			// Save original client Host for X-Forwarded-Host and default passthrough.
			originalHost := req.Host
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
			// Forward the real remote address (IP only, no port).
			if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				if prior, ok := req.Header["X-Forwarded-For"]; ok {
					req.Header.Set("X-Forwarded-For", strings.Join(prior, ", ")+", "+clientIP)
				} else {
					req.Header.Set("X-Forwarded-For", clientIP)
				}
			}
			req.Header.Set("X-Forwarded-Host", originalHost)
			req.Header.Set("X-Forwarded-Proto", schemeOf(req))
			// If proxy auth is active, strip Authorization so the proxy credentials
			// never reach the upstream. The user-defined add/delete loop below runs
			// afterwards, so add-header:Authorization or delete-header:Authorization
			// in the config still work as normal — no special casing needed.
			if effectiveAuth != nil {
				req.Header.Del("Authorization")
			}

			// --- User-defined header manipulation ---
			// Snapshot original client headers before any modification when variables
			// are in use — $header.X must reflect what the client sent, not the
			// post-modification state.
			var originalHeaders http.Header
			if rc.AddHasVars {
				originalHeaders = req.Header.Clone()
				originalHeaders.Set("Host", req.Host)
			}

			// Delete first, then add/overwrite, so add always wins.
			// Host is special: Go ignores req.Header["Host"] — it reads req.Host.
			for _, name := range rc.DeleteHeaders {
				if strings.EqualFold(name, "host") {
					req.Host = "" // fall back to req.URL.Host (upstream address)
				}
			}
			applyDeleteHeaders(req.Header, rc.DeleteHeaders, rc.DeleteHasWildcard)

			if rc.AddHasVars {
				// Slow path — resolve variables in header values.
				clientIP, clientPort, _ := net.SplitHostPort(req.RemoteAddr)
				scheme := schemeOf(req)
				requestURI := req.RequestURI
				for name, val := range rc.AddHeaders {
					resolved := resolveHeaderValue(val, clientIP, clientPort, scheme, requestURI, originalHeaders)
					if strings.EqualFold(name, "host") {
						req.Host = resolved
						continue
					}
					req.Header.Set(name, resolved)
				}
			} else {
				// Fast path — plain values, no variable resolution.
				for name, val := range rc.AddHeaders {
					if strings.EqualFold(name, "host") {
						req.Host = val
						continue
					}
					req.Header.Set(name, val)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error [%s → %s]: %v", r.URL.Path, destURL, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// handleWS uses effectiveAuth which is declared above.
	handleWS := func(w http.ResponseWriter, r *http.Request) {
		serveWebSocket(w, r, destURL, routePath, rc, effectiveAuth)
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

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}
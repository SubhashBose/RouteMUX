package acme

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// challengePrefix is the well-known path prefix for HTTP-01 challenges.
const challengePrefix = "/.well-known/acme-challenge/"

// httpChallengeServer holds active HTTP-01 challenge responses and serves them.
// The same instance is consulted by both the main RouteMUX router (via Handler)
// and, when enabled, a temporary port-80 listener.
type httpChallengeServer struct {
	mu     sync.RWMutex
	tokens map[string]string // path → key authorization

	// Temporary port-80 listener state.
	servePort80 bool
	port80mu    sync.Mutex
	port80ln    net.Listener
	port80srv   *http.Server
	port80refs  int // active challenge windows requiring port 80
}

func newHTTPChallengeServer(servePort80 bool) *httpChallengeServer {
	return &httpChallengeServer{
		tokens:      make(map[string]string),
		servePort80: servePort80,
	}
}

// add registers a challenge response at the given path and, if configured,
// ensures the temporary port-80 listener is up for the challenge window.
func (h *httpChallengeServer) add(path, keyAuth string) {
	h.mu.Lock()
	h.tokens[path] = keyAuth
	h.mu.Unlock()
	h.openPort80()
}

// remove clears a challenge response and tears down the temporary port-80
// listener once no challenges remain.
func (h *httpChallengeServer) remove(path string) {
	h.mu.Lock()
	delete(h.tokens, path)
	h.mu.Unlock()
	h.closePort80()
}

// response returns the key authorization for a challenge path, or "".
func (h *httpChallengeServer) response(path string) string {
	h.mu.RLock()
	v := h.tokens[path]
	h.mu.RUnlock()
	return v
}

// Handler returns an http.Handler that serves ACME HTTP-01 challenge tokens and
// returns 404 for everything else. It is intended to be mounted by the main
// router at the challenge prefix so challenges work on whatever port RouteMUX
// already serves (e.g. behind a downstream proxy forwarding port 80).
func (h *httpChallengeServer) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if resp := h.response(r.URL.Path); resp != "" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	})
}

// IsChallengeRequest reports whether a request targets the ACME challenge path.
func IsChallengeRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, challengePrefix)
}

// openPort80 starts a temporary listener on :80 serving only challenge tokens,
// if servePort80 is enabled and nothing else already holds the port. Reference
// counted so concurrent challenge windows share one listener.
func (h *httpChallengeServer) openPort80() {
	if !h.servePort80 {
		return
	}
	h.port80mu.Lock()
	defer h.port80mu.Unlock()
	h.port80refs++
	if h.port80ln != nil {
		return // already open
	}
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		// Another process (e.g. a downstream proxy) holds port 80. That's fine:
		// challenges can still be forwarded to the main router's Handler.
		log.Printf("acme: cannot open temporary port 80 for HTTP-01 (%v); relying on existing listener/forwarding", err)
		h.port80refs-- // we didn't actually open it
		return
	}
	srv := &http.Server{
		Handler:           h.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	h.port80ln = ln
	h.port80srv = srv
	go srv.Serve(ln)
	log.Printf("acme: temporary port-80 listener started for HTTP-01 challenge")
}

// closePort80 decrements the reference count and shuts the temporary listener
// when the last challenge window completes.
func (h *httpChallengeServer) closePort80() {
	if !h.servePort80 {
		return
	}
	h.port80mu.Lock()
	defer h.port80mu.Unlock()
	if h.port80refs > 0 {
		h.port80refs--
	}
	if h.port80refs == 0 && h.port80srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = h.port80srv.Shutdown(ctx)
		cancel()
		h.port80srv = nil
		h.port80ln = nil
		log.Printf("acme: temporary port-80 listener stopped")
	}
}

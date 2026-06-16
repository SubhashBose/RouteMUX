package main

import (
	"net/http"
	"strings"
)

// isWebSocketUpgrade returns true if the request is a WebSocket (or other
// protocol) upgrade. RouteMUX uses this only to route upgrade requests around
// the per-route timeout wrapper: http.TimeoutHandler replaces the
// ResponseWriter with one that does not implement http.Hijacker, which would
// break the connection upgrade that Go's httputil.ReverseProxy performs for
// 101 Switching Protocols responses. The upgrade itself (request forwarding,
// header manipulation via Director/ModifyResponse, and bidirectional piping)
// is handled natively by ReverseProxy.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}
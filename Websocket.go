package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// isWebSocketUpgrade returns true if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// dialUpstream opens a raw TCP (or TLS) connection to the upstream host.
func dialUpstream(destURL *url.URL, noTLSVerify bool) (net.Conn, error) {
	host := destURL.Host
	// Ensure there is a port.
	if _, _, err := net.SplitHostPort(host); err != nil {
		switch destURL.Scheme {
		case "wss", "https":
			host = host + ":443"
		default:
			host = host + ":80"
		}
	}
	switch destURL.Scheme {
	case "wss", "https":
		return tlsDial("tcp", host, tlsConfigForDial(noTLSVerify))
	default:
		return net.Dial("tcp", host)
	}
}

// serveWebSocket tunnels a WebSocket upgrade request to the upstream.
func serveWebSocket(w http.ResponseWriter, r *http.Request, destURL *url.URL, routePath string, rc *RouteConfig, effectiveAuth *Auth, trustClientHeaders bool) {
	// --- 1. Hijack the client connection ---
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported by this server", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// --- 2. Dial upstream ---
	upstreamConn, err := dialUpstream(destURL, rc.NoTLSVerify)
	if err != nil {
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstreamConn.Close()

	// --- 3. Forward the upgrade request to upstream ---
	upstreamPath := destURL.Path
	if !strings.HasSuffix(upstreamPath, "/") {
		upstreamPath += "/"
	}
	stripped := strings.TrimPrefix(r.URL.Path, routePath)
	upstreamPath += stripped
	if r.URL.RawQuery != "" {
		upstreamPath += "?" + r.URL.RawQuery
	}

	// Determine the Host to send upstream.
	// Default: pass client Host through unchanged.
	// dest-del-header:Host → use upstream host instead.
	// dest-add-header:Host    → use user-supplied value.
	// Determine Host: default to client Host, dest-del-header:Host falls back to
	// upstream host. dest-add-header:Host is handled below in the same loop as all
	// other headers — outHost starts as the default and gets overwritten there.
	outHost := r.Host
	for _, name := range rc.DeleteHeaders {
		if strings.EqualFold(name, "host") {
			outHost = destURL.Host
		}
	}

	fmt.Fprintf(upstreamConn, "GET %s HTTP/1.1\r\n", upstreamPath)
	// Build remaining headers: copy client headers (skip Host — written above),
	// then apply delete and add rules. Host is included here too — if add-header
	// sets Host it overwrites outHost and we write the corrected value at the end.
	outHeaders := make(http.Header)
	for k, vals := range r.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		outHeaders[k] = vals
	}
	// Parse client address once — reused for XFF and $remote_addr/$remote_port variables.
	clientIP, clientPort, _ := net.SplitHostPort(r.RemoteAddr)

	// X-Forwarded-* handling mirrors the HTTP proxy path.
	if clientIP != "" {
		if trustClientHeaders {
			if prior, ok := outHeaders["X-Forwarded-For"]; ok {
				outHeaders.Set("X-Forwarded-For", strings.Join(prior, ", ")+", "+clientIP)
			} else {
				outHeaders.Set("X-Forwarded-For", clientIP)
			}
			// Leave X-Forwarded-Host and X-Forwarded-Proto untouched.
		} else {
			outHeaders.Set("X-Forwarded-For", clientIP)
		}
	}
	// X-Forwarded-Host and X-Forwarded-Proto don't depend on clientIP —
	// set them unconditionally when not trusting client headers.
	if !trustClientHeaders {
		outHeaders.Set("X-Forwarded-Host", r.Host)
		outHeaders.Set("X-Forwarded-Proto", schemeOf(r))
	}
	// If proxy auth is active, strip Authorization so proxy credentials never
	// reach upstream. The add/delete loop below runs after, so add-header or
	// dest-del-header for Authorization still work normally.
	if effectiveAuth != nil {
		outHeaders.Del("Authorization")
	}
	applyDeleteHeaders(outHeaders, rc.DeleteHeaders, rc.DeleteHasWildcard)
	if len(rc.ParsedAddHeaders) > 0 {
		// clientIP and clientPort already parsed above — reused here.
		// scheme and requestURI only computed when a variable header is present.
		var scheme, requestURI, requestHost string
		if rc.AddHasVars {
			scheme = "ws"
			if destURL.Scheme == "wss" || destURL.Scheme == "https" {
				scheme = "wss"
			}
			requestURI = r.RequestURI
			requestHost = r.Host
		}
		// Build snapshot with Host injected so ${header.Host} works.
		// Only needed when at least one header references ${header.X}.
		var originalWS http.Header
		if rc.NeedsOriginal {
			originalWS = r.Header.Clone()
			originalWS.Set("Host", r.Host)
		}
		for name, ph := range rc.ParsedAddHeaders {
			resolved := ph.eval(requestHost, clientIP, clientPort, scheme, requestURI, originalWS)
			if strings.EqualFold(name, "host") {
				outHost = resolved // overwrite the default/delete-derived host
				continue
			}
			outHeaders.Set(name, resolved)
		}
	}
	// Write the final Host (default, delete-derived, or add-header override).
	fmt.Fprintf(upstreamConn, "Host: %s\r\n", outHost)
	for k, vals := range outHeaders {
		for _, v := range vals {
			fmt.Fprintf(upstreamConn, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(upstreamConn, "\r\n")

	// Flush any bytes the client already sent after the HTTP headers.
	if n := clientBuf.Reader.Buffered(); n > 0 {
		data := make([]byte, n)
		clientBuf.Read(data)
		upstreamConn.Write(data)
	}

	// --- 4. Pipe both directions; wait for BOTH to finish ---
	done := make(chan struct{}, 2)

	// halfClose shuts down the write side of a conn if supported,
	// otherwise just closes the whole conn. This signals EOF to the
	// reader on the other end without killing the reverse direction.
	halfClose := func(c net.Conn) {
		type writeCloser interface {
			CloseWrite() error
		}
		if wc, ok := c.(writeCloser); ok {
			wc.CloseWrite()
		} else {
			c.Close()
		}
	}

	go func() {
		io.Copy(upstreamConn, clientConn)
		halfClose(upstreamConn) // tell upstream: client is done sending
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, upstreamConn)
		halfClose(clientConn) // tell client: upstream is done sending
		done <- struct{}{}
	}()

	// Wait for both directions to drain before returning
	// (defers will close both conns cleanly).
	<-done
	<-done
}
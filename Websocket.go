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
func serveWebSocket(w http.ResponseWriter, r *http.Request, destURL *url.URL, routePath string, noTLSVerify bool) {
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
	upstreamConn, err := dialUpstream(destURL, noTLSVerify)
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

	fmt.Fprintf(upstreamConn, "GET %s HTTP/1.1\r\n", upstreamPath)
	fmt.Fprintf(upstreamConn, "Host: %s\r\n", destURL.Host)
	for k, vals := range r.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
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
package main

import (
	"crypto/tls"
	"net"
)

// tlsConfigForDial returns a tls.Config for outbound WebSocket TLS dials.
func tlsConfigForDial(insecureSkipVerify bool) *tls.Config {
	return &tls.Config{InsecureSkipVerify: insecureSkipVerify} //nolint:gosec
}

// tlsDial wraps net.Dial with TLS.
func tlsDial(network, addr string, cfg *tls.Config) (net.Conn, error) {
	return tls.Dial(network, addr, cfg)
}
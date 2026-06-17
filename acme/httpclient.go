package acme

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// acmeHTTPClient builds the HTTP client used by the ACME protocol client. For
// production CAs it is the default client. For private/test ACME servers
// (e.g. Pebble) it can trust a custom CA bundle or skip verification entirely.
func acmeHTTPClient(caRootFile string, insecure bool) (*http.Client, error) {
	if caRootFile == "" && !insecure {
		return &http.Client{Timeout: 60 * time.Second}, nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if insecure {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // testing only, gated by config
	}
	if caRootFile != "" {
		pemData, err := os.ReadFile(caRootFile)
		if err != nil {
			return nil, fmt.Errorf("reading ACME CA root file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("no certificates found in ACME CA root file %s", caRootFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

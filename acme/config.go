// Package acme implements automatic TLS certificate issuance and renewal via
// the ACME protocol (RFC 8555), supporting Let's Encrypt and other ACME CAs.
//
// The package is self-contained: the main RouteMUX server interacts with it
// through a small surface — a Manager that supplies certificates for the TLS
// listener (via GetCertificate) and runs issuance/renewal in the background.
package acme

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Default locations and timings.
const (
	// defaultCacheDir is used when no cache-dir is configured and the process
	// runs as root. For non-root users, userCacheDir() is preferred.
	defaultCacheDirRoot = "/var/lib/routemux/acme"

	// Let's Encrypt production and staging directory endpoints.
	letsEncryptProd    = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// ZeroSSL ACME directory and its EAB-credentials endpoint.
	zeroSSLDirectory = "https://acme.zerossl.com/v2/DV90"

)

// ChallengeMode selects which ACME challenge type RouteMUX uses to prove
// domain control.
type ChallengeMode int

const (
	// ChallengeHTTP01 serves a token at /.well-known/acme-challenge/<token>.
	// The CA validates over HTTP on port 80.
	ChallengeHTTP01 ChallengeMode = iota
	// ChallengeTLSALPN01 answers a special TLS handshake on port 443 with a
	// challenge certificate. No port 80 listener is required.
	ChallengeTLSALPN01
)

// GlobalConfig holds account-level ACME settings shared across all vhosts.
// It corresponds to the `global.acme` block in the config file.
type GlobalConfig struct {
	// Email is the account contact address. Required when any vhost uses ACME;
	// some CAs (e.g. ZeroSSL) also require it to generate account credentials.
	Email string

	// CacheDir stores the per-CA ACME account material (account key + KID) and
	// any certificates whose vhost does not specify explicit cert/key paths.
	CacheDir string

	// ChallengeMode selects HTTP-01 (default) or TLS-ALPN-01.
	ChallengeMode ChallengeMode

	// ServePort80, when true, allows RouteMUX to open a temporary port-80
	// listener during an HTTP-01 challenge window if it is not already serving
	// on port 80. Ignored for TLS-ALPN-01.
	ServePort80 bool

	// DirectoryURL overrides the ACME directory endpoint (e.g. for staging or
	// a private CA). When empty, the per-vhost acme-source selects it.
	DirectoryURL string

	// CARootFile is an optional PEM file of CA certificates the ACME HTTP client
	// should trust when connecting to the directory endpoint. Used with private
	// or test ACME servers (e.g. Pebble) that present a self-signed endpoint.
	CARootFile string

	// InsecureSkipVerify disables TLS verification of the ACME directory
	// endpoint. FOR TESTING ONLY (e.g. Pebble). Never use against a real CA.
	InsecureSkipVerify bool
}

// VHostConfig holds per-vhost TLS settings, corresponding to a vhost's `tls`
// block. A vhost has either explicit static cert/key, or ACME issuance
// (AcmeSource set), or both paths used as the ACME storage location.
type VHostConfig struct {
	// Domains is the set of DNS names this vhost serves; a single SAN
	// certificate is issued covering all of them.
	Domains []string

	// CertPath and KeyPath are the PEM file locations. When AcmeSource is set
	// they are where the issued cert/key are written (storage); when AcmeSource
	// is empty they are an existing static cert/key to serve. When empty and
	// AcmeSource is set, defaults under CacheDir are used.
	CertPath string
	KeyPath  string

	// AcmeSource selects the CA ("letsencrypt", "letsencrypt-staging",
	// "zerossl"). Empty means no ACME — serve the static CertPath/KeyPath.
	AcmeSource string

	// RenewBefore overrides when renewal begins. Zero means the default: renew
	// once one third of the certificate's lifetime remains.
	RenewBefore time.Duration
}

// UsesACME reports whether this vhost should have a certificate auto-issued.
func (v *VHostConfig) UsesACME() bool {
	return v.AcmeSource != ""
}

// directoryURL maps an acme-source name (and optional global override) to an
// ACME directory endpoint.
func (v *VHostConfig) directoryURL(global *GlobalConfig) (string, error) {
	if global.DirectoryURL != "" {
		return global.DirectoryURL, nil
	}
	switch strings.ToLower(v.AcmeSource) {
	case "letsencrypt", "le":
		return letsEncryptProd, nil
	case "letsencrypt-staging", "le-staging", "staging":
		return letsEncryptStaging, nil
	case "zerossl":
		return zeroSSLDirectory, nil
	default:
		return "", fmt.Errorf("unknown acme-source %q (want letsencrypt, letsencrypt-staging, or zerossl)", v.AcmeSource)
	}
}

// shortestDomain returns the shortest domain name, used as the default base
// filename for a vhost's certificate when no explicit paths are configured.
func shortestDomain(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	best := domains[0]
	for _, d := range domains[1:] {
		if len(d) < len(best) {
			best = d
		}
	}
	return best
}

// resolveCertPaths returns the cert and key file paths for a vhost, applying
// the default (cacheDir/<shortest-domain>.crt|.key) when not explicitly set.
func (v *VHostConfig) resolveCertPaths(cacheDir string) (certPath, keyPath string) {
	certPath, keyPath = v.CertPath, v.KeyPath
	if certPath == "" {
		certPath = filepath.Join(cacheDir, shortestDomain(v.Domains)+".crt")
	}
	if keyPath == "" {
		keyPath = filepath.Join(cacheDir, shortestDomain(v.Domains)+".key")
	}
	return certPath, keyPath
}

// ResolveCacheDir returns the effective cache directory: the configured value,
// or a sensible default (/var/lib/routemux/acme for root, else a user dir).
func ResolveCacheDir(configured string) string {
	if configured != "" {
		return expandHome(configured)
	}
	if os.Geteuid() == 0 {
		return defaultCacheDirRoot
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "share", "routemux")
	}
	return defaultCacheDirRoot
}

// expandHome expands a leading ~ or $HOME in a path.
func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	if strings.HasPrefix(p, "$HOME") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + strings.TrimPrefix(p, "$HOME")
		}
	}
	return p
}

// ParseChallengeMode converts a config string to a ChallengeMode.
// "" and "http" → HTTP-01; "https" → TLS-ALPN-01.
func ParseChallengeMode(s string) (ChallengeMode, error) {
	switch strings.ToLower(s) {
	case "", "http":
		return ChallengeHTTP01, nil
	case "https":
		return ChallengeTLSALPN01, nil
	default:
		return ChallengeHTTP01, fmt.Errorf("invalid challenge-mode %q (want http or https)", s)
	}
}

// defaultRenewBefore computes the renewal lead time as one third of the
// certificate lifetime (notAfter - notBefore), matching the documented default.
func defaultRenewBefore(notBefore, notAfter time.Time) time.Duration {
	lifetime := notAfter.Sub(notBefore)
	return lifetime / 3
}

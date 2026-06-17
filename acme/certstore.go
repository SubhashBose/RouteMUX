package acme

import (
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
)

// certStore holds the live certificates indexed by domain name and answers TLS
// SNI handshakes. It is safe for concurrent use: the TLS listener reads via
// GetCertificate on many goroutines while issuance/renewal swaps certs in.
type certStore struct {
	mu sync.RWMutex
	// byDomain maps an exact lower-case DNS name to its certificate. A SAN cert
	// covering multiple names is referenced once per name.
	byDomain map[string]*tls.Certificate

	// challenge holds TLS-ALPN-01 challenge certs keyed by domain, consulted
	// only during a challenge handshake (acme-tls/1 ALPN).
	challenge map[string]*tls.Certificate

	// fallback is an optional certificate used when SNI does not match any
	// known domain (e.g. the global tls-cert). May be nil.
	fallback *tls.Certificate
}

func newCertStore() *certStore {
	return &certStore{
		byDomain:  make(map[string]*tls.Certificate),
		challenge: make(map[string]*tls.Certificate),
	}
}

// setCert installs cert for every domain it should serve.
func (s *certStore) setCert(domains []string, cert *tls.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range domains {
		s.byDomain[strings.ToLower(d)] = cert
	}
}

// setFallback installs the fallback certificate (used for unmatched SNI).
func (s *certStore) setFallback(cert *tls.Certificate) {
	s.mu.Lock()
	s.fallback = cert
	s.mu.Unlock()
}

// hasFallback reports whether a fallback certificate is installed.
func (s *certStore) hasFallback() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fallback != nil
}

// setChallengeCert installs a TLS-ALPN-01 challenge cert for a domain.
func (s *certStore) setChallengeCert(domain string, cert *tls.Certificate) {
	s.mu.Lock()
	s.challenge[strings.ToLower(domain)] = cert
	s.mu.Unlock()
}

// removeChallengeCert clears a domain's challenge cert after validation.
func (s *certStore) removeChallengeCert(domain string) {
	s.mu.Lock()
	delete(s.challenge, strings.ToLower(domain))
	s.mu.Unlock()
}

// hasCert reports whether a (non-challenge) certificate is installed for domain.
func (s *certStore) hasCert(domain string) bool {
	s.mu.RLock()
	_, ok := s.byDomain[strings.ToLower(domain)]
	s.mu.RUnlock()
	return ok
}

// GetCertificate is the tls.Config.GetCertificate callback. It returns the
// TLS-ALPN-01 challenge certificate during a challenge handshake, otherwise the
// real certificate for the requested SNI host, otherwise the fallback.
func (s *certStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))

	// TLS-ALPN-01: the CA offers the special acme-tls/1 protocol. Answer with
	// the challenge certificate for this name.
	for _, proto := range hello.SupportedProtos {
		if proto == acmeALPNProto {
			s.mu.RLock()
			cert := s.challenge[name]
			s.mu.RUnlock()
			if cert == nil {
				return nil, fmt.Errorf("acme: no TLS-ALPN-01 challenge cert for %q", name)
			}
			return cert, nil
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if cert, ok := s.byDomain[name]; ok {
		return cert, nil
	}
	// Try a wildcard match (*.example.com) for completeness.
	if i := strings.IndexByte(name, '.'); i > 0 {
		if cert, ok := s.byDomain["*"+name[i:]]; ok {
			return cert, nil
		}
	}
	if s.fallback != nil {
		return s.fallback, nil
	}
	return nil, fmt.Errorf("acme: no certificate for %q", name)
}
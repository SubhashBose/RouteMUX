package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"sync"

	xacme "golang.org/x/crypto/acme"
)

// acmeALPNProto is the ALPN protocol name used in TLS-ALPN-01 challenges.
const acmeALPNProto = xacme.ALPNProto

// Manager coordinates certificate provisioning for the TLS listener. It loads
// existing certificates from disk, supplies them to the listener via
// GetCertificate, and (in later phases) issues and renews them via ACME.
//
// The server creates one Manager from the parsed config and wires
// Manager.GetCertificate into its tls.Config. All ACME-specific state and
// behaviour lives here, keeping the core server code unaware of the protocol.
type Manager struct {
	global GlobalConfig
	vhosts []VHostConfig

	store         *certStore
	httpChallenge *httpChallengeServer
	issueState    *issueState

	mu      sync.Mutex // guards issuance scheduling
	ctx     context.Context
	cancel  context.CancelFunc
	stopped bool
}

// NewManager builds a Manager from the global ACME config and the per-vhost TLS
// configs. It does not perform any network calls; call Start to load existing
// certs and begin background issuance/renewal.
func NewManager(global GlobalConfig, vhosts []VHostConfig) (*Manager, error) {
	global.CacheDir = ResolveCacheDir(global.CacheDir)

	// Validate: any ACME vhost requires an account email.
	for _, v := range vhosts {
		if v.UsesACME() && global.Email == "" {
			return nil, fmt.Errorf("acme: vhost %v uses acme-source but global acme email is not set", v.Domains)
		}
		if v.UsesACME() {
			if _, err := v.directoryURL(&global); err != nil {
				return nil, fmt.Errorf("acme: vhost %v: %w", v.Domains, err)
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		global:        global,
		vhosts:        vhosts,
		store:         newCertStore(),
		issueState:    newIssueState().withPersistence(filepath.Join(global.CacheDir, "issue-state.json")),
		httpChallenge: newHTTPChallengeServer(global.ServePort80),
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

// HTTPChallengeHandler returns the handler that serves ACME HTTP-01 challenge
// tokens. The main router mounts this at /.well-known/acme-challenge/ so
// challenges work on whatever port RouteMUX serves. Returns nil when ACME is
// not using HTTP-01.
func (m *Manager) HTTPChallengeHandler() http.Handler {
	if m.global.ChallengeMode != ChallengeHTTP01 {
		return nil
	}
	return m.httpChallenge.Handler()
}

// SetFallback installs a fallback certificate (e.g. the global tls-cert) used
// when an SNI name matches no managed vhost.
func (m *Manager) SetFallback(cert *tls.Certificate) {
	m.store.setFallback(cert)
}

// GetCertificate is the tls.Config.GetCertificate callback for the listener.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.store.GetCertificate(hello)
}

// TLSConfig returns a *tls.Config wired to this Manager, including the ALPN
// protocol required for TLS-ALPN-01 challenges when that mode is selected.
// ManagedDomains returns the set of domains that have a certificate of their
// own configured (static or ACME) — i.e. that will NOT be served by the SNI
// fallback. Used by the server to warn about vhosts relying on the fallback.
func (m *Manager) ManagedDomains() map[string]bool {
	set := make(map[string]bool)
	for i := range m.vhosts {
		for _, d := range m.vhosts[i].Domains {
			set[strings.ToLower(d)] = true
		}
	}
	return set
}

// UsesACME reports whether any managed vhost uses automatic (ACME) issuance, as
// opposed to only static per-vhost certificates.
func (m *Manager) UsesACME() bool {
	for i := range m.vhosts {
		if m.vhosts[i].UsesACME() {
			return true
		}
	}
	return false
}

func (m *Manager) TLSConfig() *tls.Config {
	cfg := &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
	if m.global.ChallengeMode == ChallengeTLSALPN01 {
		cfg.NextProtos = append(cfg.NextProtos, acmeALPNProto)
	}
	return cfg
}

// Start loads existing certificates, issues any that are missing, and launches
// the background renewal loop. Returns an error only for unrecoverable setup
// problems; per-vhost issuance failures are logged and retried by the loop.
func (m *Manager) Start() error {
	if err := os.MkdirAll(m.global.CacheDir, 0o700); err != nil {
		return fmt.Errorf("acme: creating cache dir %s: %w", m.global.CacheDir, err)
	}

	// Install a self-signed bootstrap certificate as the fallback so the TLS
	// listener can complete handshakes before any real certificate exists.
	// This also lets the HTTP-01 challenge be served over HTTPS when a CA
	// follows an HTTP->HTTPS redirect. A real per-domain cert, once installed,
	// always takes precedence over this fallback in GetCertificate. If an
	// explicit global tls-cert was set as the fallback, we keep that instead.
	if !m.store.hasFallback() {
		if bootstrap, err := newBootstrapCert(); err == nil {
			m.store.setFallback(bootstrap)
		} else {
			log.Printf("acme: could not create bootstrap certificate: %v", err)
		}
	}

	var needIssue []*VHostConfig
	for i := range m.vhosts {
		v := &m.vhosts[i]
		certPath, keyPath := v.resolveCertPaths(m.global.CacheDir)
		cert, err := loadCertPair(certPath, keyPath)
		if err == nil {
			m.store.setCert(v.Domains, cert)
			kind := "static"
			if v.UsesACME() {
				kind = "ACME"
			}
			// The leaf is already in memory from the load — parse it once to
			// surface expiry and issuer in the startup log (works for both
			// static and ACME certs).
			if detail := certDetail(cert); detail != "" {
				log.Printf("tls: loaded %s certificate for %v from %s (%s)", kind, v.Domains, certPath, detail)
			} else {
				log.Printf("tls: loaded %s certificate for %v from %s", kind, v.Domains, certPath)
			}
			continue
		}
		if !v.UsesACME() {
			log.Printf("tls: failed to load static certificate for %v: %v", v.Domains, err)
			continue
		}
		needIssue = append(needIssue, v)
	}

	// Issue missing certificates in the background. Doing this asynchronously is
	// essential: the HTTP-01 challenge must be reachable on the listener, which
	// is only serving after Start() returns. Until issuance completes, the
	// bootstrap certificate keeps the listener functional.
	if len(needIssue) > 0 {
		go func() {
			for _, v := range needIssue {
				log.Printf("acme: obtaining certificate for %v", v.Domains)
				if err := m.issueAndStore(m.ctx, v); err != nil {
					log.Printf("acme: initial issuance for %v failed: %v (will retry)", v.Domains, err)
				}
			}
		}()
	}

	// Launch the background renewal loop if any vhost uses ACME.
	for i := range m.vhosts {
		if m.vhosts[i].UsesACME() {
			go m.renewLoop()
			break
		}
	}
	return nil
}

// Stop cancels background issuance/renewal. Safe to call multiple times.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.stopped {
		m.stopped = true
		m.cancel()
	}
}

// issueAndStore obtains a certificate for the vhost via ACME, writes the PEM
// files to the resolved paths, and installs the cert in the SNI store.
// issueAndStore is the rate-limit-safe entry point for issuance. It enforces a
// per-domain backoff window so repeated failures (bad config, CA rejection,
// rate limits) cannot hammer the CA and trigger a lockout. On success the
// backoff state is cleared; on failure the next-eligible time is advanced
// (honoring a CA Retry-After when present).
func (m *Manager) issueAndStore(ctx context.Context, v *VHostConfig) error {
	if ok, wait := m.issueState.shouldAttempt(v.Domains); !ok {
		return fmt.Errorf("issuance for %v skipped: backing off for %s after prior failure", v.Domains, wait.Round(time.Second))
	}
	m.issueState.recordAttempt(v.Domains)

	err := m.doIssue(ctx, v)
	if err == nil {
		m.issueState.recordSuccess(v.Domains)
		return nil
	}

	// Retry once after a brief pause in case the failure was a transient fluke
	// (network blip, momentary CA hiccup) — but only for non-permanent errors,
	// so we don't waste an attempt on a config/policy problem. This mirrors
	// Caddy's "retry once in case it was a fluke" before the long backoff.
	if !isPermanentError(err) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
		if err2 := m.doIssue(ctx, v); err2 == nil {
			m.issueState.recordSuccess(v.Domains)
			return nil
		} else {
			err = err2
		}
	}

	backoff := m.issueState.recordFailure(v.Domains, err)
	if isPermanentError(err) {
		log.Printf("acme: issuance for %v failed with a likely permanent error: %v (will not retry frequently; next attempt after %s)", v.Domains, err, backoff.Round(time.Second))
	}
	return fmt.Errorf("%w (next attempt after %s)", err, backoff.Round(time.Second))
}

// doIssue performs the actual ACME issuance and certificate installation.
func (m *Manager) doIssue(ctx context.Context, v *VHostConfig) error {
	// Pre-flight: if a domain does not resolve in DNS at all, the CA cannot
	// reach this server, so issuance is guaranteed to fail and would only burn
	// the CA's failed-authorization rate-limit budget. Skip with a clear log
	// rather than attempting. (This is a weak resolve-check, not a "points at
	// me" check, so proxied/CDN setups are not false-rejected.)
	if unresolved := preflightDomains(ctx, v.Domains); len(unresolved) > 0 {
		return fmt.Errorf("skipping issuance: domain(s) %v do not resolve in DNS yet — check DNS before the CA is asked to validate (avoids rate-limit waste)", unresolved)
	}

	directoryURL, err := v.directoryURL(&m.global)
	if err != nil {
		return err
	}

	// Per-CA External Account Binding (ZeroSSL needs it; Let's Encrypt does not).
	var eab *xacme.ExternalAccountBinding
	if isZeroSSL(v.AcmeSource) {
		eab, err = generateZeroSSLEAB(ctx, m.global.Email)
		if err != nil {
			return fmt.Errorf("zerossl EAB: %w", err)
		}
	}

	httpClient, err := acmeHTTPClient(m.global.CARootFile, m.global.InsecureSkipVerify)
	if err != nil {
		return err
	}
	accDir := m.accountDir(directoryURL)
	client, err := ensureAccount(ctx, accDir, directoryURL, m.global.Email, eab, httpClient)
	if err != nil {
		return err
	}

	is := &issuer{
		client:        client,
		challengeMode: m.global.ChallengeMode,
		httpChallenge: m.httpChallenge,
		store:         m.store,
	}

	certDER, key, err := is.obtainCertificate(ctx, v.Domains)
	if err != nil {
		// If the CA reports the saved account no longer exists (e.g. it was
		// deactivated, or a test CA like Pebble was restarted and forgot it),
		// discard the stale account and register a fresh one, then retry once.
		if isAccountNotExist(err) {
			log.Printf("acme: saved account rejected by CA (%v); re-registering", err)
			if derr := discardAccount(accDir); derr != nil {
				return fmt.Errorf("discarding stale account: %w", derr)
			}
			client, err = ensureAccount(ctx, accDir, directoryURL, m.global.Email, eab, httpClient)
			if err != nil {
				return err
			}
			is.client = client
			certDER, key, err = is.obtainCertificate(ctx, v.Domains)
		}
		if err != nil {
			return err
		}
	}

	// Persist PEM files atomically at the configured/default paths.
	certPath, keyPath := v.resolveCertPaths(m.global.CacheDir)
	keyPEM, err := encodeKeyPEM(key)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(certPath, encodeCertPEM(certDER), 0o644); err != nil {
		return fmt.Errorf("writing cert: %w", err)
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}

	// Install in the SNI store.
	tlsCert, err := loadCertPair(certPath, keyPath)
	if err != nil {
		return err
	}
	m.store.setCert(v.Domains, tlsCert)

	if na, err := certNotAfter(certDER); err == nil {
		logIssued(v.Domains, na)
	}
	return nil
}

// isZeroSSL reports whether the acme-source names ZeroSSL.
func isZeroSSL(source string) bool {
	return source == "zerossl"
}

// isAccountNotExist reports whether err indicates the CA does not recognise the
// account (RFC 8555 "accountDoesNotExist"). This happens if the account was
// deactivated or, for ephemeral test CAs like Pebble, if the server restarted
// and forgot the account.
func isAccountNotExist(err error) bool {
	if err == nil {
		return false
	}
	var ae *xacme.Error
	if errors.As(err, &ae) {
		return strings.Contains(strings.ToLower(ae.ProblemType), "accountdoesnotexist")
	}
	// Fall back to substring match for wrapped/string errors.
	return strings.Contains(strings.ToLower(err.Error()), "accountdoesnotexist")
}

// discardAccount removes the persisted account material so a fresh account is
// registered on the next ensureAccount call.
func discardAccount(dir string) error {
	for _, name := range []string{"account.key", "account.json"} {
		p := filepath.Join(dir, name)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// loadCertPair loads a PEM certificate and key from the given paths.
func loadCertPair(certPath, keyPath string) (*tls.Certificate, error) {
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("cert/key path not set")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// certDetail parses the leaf certificate (already in memory from loading) and
// returns a short human-readable summary of its issuer and expiry for logging.
// Returns "" if the leaf cannot be parsed.
func certDetail(cert *tls.Certificate) string {
	if cert == nil || len(cert.Certificate) == 0 {
		return ""
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return ""
	}
	// Prefer the issuer Organization (e.g. "Let's Encrypt", "ZeroSSL") — it is
	// human-recognizable and stable, whereas the CN is the specific intermediate
	// (e.g. "R10", "R11") which is cryptic and rotates between renewals. Fall
	// back to CN if no Organization is set (some private/test CAs only set CN).
	issuer := ""
	if len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}
	if issuer == "" {
		issuer = leaf.Issuer.CommonName
	}
	expiry := leaf.NotAfter.UTC().Format("2006-01-02")
	if time.Now().After(leaf.NotAfter) {
		return fmt.Sprintf("issuer %q, EXPIRED %s", issuer, expiry)
	}
	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
	return fmt.Sprintf("issuer %q, expires %s, %dd left", issuer, expiry, daysLeft)
}

// cacheDir returns the resolved cache directory (for account storage etc.).
func (m *Manager) cacheDir() string {
	return m.global.CacheDir
}

// accountDir returns the per-CA account storage directory for a directory URL.
func (m *Manager) accountDir(directoryURL string) string {
	return filepath.Join(m.cacheDir(), "accounts", sanitizeForPath(directoryURL))
}

// sanitizeForPath turns a directory URL into a filesystem-safe folder name.
func sanitizeForPath(s string) string {
	repl := func(r rune) rune {
		switch r {
		case '/', ':', '?', '&', '=', '\\':
			return '_'
		}
		return r
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		out = append(out, repl(r))
	}
	return string(out)
}

// errNoPEM is returned when a certificate file contains no PEM block.
var errNoPEM = fmt.Errorf("no PEM data in certificate")
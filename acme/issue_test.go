package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// TestIssuer_HTTPChallengePrepCleanup verifies HTTP-01 challenge prep installs
// the token response and cleanup removes it.
func TestIssuer_HTTPChallengePrepCleanup(t *testing.T) {
	accKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hc := newHTTPChallengeServer(false)
	is := &issuer{
		client:        &xacme.Client{Key: accKey},
		challengeMode: ChallengeHTTP01,
		httpChallenge: hc,
		store:         newCertStore(),
	}
	chal := &xacme.Challenge{Type: "http-01", Token: "tok-abc"}
	cleanup, err := is.prepareChallenge("example.test", chal)
	if err != nil {
		t.Fatal(err)
	}
	path := is.client.HTTP01ChallengePath("tok-abc")
	if hc.response(path) == "" {
		t.Error("challenge response not installed")
	}
	cleanup()
	if hc.response(path) != "" {
		t.Error("challenge response not cleaned up")
	}
}

// TestIssuer_TLSALPNChallengePrepCleanup verifies TLS-ALPN-01 challenge prep
// installs a challenge cert and cleanup removes it.
func TestIssuer_TLSALPNChallengePrepCleanup(t *testing.T) {
	accKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	store := newCertStore()
	is := &issuer{
		client:        &xacme.Client{Key: accKey},
		challengeMode: ChallengeTLSALPN01,
		httpChallenge: newHTTPChallengeServer(false),
		store:         store,
	}
	chal := &xacme.Challenge{Type: "tls-alpn-01", Token: "tok-xyz"}
	cleanup, err := is.prepareChallenge("example.test", chal)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.RLock()
	_, ok := store.challenge["example.test"]
	store.mu.RUnlock()
	if !ok {
		t.Error("TLS-ALPN challenge cert not installed")
	}
	cleanup()
	store.mu.RLock()
	_, ok = store.challenge["example.test"]
	store.mu.RUnlock()
	if ok {
		t.Error("TLS-ALPN challenge cert not cleaned up")
	}
}

// TestFindChallenge checks challenge-type selection.
func TestFindChallenge(t *testing.T) {
	chals := []*xacme.Challenge{
		{Type: "dns-01"}, {Type: "http-01"}, {Type: "tls-alpn-01"},
	}
	if findChallenge(chals, "http-01") == nil {
		t.Error("http-01 not found")
	}
	if findChallenge(chals, "tls-alpn-01") == nil {
		t.Error("tls-alpn-01 not found")
	}
	if findChallenge(chals, "nonexistent") != nil {
		t.Error("nonexistent should be nil")
	}
}

// TestPEMEncoding checks cert/key PEM round-trips.
func TestPEMEncoding(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"x.test"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	certPEM := encodeCertPEM([][]byte{der})
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("cert PEM did not round-trip")
	}
	keyPEM, err := encodeKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "EC PRIVATE KEY" {
		t.Fatal("key PEM did not round-trip")
	}

	na, err := certNotAfter([][]byte{der})
	if err != nil || na.IsZero() {
		t.Errorf("certNotAfter failed: %v", err)
	}
}

// TestRenewalDue checks the renewal-window logic.
func TestRenewalDue(t *testing.T) {
	dir := t.TempDir()
	fresh := writeCertWithLifetime(t, dir, "fresh.crt", time.Now().Add(-time.Hour), time.Now().Add(89*24*time.Hour))
	if due, err := renewalDue(fresh, 0); err != nil || due {
		t.Errorf("fresh cert should not be due: due=%v err=%v", due, err)
	}
	old := writeCertWithLifetime(t, dir, "old.crt", time.Now().Add(-85*24*time.Hour), time.Now().Add(5*24*time.Hour))
	if due, err := renewalDue(old, 0); err != nil || !due {
		t.Errorf("near-expiry cert should be due: due=%v err=%v", due, err)
	}
	if due, _ := renewalDue(old, 10*24*time.Hour); !due {
		t.Error("cert within explicit renew-before should be due")
	}
}

// TestRenewalDue_ClampsLongRenewBefore verifies an acme-renewal longer than the
// certificate lifetime does not make a fresh certificate due immediately.
func TestRenewalDue_ClampsLongRenewBefore(t *testing.T) {
	dir := t.TempDir()
	fresh := writeCertWithLifetime(t, dir, "fresh.crt", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	if due, err := renewalDue(fresh, 100*24*time.Hour); err != nil || due {
		t.Errorf("fresh cert with acme-renewal > lifetime must not be due: due=%v err=%v", due, err)
	}
	aged := writeCertWithLifetime(t, dir, "aged.crt", time.Now().Add(-31*24*time.Hour), time.Now().Add(59*24*time.Hour))
	if due, _ := renewalDue(aged, 100*24*time.Hour); !due {
		t.Error("cert past a third of its lifetime should be due under a clamped acme-renewal")
	}
}

// TestNextCheckDelay verifies the renewal loop wakes for a pending retry
// instead of waiting for the next regular check.
func TestNextCheckDelay(t *testing.T) {
	domains := []string{"a.example"}
	mgr, err := NewManager(
		GlobalConfig{Email: "a@b.com", CacheDir: t.TempDir()},
		[]VHostConfig{
			{Domains: domains, AcmeSource: "letsencrypt"},
			{Domains: []string{"s.example"}, CertPath: "/c", KeyPath: "/k"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if d := mgr.nextCheckDelay(); d != renewCheckInterval {
		t.Errorf("no failures: delay = %s, want %s", d, renewCheckInterval)
	}

	backoff := mgr.issueState.recordFailure(domains, errors.New("challenge validation failed"))
	if d := mgr.nextCheckDelay(); d > backoff || d < backoff-time.Minute {
		t.Errorf("after failure: delay = %s, want ~%s", d, backoff)
	}

	// An elapsed backoff window must not shorten the delay (no spinning).
	mgr.issueState.entries[issueKey(domains)].NextEligible = time.Now().Add(-time.Minute)
	if d := mgr.nextCheckDelay(); d != renewCheckInterval {
		t.Errorf("elapsed backoff: delay = %s, want %s", d, renewCheckInterval)
	}

	mgr.issueState.recordSuccess(domains)
	if d := mgr.nextCheckDelay(); d != renewCheckInterval {
		t.Errorf("after success: delay = %s, want %s", d, renewCheckInterval)
	}
}

func writeCertWithLifetime(t *testing.T, dir, name string, notBefore, notAfter time.Time) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"x.test"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	path := dir + "/" + name
	f, _ := os.Create(path)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.Close()
	return path
}

// fakeRateLimitedCA is a minimal ACME server that answers every account or
// order request with a 429 rateLimited problem. It counts requests so tests can
// assert RouteMUX stops calling a rate-limited CA.
func fakeRateLimitedCA(t *testing.T, retryAfter string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", calls.Load()))
		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`,
				srv.URL+"/nonce", srv.URL+"/account", srv.URL+"/order")
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		default:
			w.Header().Set("Content-Type", "application/problem+json")
			w.Header().Set("Retry-After", retryAfter)
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many requests"}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// TestIssueAndStore_RateLimitedCA verifies a rate-limited CA gets a bounded
// number of requests per attempt, that its Retry-After becomes the backoff, and
// that no further requests are made while backing off. The acme package's
// default retry policy would retry the 429 indefinitely and hang this test.
func TestIssueAndStore_RateLimitedCA(t *testing.T) {
	srv, calls := fakeRateLimitedCA(t, "3600")
	domains := []string{"localhost"} // must resolve for the DNS preflight
	mgr, err := NewManager(
		GlobalConfig{Email: "a@b.com", CacheDir: t.TempDir(), DirectoryURL: srv.URL + "/directory"},
		[]VHostConfig{{Domains: domains, AcmeSource: "letsencrypt"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mgr.issueAndStore(ctx, &mgr.vhosts[0]); err == nil {
		t.Fatal("expected issuance to fail against a rate-limited CA")
	}
	if n := calls.Load(); n > 5 {
		t.Errorf("rate-limited CA received %d requests in one attempt, want at most 5", n)
	}
	ok, wait := mgr.issueState.shouldAttempt(domains)
	if ok || wait < 59*time.Minute {
		t.Errorf("backoff after 429 = %s (attempt allowed: %v), want the CA's Retry-After of 1h", wait, ok)
	}

	before := calls.Load()
	if err := mgr.issueAndStore(ctx, &mgr.vhosts[0]); err == nil {
		t.Fatal("expected issuance to be skipped while backing off")
	}
	if n := calls.Load() - before; n != 0 {
		t.Errorf("CA received %d requests while backing off, want 0", n)
	}
}

// TestIssueState_AttemptAndRestart verifies an attempt is persisted before the
// CA is contacted, and that the failure count survives a restart after the
// backoff window has elapsed (so the backoff keeps growing).
func TestIssueState_AttemptAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issue-state.json")
	domains := []string{"a.example"}

	s := newIssueState().withPersistence(path)
	s.recordAttempt(domains)
	if ok, _ := newIssueState().withPersistence(path).shouldAttempt(domains); ok {
		t.Error("a restart right after an attempt started must not allow another attempt")
	}

	s.recordFailure(domains, errors.New("validation failed"))
	s.recordFailure(domains, errors.New("validation failed"))
	s.entries[issueKey(domains)].NextEligible = time.Now().Add(-time.Minute) // window elapsed
	s.mu.Lock()
	s.saveLocked()
	s.mu.Unlock()

	restarted := newIssueState().withPersistence(path)
	if ok, _ := restarted.shouldAttempt(domains); !ok {
		t.Error("an elapsed backoff window must allow an attempt after restart")
	}
	if got := restarted.recordFailure(domains, errors.New("validation failed")); got != 4*minIssueBackoff {
		t.Errorf("third failure after restart: backoff = %s, want %s (count must survive restart)", got, 4*minIssueBackoff)
	}
}

func TestRateLimitRetryAfter_Wrapped(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "120")
	err := fmt.Errorf("creating order: %w", &xacme.Error{
		StatusCode:  http.StatusTooManyRequests,
		ProblemType: "urn:ietf:params:acme:error:rateLimited",
		Header:      h,
	})
	if d, ok := rateLimitRetryAfter(err); !ok || d != 2*time.Minute {
		t.Errorf("got (%s, %v), want (2m0s, true)", d, ok)
	}
	backoff := newIssueState().recordFailure([]string{"a.example"}, err)
	if backoff != 2*time.Minute {
		t.Errorf("recordFailure backoff = %s, want the Retry-After of 2m0s", backoff)
	}
}

func TestIsTransientError(t *testing.T) {
	netErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"network error", fmt.Errorf("creating order: %w", netErr), true},
		{"ACME problem", fmt.Errorf("creating order: %w", &xacme.Error{StatusCode: 500, ProblemType: "urn:ietf:params:acme:error:serverInternal"}), false},
		{"failed validation", fmt.Errorf("challenge validation: %w", &xacme.AuthorizationError{Identifier: "a.example"}), false},
		{"invalid order", &xacme.OrderError{Status: xacme.StatusInvalid}, false},
		{"attempt timed out", fmt.Errorf("waiting: %w", context.DeadlineExceeded), false},
		{"plain error", errors.New("order became invalid during finalization"), false},
	}
	for _, c := range cases {
		if got := isTransientError(c.err); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsNoVerdictError(t *testing.T) {
	netErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"network error", fmt.Errorf("creating order: %w", netErr), true},
		{"CA 503", fmt.Errorf("creating order: %w", &xacme.Error{StatusCode: http.StatusServiceUnavailable}), true},
		{"DNS pre-check", fmt.Errorf("%w: domain(s) [a.example] do not resolve", errPrecheck), true},
		{"directory pre-check", fmt.Errorf("%w: certificate directory is not writable (%w)", errPrecheck, os.ErrPermission), true},
		{"failed validation", fmt.Errorf("challenge validation: %w", &xacme.AuthorizationError{Identifier: "a.example"}), false},
		{"rate limited", &xacme.Error{StatusCode: http.StatusTooManyRequests, ProblemType: "urn:ietf:params:acme:error:rateLimited"}, false},
		{"ACME 4xx problem", &xacme.Error{StatusCode: http.StatusForbidden, ProblemType: "urn:ietf:params:acme:error:unauthorized"}, false},
		{"invalid order", &xacme.OrderError{Status: xacme.StatusInvalid}, false},
		{"attempt timed out", fmt.Errorf("waiting: %w", context.DeadlineExceeded), false},
		{"unrecognised error", errors.New("order became invalid during finalization"), false},
	}
	for _, c := range cases {
		if got := isNoVerdictError(c.err); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestRecordFailure_NoVerdict verifies a failure without a CA verdict is not
// counted, retries 5 minutes later, writes nothing beyond the attempt marker,
// and that a long Retry-After on a 5xx is honored and persisted.
func TestRecordFailure_NoVerdict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issue-state.json")
	domains := []string{"a.example"}
	netErr := fmt.Errorf("creating order: %w", &net.OpError{Op: "dial", Err: errors.New("connection refused")})
	verdict := fmt.Errorf("challenge validation: %w", &xacme.AuthorizationError{Identifier: "a.example"})

	s := newIssueState().withPersistence(path)
	s.recordFailure(domains, verdict) // an earlier CA verdict: Failures=1
	s.entries[issueKey(domains)].NextEligible = time.Now().Add(-time.Minute)
	s.recordAttempt(domains)
	onDisk, _ := os.ReadFile(path)

	if got := s.recordFailure(domains, netErr); got != minIssueBackoff {
		t.Errorf("network failure: wait = %s, want %s", got, minIssueBackoff)
	}
	if f := s.entries[issueKey(domains)].Failures; f != 1 {
		t.Errorf("network failure changed the verdict count: Failures = %d, want 1", f)
	}
	if after, _ := os.ReadFile(path); string(after) != string(onDisk) {
		t.Errorf("network failure rewrote the state file:\nbefore %s\nafter  %s", onDisk, after)
	}
	// A restart waits at most 5 minutes (the attempt marker), not a backoff.
	if ok, wait := newIssueState().withPersistence(path).shouldAttempt(domains); ok || wait > minIssueBackoff {
		t.Errorf("restart after network failure: attempt allowed=%v wait=%s, want a wait of at most %s", ok, wait, minIssueBackoff)
	}
	// The next CA verdict continues from the earlier count (2nd failure: 10m).
	if got := s.recordFailure(domains, verdict); got != 2*minIssueBackoff {
		t.Errorf("verdict after network failure: backoff = %s, want %s", got, 2*minIssueBackoff)
	}

	// CA maintenance: 503 with a long Retry-After is honored and persisted.
	h := http.Header{}
	h.Set("Retry-After", "3600")
	maint := fmt.Errorf("creating order: %w", &xacme.Error{StatusCode: http.StatusServiceUnavailable, Header: h})
	other := []string{"b.example"}
	if got := s.recordFailure(other, maint); got != time.Hour {
		t.Errorf("503 with Retry-After 3600: wait = %s, want 1h0m0s", got)
	}
	if ok, wait := newIssueState().withPersistence(path).shouldAttempt(other); ok || wait < 59*time.Minute {
		t.Errorf("restart after 503 Retry-After: attempt allowed=%v wait=%s, want ~1h", ok, wait)
	}
	if f := s.entries[issueKey(other)].Failures; f != 0 {
		t.Errorf("503 counted as a verdict: Failures = %d, want 0", f)
	}
}

// TestIssueAndStore_UnreachableCA verifies an attempt against an unreachable CA
// is not counted as a failure and is retried 5 minutes later.
func TestIssueAndStore_UnreachableCA(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	unreachable := srv.URL + "/directory"
	srv.Close() // connections are now refused

	domains := []string{"localhost"} // must resolve for the DNS pre-check
	mgr, err := NewManager(
		GlobalConfig{Email: "a@b.com", CacheDir: t.TempDir(), DirectoryURL: unreachable},
		[]VHostConfig{{Domains: domains, AcmeSource: "letsencrypt"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.issueAndStore(context.Background(), &mgr.vhosts[0]); err == nil {
		t.Fatal("expected issuance to fail against an unreachable CA")
	}
	e := mgr.issueState.entries[issueKey(domains)]
	if e.Failures != 0 {
		t.Errorf("unreachable CA counted as a CA verdict: Failures = %d, want 0", e.Failures)
	}
	if d := mgr.nextCheckDelay(); d > minIssueBackoff || d < minIssueBackoff-time.Minute {
		t.Errorf("next check in %s, want ~%s", d, minIssueBackoff)
	}
}

// TestRecordFailure_NoVerdictAfterLongAttempt verifies a network failure at the
// end of an attempt that outlasted the 5-minute marker (e.g. timeouts) still
// schedules a retry 5 minutes later, instead of leaving an elapsed time that
// the renewal loop would skip until its next regular check.
func TestRecordFailure_NoVerdictAfterLongAttempt(t *testing.T) {
	domains := []string{"a.example"}
	mgr, err := NewManager(
		GlobalConfig{Email: "a@b.com", CacheDir: t.TempDir()},
		[]VHostConfig{{Domains: domains, AcmeSource: "letsencrypt"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	mgr.issueState.recordAttempt(domains)
	mgr.issueState.entries[issueKey(domains)].NextEligible = time.Now().Add(-time.Minute) // attempt ran 6 minutes
	mgr.issueState.recordFailure(domains, fmt.Errorf("fetching: %w", &net.OpError{Op: "read", Err: errors.New("i/o timeout")}))
	if d := mgr.nextCheckDelay(); d > minIssueBackoff || d < minIssueBackoff-time.Minute {
		t.Errorf("next check in %s, want ~%s", d, minIssueBackoff)
	}
}

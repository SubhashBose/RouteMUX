package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
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

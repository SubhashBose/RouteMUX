package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"fmt"
	"testing"

	xacme "golang.org/x/crypto/acme"
	"time"
)

func TestShortestDomain(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"www.example.com", "example.com"}, "example.com"},
		{[]string{"a.io", "bb.io", "c.io"}, "a.io"},
		{[]string{"only.example.org"}, "only.example.org"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := shortestDomain(c.in); got != c.want {
			t.Errorf("shortestDomain(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResolveCertPaths_Default(t *testing.T) {
	v := &VHostConfig{Domains: []string{"www.example.com", "example.com"}}
	cert, key := v.resolveCertPaths("/cache")
	if cert != filepath.Join("/cache", "example.com.crt") {
		t.Errorf("cert path = %q", cert)
	}
	if key != filepath.Join("/cache", "example.com.key") {
		t.Errorf("key path = %q", key)
	}
}

func TestResolveCertPaths_Explicit(t *testing.T) {
	v := &VHostConfig{
		Domains:  []string{"example.com"},
		CertPath: "/etc/ssl/my.crt",
		KeyPath:  "/etc/ssl/my.key",
	}
	cert, key := v.resolveCertPaths("/cache")
	if cert != "/etc/ssl/my.crt" || key != "/etc/ssl/my.key" {
		t.Errorf("explicit paths not honoured: cert=%q key=%q", cert, key)
	}
}

func TestDirectoryURL(t *testing.T) {
	g := &GlobalConfig{}
	cases := map[string]string{
		"letsencrypt":         letsEncryptProd,
		"letsencrypt-staging": letsEncryptStaging,
		"zerossl":             zeroSSLDirectory,
	}
	for src, want := range cases {
		v := &VHostConfig{AcmeSource: src}
		got, err := v.directoryURL(g)
		if err != nil || got != want {
			t.Errorf("directoryURL(%q) = %q, %v; want %q", src, got, err, want)
		}
	}
	// Unknown source errors.
	v := &VHostConfig{AcmeSource: "bogus"}
	if _, err := v.directoryURL(g); err == nil {
		t.Error("expected error for unknown acme-source")
	}
	// Global override wins.
	g2 := &GlobalConfig{DirectoryURL: "https://custom/dir"}
	v2 := &VHostConfig{AcmeSource: "letsencrypt"}
	if got, _ := v2.directoryURL(g2); got != "https://custom/dir" {
		t.Errorf("override not honoured: %q", got)
	}
}

func TestParseChallengeMode(t *testing.T) {
	cases := map[string]ChallengeMode{
		"":      ChallengeHTTP01,
		"http":  ChallengeHTTP01,
		"HTTP":  ChallengeHTTP01,
		"https": ChallengeTLSALPN01,
	}
	for in, want := range cases {
		got, err := ParseChallengeMode(in)
		if err != nil || got != want {
			t.Errorf("ParseChallengeMode(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseChallengeMode("ftp"); err == nil {
		t.Error("expected error for invalid challenge-mode")
	}
}

func TestDefaultRenewBefore(t *testing.T) {
	nb := time.Now()
	na := nb.Add(90 * 24 * time.Hour) // 90-day cert
	got := defaultRenewBefore(nb, na)
	want := 30 * 24 * time.Hour // one third
	if got != want {
		t.Errorf("defaultRenewBefore = %v, want %v", got, want)
	}
}

// makeTestCert creates a self-signed cert for the given domains and writes the
// PEM files, returning their paths.
func makeTestCert(t *testing.T, dir string, domains ...string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     domains,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, domains[0]+".crt")
	keyPath = filepath.Join(dir, domains[0]+".key")
	certOut, _ := os.Create(certPath)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyOut, _ := os.Create(keyPath)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyOut.Close()
	return certPath, keyPath
}

func TestCertStore_SNISelection(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := makeTestCert(t, dir, "example.com", "www.example.com")
	cert, err := loadCertPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	store := newCertStore()
	store.setCert([]string{"example.com", "www.example.com"}, cert)

	// Both SAN names resolve.
	for _, name := range []string{"example.com", "www.example.com", "EXAMPLE.COM"} {
		got, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
		if err != nil || got != cert {
			t.Errorf("SNI %q: got %v, err %v", name, got, err)
		}
	}

	// Unknown name with no fallback errors.
	if _, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.com"}); err == nil {
		t.Error("expected error for unknown SNI without fallback")
	}

	// With fallback, unknown name resolves to fallback.
	store.setFallback(cert)
	if got, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.com"}); err != nil || got != cert {
		t.Errorf("fallback not used: got %v, err %v", got, err)
	}
}

func TestCertStore_TLSALPNChallenge(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := makeTestCert(t, dir, "example.com")
	realCert, _ := loadCertPair(certPath, keyPath)
	chalPath, chalKey := makeTestCert(t, dir, "challenge.example.com")
	chalCert, _ := loadCertPair(chalPath, chalKey)

	store := newCertStore()
	store.setCert([]string{"example.com"}, realCert)
	store.setChallengeCert("example.com", chalCert)

	// Normal handshake → real cert.
	got, _ := store.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if got != realCert {
		t.Error("normal handshake should return real cert")
	}

	// ACME-ALPN handshake → challenge cert.
	got, err := store.GetCertificate(&tls.ClientHelloInfo{
		ServerName:     "example.com",
		SupportedProtos: []string{acmeALPNProto},
	})
	if err != nil || got != chalCert {
		t.Errorf("ALPN handshake should return challenge cert: got %v, err %v", got, err)
	}

	// After removal, ALPN handshake errors.
	store.removeChallengeCert("example.com")
	if _, err := store.GetCertificate(&tls.ClientHelloInfo{
		ServerName:     "example.com",
		SupportedProtos: []string{acmeALPNProto},
	}); err == nil {
		t.Error("expected error after challenge cert removed")
	}
}

func TestManager_StartLoadsExisting(t *testing.T) {
	dir := t.TempDir()
	makeTestCert(t, dir, "example.com")

	mgr, err := NewManager(
		GlobalConfig{CacheDir: dir},
		[]VHostConfig{{
			Domains:  []string{"example.com"},
			CertPath: filepath.Join(dir, "example.com.crt"),
			KeyPath:  filepath.Join(dir, "example.com.key"),
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatal(err)
	}
	if !mgr.store.hasCert("example.com") {
		t.Error("Start should have loaded the existing certificate")
	}
}

func TestManager_RequiresEmailForACME(t *testing.T) {
	_, err := NewManager(
		GlobalConfig{}, // no email
		[]VHostConfig{{Domains: []string{"example.com"}, AcmeSource: "letsencrypt"}},
	)
	if err == nil {
		t.Error("expected error: ACME vhost without global email")
	}
}

func TestManager_TLSConfig_ALPN(t *testing.T) {
	mgr, _ := NewManager(GlobalConfig{ChallengeMode: ChallengeTLSALPN01}, nil)
	cfg := mgr.TLSConfig()
	found := false
	for _, p := range cfg.NextProtos {
		if p == acmeALPNProto {
			found = true
		}
	}
	if !found {
		t.Error("TLS-ALPN-01 mode must advertise acme-tls/1 in NextProtos")
	}
}

func TestIsAccountNotExist(t *testing.T) {
	// Wrapped acme.Error with the problem type.
	ae := &xacme.Error{ProblemType: "urn:ietf:params:acme:error:accountDoesNotExist", Detail: "nope"}
	wrapped := fmt.Errorf("creating order: %w", ae)
	if !isAccountNotExist(wrapped) {
		t.Error("should detect accountDoesNotExist in wrapped acme.Error")
	}
	// Unrelated error.
	if isAccountNotExist(fmt.Errorf("connection refused")) {
		t.Error("should not flag unrelated error")
	}
	if isAccountNotExist(nil) {
		t.Error("nil should be false")
	}
}

func TestDiscardAccount(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/account.key", []byte("k"), 0o600)
	os.WriteFile(dir+"/account.json", []byte("{}"), 0o600)
	if err := discardAccount(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir + "/account.key"); !os.IsNotExist(err) {
		t.Error("account.key should be removed")
	}
	// Idempotent: discarding again is fine.
	if err := discardAccount(dir); err != nil {
		t.Errorf("second discard should not error: %v", err)
	}
}

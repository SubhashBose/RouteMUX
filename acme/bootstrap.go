package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// newBootstrapCert creates an in-memory self-signed certificate used as the SNI
// fallback before any real certificate has been obtained. It lets the TLS
// listener complete handshakes so that:
//   - normal clients get a connection (untrusted, but functional), and
//   - the ACME HTTP-01 challenge can be served over the HTTPS listener when a
//     CA follows an HTTP->HTTPS redirect (CAs do not validate the certificate
//     during challenge validation).
//
// The certificate is never written to disk and is replaced as soon as a real
// certificate is installed for a domain.
func newBootstrapCert() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "RouteMUX bootstrap"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"routemux.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}
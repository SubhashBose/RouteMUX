package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// issuer performs ACME certificate issuance for one vhost against one CA.
type issuer struct {
	client        *xacme.Client
	challengeMode ChallengeMode
	httpChallenge *httpChallengeServer // for HTTP-01
	store         *certStore           // for TLS-ALPN-01 challenge certs
}

// obtainCertificate runs the full ACME flow for the given domains and returns
// the issued certificate chain (DER) and the private key. The caller persists
// them to disk and installs them in the cert store.
func (is *issuer) obtainCertificate(ctx context.Context, domains []string) (certDER [][]byte, key *ecdsa.PrivateKey, err error) {
	// Build the authorization identifiers.
	ids := make([]xacme.AuthzID, len(domains))
	for i, d := range domains {
		ids[i] = xacme.AuthzID{Type: "dns", Value: d}
	}

	order, err := is.client.AuthorizeOrder(ctx, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("creating order: %w", err)
	}
	// Preserve the order URI and finalize URL from the initial order. Later
	// order responses (from WaitOrder/finalize) are populated from response
	// bodies that may omit the Location header, leaving these fields empty.
	orderURI := order.URI
	finalizeURL := order.FinalizeURL

	// Solve each authorization.
	for _, authzURL := range order.AuthzURLs {
		if err := is.solveAuthorization(ctx, authzURL); err != nil {
			return nil, nil, err
		}
	}

	// Wait for the order to leave the pending state.
	order, err = is.client.WaitOrder(ctx, orderURI)
	if err != nil {
		return nil, nil, fmt.Errorf("waiting for order: %w", err)
	}
	if order.FinalizeURL != "" {
		finalizeURL = order.FinalizeURL
	}

	// Generate the certificate key and CSR.
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating CSR: %w", err)
	}

	// If the order is already valid and has a certificate URL, fetch it
	// directly. Otherwise finalize with the CSR.
	if order.Status == xacme.StatusValid && order.CertURL != "" {
		certDER, err = is.client.FetchCert(ctx, order.CertURL, true)
		if err != nil {
			return nil, nil, fmt.Errorf("fetching certificate: %w", err)
		}
		return certDER, key, nil
	}

	if finalizeURL == "" {
		return nil, nil, fmt.Errorf("finalizing order: no finalize URL available (order status %q)", order.Status)
	}

	// Finalize the order. CreateOrderCert submits the CSR and attempts to fetch
	// the certificate. Some CAs (notably Pebble) return the finalized order
	// before the certificate URL is populated, which makes the library's
	// immediate fetch fail. If that happens, poll the order ourselves until the
	// certificate URL appears, then fetch it.
	certDER, certURL, err := is.client.CreateOrderCert(ctx, finalizeURL, csrDER, true)
	if err == nil {
		return certDER, key, nil
	}

	// Some CAs do not return the certificate on the finalize response; poll
	// the order until the certificate URL is available.
	if orderURI == "" {
		return nil, nil, fmt.Errorf("finalizing order: order URI unavailable for polling")
	}
	for attempt := 0; attempt < 15; attempt++ {
		o, gerr := is.client.GetOrder(ctx, orderURI)
		if gerr != nil {
			return nil, nil, fmt.Errorf("polling order: %w", gerr)
		}
		if o.Status == xacme.StatusInvalid {
			return nil, nil, fmt.Errorf("order became invalid during finalization")
		}
		if o.Status == xacme.StatusValid && o.CertURL != "" {
			certURL = o.CertURL
			break
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if certURL == "" {
		return nil, nil, fmt.Errorf("finalizing order: certificate URL never became available")
	}
	certDER, err = is.client.FetchCert(ctx, certURL, true)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching certificate: %w", err)
	}
	return certDER, key, nil
}

// solveAuthorization handles a single domain authorization using the configured
// challenge type.
func (is *issuer) solveAuthorization(ctx context.Context, authzURL string) error {
	authz, err := is.client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("getting authorization: %w", err)
	}

	// Already valid (e.g. cached by the CA) — nothing to do.
	if authz.Status == xacme.StatusValid {
		return nil
	}

	domain := authz.Identifier.Value

	var chal *xacme.Challenge
	switch is.challengeMode {
	case ChallengeTLSALPN01:
		chal = findChallenge(authz.Challenges, "tls-alpn-01")
	default:
		chal = findChallenge(authz.Challenges, "http-01")
	}
	if chal == nil {
		return fmt.Errorf("no supported challenge for %s", domain)
	}

	// Set up the challenge response.
	cleanup, err := is.prepareChallenge(domain, chal)
	if err != nil {
		return err
	}
	defer cleanup()

	// Tell the CA we're ready.
	if _, err := is.client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accepting challenge for %s: %w", domain, err)
	}

	// Wait for the CA to validate.
	if _, err := is.client.WaitAuthorization(ctx, authzURL); err != nil {
		return fmt.Errorf("challenge validation for %s: %w", domain, err)
	}
	return nil
}

// prepareChallenge installs the challenge response (HTTP token or ALPN cert)
// and returns a cleanup function to remove it afterwards.
func (is *issuer) prepareChallenge(domain string, chal *xacme.Challenge) (func(), error) {
	switch is.challengeMode {
	case ChallengeTLSALPN01:
		cert, err := is.client.TLSALPN01ChallengeCert(chal.Token, domain)
		if err != nil {
			return nil, fmt.Errorf("building TLS-ALPN-01 cert: %w", err)
		}
		is.store.setChallengeCert(domain, &cert)
		return func() { is.store.removeChallengeCert(domain) }, nil

	default: // HTTP-01
		resp, err := is.client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return nil, fmt.Errorf("building HTTP-01 response: %w", err)
		}
		path := is.client.HTTP01ChallengePath(chal.Token)
		is.httpChallenge.add(path, resp)
		return func() { is.httpChallenge.remove(path) }, nil
	}
}

// findChallenge returns the challenge of the given type, or nil.
func findChallenge(challenges []*xacme.Challenge, typ string) *xacme.Challenge {
	for _, c := range challenges {
		if c.Type == typ {
			return c
		}
	}
	return nil
}

// encodeCertPEM serialises a DER chain to PEM.
func encodeCertPEM(der [][]byte) []byte {
	var out []byte
	for _, b := range der {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	return out
}

// encodeKeyPEM serialises an EC private key to PEM.
func encodeKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// certNotAfter parses the leaf certificate's expiry from a DER chain.
func certNotAfter(der [][]byte) (time.Time, error) {
	if len(der) == 0 {
		return time.Time{}, fmt.Errorf("empty cert chain")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

// logIssued logs a successful issuance.
func logIssued(domains []string, notAfter time.Time) {
	log.Printf("acme: issued certificate for %v (expires %s)", domains, notAfter.UTC().Format(time.RFC3339))
}

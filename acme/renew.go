package acme

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"time"
)

// renewCheckInterval is how often the renewal loop wakes to check certs.
const renewCheckInterval = 12 * time.Hour

// renewLoop periodically checks each ACME vhost's certificate and renews any
// that are within their renewal window. It runs until the Manager is stopped.
func (m *Manager) renewLoop() {
	// Initial delay so startup issuance settles first.
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-timer.C:
			m.checkRenewals()
			timer.Reset(renewCheckInterval)
		}
	}
}

// checkRenewals inspects every ACME vhost and renews certs past their window.
func (m *Manager) checkRenewals() {
	for i := range m.vhosts {
		v := &m.vhosts[i]
		if !v.UsesACME() {
			continue
		}
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		certPath, keyPath := v.resolveCertPaths(m.global.CacheDir)
		due, err := renewalDue(certPath, v.RenewBefore)
		if err != nil {
			// No readable cert — (re)issue.
			log.Printf("acme: %v has no usable cert (%v); issuing", v.Domains, err)
			if ierr := m.issueAndStore(m.ctx, v); ierr != nil {
				log.Printf("acme: issuance for %v failed: %v", v.Domains, ierr)
			}
			continue
		}
		if !due {
			continue
		}
		log.Printf("acme: renewing certificate for %v", v.Domains)
		if err := m.issueAndStore(m.ctx, v); err != nil {
			log.Printf("acme: renewal for %v failed: %v (will retry)", v.Domains, err)
		}
		_ = keyPath
	}
}

// renewalDue reports whether the certificate at certPath should be renewed now.
// renewBefore overrides the lead time; when zero, the default (1/3 of lifetime)
// is used.
func renewalDue(certPath string, renewBefore time.Duration) (bool, error) {
	pemData, err := os.ReadFile(certPath)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return false, errNoPEM
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	lead := renewBefore
	if lead <= 0 {
		lead = defaultRenewBefore(cert.NotBefore, cert.NotAfter)
	}
	renewAt := cert.NotAfter.Add(-lead)
	return time.Now().After(renewAt), nil
}

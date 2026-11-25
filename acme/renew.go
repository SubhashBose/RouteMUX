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

// renewLoop first obtains certificates for the vhosts in initial (those with no
// usable certificate at startup), then periodically checks each ACME vhost's
// certificate and renews any that are within their renewal window. It runs
// until the Manager is stopped.
//
// It is the only goroutine that ever issues certificates. Keeping initial
// issuance and renewal in one goroutine means two issuances for the same vhost
// can never overlap, which would place duplicate orders with the CA and could
// issue duplicate certificates (a separately rate-limited resource).
func (m *Manager) renewLoop(initial []*VHostConfig) {
	for _, v := range initial {
		if m.ctx.Err() != nil {
			return
		}
		log.Printf("acme: obtaining certificate for %v from %s", v.Domains, v.AcmeSource)
		if err := m.issueAndStore(m.ctx, v); err != nil {
			log.Printf("acme: initial issuance for %v failed: %v (will retry)", v.Domains, err)
		}
	}

	// First check shortly after startup picks up renewals already due at boot.
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-timer.C:
			m.checkRenewals()
			timer.Reset(m.nextCheckDelay())
		}
	}
}

// nextCheckDelay returns how long the renewal loop should sleep before the next
// check: the regular renewCheckInterval, or less when a failed issuance becomes
// eligible for retry sooner. Without this, a failure's backoff window (minutes)
// would only be honored at the next regular check (hours later).
//
// Only backoff windows still in the future count, so a stale entry for a vhost
// that is no longer due (e.g. its cert was replaced out-of-band) cannot make the
// loop spin.
func (m *Manager) nextCheckDelay() time.Duration {
	delay := renewCheckInterval
	for i := range m.vhosts {
		v := &m.vhosts[i]
		if !v.UsesACME() {
			continue
		}
		if ok, wait := m.issueState.shouldAttempt(v.Domains); !ok && wait < delay {
			delay = wait
		}
	}
	return delay
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
		// Still backing off after a failure: skip quietly. nextCheckDelay wakes
		// the loop again when the backoff window ends.
		if ok, _ := m.issueState.shouldAttempt(v.Domains); !ok {
			continue
		}

		certPath, _ := v.resolveCertPaths(m.global.CacheDir)
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
	} else if limit := maxRenewBefore(cert.NotBefore, cert.NotAfter); lead > limit {
		// An acme-renewal close to (or beyond) the certificate lifetime would
		// make a freshly issued certificate due again immediately, renewing on
		// every check and quickly exhausting the CA's duplicate-certificate
		// limit (Let's Encrypt: 5 per week for the same domain set).
		log.Printf("acme: acme-renewal %s is too close to the certificate lifetime %s for %s; using %s instead",
			lead, cert.NotAfter.Sub(cert.NotBefore).Round(time.Hour), certPath, limit.Round(time.Hour))
		lead = limit
	}
	renewAt := cert.NotAfter.Add(-lead)
	return time.Now().After(renewAt), nil
}

package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"routemux/acme"
)

// revertVHostTLS restores each new-config vhost's TLS block to the value from
// the old config (matched by domain set), so the in-memory config stays
// consistent with the ACME manager that persists across reloads. New vhosts
// with no counterpart in the old config keep their TLS as-is but it will not be
// acted on until restart (the warning covers this).
func revertVHostTLS(oldVHosts []VHost, newVHosts []VHost) {
	oldMap := make(map[string]*VHostTLS, len(oldVHosts))
	for i := range oldVHosts {
		key := strings.Join(oldVHosts[i].Domains, "|")
		oldMap[key] = oldVHosts[i].TLS
	}
	for i := range newVHosts {
		key := strings.Join(newVHosts[i].Domains, "|")
		if oldTLS, ok := oldMap[key]; ok {
			newVHosts[i].TLS = oldTLS
		}
	}
}

// acmeConfigChanged reports whether ACME-relevant settings differ between two
// configs — either the global acme block or any vhost's tls block. These take
// effect only at server start (the acme.Manager is built once and persists
// across reloads), so a reload must warn and revert them rather than silently
// ignoring the change.
func acmeConfigChanged(oldCfg, newCfg *Config) bool {
	if !sameACMEGlobal(oldCfg.ACME, newCfg.ACME) {
		return true
	}
	return !sameVHostTLSSet(oldCfg.VHosts, newCfg.VHosts)
}

func sameACMEGlobal(a, b *ACMEConfig) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	return *a == *b
}

// sameVHostTLSSet compares the per-vhost TLS configuration across two vhost
// lists, keyed by the vhost's domain set, so reordering alone is not a change.
func sameVHostTLSSet(oldV, newV []VHost) bool {
	oldMap := vhostTLSMap(oldV)
	newMap := vhostTLSMap(newV)
	if len(oldMap) != len(newMap) {
		return false
	}
	for k, ot := range oldMap {
		nt, ok := newMap[k]
		if !ok || ot != nt {
			return false
		}
	}
	return true
}

// vhostTLSMap builds a map from a vhost's domain set (joined) to a comparable
// snapshot of its TLS settings. Vhosts without TLS are recorded as the empty
// value so adding/removing a tls block is detected.
func vhostTLSMap(vhosts []VHost) map[string]VHostTLS {
	m := make(map[string]VHostTLS, len(vhosts))
	for _, vh := range vhosts {
		key := strings.Join(vh.Domains, "|")
		if vh.TLS != nil {
			m[key] = *vh.TLS
		} else {
			m[key] = VHostTLS{}
		}
	}
	return m
}

// buildACMEManager constructs an acme.Manager from the parsed config, or
// returns nil if no ACME/automatic TLS or per-vhost TLS is configured.
//
// It is also responsible for collecting per-vhost static certificates so the
// SNI listener can serve them — a vhost may have a static cert/key even when
// global ACME is absent.
func buildACMEManager(cfg *Config) (*acme.Manager, error) {
	// Determine whether any vhost needs the SNI manager at all: either a
	// per-vhost tls block (static or ACME) exists, or global ACME is set.
	var tlsVHosts []acme.VHostConfig
	hasAny := false

	var challengeMode string
	var email, cacheDir, directoryURL string
	var caRootFile string
	var insecure bool
	servePort80 := false
	if cfg.ACME != nil {
		email = cfg.ACME.Email
		cacheDir = cfg.ACME.CacheDir
		challengeMode = cfg.ACME.ChallengeMode
		servePort80 = cfg.ACME.ServePort80
		directoryURL = cfg.ACME.DirectoryURL
		caRootFile = cfg.ACME.CARootFile
		insecure = cfg.ACME.Insecure
	}

	for _, vh := range cfg.VHosts {
		if vh.TLS == nil {
			continue
		}
		// A tls block only counts if it actually configures TLS: a static
		// cert/key pair, or acme-source for automatic issuance. An empty tls
		// block (or one with only acme-renewal and nothing else) is inert.
		usesACME := vh.TLS.AcmeSource != ""
		usesStatic := vh.TLS.Cert != "" || vh.TLS.Key != ""
		if !usesACME && !usesStatic {
			continue
		}
		hasAny = true
		// For ACME vhosts, reject domain lists that cannot work (catch-all,
		// wildcard, or malformed) up front, with a clear message — rather than
		// letting them fail confusingly at the CA and burn rate-limit budget.
		if usesACME {
			if err := acme.ValidateDomainsForACME(vh.Domains); err != nil {
				return nil, fmt.Errorf("vhost %v: %w", vh.Domains, err)
			}
		}
		var renew time.Duration
		if vh.TLS.RenewBefore != "" {
			d, err := parseDayDuration(vh.TLS.RenewBefore)
			if err != nil {
				return nil, fmt.Errorf("vhost %v: invalid acme-renewal %q: %w", vh.Domains, vh.TLS.RenewBefore, err)
			}
			renew = d
		}
		tlsVHosts = append(tlsVHosts, acme.VHostConfig{
			Domains:     vh.Domains,
			CertPath:    vh.TLS.Cert,
			KeyPath:     vh.TLS.Key,
			AcmeSource:  vh.TLS.AcmeSource,
			RenewBefore: renew,
		})
	}

	// Build the SNI manager only if at least one vhost actually configures TLS
	// (static cert/key or acme-source). A global `acme:` block, or an empty
	// `tls:` block, does not by itself enable TLS — the user opts in via
	// global-tls-cert/key, per-vhost cert/key, or per-vhost acme-source.
	// (global-tls-cert alone is served by the legacy single-cert path, which
	// does not need this manager.)
	if !hasAny {
		return nil, nil
	}

	mode, err := acme.ParseChallengeMode(challengeMode)
	if err != nil {
		return nil, err
	}

	// Detect a misconfiguration that silently fails at challenge time: if the
	// main listener is on port 80 and we'd use HTTP-01 with serve-port80, the
	// temporary plain-HTTP challenge listener cannot bind (the main TLS listener
	// already holds :80), and the main listener can't serve a plain-HTTP
	// challenge because it speaks TLS. TLS-ALPN-01 is the correct choice when
	// RouteMUX terminates TLS directly on the challenge port.
	if cfg.Port == 80 && mode == acme.ChallengeHTTP01 && servePort80 {
		log.Printf("acme: WARNING — RouteMUX is configured to serve TLS on port 80 with " +
			"challenge-mode: http and serve-port80: true. The temporary port-80 challenge " +
			"listener cannot bind because the main TLS listener already holds port 80, and " +
			"HTTP-01 challenges cannot be served over the TLS listener. Use challenge-mode: https " +
			"(TLS-ALPN-01) instead, which validates over the TLS handshake on port 80 and needs no " +
			"separate HTTP listener.")
	}

	mgr, err := acme.NewManager(acme.GlobalConfig{
		Email:         email,
		CacheDir:      cacheDir,
		ChallengeMode: mode,
		ServePort80:   servePort80,
		DirectoryURL:  directoryURL,
		CARootFile:    caRootFile,
		InsecureSkipVerify: insecure,
	}, tlsVHosts)
	if err != nil {
		return nil, err
	}
	return mgr, nil
}

// parseDayDuration parses a duration that may use a "d" (days) suffix, e.g.
// "30d", in addition to standard Go durations like "12h".
func parseDayDuration(s string) (time.Duration, error) {
	if len(s) > 1 && s[len(s)-1] == 'd' {
		var days int
		if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &days); err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
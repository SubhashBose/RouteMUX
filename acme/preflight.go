package acme

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// ValidateDomainsForACME checks that a vhost's domains are suitable for
// automatic issuance, returning a clear error for inputs that would otherwise
// fail confusingly at the CA (wasting rate-limit budget) or produce odd cert
// filenames. It is only meaningful when the vhost uses acme-source.
func ValidateDomainsForACME(domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("acme-source set but no domains listed")
	}
	for _, d := range domains {
		switch {
		case d == "" || d == "*":
			return fmt.Errorf("cannot auto-issue a certificate for a catch-all vhost (%q); ACME requires explicit domain names", d)
		case strings.HasPrefix(d, "*."):
			return fmt.Errorf("wildcard domain %q requires the DNS-01 challenge, which is not yet supported (and wildcard vhost matching is unsupported); list explicit names instead", d)
		case !isValidDomainName(d):
			return fmt.Errorf("invalid domain name %q for acme-source", d)
		}
	}
	return nil
}

// isValidDomainName does a conservative syntactic check for a DNS hostname:
// one or more dot-separated labels, each 1-63 chars of letters/digits/hyphens,
// not starting or ending with a hyphen, and an overall length under 254.
func isValidDomainName(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	if strings.HasSuffix(d, ".") {
		d = d[:len(d)-1] // tolerate a trailing dot (FQDN form)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false // require at least name.tld
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-'
			if !ok {
				return false
			}
		}
	}
	return true
}

// preflightTimeout bounds the DNS lookup done before issuance.
const preflightTimeout = 5 * time.Second

// domainResolves reports whether the domain has any A/AAAA record at all. A
// domain that does not resolve cannot possibly pass an HTTP-01 or TLS-ALPN-01
// challenge (the CA could not reach this server), so attempting issuance would
// only burn the CA's "failed authorization" rate-limit budget.
//
// This is intentionally a weak check: it confirms the name resolves to
// *something*, not that it points at this specific server (which a proxy/CDN or
// split-horizon DNS would defeat). It catches the most common and most damaging
// mistake — issuing for a domain with no DNS at all — without false-rejecting
// legitimate proxied setups.
func domainResolves(ctx context.Context, domain string) bool {
	ctx, cancel := context.WithTimeout(ctx, preflightTimeout)
	defer cancel()
	var r net.Resolver
	addrs, err := r.LookupHost(ctx, domain)
	return err == nil && len(addrs) > 0
}

// preflightDomains returns the subset of domains that do not resolve. An empty
// result means all domains resolve (issuance may proceed).
func preflightDomains(ctx context.Context, domains []string) (unresolved []string) {
	for _, d := range domains {
		if !domainResolves(ctx, d) {
			unresolved = append(unresolved, d)
		}
	}
	return unresolved
}
package jwtverify

import "testing"

// TestIssuerSSRF_PathTrick verifies that issuer strings which merely *contain*
// a trusted suffix in their path/query/fragment cannot redirect the JWKS fetch
// to an attacker host.
func TestIssuerSSRF_PathTrick(t *testing.T) {
	attacks := []string{
		"https://evil.com/.cloudflareaccess.com",
		"https://evil.com#.cloudflareaccess.com",
		"https://evil.com?.cloudflareaccess.com",
		"https://evil.com/.auth0.com",
		"https://team.cloudflareaccess.com.evil.com",
		"http://team.cloudflareaccess.com", // not https
		"https://user:pass@team.cloudflareaccess.com",
		"not-a-url",
		"",
	}
	for _, iss := range attacks {
		_, err := jwksURLForIssuer(iss)
		if err == nil {
			t.Errorf("SECURITY: issuer %q was accepted but should be rejected", iss)
		}
	}
}

// TestIssuerValid_Reconstructed verifies a legitimate issuer resolves to the
// correct JWKS URL, reconstructed from scheme+host only.
func TestIssuerValid_Reconstructed(t *testing.T) {
	cases := map[string]string{
		"https://team.cloudflareaccess.com":        "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
		"https://myorg.auth0.com":                  "https://myorg.auth0.com/.well-known/jwks.json",
		"https://team.cloudflareaccess.com/":        "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
		"https://team.cloudflareaccess.com/ignored": "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
	}
	for iss, want := range cases {
		got, err := jwksURLForIssuer(iss)
		if err != nil {
			t.Errorf("issuer %q: unexpected error %v", iss, err)
			continue
		}
		if got != want {
			t.Errorf("issuer %q: got %q, want %q", iss, got, want)
		}
	}
}
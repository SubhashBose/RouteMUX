// Package jwtverify provides utilities for verifying JWT tokens
// and extracting payload values by key.
package jwtverify

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Sentinel errors.
var (
	ErrTokenInvalid            = errors.New("token is invalid")
	ErrTokenExpired            = errors.New("token has expired")
	ErrAudienceMismatch        = errors.New("token audience does not match expected audience")
	ErrClaimNotFound           = errors.New("claim not found in token payload")
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
	ErrJWKSKeyNotFound         = errors.New("no matching key found in JWKS")
	ErrMissingKey              = errors.New("no Key provided and issuer is not a recognised auto-provider (Cloudflare Access, Auth0)")
)

// jwksResponse is the shape returned by a JWKS endpoint.
type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	// RSA fields
	N string `json:"n"`
	E string `json:"e"`
	// EC fields
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Verify validates a JWT token.
//
// Parameters:
//   - tokenString:    the raw JWT string.
//   - ClaimUsername:  the claim key whose value to extract from the payload.
//                     Pass "" to skip this check entirely (no error returned).
//   - Key:            the HMAC secret ([]byte) or PEM-encoded public key (RSA/EC).
//                     Pass nil or empty to use automatic JWKS resolution.
//   - JwkURL:         explicit JWKS endpoint. Used when Key is empty.
//                     When both Key and JwkURL are empty the token's "iss" claim
//                     is inspected for known providers:
//                       • ends with ".cloudflareaccess.com" → {iss}/cdn-cgi/access/certs
//                       • ends with ".auth0.com"            → {iss}/.well-known/jwks.json
//   - Audience:       expected value of the "aud" claim. Pass "" to skip aud
//                     verification. When non-empty the token must carry an "aud"
//                     claim that contains this value (string or string array).
//
// Claim checks performed (in order):
//  1. Signature verification.
//  2. "exp" — returns ErrTokenExpired when present and elapsed.
//  3. "aud" — returns ErrAudienceMismatch when Audience is set and not matched.
//  4. ClaimUsername extraction.
//
// Returns:
//   - valid: true if the token passes all checks above.
//   - value: the payload value for ClaimUsername (nil if ClaimUsername == "").
//   - err:   non-nil on any failure.
func Verify(tokenString string, ClaimUsername string, Key []byte, JwkURL string, Audience string) (value interface{}, err error) {
	// Parse without validation first so we can inspect headers and claims.
	unverified, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	// Resolve the key material to use for verification.
	keyFunc, err := resolveKeyFunc(unverified, Key, JwkURL)
	if err != nil {
		return nil, err
	}

	// Fully parse and verify signature. We disable the library's built-in claim
	// validation so we can return our own typed sentinel errors.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, parseErr := parser.Parse(tokenString, keyFunc)
	if parseErr != nil || !token.Valid {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, parseErr)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrTokenInvalid
	}

	// ── exp ──────────────────────────────────────────────────────────────────
	if err := checkExp(claims); err != nil {
		return nil, err
	}

	// ── nbf ──────────────────────────────────────────────────────────────────
	if err := checkNbf(claims); err != nil {
		return nil, err
	}

	// ── aud ──────────────────────────────────────────────────────────────────
	if Audience != "" {
		if err := checkAud(claims, Audience); err != nil {
			return nil, err
		}
	}

	// ── ClaimUsername extraction ──────────────────────────────────────────────
	if ClaimUsername == "" {
		return nil, nil
	}

	val, exists := claims[ClaimUsername]
	if !exists {
		return nil, fmt.Errorf("%w: %q", ErrClaimNotFound, ClaimUsername)
	}

	return val, nil
}

// ── key resolution ───────────────────────────────────────────────────────────

// resolveKeyFunc picks the right jwt.Keyfunc based on the supplied arguments
// and the token's own "iss" claim.
func resolveKeyFunc(unverified *jwt.Token, Key []byte, JwkURL string) (jwt.Keyfunc, error) {
	switch {
	case len(Key) > 0:
		return staticKeyFunc(Key), nil

	case JwkURL != "":
		kid, _ := unverified.Header["kid"].(string)
		pubKey, err := globalJWKSCache.getKey(JwkURL, kid)
		if err != nil {
			return nil, err
		}
		return func(_ *jwt.Token) (interface{}, error) { return pubKey, nil }, nil

	default:
		return issuerKeyFunc(unverified)
	}
}

// issuerKeyFunc resolves a JWKS URL from the token's "iss" claim for known
// auto-providers and fetches the signing key via the cache.
func issuerKeyFunc(unverified *jwt.Token) (jwt.Keyfunc, error) {
	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrTokenInvalid
	}

	iss, _ := claims["iss"].(string)
	iss = strings.TrimRight(iss, "/")
	kid, _ := unverified.Header["kid"].(string)

	jwksURL, err := jwksURLForIssuer(iss)
	if err != nil {
		return nil, err
	}

	pubKey, err := globalJWKSCache.getKey(jwksURL, kid)
	if err != nil {
		return nil, err
	}
	return func(_ *jwt.Token) (interface{}, error) { return pubKey, nil }, nil
}

// allowedIssuerHosts maps a trusted provider's domain suffix to the path of its
// JWKS endpoint. The match is performed against the parsed URL HOST, not the raw
// string, so attacker-crafted issuers like
// "https://evil.com/.cloudflareaccess.com" cannot pass.
var allowedIssuerHosts = []struct {
	suffix   string
	jwksPath string
}{
	{".cloudflareaccess.com", "/cdn-cgi/access/certs"},
	{".auth0.com", "/.well-known/jwks.json"},
}

// jwksURLForIssuer maps a known issuer domain to its JWKS endpoint.
// The issuer must be an https URL whose HOST ends with a trusted provider
// suffix. The JWKS URL is reconstructed from the validated scheme+host, never
// from the raw issuer string, to prevent SSRF via path/query/fragment tricks.
// Returns ErrMissingKey for unrecognised or malformed issuers.
func jwksURLForIssuer(iss string) (string, error) {
	u, err := url.Parse(iss)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", ErrMissingKey
	}
	// Reject anything with userinfo, since that does not belong in an issuer.
	if u.User != nil {
		return "", ErrMissingKey
	}
	host := u.Hostname() // strips any port
	for _, p := range allowedIssuerHosts {
		if strings.HasSuffix(host, p.suffix) {
			// Reconstruct from validated scheme+host only — discard any
			// attacker-controlled path, query, or fragment from the issuer.
			return "https://" + u.Host + p.jwksPath, nil
		}
	}
	return "", ErrMissingKey
}

// keyKind classifies the configured key material so we can pin the acceptable
// signing algorithms and prevent algorithm-confusion attacks (e.g. an attacker
// forging an HS256 token signed with an RSA *public* key as the HMAC secret).
type keyKind int

const (
	keyKindHMAC keyKind = iota // raw shared secret → HMAC algorithms only
	keyKindRSA                 // PEM RSA public key → RSA algorithms only
	keyKindEC                  // PEM EC public key  → ECDSA algorithms only
)

// classifiedKey is the cached result of parsing a configured key.
type classifiedKey struct {
	kind keyKind
	key  interface{}
}

// keyClassCache memoizes classifyKey results so PEM/ASN.1 parsing happens once
// per distinct key, not on every request. The configured key is stable, so the
// cache is effectively populated once at first use. Keyed by the raw key bytes.
var (
	keyClassCache   = map[string]classifiedKey{}
	keyClassCacheMu sync.RWMutex
)

// classifyKey inspects the key material. If it parses as a PEM public key it is
// asymmetric (RSA or EC); otherwise it is treated as a raw HMAC secret.
// Results are cached by key bytes to avoid re-parsing on every request.
func classifyKey(raw []byte) (keyKind, interface{}, error) {
	cacheKey := string(raw)
	keyClassCacheMu.RLock()
	if ck, ok := keyClassCache[cacheKey]; ok {
		keyClassCacheMu.RUnlock()
		return ck.kind, ck.key, nil
	}
	keyClassCacheMu.RUnlock()

	var ck classifiedKey
	if pub, err := jwt.ParseRSAPublicKeyFromPEM(raw); err == nil {
		ck = classifiedKey{keyKindRSA, pub}
	} else if pub, err := jwt.ParseECPublicKeyFromPEM(raw); err == nil {
		ck = classifiedKey{keyKindEC, pub}
	} else {
		// Not a PEM public key → treat as an HMAC shared secret.
		ck = classifiedKey{keyKindHMAC, raw}
	}

	keyClassCacheMu.Lock()
	keyClassCache[cacheKey] = ck
	keyClassCacheMu.Unlock()
	return ck.kind, ck.key, nil
}

// staticKeyFunc returns a jwt.Keyfunc that pins the signing algorithm family to
// the type of the configured key. This is critical: the algorithm is chosen by
// the KEY, never by the token header, which closes the RS256→HS256 confusion
// attack where a public key is abused as an HMAC secret.
func staticKeyFunc(raw []byte) jwt.Keyfunc {
	kind, key, _ := classifyKey(raw)
	return func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			if kind != keyKindHMAC {
				return nil, fmt.Errorf("%w: token uses HMAC but configured key is asymmetric", ErrUnexpectedSigningMethod)
			}
			return key, nil
		case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
			if kind != keyKindRSA {
				return nil, fmt.Errorf("%w: token uses RSA but configured key is not RSA", ErrUnexpectedSigningMethod)
			}
			return key, nil
		case *jwt.SigningMethodECDSA:
			if kind != keyKindEC {
				return nil, fmt.Errorf("%w: token uses ECDSA but configured key is not EC", ErrUnexpectedSigningMethod)
			}
			return key, nil
		default:
			return nil, fmt.Errorf("%w: %v", ErrUnexpectedSigningMethod, token.Header["alg"])
		}
	}
}

// ── claim checks ─────────────────────────────────────────────────────────────

// checkExp validates the "exp" claim. A token without an exp claim is rejected:
// non-expiring tokens are a security risk, so exp is mandatory.
func checkExp(claims jwt.MapClaims) error {
	expVal, exists := claims["exp"]
	if !exists {
		return fmt.Errorf("%w: token has no exp claim", ErrTokenInvalid)
	}
	expUnix, ok := claimToUnix(expVal)
	if !ok {
		return fmt.Errorf("%w: exp claim has invalid type", ErrTokenInvalid)
	}
	if time.Now().Unix() > expUnix {
		return fmt.Errorf("%w: expired at %s",
			ErrTokenExpired, time.Unix(expUnix, 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// checkNbf validates the "nbf" (not-before) claim when present. A token whose
// nbf is in the future is not yet valid and is rejected.
func checkNbf(claims jwt.MapClaims) error {
	nbfVal, exists := claims["nbf"]
	if !exists {
		return nil // nbf is optional
	}
	nbfUnix, ok := claimToUnix(nbfVal)
	if !ok {
		return fmt.Errorf("%w: nbf claim has invalid type", ErrTokenInvalid)
	}
	// Allow a small clock-skew tolerance of 60 seconds.
	if time.Now().Unix()+60 < nbfUnix {
		return fmt.Errorf("%w: token not valid before %s",
			ErrTokenInvalid, time.Unix(nbfUnix, 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// claimToUnix converts a numeric JWT time claim to a Unix timestamp.
// Returns ok=false for missing, zero, negative, or non-numeric values.
func claimToUnix(v interface{}) (int64, bool) {
	var n int64
	switch t := v.(type) {
	case float64:
		n = int64(t)
	case json.Number:
		parsed, err := t.Int64()
		if err != nil {
			return 0, false
		}
		n = parsed
	case int64:
		n = t
	case int:
		n = int64(t)
	default:
		return 0, false
	}
	if n <= 0 {
		return 0, false
	}
	return n, true
}

// checkAud validates that the "aud" claim contains the expected audience.
// The "aud" claim may be a single string or a JSON array of strings.
func checkAud(claims jwt.MapClaims, expected string) error {
	raw, exists := claims["aud"]
	if !exists {
		return fmt.Errorf("%w: token has no aud claim", ErrAudienceMismatch)
	}

	switch v := raw.(type) {
	case string:
		if v == expected {
			return nil
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return nil
			}
		}
	case []string:
		for _, s := range v {
			if s == expected {
				return nil
			}
		}
	}

	return fmt.Errorf("%w: expected %q", ErrAudienceMismatch, expected)
}

// ── JWK parsing ──────────────────────────────────────────────────────────────

// jwkToPublicKey converts a JWK struct into a Go crypto public key.
func jwkToPublicKey(k jwk) (interface{}, error) {
	single, err := json.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("re-encoding JWK: %w", err)
	}
	switch k.Kty {
	case "RSA":
		return parseRSAJWK(single)
	case "EC":
		return parseECJWK(single)
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %s", k.Kty)
	}
}

// parseRSAJWK decodes a JSON RSA public key.
func parseRSAJWK(data []byte) (*rsa.PublicKey, error) {
	var raw struct {
		N string `json:"n"`
		E string `json:"e"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	n, err := base64URLDecodeBigInt(raw.N)
	if err != nil {
		return nil, fmt.Errorf("RSA modulus: %w", err)
	}
	eBuf, err := base64URLDecodeBytes(raw.E)
	if err != nil {
		return nil, fmt.Errorf("RSA exponent: %w", err)
	}
	e := 0
	for _, b := range eBuf {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// parseECJWK decodes a JSON EC public key.
func parseECJWK(data []byte) (*ecdsa.PublicKey, error) {
	var raw struct {
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	curve, err := curveByName(raw.Crv)
	if err != nil {
		return nil, err
	}
	x, err := base64URLDecodeBigInt(raw.X)
	if err != nil {
		return nil, fmt.Errorf("EC x: %w", err)
	}
	y, err := base64URLDecodeBigInt(raw.Y)
	if err != nil {
		return nil, fmt.Errorf("EC y: %w", err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
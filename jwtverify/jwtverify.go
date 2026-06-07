// Package jwtverify provides utilities for verifying JWT tokens
// and extracting payload values by key.
package jwtverify

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

// jwksURLForIssuer maps a known issuer domain to its JWKS endpoint.
// Returns ErrMissingKey for unrecognised issuers.
func jwksURLForIssuer(iss string) (string, error) {
	switch {
	case strings.HasSuffix(iss, ".cloudflareaccess.com"):
		return iss + "/cdn-cgi/access/certs", nil
	case strings.HasSuffix(iss, ".auth0.com"):
		return iss + "/.well-known/jwks.json", nil
	default:
		return "", ErrMissingKey
	}
}

// staticKeyFunc returns a jwt.Keyfunc that uses a fixed []byte secret or PEM key,
// accepting any algorithm declared in the token header.
func staticKeyFunc(raw []byte) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			return raw, nil
		case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
			pub, err := jwt.ParseRSAPublicKeyFromPEM(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid RSA public key: %w", err)
			}
			return pub, nil
		case *jwt.SigningMethodECDSA:
			pub, err := jwt.ParseECPublicKeyFromPEM(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid EC public key: %w", err)
			}
			return pub, nil
		default:
			return nil, fmt.Errorf("%w: %v", ErrUnexpectedSigningMethod, token.Header["alg"])
		}
	}
}

// ── claim checks ─────────────────────────────────────────────────────────────

// checkExp validates the "exp" claim when present.
func checkExp(claims jwt.MapClaims) error {
	expVal, exists := claims["exp"]
	if !exists {
		return nil
	}
	var expUnix int64
	switch v := expVal.(type) {
	case float64:
		expUnix = int64(v)
	case json.Number:
		expUnix, _ = v.Int64()
	case int64:
		expUnix = v
	}
	if expUnix > 0 && time.Now().Unix() > expUnix {
		return fmt.Errorf("%w: expired at %s",
			ErrTokenExpired, time.Unix(expUnix, 0).UTC().Format(time.RFC3339))
	}
	return nil
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
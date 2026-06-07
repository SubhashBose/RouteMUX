package jwtverify

import (
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
)

// base64URLDecodeBytes decodes a base64url-encoded string (no padding).
func base64URLDecodeBytes(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// base64URLDecodeBigInt decodes a base64url-encoded string into a *big.Int.
func base64URLDecodeBigInt(s string) (*big.Int, error) {
	b, err := base64URLDecodeBytes(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// curveByName returns the elliptic.Curve for a JWK "crv" value.
func curveByName(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", crv)
	}
}
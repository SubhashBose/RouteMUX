package jwtverify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"routemux/jwtverify"
)

var testSecret = []byte("super-secret-key")

// ── token factories ──────────────────────────────────────────────────────────

func makeHMAC(claims jwt.MapClaims) string {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := t.SignedString(testSecret)
	return s
}

func makeRSA(claims jwt.MapClaims, key *rsa.PrivateKey) string {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, _ := t.SignedString(key)
	return s
}

func makeEC(claims jwt.MapClaims, key *ecdsa.PrivateKey) string {
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	s, _ := t.SignedString(key)
	return s
}

func liveClaims(extra jwt.MapClaims) jwt.MapClaims {
	c := jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func expiredClaims(extra jwt.MapClaims) jwt.MapClaims {
	c := jwt.MapClaims{"exp": time.Now().Add(-time.Hour).Unix()}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func serveECJWKS(t *testing.T, priv *ecdsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	pub := &priv.PublicKey
	body, _ := json.Marshal(map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "EC", "kid": kid, "crv": "P-256",
				"x": encodeBase64URL(pub.X.Bytes()),
				"y": encodeBase64URL(pub.Y.Bytes()),
			},
		},
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

func signEC(priv *ecdsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	tok := jwt.New(jwt.SigningMethodES256)
	tok.Header["kid"] = kid
	tok.Claims = claims
	s, _ := tok.SignedString(priv)
	return s
}

// ── HMAC ─────────────────────────────────────────────────────────────────────

func TestHMAC_ValidTokenAndClaim(t *testing.T) {
	tok := makeHMAC(liveClaims(jwt.MapClaims{"sub": "user-42"}))
	val, err := jwtverify.Verify(tok, "sub", testSecret, "", "")
	if err != nil || val != "user-42" {
		t.Fatalf("want val=user-42 err=nil; got val=%v err=%v", val, err)
	}
}

func TestHMAC_EmptyClaimUsername_SkipsCheck(t *testing.T) {
	tok := makeHMAC(liveClaims(jwt.MapClaims{"sub": "user-42"}))
	val, err := jwtverify.Verify(tok, "", testSecret, "", "")
	if err != nil || val != nil {
		t.Fatalf("want val=nil err=nil; got val=%v err=%v", val, err)
	}
}

func TestHMAC_ClaimNotFound(t *testing.T) {
	tok := makeHMAC(liveClaims(jwt.MapClaims{"sub": "user-42"}))
	val, err := jwtverify.Verify(tok, "role", testSecret, "", "")
	if val != nil {
		t.Fatalf("want nil value for missing claim, got %v", val)
	}
	if !errors.Is(err, jwtverify.ErrClaimNotFound) {
		t.Fatalf("want ErrClaimNotFound, got %v", err)
	}
}

func TestHMAC_WrongSecret(t *testing.T) {
	tok := makeHMAC(liveClaims(jwt.MapClaims{"sub": "user-42"}))
	_, err := jwtverify.Verify(tok, "sub", []byte("wrong"), "", "")
	if !errors.Is(err, jwtverify.ErrTokenInvalid) {
		t.Fatalf("want ErrTokenInvalid; got %v", err)
	}
}

func TestHMAC_ExpiredToken(t *testing.T) {
	tok := makeHMAC(expiredClaims(jwt.MapClaims{"sub": "user-42"}))
	_, err := jwtverify.Verify(tok, "sub", testSecret, "", "")
	if !errors.Is(err, jwtverify.ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired; got %v", err)
	}
}

func TestHMAC_NoExpClaim_Rejected(t *testing.T) {
	// A token without an exp claim is rejected — non-expiring tokens are a
	// security risk, so exp is mandatory.
	tok := makeHMAC(jwt.MapClaims{"sub": "user-42"}) // no exp
	_, err := jwtverify.Verify(tok, "sub", testSecret, "", "")
	if !errors.Is(err, jwtverify.ErrTokenInvalid) {
		t.Fatalf("want ErrTokenInvalid for missing exp; got %v", err)
	}
}

func TestHMAC_MalformedToken(t *testing.T) {
	_, err := jwtverify.Verify("not.a.token", "sub", testSecret, "", "")
	if !errors.Is(err, jwtverify.ErrTokenInvalid) {
		t.Fatalf("want ErrTokenInvalid; got %v", err)
	}
}

// ── aud verification ─────────────────────────────────────────────────────────

func TestAud_StringMatch(t *testing.T) {
	tok := makeHMAC(liveClaims(jwt.MapClaims{"sub": "u", "aud": "my-api"}))
	_, err := jwtverify.Verify(tok, "", testSecret, "", "my-api")
	if err != nil {
		t.Fatalf("want err=nil; got %v", err)
	}
}

func TestAud_ArrayContainsExpected(t *testing.T) {
	tok := makeHMAC(liveClaims(jwt.MapClaims{
		"sub": "u",
		"aud": []string{"other-api", "my-api", "another-api"},
	}))
	_, err := jwtverify.Verify(tok, "", testSecret, "", "my-api")
	if err != nil {
		t.Fatalf("want err=nil; got %v", err)
	}
}

func TestAud_Mismatch(t *testing.T) {
	tok := makeHMAC(liveClaims(jwt.MapClaims{"sub": "u", "aud": "wrong-api"}))
	_, err := jwtverify.Verify(tok, "", testSecret, "", "my-api")
	if !errors.Is(err, jwtverify.ErrAudienceMismatch) {
		t.Fatalf("want ErrAudienceMismatch; got %v", err)
	}
}

func TestAud_MissingClaim(t *testing.T) {
	tok := makeHMAC(liveClaims(jwt.MapClaims{"sub": "u"})) // no aud
	_, err := jwtverify.Verify(tok, "", testSecret, "", "my-api")
	if !errors.Is(err, jwtverify.ErrAudienceMismatch) {
		t.Fatalf("want ErrAudienceMismatch; got %v", err)
	}
}

func TestAud_EmptyAudienceArg_SkipsCheck(t *testing.T) {
	tok := makeHMAC(liveClaims(jwt.MapClaims{"sub": "u"})) // no aud claim
	_, err := jwtverify.Verify(tok, "", testSecret, "", "")
	if err != nil {
		t.Fatalf("want err=nil when Audience=\"\"; got %v", err)
	}
}

// ── RSA ──────────────────────────────────────────────────────────────────────

func TestRSA_ValidTokenAndClaim(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := makeRSA(liveClaims(jwt.MapClaims{"sub": "rsa-user"}), priv)
	pubPEM, err := rsaPubPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	val, verr := jwtverify.Verify(tok, "sub", pubPEM, "", "")
	if verr != nil || val != "rsa-user" {
		t.Fatalf("RSA: want val=rsa-user err=nil; got val=%v err=%v", val, verr)
	}
}

func TestRSA_ExpiredToken(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := makeRSA(expiredClaims(jwt.MapClaims{"sub": "rsa-user"}), priv)
	pubPEM, _ := rsaPubPEM(&priv.PublicKey)
	_, err := jwtverify.Verify(tok, "sub", pubPEM, "", "")
	if !errors.Is(err, jwtverify.ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired; got %v", err)
	}
}

func TestRSA_WrongKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := makeRSA(liveClaims(jwt.MapClaims{"sub": "rsa-user"}), priv)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubPEM, _ := rsaPubPEM(&other.PublicKey)
	_, err := jwtverify.Verify(tok, "sub", pubPEM, "", "")
	if !errors.Is(err, jwtverify.ErrTokenInvalid) {
		t.Fatalf("want ErrTokenInvalid; got %v", err)
	}
}

// ── ECDSA ─────────────────────────────────────────────────────────────────────

func TestEC_ValidTokenAndClaim(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok := makeEC(liveClaims(jwt.MapClaims{"sub": "ec-user"}), priv)
	pubPEM, err := ecPubPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	val, verr := jwtverify.Verify(tok, "sub", pubPEM, "", "")
	if verr != nil || val != "ec-user" {
		t.Fatalf("EC: want val=ec-user err=nil; got val=%v err=%v", val, verr)
	}
}

func TestEC_ExpiredToken(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok := makeEC(expiredClaims(jwt.MapClaims{"sub": "ec-user"}), priv)
	pubPEM, _ := ecPubPEM(&priv.PublicKey)
	_, err := jwtverify.Verify(tok, "sub", pubPEM, "", "")
	if !errors.Is(err, jwtverify.ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired; got %v", err)
	}
}

// ── JwkURL ────────────────────────────────────────────────────────────────────

func TestJwkURL_ValidEC(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const kid = "jwkurl-kid-1"
	tok := signEC(priv, kid, liveClaims(jwt.MapClaims{"sub": "jwk-user"}))
	srv := serveECJWKS(t, priv, kid)
	defer srv.Close()
	val, err := jwtverify.Verify(tok, "sub", nil, srv.URL, "")
	if err != nil || val != "jwk-user" {
		t.Fatalf("want val=jwk-user err=nil; got val=%v err=%v", val, err)
	}
}

func TestJwkURL_WithAud(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const kid = "jwkurl-aud-kid"
	tok := signEC(priv, kid, liveClaims(jwt.MapClaims{"sub": "u", "aud": "svc-a"}))
	srv := serveECJWKS(t, priv, kid)
	defer srv.Close()

	_, err := jwtverify.Verify(tok, "", nil, srv.URL, "svc-a")
	if err != nil {
		t.Fatalf("correct aud: want err=nil; got %v", err)
	}

	_, err = jwtverify.Verify(tok, "", nil, srv.URL, "svc-b")
	if !errors.Is(err, jwtverify.ErrAudienceMismatch) {
		t.Fatalf("wrong aud: want ErrAudienceMismatch; got %v", err)
	}
}

func TestJwkURL_KidMismatch(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok := signEC(priv, "token-kid", liveClaims(jwt.MapClaims{"sub": "u"}))
	srv := serveECJWKS(t, priv, "server-kid")
	defer srv.Close()
	_, err := jwtverify.Verify(tok, "sub", nil, srv.URL, "")
	if !errors.Is(err, jwtverify.ErrJWKSKeyNotFound) {
		t.Fatalf("want ErrJWKSKeyNotFound; got %v", err)
	}
}

// ── Auth0 / Cloudflare iss fallback ──────────────────────────────────────────

func TestIss_UnknownDomain_ReturnsErrMissingKey(t *testing.T) {
	for _, iss := range []string{
		"https://example.com",
		"https://notauth0.com",
		"https://notcloudflareaccess.com",
	} {
		tok := makeHMAC(liveClaims(jwt.MapClaims{"sub": "u", "iss": iss}))
		_, err := jwtverify.Verify(tok, "sub", nil, "", "")
		if !errors.Is(err, jwtverify.ErrMissingKey) {
			t.Fatalf("iss=%s: want ErrMissingKey; got %v", iss, err)
		}
	}
}
// ── Security regression tests ────────────────────────────────────────────────

// TestAlgConfusion_RSAPublicKeyAsHMAC verifies the RS256→HS256 confusion attack
// is blocked. An attacker takes the RSA public key (public knowledge), forges an
// HS256 token signing it with the public key PEM as the HMAC secret. The server,
// configured with that same public key, must NOT accept it.
func TestAlgConfusion_RSAPublicKeyAsHMAC(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubPEM, _ := rsaPubPEM(&priv.PublicKey)

	// Attacker forges an HS256 token using the public key PEM as the HMAC secret.
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, liveClaims(jwt.MapClaims{"sub": "attacker"}))
	forgedStr, err := forged.SignedString(pubPEM)
	if err != nil {
		t.Fatal(err)
	}

	// Server is configured with the RSA public key. It must reject the forged token.
	_, err = jwtverify.Verify(forgedStr, "sub", pubPEM, "", "")
	if err == nil {
		t.Fatal("SECURITY: algorithm confusion attack succeeded — forged HS256 token accepted with RSA public key")
	}
	if !errors.Is(err, jwtverify.ErrUnexpectedSigningMethod) && !errors.Is(err, jwtverify.ErrTokenInvalid) {
		t.Fatalf("want signing method rejection; got %v", err)
	}
}

// TestNbf_FutureTokenRejected verifies a token with a future nbf is rejected.
func TestNbf_FutureTokenRejected(t *testing.T) {
	claims := liveClaims(jwt.MapClaims{
		"sub": "user",
		"nbf": time.Now().Add(time.Hour).Unix(), // valid only in 1 hour
	})
	tok := makeHMAC(claims)
	_, err := jwtverify.Verify(tok, "sub", testSecret, "", "")
	if !errors.Is(err, jwtverify.ErrTokenInvalid) {
		t.Fatalf("want ErrTokenInvalid for future nbf; got %v", err)
	}
}

// TestNbf_PastTokenAccepted verifies a token with a past nbf is accepted.
func TestNbf_PastTokenAccepted(t *testing.T) {
	claims := liveClaims(jwt.MapClaims{
		"sub": "user",
		"nbf": time.Now().Add(-time.Hour).Unix(),
	})
	tok := makeHMAC(claims)
	val, err := jwtverify.Verify(tok, "sub", testSecret, "", "")
	if err != nil || val != "user" {
		t.Fatalf("want val=user err=nil; got val=%v err=%v", val, err)
	}
}

// TestExp_InvalidType verifies a token with a non-numeric exp is rejected.
func TestExp_InvalidType(t *testing.T) {
	tok := makeHMAC(jwt.MapClaims{"sub": "user", "exp": "not-a-number"})
	_, err := jwtverify.Verify(tok, "sub", testSecret, "", "")
	if !errors.Is(err, jwtverify.ErrTokenInvalid) {
		t.Fatalf("want ErrTokenInvalid for invalid exp type; got %v", err)
	}
}

// TestExp_NegativeRejected verifies a token with exp <= 0 is rejected.
func TestExp_ZeroRejected(t *testing.T) {
	tok := makeHMAC(jwt.MapClaims{"sub": "user", "exp": 0})
	_, err := jwtverify.Verify(tok, "sub", testSecret, "", "")
	if !errors.Is(err, jwtverify.ErrTokenInvalid) {
		t.Fatalf("want ErrTokenInvalid for exp=0; got %v", err)
	}
}

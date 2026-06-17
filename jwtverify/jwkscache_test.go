package jwtverify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"routemux/jwtverify"
	"github.com/golang-jwt/jwt/v5"
)

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// countingServer serves a single-key EC JWKS and counts HTTP hits.
func countingServer(t *testing.T, priv *ecdsa.PrivateKey, kid string, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	return countingServerWithCacheControl(t, priv, kid, -1, hits)
}

// countingServerWithCacheControl serves a JWKS with an optional Cache-Control header.
// Pass maxAge < 0 to omit the header entirely.
func countingServerWithCacheControl(t *testing.T, priv *ecdsa.PrivateKey, kid string, maxAge int, hits *atomic.Int64) *httptest.Server {
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
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if maxAge >= 0 {
			w.Header().Set("Cache-Control", "public, max-age="+itoa(maxAge))
		}
		_, _ = w.Write(body)
	}))
}

// ── repeated calls hit cache ──────────────────────────────────────────────────

func TestCache_HitOnSecondCall(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const kid = "cache-hit-kid"
	var hits atomic.Int64
	srv := countingServer(t, priv, kid, &hits)
	defer srv.Close()

	tok := signEC(priv, kid, liveClaims(jwt.MapClaims{"sub": "u"}))
	for i := 0; i < 5; i++ {
		if _, err := jwtverify.Verify(tok, "", nil, srv.URL, ""); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("expected exactly 1 HTTP fetch, got %d", n)
	}
}

// ── known kid never expires ───────────────────────────────────────────────────

func TestCache_KnownKidNeverExpires(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const kid = "permanent-kid"
	var hits atomic.Int64
	// max-age=0 would make the TTL zero, but the kid is present so no re-fetch.
	srv := countingServerWithCacheControl(t, priv, kid, 0, &hits)
	defer srv.Close()

	tok := signEC(priv, kid, liveClaims(jwt.MapClaims{"sub": "u"}))
	for i := 0; i < 5; i++ {
		if _, err := jwtverify.Verify(tok, "", nil, srv.URL, ""); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("known kid should stay cached regardless of TTL; got %d fetches", n)
	}
}

// ── unknown kid respects TTL before re-fetching ───────────────────────────────

func TestCache_UnknownKid_NoRefetchWithinTTL(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const presentKid = "present-kid"
	const missingKid = "missing-kid"
	var hits atomic.Int64
	srv := countingServerWithCacheControl(t, priv, presentKid, 3600, &hits)
	defer srv.Close()

	// Warm up the cache with the present kid.
	tok1 := signEC(priv, presentKid, liveClaims(jwt.MapClaims{"sub": "u"}))
	jwtverify.Verify(tok1, "", nil, srv.URL, "")
	if hits.Load() != 1 {
		t.Fatalf("expected 1 fetch after warm-up, got %d", hits.Load())
	}

	// Missing kid within TTL must not trigger a re-fetch.
	tok2 := signEC(priv, missingKid, liveClaims(jwt.MapClaims{"sub": "u"}))
	for i := 0; i < 3; i++ {
		_, err := jwtverify.Verify(tok2, "", nil, srv.URL, "")
		if !errors.Is(err, jwtverify.ErrJWKSKeyNotFound) {
			t.Fatalf("expected ErrJWKSKeyNotFound, got %v", err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("expected no re-fetch within TTL; got %d total fetches", hits.Load())
	}
}

// ── max-age=0 allows immediate re-fetch for unknown kid ───────────────────────

func TestCache_CacheControlMaxAge_ZeroAllowsImmediateRefetch(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const presentKid = "cc-present-kid"
	const missingKid = "cc-missing-kid"
	var hits atomic.Int64
	srv := countingServerWithCacheControl(t, priv, presentKid, 0, &hits)
	defer srv.Close()

	// Warm up.
	tok1 := signEC(priv, presentKid, liveClaims(jwt.MapClaims{"sub": "u"}))
	jwtverify.Verify(tok1, "", nil, srv.URL, "")

	// Each missing-kid call should re-fetch because TTL=0.
	tok2 := signEC(priv, missingKid, liveClaims(jwt.MapClaims{"sub": "u"}))
	jwtverify.Verify(tok2, "", nil, srv.URL, "")
	jwtverify.Verify(tok2, "", nil, srv.URL, "")

	if hits.Load() < 2 {
		t.Fatalf("expected re-fetch with max-age=0; got %d total fetches", hits.Load())
	}
}

// ── concurrent access ─────────────────────────────────────────────────────────

func TestCache_ConcurrentAccess(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const kid = "concurrent-kid"
	var hits atomic.Int64
	srv := countingServer(t, priv, kid, &hits)
	defer srv.Close()

	tok := signEC(priv, kid, liveClaims(jwt.MapClaims{"sub": "u"}))
	const goroutines = 50
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			_, err := jwtverify.Verify(tok, "", nil, srv.URL, "")
			errs <- err
		}()
	}
	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("goroutine error: %v", err)
		}
	}
	// Allow small burst due to concurrent first-access before write lock settles.
	if n := hits.Load(); n > 3 {
		t.Fatalf("too many fetches under concurrency: %d (expected ~1)", n)
	}
}

// ── multiple URLs cached independently ───────────────────────────────────────

func TestCache_MultipleURLsIndependent(t *testing.T) {
	priv1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var hits1, hits2 atomic.Int64
	srv1 := countingServer(t, priv1, "kid1", &hits1)
	srv2 := countingServer(t, priv2, "kid2", &hits2)
	defer srv1.Close()
	defer srv2.Close()

	tok1 := signEC(priv1, "kid1", liveClaims(jwt.MapClaims{"sub": "u1"}))
	tok2 := signEC(priv2, "kid2", liveClaims(jwt.MapClaims{"sub": "u2"}))
	for i := 0; i < 4; i++ {
		jwtverify.Verify(tok1, "", nil, srv1.URL, "")
		jwtverify.Verify(tok2, "", nil, srv2.URL, "")
	}
	if hits1.Load() != 1 {
		t.Fatalf("srv1: expected 1 fetch, got %d", hits1.Load())
	}
	if hits2.Load() != 1 {
		t.Fatalf("srv2: expected 1 fetch, got %d", hits2.Load())
	}
}

var _ = time.Second // keep time import used
var _ = jwt.MapClaims{} // keep jwt import used
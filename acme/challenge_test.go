package acme

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestZeroSSLEAB_Success(t *testing.T) {
	hmacKey := []byte("super-secret-hmac-material")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("form parse: %v", err)
		}
		if r.FormValue("email") != "admin@example.com" {
			t.Errorf("email = %q", r.FormValue("email"))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"success":      true,
			"eab_kid":      "kid-123",
			"eab_hmac_key": base64.StdEncoding.EncodeToString(hmacKey),
		})
	}))
	defer srv.Close()

	// Point the package endpoint at the test server via a local override.
	old := zeroSSLEABEndpoint
	zeroSSLEABEndpoint = srv.URL
	defer func() { zeroSSLEABEndpoint = old }()

	eab, err := generateZeroSSLEAB(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if eab.KID != "kid-123" {
		t.Errorf("KID = %q, want kid-123", eab.KID)
	}
	if string(eab.Key) != string(hmacKey) {
		t.Errorf("HMAC key mismatch")
	}
}

func TestZeroSSLEAB_RequiresEmail(t *testing.T) {
	if _, err := generateZeroSSLEAB(context.Background(), ""); err == nil {
		t.Error("expected error when email is empty")
	}
}

func TestHTTPChallengeServer_ServesToken(t *testing.T) {
	hc := newHTTPChallengeServer(false)
	hc.add("/.well-known/acme-challenge/tok1", "keyauth-1")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/tok1", nil)
	hc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "keyauth-1" {
		t.Errorf("body = %q, want keyauth-1", rec.Body.String())
	}

	// Unknown token → 404.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/.well-known/acme-challenge/unknown", nil)
	hc.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("unknown token status = %d, want 404", rec2.Code)
	}

	// After removal → 404.
	hc.remove("/.well-known/acme-challenge/tok1")
	rec3 := httptest.NewRecorder()
	hc.Handler().ServeHTTP(rec3, httptest.NewRequest("GET", "/.well-known/acme-challenge/tok1", nil))
	if rec3.Code != http.StatusNotFound {
		t.Errorf("removed token status = %d, want 404", rec3.Code)
	}
}

func TestIsChallengeRequest(t *testing.T) {
	yes := httptest.NewRequest("GET", "/.well-known/acme-challenge/abc", nil)
	if !IsChallengeRequest(yes) {
		t.Error("should detect challenge request")
	}
	no := httptest.NewRequest("GET", "/api/users", nil)
	if IsChallengeRequest(no) {
		t.Error("should not flag normal request")
	}
}

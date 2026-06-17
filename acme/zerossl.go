package acme

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// zeroSSLEABEndpoint is the ZeroSSL EAB-credentials API (var for test override).
var zeroSSLEABEndpoint = "https://api.zerossl.com/acme/eab-credentials-email"

// zeroSSLEABResponse is the JSON returned by ZeroSSL's EAB endpoint.
type zeroSSLEABResponse struct {
	Success    bool   `json:"success"`
	EABKID     string `json:"eab_kid"`
	EABHMACKey string `json:"eab_hmac_key"`
}

// generateZeroSSLEAB fetches External Account Binding credentials from ZeroSSL
// using the account email, mirroring how Caddy bootstraps ZeroSSL. The returned
// ExternalAccountBinding is passed to account registration.
func generateZeroSSLEAB(ctx context.Context, email string) (*xacme.ExternalAccountBinding, error) {
	if email == "" {
		return nil, fmt.Errorf("zerossl requires an email address to generate EAB credentials")
	}

	form := url.Values{}
	form.Set("email", email)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, zeroSSLEABEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting ZeroSSL EAB: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ZeroSSL EAB endpoint returned status %d", resp.StatusCode)
	}

	var out zeroSSLEABResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding ZeroSSL EAB response: %w", err)
	}
	if !out.Success || out.EABKID == "" || out.EABHMACKey == "" {
		return nil, fmt.Errorf("ZeroSSL did not return EAB credentials")
	}

	hmacKey, err := base64.RawURLEncoding.DecodeString(out.EABHMACKey)
	if err != nil {
		// ZeroSSL returns standard base64; try that too.
		hmacKey, err = base64.StdEncoding.DecodeString(out.EABHMACKey)
		if err != nil {
			return nil, fmt.Errorf("decoding EAB HMAC key: %w", err)
		}
	}

	return &xacme.ExternalAccountBinding{
		KID: out.EABKID,
		Key: hmacKey,
	}, nil
}

// verifyHMAC is a tiny helper kept for completeness/testing of the HMAC path.
func verifyHMAC(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

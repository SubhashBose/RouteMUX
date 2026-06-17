package acme

import (
	"context"
	"net/http"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	xacme "golang.org/x/crypto/acme"
)

// account holds the persisted ACME account state for one CA.
type account struct {
	// Email is the contact address registered with the CA.
	Email string `json:"email"`
	// URI is the account URL (the "kid") returned by the CA on registration.
	URI string `json:"uri"`
	// DirectoryURL is the CA directory this account belongs to.
	DirectoryURL string `json:"directory_url"`
}

// accountStore loads and persists the account key + metadata for a CA under
// <cacheDir>/accounts/<ca>/.
type accountStore struct {
	dir string
}

func newAccountStore(dir string) *accountStore {
	return &accountStore{dir: dir}
}

func (s *accountStore) keyPath() string  { return filepath.Join(s.dir, "account.key") }
func (s *accountStore) metaPath() string { return filepath.Join(s.dir, "account.json") }

// load reads an existing account key + metadata. Returns (nil, nil, nil) when
// no account exists yet (not an error — caller registers a new one).
func (s *accountStore) load() (*ecdsa.PrivateKey, *account, error) {
	keyPEM, err := os.ReadFile(s.keyPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("account key: invalid PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("account key: %w", err)
	}
	metaJSON, err := os.ReadFile(s.metaPath())
	if err != nil {
		// Key without metadata — treat as no account so we re-register.
		return nil, nil, nil
	}
	var acct account
	if err := json.Unmarshal(metaJSON, &acct); err != nil {
		return nil, nil, fmt.Errorf("account meta: %w", err)
	}
	return key, &acct, nil
}

// save persists the account key and metadata atomically.
func (s *accountStore) save(key *ecdsa.PrivateKey, acct *account) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := writeFileAtomic(s.keyPath(), keyPEM, 0o600); err != nil {
		return err
	}
	metaJSON, err := json.MarshalIndent(acct, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.metaPath(), metaJSON, 0o600)
}

// ensureAccount loads an existing account for the CA or registers a new one,
// returning a ready-to-use acme.Client. eab, when non-nil, supplies External
// Account Binding credentials (required by some CAs, e.g. ZeroSSL). httpClient,
// when non-nil, is used for all ACME requests (needed for test CAs like Pebble
// that present a self-signed directory endpoint).
func ensureAccount(ctx context.Context, dir, directoryURL, email string, eab *xacme.ExternalAccountBinding, httpClient *http.Client) (*xacme.Client, error) {
	store := newAccountStore(dir)
	key, acct, err := store.load()
	if err != nil {
		return nil, fmt.Errorf("loading account: %w", err)
	}

	if key != nil && acct != nil {
		// Existing account — reuse it.
		client := &xacme.Client{Key: key, DirectoryURL: directoryURL, HTTPClient: httpClient}
		client.KID = xacme.KeyID(acct.URI)
		return client, nil
	}

	// Register a new account.
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	client := &xacme.Client{Key: newKey, DirectoryURL: directoryURL, HTTPClient: httpClient}

	reg := &xacme.Account{}
	if email != "" {
		reg.Contact = []string{"mailto:" + email}
	}
	if eab != nil {
		reg.ExternalAccountBinding = eab
	}

	registered, err := client.Register(ctx, reg, xacme.AcceptTOS)
	if err != nil {
		return nil, fmt.Errorf("registering account: %w", err)
	}

	if err := store.save(newKey, &account{
		Email:        email,
		URI:          registered.URI,
		DirectoryURL: directoryURL,
	}); err != nil {
		return nil, fmt.Errorf("persisting account: %w", err)
	}
	return client, nil
}

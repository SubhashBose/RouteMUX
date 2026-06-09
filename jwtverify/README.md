# jwtverify

A Go package for verifying JWT tokens. It supports HMAC, RSA, and ECDSA algorithms, automatic JWKS key resolution for Cloudflare Access and Auth0, audience and expiry validation, and an in-memory JWKS cache with `Cache-Control`-aware TTL.

## Installation

```bash
go get github.com/yourorg/jwtverify
```

## Quick start

```go
import "github.com/yourorg/jwtverify"

value, err := jwtverify.Verify(tokenString, "sub", secretOrKey, jwksURL, audience)
```

## Function signature

```go
func Verify(
    tokenString   string,  // raw JWT string
    ClaimUsername string,  // payload claim to extract; "" to skip
    Key           []byte,  // HMAC secret or PEM public key; nil for JWKS auto-resolution
    JwkURL        string,  // explicit JWKS endpoint; "" to use iss-based auto-resolution
    Audience      string,  // expected aud value; "" to skip audience check
) (value interface{}, err error)
```

On success `value` contains the payload value for `ClaimUsername` (or `nil` when `ClaimUsername` is `""`). On failure `value` is `nil` and `err` is one of the sentinel errors listed below.

## Key resolution

The package resolves the signing key in the following priority order:

| Condition | Key source |
|---|---|
| `Key` is non-empty | Used directly as an HMAC secret (`[]byte`) or PEM-encoded RSA/EC public key |
| `Key` is empty, `JwkURL` is non-empty | JWKS fetched from `JwkURL` |
| Both empty, `iss` ends with `.cloudflareaccess.com` | JWKS fetched from `{iss}/cdn-cgi/access/certs` |
| Both empty, `iss` ends with `.auth0.com` | JWKS fetched from `{iss}/.well-known/jwks.json` |
| Both empty, `iss` is anything else | `ErrMissingKey` |

Key selection from JWKS uses the `kid` field in the token header, which must match one of the `kid` values in the `keys` array of the JWKS response.

## Supported algorithms

| Family | Algorithms |
|---|---|
| HMAC | HS256, HS384, HS512 |
| RSA PKCS#1 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| ECDSA | ES256, ES384, ES512 |

The algorithm is read from the token's `alg` header. No algorithm is hard-coded or restricted.

## Claim validation

Checks are performed in this order after signature verification:

1. **`exp`** — if present, the token is rejected with `ErrTokenExpired` when the current time is past the Unix timestamp. Tokens without an `exp` claim are accepted.
2. **`aud`** — if `Audience` is non-empty, the token must carry an `aud` claim whose value equals `Audience`. The claim may be a single string or an array of strings. Missing or non-matching audience returns `ErrAudienceMismatch`.
3. **`ClaimUsername`** — if non-empty, the named claim is extracted from the payload. If the token is valid but the claim is absent, `ErrClaimNotFound` is returned (see sentinel errors below for how to distinguish this from a hard failure).

## Sentinel errors

Use `errors.Is` to inspect the returned error:

```go
value, err := jwtverify.Verify(tok, "sub", nil, jwksURL, "my-api")
switch {
case err == nil:
    // fully verified; use value
case errors.Is(err, jwtverify.ErrClaimNotFound):
    // token is cryptographically valid, but ClaimUsername was not in the payload
case errors.Is(err, jwtverify.ErrTokenExpired):
    // valid signature, token is past its exp timestamp
case errors.Is(err, jwtverify.ErrAudienceMismatch):
    // valid signature, aud claim did not contain the expected audience
case errors.Is(err, jwtverify.ErrTokenInvalid):
    // bad signature, malformed token, or structural parse failure
case errors.Is(err, jwtverify.ErrJWKSKeyNotFound):
    // JWKS was fetched but no key matched the token's kid
case errors.Is(err, jwtverify.ErrMissingKey):
    // Key and JwkURL are both empty and iss is not a recognised auto-provider
default:
    // network error, JWKS parse error, or unsupported algorithm
}
```

| Error | Meaning |
|---|---|
| `ErrTokenInvalid` | Signature verification failed, token is malformed, or structural parse error |
| `ErrTokenExpired` | Token has a valid signature but `exp` is in the past |
| `ErrAudienceMismatch` | Token has a valid signature but `aud` does not match the expected audience |
| `ErrClaimNotFound` | Token passed all security checks but `ClaimUsername` is not in the payload |
| `ErrJWKSKeyNotFound` | JWKS endpoint responded successfully but no key matches the token's `kid` |
| `ErrMissingKey` | No `Key`, no `JwkURL`, and `iss` is not Cloudflare Access or Auth0 |
| `ErrUnexpectedSigningMethod` | Token uses an algorithm not in the supported list above |

## JWKS caching

JWKS responses are cached in memory for the lifetime of the process. The cache is shared across all `Verify` calls and is safe for concurrent use.

**Cache behaviour by scenario:**

| Scenario | Network call? |
|---|---|
| `kid` found in cache | Never — cached key is returned immediately regardless of TTL |
| URL never fetched | Yes — fetch on first call |
| URL fetched, `kid` absent, TTL not elapsed | No — returns `ErrJWKSKeyNotFound` immediately |
| URL fetched, `kid` absent, TTL elapsed | Yes — re-fetches and tries again |

**TTL** is derived from the `Cache-Control: max-age=N` header of the JWKS HTTP response. When the header is absent or contains no `max-age` directive, the default TTL of **300 seconds** is used. A server-returned `max-age=0` means every missing-`kid` lookup triggers an immediate re-fetch.

The intentional asymmetry — known kids never expire, unknown kids wait for TTL — means key rotation is handled gracefully: new tokens signed with a rotated key will trigger one re-fetch to discover the new `kid`, while tokens signed with the old key continue to work from cache without any disruption.

## Usage examples

### HMAC (HS256)

```go
secret := []byte("my-secret")

value, err := jwtverify.Verify(tokenString, "sub", secret, "", "")
if err != nil {
    log.Fatal(err)
}
fmt.Println("subject:", value)
```

### RSA or ECDSA with a PEM public key

```go
pubKeyPEM, _ := os.ReadFile("public.pem")

value, err := jwtverify.Verify(tokenString, "sub", pubKeyPEM, "", "")
```

### Explicit JWKS URL

Suitable for Keycloak, Firebase, or any provider that exposes a standard JWKS endpoint:

```go
const jwksURL = "https://login.example.com/realms/myrealm/protocol/openid-connect/certs"

value, err := jwtverify.Verify(tokenString, "email", nil, jwksURL, "")
```

### Auth0 (automatic, via `iss`)

When `Key` and `JwkURL` are both empty the package reads `iss` from the token payload. For Auth0 tenants it constructs the JWKS URL automatically:

```go
// Token iss: "https://your-tenant.auth0.com"
// JWKS fetched from: "https://your-tenant.auth0.com/.well-known/jwks.json"

value, err := jwtverify.Verify(tokenString, "sub", nil, "", "https://your-api.example.com")
if errors.Is(err, jwtverify.ErrAudienceMismatch) {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}
```

### Cloudflare Access (automatic, via `iss`)

```go
// Token iss: "https://yourteam.cloudflareaccess.com"
// JWKS fetched from: "https://yourteam.cloudflareaccess.com/cdn-cgi/access/certs"

value, err := jwtverify.Verify(tokenString, "email", nil, "", "")
```

### Skip optional checks

```go
// Skip ClaimUsername extraction (value will be nil on success):
_, err := jwtverify.Verify(tokenString, "", secret, "", "")

// Skip audience check:
value, err := jwtverify.Verify(tokenString, "sub", secret, "", "")

// Skip both:
_, err = jwtverify.Verify(tokenString, "", secret, "", "")
```

### Distinguishing a valid token with a missing claim

`ErrClaimNotFound` means the token passed all security checks — only the requested claim key was absent. This is the one case where the token is valid but the claim extraction failed:

```go
value, err := jwtverify.Verify(tokenString, "preferred_username", secret, "", "")
if errors.Is(err, jwtverify.ErrClaimNotFound) {
    // token is genuine; fall back to a different claim
    value, err = jwtverify.Verify(tokenString, "sub", secret, "", "")
}
```

## Provider compatibility

| Provider | Recommended usage | Notes |
|---|---|---|
| **Auth0** | Pass `Audience` matching your API identifier; leave `Key` and `JwkURL` empty | RS256 by default; JWKS auto-resolved from `iss` |
| **Cloudflare Access** | Leave `Key` and `JwkURL` empty | RS256; JWKS auto-resolved from `iss` |
| **Keycloak** | Set `JwkURL` to `{realm-url}/protocol/openid-connect/certs` | Multiple simultaneous keys handled correctly |
| **Firebase** | Set `JwkURL` to the Google service-account JWK URL | Keys rotate every ~6 hours; `Cache-Control` TTL is honoured automatically |
| **Any JWKS provider** | Set `JwkURL` | Standard `kid`-based key selection |
| **Custom / self-signed** | Pass PEM public key as `Key` | Supports RSA and ECDSA PEM blocks |

## Dependencies

```
github.com/golang-jwt/jwt/v5
```

No other third-party dependencies. JWK parsing (RSA and EC) is implemented using only the Go standard library.

## License

MIT
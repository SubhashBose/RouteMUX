# RouteMUX

A lightweight, flexible reverse proxy written in Go. Routes HTTP and WebSocket traffic to upstream destinations with per-route configuration for authentication, header manipulation, TLS, and timeouts.

## Features

- **Path-based routing** — forward different URL paths to different upstream services
- **HTTP & WebSocket** — transparently proxies both HTTP and WebSocket connections
- **TLS termination** — serve HTTPS with your own certificate; connect to HTTPS upstreams with optional verification skip
- **HTTP Basic Auth** — global auth for all routes, per-route override, or explicit disable
- **Header manipulation** — add, overwrite, or delete upstream request headers per route, with wildcard support (`CF-*`, `X-*`) and variable interpolation (`$remote_addr`, `$header.User-Agent`, etc.)
- **Config file + CLI** — configure via `config.yml`, command-line flags, or both; CLI takes precedence
- **Zero external dependencies** at runtime (only [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) for config parsing)

---

## Installation

```bash
git clone https://github.com/you/routemux
cd routemux
go build -o routemux .
```

---

## Quick Start

```bash
# Forward /api/ to a local service
./routemux --route /api/ --dest http://localhost:3000/

# With a config file
./routemux --config config.yml

# HTTPS termination
./routemux --tls-cert cert.pem --tls-key key.pem --route / --dest http://localhost:8080/
```

---

## Configuration File

RouteMUX looks for `config.yml` in this order:

1. Path given by `--config`
2. Same directory as the binary
3. Current working directory
4. `~/.config/routemux/config.yml`

```yaml
global:
  listen:           # IP address or interface name (e.g. 192.168.1.10, eth0, lo). Empty = all interfaces.
  port: 8080        # Port to listen on (default: 8080)
  # tls-cert: /path/to/cert.pem
  # tls-key:  /path/to/key.pem
  # global-auth: ["admin", "s3cr3t"]   # HTTP Basic Auth applied to all routes

routes:
  /api/:
    dest: http://localhost:3000/v1/   # Upstream destination URL
    timeout: 30s                       # Optional upstream timeout (e.g. 30s, 2m)
    # noTLSverify: true                # Skip TLS certificate verification for upstream
    # auth: ["user", "pass"]           # Per-route auth (overrides global-auth)
    # auth: []                         # Explicitly disable auth for this route
    add-header:
      X-Proxy: RouteMUX               # Add or overwrite a header sent to upstream
    delete-header:
      - Cookie                         # Delete a specific header
      - CF-*                           # Delete all headers matching wildcard

  /app/:
    dest: http://localhost:8000/
    timeout: 120s
```

---

## Command-Line Reference

```
routemux [global options] \
         --route PATH --dest URL [route options] \
        [--route PATH2 --dest URL [route options]] ...
```

### Global Options

| Flag | Description |
|------|-------------|
| `--config PATH` | Config file path. Pass `""` to disable config file loading. |
| `--listen ADDR` | IP address or interface name to listen on (default: all interfaces) |
| `--port PORT` | Port to listen on (default: `8080`) |
| `--tls-cert FILE` | TLS certificate file — enables HTTPS |
| `--tls-key FILE` | TLS key file — required when `--tls-cert` is set |
| `--global-auth USER:PASS` | HTTP Basic Auth for all routes |

### Route Options

Route options must follow `--route`. The `--route` + route options block can be repeated for multiple routes.

| Flag | Description |
|------|-------------|
| `--route PATH` | Route path prefix (e.g. `/api/`) |
| `--dest URL` | Upstream destination URL |
| `--noTLSverify` | Skip TLS certificate verification for this upstream |
| `--auth USER:PASS` | Per-route Basic Auth (overrides `--global-auth`) |
| `--auth ""` | Explicitly disable auth for this route |
| `--timeout DURATION` | Upstream request timeout (e.g. `30s`, `2m`) |
| `--add-header "Name: Value"` | Add or overwrite a header (repeatable) |
| `--delete-header NAME` | Delete a header (repeatable, supports wildcards) |

### Examples

```bash
# Basic proxy
routemux --route /api/ --dest http://localhost:3000/

# Multiple routes
routemux \
  --route /api/ --dest http://localhost:3000/ --timeout 30s \
  --route /app/ --dest http://localhost:8000/ --timeout 120s

# Global auth, public route
routemux \
  --global-auth admin:secret \
  --route /api/ --dest http://localhost:3000/ \
  --route /public/ --dest http://localhost:4000/ --auth ""

# Header manipulation
routemux \
  --route /api/ --dest http://localhost:3000/ \
  --add-header "X-Internal: true" \
  --delete-header "Cookie" \
  --delete-header "CF-*"

# HTTPS termination
routemux \
  --tls-cert /etc/ssl/cert.pem \
  --tls-key  /etc/ssl/key.pem \
  --port 443 \
  --route / --dest http://localhost:8080/
```

---

## Routing

Routes are matched by **longest prefix first**, so more specific paths always win:

```yaml
routes:
  /api/v2/:           # matched first for /api/v2/...
    dest: http://localhost:3001/
  /api/:              # matched for /api/... (not /api/v2/)
    dest: http://localhost:3000/
  /:                  # catch-all
    dest: http://localhost:8080/
```

The route prefix is stripped and the upstream base path is prepended:

```
Request:  GET /api/users/42
Route:    /api/ → dest: http://localhost:3000/v1/
Upstream: GET http://localhost:3000/v1/users/42
```

---

## Authentication

HTTP Basic Auth can be configured at two levels:

```yaml
global:
  global-auth: ["admin", "secret"]   # applies to all routes

routes:
  /api/:
    dest: http://localhost:3000/
    auth: ["apiuser", "apipass"]      # overrides global-auth for this route

  /public/:
    dest: http://localhost:4000/
    auth: []                          # disables auth for this route even with global-auth set
```

When proxy auth is active on a route, the `Authorization` header is **automatically stripped** before forwarding to the upstream — the upstream never sees the proxy credentials. You can still set your own `Authorization` header to the upstream via `add-header`.

---

## Header Manipulation

Headers are processed in this order for each request:

1. Proxy auth active → `Authorization` header deleted
2. `delete-header` patterns applied
3. `add-header` values set (always wins — runs last)

### Wildcards in `delete-header`

Wildcard patterns use `*` as a glob character:

```yaml
delete-header:
  - CF-*          # deletes CF-Ray, CF-Connecting-IP, CF-IPCountry, etc.
  - *-Secret      # deletes X-Secret, Api-Secret, etc.
  - X-*-Internal  # deletes X-Foo-Internal, X-Bar-Internal, etc.
```

Wildcard matching is **case-insensitive**.

> **Performance note:** routes with no wildcards take a fast path (direct map lookup per pattern). The wildcard path (iterating the header map) is only taken when at least one delete pattern contains `*`, and this is determined once at startup — not per request.

### Variables in `add-header`

Header values can reference request properties using `$variable` syntax. Variables are only resolved when at least one `add-header` value contains `$` — routes without variables take a zero-overhead fast path.

| Variable | Value |
|----------|-------|
| `$remote_addr` | Client IP address (no port) |
| `$remote_port` | Client port |
| `$scheme` | Request scheme — `http` or `https` |
| `$request_uri` | Full request URI including query string |
| `$header.Name` | Value of any client request header by name |
| `$header.Host` | Original client `Host` header |

Use `\$` to send a literal dollar sign (e.g. `\$remote_addr` → `$remote_addr`).

```yaml
routes:
  /api/:
    dest: http://localhost:3000/
    add-header:
      X-Real-IP:      $remote_addr          # client IP
      X-Real-Port:    $remote_port          # client port
      X-Scheme:       $scheme               # http or https
      X-Request-URI:  $request_uri          # full URI with query string
      X-Original-Host: $header.Host        # original Host header
      X-Original-UA:  $header.User-Agent   # copy any client header
      X-Literal:      \$remote_addr        # literal "$remote_addr"
    delete-header:
      - User-Agent    # deleted from upstream — but $header.User-Agent
                      # still captures the original value
```


### Special Headers

| Header | Behaviour |
|--------|-----------|
| `Host` | Passed through from client by default. `delete-header: Host` uses the upstream host. `add-header: Host: custom.example.com` sets a custom value. |
| `Authorization` | Passed through when no proxy auth. Stripped when proxy auth is active (to prevent credential leakage). |
| `X-Forwarded-For` | Built and appended per hop. `delete-header: X-Forwarded-For` suppresses it entirely. |
| `X-Forwarded-Host` | Set to the original client `Host` header. |
| `X-Forwarded-Proto` | Set to `http` or `https` based on the incoming connection. |

---

## TLS

### Serving HTTPS

```yaml
global:
  tls-cert: /path/to/cert.pem
  tls-key:  /path/to/key.pem
  port: 443
```

Both `tls-cert` and `tls-key` must be set together.

### Upstream TLS

When `dest` uses `https://`, RouteMUX verifies the upstream certificate by default. To skip verification (e.g. self-signed certs):

```yaml
routes:
  /api/:
    dest: https://internal-service/
    noTLSverify: true
```

---

## WebSocket

WebSocket connections are automatically detected and tunnelled — no special configuration needed. WebSocket routes support the same auth, header manipulation, and TLS options as HTTP routes.

The `timeout` setting is intentionally **not** applied to WebSocket connections since they are long-lived by design.

---

## X-Forwarded-For Details

RouteMUX builds the `X-Forwarded-For` chain correctly:

- If the client sends an existing `X-Forwarded-For`, the proxy's connecting IP is appended
- If the client sends none, the connecting IP is set as the initial value
- Go's `ReverseProxy` internally appends the client IP again after the Director runs — RouteMUX's `xffRoundTripper` removes that duplicate before the request hits the wire

To suppress `X-Forwarded-For` entirely:

```yaml
delete-header:
  - X-Forwarded-For
```

---

## Building

```bash
# Standard build
go build -o routemux .

# Cross-compile for Linux amd64
GOOS=linux GOARCH=amd64 go build -o routemux-linux-amd64 .

# Cross-compile for ARM (e.g. Raspberry Pi)
GOOS=linux GOARCH=arm64 go build -o routemux-linux-arm64 .

# Stripped binary (smaller)
go build -ldflags="-s -w" -o routemux .
```

---

## Running Tests

```bash
go test ./...
```

---

## License

MIT
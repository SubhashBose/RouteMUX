# RouteMUX

A lightweight, flexible, and easy configurable reverse proxy written in Go. Routes HTTP and WebSocket traffic to upstream destinations with virtual hosts and per-route configuration for authentication, header manipulation, TLS, timeouts, and weighted load-balancing to multiple upstreams. It is a high performance and multithreaded (thanks to Go) cross-platform server with small memory footprint.

## Features

- **Path-based routing** — forward different URL paths to different upstream services
- **Virtual host** - virtual host configuration to accept connection for multiple domain names, and forward to specific set of routes per domain
- **HTTP & WebSocket** — transparently proxies both HTTP and WebSocket connections
- **TLS termination** — serve HTTPS with your own certificate; connect to HTTPS upstreams with optional verification skip
- **HTTP Basic Auth** — global auth for all routes, per-route override, or explicit disable
- **Header manipulation** — add, overwrite, or delete upstream request headers per route, with wildcard support (`CF-*`, `X-*`) and variable interpolation (`${remote_addr}`, `${header.User-Agent}`, etc.)
- **Config file + CLI** — full configuration via `config.yml` as well as command-line flags, or combining both; CLI takes precedence.
- **Trusted proxy support** — `trust-client-headers` mode for deployments behind an upstream proxy
- **Load balancing** — weighted random or weighted round-robin across multiple upstream destinations
- **Static responses** — return a fixed HTTP status code and body directly from RouteMUX, no upstream needed
- **IP filter** — allow or block connections by IP address or CIDR range, loaded from inline values, local files, or remote URLs with optional periodic refresh
- **Zero external dependencies** - standalone binary available in 15 OS and architecture combinations.

---

## Download & Update

Download the appropriate binary from the [release](https://github.com/SubhashBose/RouteMUX/releases) section.

The installed binary can self update to the latest release version

```bash
routemux --upgrade
```

---

## Quick Start

```bash
# Forward /api/ to a local service
./routemux --route /api/ --dest http://localhost:3000/

# HTTPS termination
./routemux --tls-cert cert.pem --tls-key key.pem --route / --dest http://localhost:8080/

# With a config file
./routemux --config config.yml
```

Or using a config file `./routemux --config config.yml`


```yaml
# config.yml
routes:
  /api/:
    dest: http://localhost:3000/
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
  # trust-client-headers: true   # default: false
  # ip-filter:
  #   blocked:
  #     - 10.0.0.0/8
  #   allowed:
  #     - 192.168.0.0/16
  #     - 127.0.0.1
  #     - ::1
  #     - https://www.cloudflare.com/ips-v4 cache=./cachelist refresh=5h

vhosts:                                    
  - domains: ["example.com", "www.example.com"] # Hostname to match following routes group
    routes:
      /api/:
        dest: http://localhost:3000/v1/   # Upstream destination URL
        timeout: 30s                       # Optional upstream timeout (e.g. 30s, 2m)
        # noTLSverify: true                # Skip TLS certificate verification for upstream
        # auth: ["user", "pass"]           # Per-route auth (overrides global-auth)
        # auth: []                         # Explicitly disable auth for this route
        add-header:
          X-Proxy: RouteMUX               # Add or overwrite a header sent to upstream
          X-Built-URL: ${scheme}://${header.host}${request_uri} #combined text and variable
        delete-header:
          - Cookie                         # Delete a specific header
          - CF-*                           # Delete all headers matching wildcard

      /app/:
        dest: http://localhost:8000/
        timeout: 120s

      # Load-balanced route
      /lb/:
        dest:
          - http://localhost:4000/  weight=2
          - http://localhost:4001/  weight=1
        load-balancer-mode: round-robin   # or "random" (default)

      # Static response route
      /health/:
        dest: STATUS 200 healthy

  - domains: ["*"]                      # All other hostnames to match
    routes:
      "/":
        dest: STATUS 200 No matched domain
```

`vhost:` and `domains:` block/key can be omitted from config, only having routes as the root block, 
then all the defines routes belong to the default host `["*"]`, i.e, all hostnames.

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
| `--trust-client-headers`  | Trust X-Forwarded-* headers from client (default: false) |
| `--ip-filter-allow ENTRY` | Allow an IP, CIDR, file, or URL (repeatable) |
| `--ip-filter-block ENTRY` | Block an IP, CIDR, file, or URL (repeatable) |

### Vhost and Route

| Flag | Description |
|------|-------------|
| `--vhost DOMAINS` | Specify list of hostnames (e.g. `"domain.com\|www.domain.com"`) to group routes under it (repeatable). Default is `'*'` |
| `--route PATH` | Define a route (e.g. `/api/`) (repeatable under a vhost). If no preceding `--vhost` specified, then the routes are applied to `'*'`, i.e., all hosts |

### Route Options

Following are the route options must follow `--route`. The `--route` + route options block can be repeated for multiple routes under each `--vhost`.

| Flag | Description |
|------|-------------|
| `--dest URL` | Upstream destination (repeatable — multiple `--dest` flags with URL and optional weight=<N> create a load-balanced route). Use `STATUS <code> [text]` for a static response. |
| `--load-balancer-mode MODE` | Load balancer mode: `random` (default) or `round-robin` |
| `--noTLSverify` | Skip TLS certificate verification for this upstream |
| `--auth USER:PASS` | Per-route Basic Auth (overrides `--global-auth`) |
| `--auth ""` | Explicitly disable auth for this route |
| `--timeout DURATION` | Upstream request timeout (e.g. `30s`, `2m`) |
| `--add-header "Name: Value"` | Add or overwrite a header (repeatable). Value can be plain text, supported variables or combination of both |
| `--delete-header NAME` | Delete a header (repeatable, supports wildcards) |

### General flags

| Flag | Description |
|------|-------------|
| `--help, -h` | Display help information |
| `--upgrade` | Self update the RouteMUX binary to the latest release version |

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

# Header manipulation with wildcard and variables
routemux \
  --route /api/ --dest http://localhost:3000/ \
  --add-header "X-Internal: true" \
  --delete-header "Cookie" \
  --delete-header "CF-*" \
  --add-header 'X-Original-UA: ${header.User-Agent}' \
  --add-header 'X-Built-URL: ${scheme}://${header.host}${request_uri}'

# HTTPS termination
routemux \
  --tls-cert /etc/ssl/cert.pem \
  --tls-key  /etc/ssl/key.pem \
  --port 443 \
  --route / --dest http://localhost:8080/

# Load-balanced route
routemux \
  --route /api/ \
  --dest "http://localhost:3000/ weight=2" \
  --dest "http://localhost:3001/" \
  --load-balancer-mode round-robin

# Static response
routemux \
  --route /health/ --dest "STATUS 200 healthy" \
  --route /api/    --dest http://localhost:3000/

# Virtual hostname matching
routemux \
  --vhost 'example.com|www.example.com' \
    --route /health/ --dest "STATUS 200 healthy" \
    --route /app/ --dest --dest http://localhost:3000/ \
  --vhost '[*]'
    --route '/'  --dest http://localhost:3000/
```

---

## Virtual hosts

Multiple host names or domains can be specified, that can group multiple routes under it.

```yaml
vhosts:
  - domains: ["example.com", "www.example.com"]
    routes:
      /app/:
        dest: http://localhost:3001/
  - domains: ["host2.com"]
    routes:
      /api/:
        dest: https://localhost:8080/
  - domains: ["*"]
    routes:
      /:
        dest: STATUS 200 Hostname not configured
```


`vhost:` can be omitted entirely, with `routes:` block starting at root level of the YAML file, in such case all the routes will
be applied to default (`["*"]`) all hostnames, all incoming connections.

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

Header values can reference request properties using `${variable}` syntax, and multiple variable and text can be combined to form the value, i.e, `${var1}text${var2}`. Values are syntex parsed upfront when loading configuration. Variables are only resolved when at least one `add-header` is parsed to have variables — routes without variables take a zero-overhead fast path.

| Variable | Value |
|----------|-------|
| `${remote_addr}` | Client IP address (no port) |
| `${remote_port}` | Client port |
| `${scheme}` | Request scheme — `http` or `https` |
| `${request_uri}` | Full request URI including query string |
| `${header.Name}` | Value of any client request header by name |
| `${header.Host}` | Original client `Host` header |

Use `\${` to send a literal  sign (e.g. `\${remote_addr}` → `${remote_addr}`). Non-existent variable or unclosed `${` will be treated as plain string

```yaml
routes:
  /api/:
    dest: http://localhost:3000/
    add-header:
      X-Real-IP:       ${remote_addr}          # client IP
      X-Real-Port:     ${remote_port}          # client port
      X-Scheme:        ${scheme}               # http or https
      X-Request-URI:   ${request_uri}          # full URI with query string
      X-Original-Host: ${header.Host}          # original Host header
      X-Original-UA:   ${header.User-Agent}    # copy any client header
      X-Literal:       \${remote_addr}         # literal "$remote_addr"
      X-Built-URL:     ${scheme}://${header.host}${request_uri}  # combining variable and strings
      X-Text:          Plain text content
    delete-header:
      - User-Agent    # deleted from upstream — but ${header.User-Agent}
                      # still captures the original value
```


### Special Headers

| Header | Behaviour |
|--------|-----------|
| `Host` | Passed through from client by default. `delete-header: Host` uses the upstream host. `add-header: Host: custom.example.com` sets a custom value. |
| `Authorization` | Passed through when no proxy auth. Stripped when proxy auth is active (to prevent credential leakage). |
| `X-Forwarded-For` | Behaviour depends on `trust-client-headers` (see below). `delete-header: X-Forwarded-For` suppresses it entirely. |
| `X-Forwarded-Host` | Set to original client `Host` when `trust-client-headers: false`. Left untouched when `true`. |
| `X-Forwarded-Proto` | Set from actual TLS state when `trust-client-headers: false`. Left untouched when `true`. |

---

## Load Balancing

A route can proxy to multiple upstream destinations. RouteMUX selects an upstream for each request using the configured mode and weights.

```yaml
routes:
  /api/:
    dest:
      - http://localhost:3000/          # weight defaults to 1
      - http://localhost:3001/ weight=3 # gets 3x the traffic
      - http://localhost:3002/ weight=1
    load-balancer-mode: round-robin     # or "random" (default)
```

### Modes

| Mode | Behaviour |
|------|-----------|
| `random` (default) | Each request picks an upstream randomly, proportional to weight |
| `round-robin` | Requests cycle through upstreams in order, proportional to weight |

### Weights

The optional `weight=N` suffix on each dest entry controls relative traffic share. Omitting it defaults to `weight=1`. An upstream with `weight=3` receives three times as many requests as one with `weight=1`.

> **Single upstream:** when only one dest is configured, the picker is bypassed entirely — no random number or lock is involved, so there is zero overhead in this plain route.

---

## Static Responses (`STATUS`)

A route can return a fixed HTTP response directly from RouteMUX without forwarding to any upstream. Useful for health check endpoints, maintenance pages, or explicitly blocking paths.

```yaml
routes:
  /health/:
    dest: STATUS 200 healthy

  /maintenance/:
    dest: STATUS 503 Service Unavailable

  /ping/:
    dest: STATUS 204        # empty body
```

The format is `STATUS <code> [text]` where:
- `<code>` is any valid HTTP status code (100–599)
- `[text]` is an optional response body (empty is fine)

Auth still applies to STATUS routes — a route with `global-auth` or per-route `auth` will require credentials before returning the static response.

STATUS is only valid as a single `dest` string. Mixing STATUS with other upstreams in a list is an error.

---

## IP Filter

RouteMUX can allow or block incoming connections by IP address before any routing or authentication takes place. The filter is evaluated against the connecting IP (`r.RemoteAddr`) — not any forwarded header.

### Filter modes

| Configuration | Behaviour |
|---|---|
| `blocked` only | Allow all connections except those from blocked IPs |
| `allowed` only | Block all connections except those from allowed IPs |
| Both `allowed` and `blocked` | Allow only IPs that are in `allowed` **and not** in `blocked` — blocked always wins |
| Neither | No filtering — all connections pass through |

### Source formats

Each entry in `allowed` or `blocked` can be:

| Format | Example |
|---|---|
| Bare IP address (→ `/32` or `/128`) | `127.0.0.1`, `::1` |
| CIDR range | `10.0.0.0/8`, `2001:db8::/32` |
| Local file (one CIDR/IP per line) | `/etc/routemux/blocklist.txt` |
| Local file with polling | `/etc/routemux/blocklist.txt refresh=6h` |
| Remote URL | `https://example.com/blocklist` |
| Remote URL with refresh and cache | `https://example.com/blocklist refresh=12h cache=/var/cache/blocklist.txt` |

Files and URLs contain one IP or CIDR per line. Lines starting with `#` and blank lines are ignored.

The `refresh=` interval uses Go duration syntax: `30m`, `6h`, `24h`, etc. For file sources, RouteMUX polls the file's modification time — it only re-reads when the file has actually changed. For URL sources, RouteMUX re-fetches on the interval regardless.

The `cache=` option (URL sources only) persists the fetched list to a local file. On startup, if the URL fetch fails (e.g. no network), RouteMUX falls back to the cache file. On every successful fetch, the cache file is updated atomically.

### YAML configuration

```yaml
global:
  ip-filter:
    blocked:
      - 10.0.0.0/8                                          # CIDR range
      - 172.16.0.0/12
      - https://example.com/blocklist refresh=12h cache=/var/cache/bl.txt
    allowed:
      - 192.168.0.0/16
      - 127.0.0.1                                           # bare IP → /32
      - ::1                                                 # IPv6 loopback
      - /etc/routemux/allowlist.txt refresh=6h              # local file
```

> **Note:** when `listen` is set to `0.0.0.0` (or left blank), connections to any `127.x.x.x` address will appear to the server as coming from `127.0.0.1` due to how the Linux kernel handles loopback routing. Use `127.0.0.0/8` to cover all loopback addresses, or add `::1` for IPv6 loopback (`localhost` on many modern systems resolves to `::1` via `nss-myhostname`).

### CLI flags

```bash
# Block a range, allow specific IPs
routemux \
  --ip-filter-block 10.0.0.0/8 \
  --ip-filter-block 172.16.0.0/12 \
  --ip-filter-allow 192.168.0.0/16 \
  --ip-filter-allow 127.0.0.1 \
  --ip-filter-allow ::1 \
  --route / --dest http://localhost:3000/

# Allow list from a URL with refresh and persistent cache
routemux \
  --ip-filter-allow "https://example.com/allowlist refresh=12h cache=/tmp/al.txt" \
  --route / --dest http://localhost:3000/

# Allow list from a local file with polling
routemux \
  --ip-filter-block "/etc/blocklist.txt refresh=5m" \
  --route / --dest http://localhost:3000/
```

The `--ip-filter-allow` and `--ip-filter-block` flags are repeatable and accept the same formats as the YAML config.

### Unmatched connections

When a connection is blocked by the IP filter, RouteMUX closes the TCP connection immediately without sending any HTTP response — the same silent-close behaviour used for unmatched vhosts. The client sees a connection reset or EOF, with no information about why.

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

## Trusted Proxy Support (`trust-client-headers`)

By default, RouteMUX treats itself as the public entry point and does not trust `X-Forwarded-*` headers sent by clients. This is the safe default — a client could forge `X-Forwarded-For: 1.1.1.1` to spoof their IP or `X-Forwarded-Proto: https` to lie about the connection type.

When RouteMUX sits behind a trusted upstream proxy (e.g. a cloud load balancer, CDN, or another RouteMUX instance), set `trust-client-headers: true` to preserve the chain the upstream proxy already built.

### Behaviour comparison

| Header | `trust-client-headers: false` (default) | `trust-client-headers: true` |
|--------|------------------------------------------|-------------------------------|
| `X-Forwarded-For` | Discard client chain — set to connecting IP only | Append connecting IP to existing chain |
| `X-Forwarded-Host` | Set to original client `Host` header | Leave untouched |
| `X-Forwarded-Proto` | Set from actual TLS state of connection | Leave untouched |

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
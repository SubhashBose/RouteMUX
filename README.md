# RouteMUX

A lightweight, flexible, and easy configurable reverse proxy written in Go. Routes HTTP and WebSocket traffic to upstream destinations with virtual hosts and per-route configuration for authentication, header manipulation, TLS, timeouts, and weighted load-balancing to multiple upstreams. It is a high performance and multithreaded (thanks to Go) cross-platform server with small memory footprint.

## Features

- **[Path-based routing](#routing)** — forward different URL paths to different upstream services
- **[Virtual host](#virtual-hosts)** - virtual host configuration to accept connection for multiple domain names, and forward to specific set of routes per domain
- **[Config file + CLI](#configuration-file)** — full configuration via `config.yml` as well as command-line flags, or combining both; CLI takes precedence.
- **[HTTP & WebSocket](#websocket)** — transparently proxies both HTTP and WebSocket connections
- **[TLS termination](#tls)** — serve HTTPS with your own certificate; connect to HTTPS upstreams with optional verification skip
- **[HTTP Basic Auth](#authentication)** — global auth for all routes, per-route override, or explicit disable
- **[Header manipulation](#upstream-request-header-manipulation)** — add, overwrite, or delete headers per route for client response or upstream request, with wildcard support (`CF-*`, `X-*`) and variable interpolation (`${remote_addr}`, `${header.User-Agent}`, etc.)
- **[Load balancing](#load-balancing)** — weighted random or weighted round-robin across multiple upstream destinations
- **[Static responses](#static-responses-status)** — return a fixed HTTP status code and body directly from RouteMUX, no upstream needed
- **[Serve static file](#serving-static-file-file)** — serve a static file directly from RouteMUX with auto-detected content-type, no upstream needed
- **[Serve a directory](#serving-a-directory-file-browse)** — serve a whole directory as a file server, with optional directory listing
- **[JWT authentication](#jwt-authentication)** — validate JSON Web Tokens from a header or cookie, with per-route user authorisation
- **[IP filter](#ip-filter)** — allow or block connections by IP address or CIDR range, loaded from inline values, local files, or remote URLs with optional periodic refresh
- **[Trusted proxy support](#trusted-proxy-support)** — `trust-client-headers` global flag or per-IP `trusted-proxies` list (similar to IP filter) for selective proxy trust. A special header manipulation variable `${trusted_xff}` is available, that sets the real client IP after evaluating trusted proxies.
- **[Environment variable support](#environment-variable-support)** - environment variable substitution is globally supported in `config.yml` file using `${env.VARIABLE}`.
- **[Inbuilt support to run as daemon](#daemonizing-routemux)** - can run as daemon process, detached from terminal
- **[Graceful reload of configuration](#graceful-reload-of-configuration)** - can gracefully reload modified configuration, without interrupting ongoing connection or requiring server restart
- **Zero external dependencies** - standalone binary (~7 MB size) available in 15 OS and architecture combinations.

## Design philosophy

RouteMUX is designed to handle heavy concurrent connections efficiently, while minimizing race conditions, memory usage, and latency.
It offers several complex features (e.g., header manipulation, ip filter, trusted proxy) that inevitably introduce some additional overhead — ranging from tens of nanoseconds to a few milliseconds in latency, and a few tens of bytes of memory per connection. However, the core design philosophy ensures that a particular channel of process is not activated unless the related feature is enabled for the given route. For example, if there are multiple routes declared, and a particular route needs header values for `add-header` manipulation, then only connections for that route will keep a copy of header variables that can be reused for header manipulation, while connections for all other routes take the shortest path with minimum overhead. 

Therefore, RouteMUX pre-determines on startup for each route what process is necessary. As a result, having a feature available in RouteMUX will have no (negligible) overhead per connection if that route does not use the feature. For a most basic configuration like `routemux --route / --dest http://localhost:8080`, the connection throughput is most optimized and is as efficient as possible.

Some examples are:
- Headers manipulations syntax is parsed and stored in simple structure at the startup only
- Copy of header is only made if Header variables and header values are in use
- `trusted_xff` variable is evaluated using trusted proxy ip list only if it is being used
- Load balancing channel is activated only if multiple `dest` is declared for a route
- Environment variables are replaced only at the startup while parsing the config file.

Another design philosophy is to maintain 100% interoperability of configurations through CLI as well as config file. No matter how complex a config file looks like, it can be fully implemented through CLI, and vice-versa. However, this is not guarantee for all features to be added in future, although full effort will be made to maintain it like this. 

---

## Download & Update

Precompiled binaries for a wide range of platforms are available in the [release](https://github.com/SubhashBose/RouteMUX/releases) section.


| OS       | Architecture   | Download Link |
|----------|----------------|---------------|
| Linux    | AMD 64-bit     | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-linux-amd64) |
| Linux    | i386 32-bit    | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-linux-386) |
| Linux    | ARM 64-bit     | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-linux-arm64) |
| Linux    | ARM 32-bit     | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-linux-arm) |
| Linux    | RISC-V 64-bit  | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-linux-riscv64) |
| Windows  | AMD 64-bit     | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-windows-amd64.exe) |
| Windows  | i386 32-bit    | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-windows-386.exe) |
| Windows  | ARM 64-bit     | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-windows-arm64.exe) |
| Windows  | ARM 32-bit     | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-windows-arm.exe) |
| MacOS    | Apple Silicon  | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-darwin-arm64) |
| MacOS    | Intel 64-bit   | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-darwin-amd64) |
| FreeBSD  | AMD 64-bit     | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-freebsd-amd64) |
| FreeBSD  | i386 32-bit    | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-freebsd-386) |
| FreeBSD  | ARM 64-bit     | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-freebsd-arm64) |
| FreeBSD  | ARM 32-bit     | [Download](https://github.com/SubhashBose/RouteMUX/releases/latest/download/routemux-freebsd-arm) |


### Update

The binary can self update to the latest release version with the `--upgrade` flag.

```bash
./routemux --upgrade
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

# start as a daemon
./routemux --config config.yml start
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
  listen:           # IP address, interface name (e.g. 192.168.1.10, eth0, lo), or unix:/path.sock. Empty = all interfaces.
  port: 8080        # Port to listen on (default: 8080)
  # tls-cert: /path/to/cert.pem
  # tls-key:  /path/to/key.pem
  global-auth: ["admin", "s3cr3t"]   # HTTP Basic Auth applied to all routes
  # trust-client-headers: true    # (default: false) Trust X-Forwarded-* from all connections
  trusted-proxies:              # Trust X-Forwarded-* from these IPs only
    - 10.0.0.0/8
    - 172.16.0.0/12
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
        dest-add-header:
          X-Proxy: RouteMUX               # Add or overwrite a header sent to upstream
          X-Built-URL: ${scheme}://${header.host}${request_uri} #combined text and variable
        dest-del-header:
          - Cookie                         # Delete a specific header to upstream
          - CF-*                           # Delete all headers matching wildcard
        client-add-header:                 # Add or overwrite a header sent to client
          Access-Control-Allow-Origin: ${scheme}://${header.host}  
        client-del-header:                 # Delete header sent to client
          - CF-*

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

      # HTTP 302 redirection using static response and client header manipulation
      /redirect/:
        dest: STATUS 302 Redirection to new site
        client-add-header:
          Location: https://google.com
      
      # Serve static file with optional HTTP code and content-type
      /file/:
        dest: FILE 200 /var/www/index.html
        # Optional content-type specified, otherwise detected from file extension
        # dest: FILE 200 /var/www/data.json application/json

  - domains: ["*"]                      # All other hostnames to match
    routes:
      "/":
        dest: STATUS 200 No matched domain
```

`vhost:` and `domains:` block/key can be omitted from config, only having routes as the root block, 
then all the defined routes belong to the default host `["*"]`, i.e, all hostnames.

By default RouteMUX will strictly evaluate the YAML config file and report error for any unrecognized fields. This is done to avoid typographical errors, where an user may run the server with a missing configuration without noticing it. The strict validation of the YAML file can be disabled with command-line flag `--no-strict-yaml`, however, not recommended from security point-of-view. 

### Environment variable support

Environment variable substitution is globally supported in configuration file. `${env.VARIABLE}` can be used to access `VARIABLE` from system environment. An optional default value can be passed as `${env.VARIABLE:default}`. `\$` is used to escape as string literal (like `\${env.VAR}` → `${env.VAR}`). The variable substitution only happens during the initial parsing of YAML file.

```yaml
global:
  port: ${env.HTTP_PORT:8080}
  global-auth: ["${env.AUTH_USER}", "${env.AUTH_PASS}"]

routes:
  /:
    dest: ${env.UPSTREAM_SERVER}
    dest-add-header:
      ${env.HDR_KEY}: ${env.HDR_VALUE}
```

> Note an extreme edge case scenario: in `*-add-header` value, if intended value is string literal `\${env.blabla}`, the entry should be double escaped as `\\\${env.blabla}`, because variable parsing first happens during YAML file read, and then again when looking for header variable.

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
| `--jwt-header KEYWORD` | HTTP header containing the JWT token |
| `--jwt-cookie KEYWORD` | Cookie containing the JWT token (fallback) |
| `--jwt-claim-user KEY` | JWT claim to extract username from |
| `--jwt-secret SECRET` | HMAC secret or PEM public key for verification |
| `--jwt-jwk-url URL` | JWKS endpoint URL |
| `--jwt-aud AUDIENCE` | Expected audience claim |
| `--jwt-default-allow-all` | Allow any authenticated user on routes with no `auth-users` |
| `--global-auth USER:PASS` | HTTP Basic Auth for all routes |
| `--trust-client-headers`  | Trust X-Forwarded-* headers from client (default: false) |
| `--trusted-proxy ENTRY`   | Trust X-Forwarded-* headers from these IP/CIDR/file/URL list (repeatable) |
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
| `--dest URL` | Upstream destination (repeatable — multiple `--dest` flags with URL and optional weight=<N> create a load-balanced route). Use `STATUS <code> [text]` for a static response. Use `FILE [code] <path>` to serve a static file, or `FILE-BROWSE <dir>` to serve a directory. Use `unix:///sock:/path` or `unixs:///sock:/path` for Unix-socket upstreams. |
| `--load-balancer-mode MODE` | Load balancer mode: `random` (default) or `round-robin` |
| `--noTLSverify` | Skip TLS certificate verification for this upstream |
| `--auth USER:PASS` | Per-route Basic Auth (overrides `--global-auth`) |
| `--auth ""` | Explicitly disable auth for this route |
| `--timeout DURATION` | Upstream request timeout (e.g. `30s`, `2m`) |
| `--dest-add-header "Name: Value"` | Add or overwrite a header (repeatable). Value can be plain text, supported variables or combination of both |
| `--dest-del-header NAME` | Delete a header (repeatable, supports wildcards) |
| `--client-add-header "Name: Value"` | Add or overwrite a response header sent to client (repeatable). Supports same variables as `--dest-add-header`; `${header.Name}` resolves from the upstream response headers |
| `--client-del-header NAME` | Delete a header from the upstream response (repeatable, supports wildcards) |
| `--auth-users USER,...` | Comma-separated JWT usernames allowed on this route |
| `--skip-jwt-auth` | Skip JWT authentication for this route |

### Daemon commands

RouteMUX can be started as daemon (background process not attached to terminal) by appending `start` command to the cli arguments.

| Command | Description |
|--------|-------------|
| start  | Start RouteMUX as a daemon |
| watch-start | Start RouteMUX as daemon along with watchdog that monitors and restart the process on failure. Also creates a logfile to monitor process output and errors |
| stop   | Stop the daemon |
| restart | Restart the demon process |
| reload | Sends signal to RouteMUX daemon process to gracefully reload configuration from file. |
| status | Show the daemon status |

### General flags

| Flag | Description |
|------|-------------|
| `--help, -h` | Display help information |
| `--version` | Show RouteMUX version and build date |
| `--upgrade` | Self update the RouteMUX binary to the latest release version |
| `--no-strict-yaml` | Disable strict YAML parsing (allow unknown config keys) |
| `--validate` | Validate configuration and exit without serving |

### Daemonizing RouteMUX

RouteMUX can be started as daemon by appending `start` or `watch-start` command with other CLI arguments. Job control commands `stop`, `status`, `reload`, or `restart` can be used to control the daemon process. RouteMUX daemon job control works by identifying the process that was started from same working directory with same executable path, and under same user. This way, RouteMUX allows to have multiple daemon process with job control from multiple working directories, and multiple users.

`watch-start` is the recommended way to start the RouteMUX daemon, unlike simple `start`, this also starts a watchdog daemon that monitor the RouteMUX process. In event of server process failure, the watchdog will restart the process. Additionally, in this mode a logfile will be attached to the daemon, that can be monitored for output and errors. The logfile can be inspected as `tail -f /path/to/logfile-watchdog.log`.

Currently RouteMUX daemonizing feature only supports UNIX like (specifically POSIX) systems, and does not support Windows OS.

### Graceful reload of configuration

RoutuMUX can gracefully relaod configuration without requiring server restart or interrupting ongoing connections. The reload is triggered on config file change, or by daemon `reload` command, or by issuing SIGHUP signal to the running server process. On Windows, reload is only triggered by config file change. While reloading, if any error is encountered, then RouteMUX will report and continue to run with previous working version of the configuration.

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
  --dest-add-header "X-Internal: true" \
  --dest-del-header "Cookie" \
  --dest-add-header 'X-Original-UA: ${header.User-Agent}' \
  --dest-add-header 'X-Built-URL: ${scheme}://${header.host}${request_uri}' \
  --client-add-header 'Access-Control-Allow-Origin: ${scheme}://${header.host}' \
  --client-del-header "CF-*" \

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
Route:    /api/ → dest: http://localhost:3000/v1/
Request:  GET /api/users/42
Upstream: GET http://localhost:3000/v1/users/42
```

It is ensured that for any combinations of route and dest a double `//` is not created in upstream call. Various edge cases are carefully dealt, which are shown in tables below. The routes and dests with and without trailing `/` are dealt differently. There are edge cases depending upon upstream server and app behavior when these configurations might be required.

For the routes having trailing `/`:

| Route | Dest | Request | Upstream gets |
|---|---|---|---|
| `/api/` | `http://localhost:3000/v1/` | `GET /api/users/42` | `GET http://localhost:3000/v1/users/42` |
| | | `GET /api` | 301 Client redirect to `/api/` |
| | | `GET /api/` | `GET http://localhost:3000/v1/` |
| `/api/` | `http://localhost:3000/v1` | `GET /api/users/42` | `GET http://localhost:3000/v1/users/42` |
| | | `GET /api` | 301 Client redirect to `/api/` |
| | | `GET /api/` | `GET http://localhost:3000/v1` |


In case the the route does not have trailing slash (`/api`), it is treated as a special case, then two handlers are created having both with and without trailing slash (`/api` and subtree `/api/`). In such case, when creating subtree handler (`/api/`) the upstream(s) path is also checked and if there is no trailing slash (`v1`), a slash is appended (`v1/`).

Unless it has specific use case, it is generally recommended avoid routes with no trailing `/`, as two route handlers are created in such case, so memory consumption (albeit tiny) is doubled per such route. 

The behavior for routes without trailing `/`':   

| Route | Dest | Request | Upstream gets |
|---|---|---|---|
| `/api` | `http://localhost:3000/v1` | `GET /api/users/42` | `GET http://localhost:3000/v1/users/42` |
| | | `GET /api` | `GET http://localhost:3000/v1` |
| | | `GET /api/` | `GET http://localhost:3000/v1/` |
| `/api` | `http://localhost:3000/v1/` | `GET /api/users/42` | `GET http://localhost:3000/v1/users/42` |
| | | `GET /api` | `GET http://localhost:3000/v1/` |
| | | `GET /api/` | `GET http://localhost:3000/v1/` |

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

When proxy auth is active on a route, the `Authorization` header is **automatically stripped** before forwarding to the upstream — the upstream never sees the proxy credentials. You can still set your own `Authorization` header to the upstream via `dest-add-header`.

---

## JWT Authentication

RouteMUX can validate JSON Web Tokens (JWT) globally. When configured, every route requires a valid token unless it opts out with `skip-jwt-auth`.

```yaml
global:
  jwt-authentication:
    header-key: Authorization        # read token from this header (Bearer prefix is stripped if there)
    cookie-key: jwt_token            # fallback: read token from this cookie
    claim-user-key: sub              # claim to extract the username from (optional)
    secret: my-shared-secret         # HMAC secret or PEM public key
    jwk-url: https://issuer/.well-known/jwks.json   # JWKS endpoint (alternative to secret)
    aud-id: my-app                   # expected audience claim
    default-allow-all: false         # see authorisation rules below

routes:
  /admin/:
    dest: http://localhost:3000/
    auth-users: [alice, bob]         # only these JWT usernames may access this route

  /app/:
    dest: http://localhost:4000/     # any authenticated user (when default-allow-all: true)

  /health/:
    dest: STATUS 200 ok
    skip-jwt-auth: true              # no token required for this route
```

### Token source

At least one of `header-key` or `cookie-key` must be set. If both are set, the **header takes precedence**; the cookie is used only when the header is absent. A `Bearer ` prefix (if present) on the header value is stripped automatically.

### Verification

The token signature is verified using `secret` (HMAC or PEM public key) or `jwk-url` (a JWKS endpoint). If `aud-id` is set, the token's `aud` claim must also match.

- `secret` accepts shared key for token verification
- `jwk-url` accepts JWT keys URL in JSON Web Key Set (JWKS) format.
- if both `secret` and `jwk-url` is set, then `secret` takes precedence over the `jwk-url`. 
- If neither is set then based on 'iss' claim value RouteMUX will try to get JWK URL for Cloudflare or Auth0
  - If you do not set either of `secret` or `jwk-url`, and want RouteMUX to automatically get JWK URL from Cloudflare or Auth0, then you must set `aud-id`. This is a restriction from security standpoint, otherwise any configured app/tenant from Cloudflare or Auth0 will issue acceptable token for your setup.

### Authorisation

- If `claim-user-key` is **not set**, RouteMUX performs authentication only — any valid token is accepted on any route (that doesn't skip JWT).
- If `claim-user-key` **is set**, the username is extracted from that claim using this key, and checked against the route's `auth-users` list:
  - Username in `auth-users` → allowed.
  - `auth-users` empty/unset and `default-allow-all: true` → any authenticated user allowed.
  - `auth-users` empty/unset and `default-allow-all: false` → denied (code `403`).
  - `auth-users` is set, and username in not in list → denied (code `403`), irrespective of `default-allow-all` value
- If `skip-jwt-auth` is set for a route, then entire JWT verification and authorisation path is skipped for request coming to this route 

### Responses

- Missing or invalid token → `401 Unauthorized`.
- Valid token but user not authorised for the route → `403 Forbidden`.

### Combining with Basic Auth

JWT and HTTP Basic Auth can be used together. When both are configured, a request must satisfy **both** — JWT is checked first, then Basic Auth.

### CLI

```bash
routemux \
  --jwt-header Authorization \
  --jwt-cookie jwt_token \
  --jwt-claim-user sub \
  --jwt-secret my-shared-secret \
  --jwt-aud my-app \
  --jwt-default-allow-all \
  --route /admin/ --dest http://localhost:3000/ --auth-users alice,bob \
  --route /health/ --dest "STATUS 200 ok" --skip-jwt-auth
```

---

## Upstream Request Header Manipulation

In between Headers received from client and sent to upstream specified by `dest` can be manipulated.

Headers are processed in this order for each request:

1. Proxy auth active → `Authorization` header deleted
2. `dest-del-header` patterns applied
3. `dest-add-header` values set (always wins — runs last)

### Wildcards in `dest-del-header`

Wildcard patterns use `*` as a glob character:

```yaml
dest-del-header:
  - CF-*          # deletes CF-Ray, CF-Connecting-IP, CF-IPCountry, etc.
  - *-Secret      # deletes X-Secret, Api-Secret, etc.
  - X-*-Internal  # deletes X-Foo-Internal, X-Bar-Internal, etc.
```

Wildcard matching is **case-insensitive**.

> **Performance note:** routes with no wildcards take a fast path (direct map lookup per pattern). The wildcard path (iterating the header map) is only taken when at least one delete pattern contains `*`, and this is determined once at startup — not per request.

### Variables in `dest-add-header`

Header values can reference request properties using `${variable}` syntax, and multiple variable and text can be combined to form the value, i.e, `${var1}text${var2}`. Values are syntex parsed upfront when loading configuration. Variables are only resolved when at least one `dest-add-header` is parsed to have variables — routes without variables take a zero-overhead fast path.

| Variable | Value |
|----------|-------|
| `${host}` | Original client `Host` header value |
| `${remote_addr}` | Client IP address (no port) |
| `${remote_port}` | Client port |
| `${scheme}` | Client request scheme — `http` or `https` |
| `${request_uri}` | Full request URI including query string |
| `${trusted_xff}` | The remote IP after evaluating `trusted-proxies` and `trust-client-headers` on the `X-Forwarded-For` chain along with connecting IP  |
| `${header.Name}` | Value of any client request header by name |
| `${header.Host}` | Original client `Host` header |

Use `\${` to send a literal  sign (e.g. `\${remote_addr}` → `${remote_addr}`). Non-existent variable or unclosed `${` will be treated as plain string.

> `${trusted_xff}` value evaluates the trusted remote IP by looking up on the `X-Forwarded-For` header IP chain, appended with the connecting IP. Each of the IPs from the chain, starting from most recent to oldest (right to left), is checked against the `trusted-proxies` list, and the first untrusted IP sets the value. If all IPs are in `trusted-proxies`, or `trust-client-headers: true` then, the left most valid IP sets `${trusted_xff}`. If neither `trusted-proxies` nor `trust-client-headers` is set, then no IP is trusted, client IP (`${remote_addr}`) sets the variable. 
> 
> The purpose of `${trusted_xff}` is to do all the validation of real client IP, and provide this to the upstream server, which it can use without doing any more IP trust verification. It is important to note the `${trusted_xff}` variable is only available for `dest-add-header`, and not for `client-add-header`.

```yaml
routes:
  /api/:
    dest: http://localhost:3000/
    dest-add-header:
      X-Client-IP:     ${remote_addr}          # client IP
      X-Trusted-XFF:   ${trusted_xff}          # Real IP behind XFF header IP chain
      X-Real-Port:     ${remote_port}          # client port
      X-Scheme:        ${scheme}               # http or https
      X-Request-URI:   ${request_uri}          # full URI with query string
      X-Original-Host: ${header.Host}          # original Host header
      X-Original-UA:   ${header.User-Agent}    # copy any client header
      X-Literal:       \${remote_addr}         # literal "$remote_addr"
      X-Built-URL:     ${scheme}://${header.host}${request_uri}  # combining variable and strings
      X-Text:          Plain text content
    dest-del-header:
      - User-Agent    # deleted from upstream — but ${header.User-Agent}
                      # still captures the original value
```


### Special Headers

| Header | Behaviour |
|--------|-----------|
| `Host` | Passed through from client by default. `dest-del-header: Host` uses the upstream host. `dest-add-header: Host: custom.example.com` sets a custom value. |
| `Authorization` | Passed through when no proxy auth. Stripped when proxy auth is active (to prevent credential leakage). |
| `X-Forwarded-For` | Adds connecting IP. Behavior (overwrite or append) depends on `trust-client-headers` and `trusted-proxies` (see [below](#trusted-proxy-behavior)). `dest-del-header: X-Forwarded-For` suppresses it entirely. |
| `X-Forwarded-Host` | Set to original client `Host`. Left untouched when `trust-client-headers: true` or remote ip is in `trusted-proxies`. |
| `X-Forwarded-Proto` | Set from actual TLS (http/https) state. Left untouched when `trust-client-headers: true` or remote ip is in `trusted-proxies`. |

---

## Client Response Header Manipulation

In addition to manipulating headers sent **to** the upstream (`dest-add-header`, `dest-del-header`), RouteMUX can manipulate headers in the **response sent back to the client**.

Processing order per response:

1. `client-del-header` patterns applied to upstream response headers
2. `client-add-header` values set (always wins — runs last)

```yaml
routes:
  /api/:
    dest: http://localhost:3000/
    client-add-header:
      X-Served-By:   RouteMUX
      Cache-Control: no-store
      X-Client-IP:   ${remote_addr}          # client IP in the response
      X-Request-Host: ${host}                # original Host header
    client-del-header:
      - Server                               # remove server banner
      - X-Powered-By
      - X-Internal-*                         # wildcard: all X-Internal-* headers
```

### Variables in `client-add-header`

The same `${variable}` syntax as `dest-add-header`, with one difference:

| Variable | Value |
|----------|-------|
| `${host}` | Client `Host` header value |
| `${remote_addr}` | Client IP address (no port) |
| `${remote_port}` | Client port |
| `${scheme}` | Client request scheme — `http` or `https` |
| `${request_uri}` | Client request URI including query string |
| `${header.Name}` | Value of `Name` from the **upstream response** headers (not the client request headers) |

This means `${header.Content-Type}` in a `client-add-header` value resolves to the `Content-Type` the upstream sent back — useful for echo/transform patterns.

### Works with static (`STATUS`) and file (`FILE`) routes

`client-add-header` and `client-del-header` apply to STATUS and FILE routes too. Since there is no upstream response, `${header.Name}` resolves to an empty string.

```yaml
routes:
  /health/:
    dest: STATUS 200 healthy
    client-add-header:
      Cache-Control: no-store
      X-Served-By:   RouteMUX

  /maintenance/:
    dest: STATUS 503 Service Unavailable
    client-add-header:
      Retry-After: "3600"
  
  /redirect/:
    dest: STATUS 302 Redirection to new site
    client-add-header:
      Location: https://google.com
```

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

See also: [Static File Responses (`FILE`)](#serving-static-file-file) for serving a file instead of inline text.

---

## Serving static File (`FILE`)

A route can serve a static file directly from RouteMUX without forwarding to any upstream. The file is read from disk on every request, so updated content is served immediately without a reload. If the file is not found at request time, a `404 Not Found` is returned.

```yaml
routes:
  /page/:
    dest: FILE /path/to/index.html        # HTTP 200 (default)

  /maintenance/:
    dest: FILE 503 /path/to/maintenance.html

  /json/:
    dest: FILE /path/to/data.json

  /data/:
    dest: FILE /path/to/data.dat
    client-add-header:
      Content-Type: text/plain
```

The format is `FILE [code] <path>` where:
- `[code]` is an optional HTTP status code (100–599). Defaults to `200` if omitted.
- `<path>` is the path to the file to serve.

### Content-Type

The `Content-Type` header is **auto-detected** from the file extension:

| Extension | Content-Type |
|-----------|-------------|
| `.html`, `.htm` | `text/html; charset=utf-8` |
| `.txt`, `.log`, `.md` | `text/plain; charset=utf-8` |
| `.css` | `text/css; charset=utf-8` |
| `.js` | `application/javascript` |
| `.json` | `application/json` |
| `.xml` | `application/xml` |
| `.jpg`, `.jpeg` | `image/jpeg` |
| `.png` | `image/png` |
| `.gif` | `image/gif` |
| `.svg` | `image/svg+xml` |
| `.pdf` | `application/pdf` |
| `.zip` | `application/zip` |
| *(other)* | `application/octet-stream` |

To override the auto-detected content-type, use `client-add-header`: `Content-Type`:

```yaml
routes:
  /data/:
    dest: FILE /path/to/file.txt
    client-add-header:
      Content-Type: application/json
```

### CLI

```bash
# Serve a file with default 200 code
routemux --route /page/ --dest "FILE /path/to/index.html"

# Serve with explicit status code
routemux --route /maint/ --dest "FILE 503 /path/to/maintenance.html"

# Combine with other routes
routemux \
  --route /api/  --dest http://localhost:3000/ \
  --route /page/ --dest "FILE /var/www/index.html" \
  --route /health/ --dest "STATUS 200 healthy"
```

### Notes

- FILE is only valid as a single `dest` value. Mixing FILE with other upstreams in a list is an error.
- The file is read on every request — no restart or reload needed when the file changes.
- Auth (`global-auth`, per-route `auth`) still applies to FILE routes.
- `client-add-header` and `client-del-header` work on FILE routes.


---

## Serving a directory (`FILE` or `FILE-BROWSE`)

A route can serve an entire directory as a file server. Use `FILE` for a directory to serve files without a directory listing, or `FILE-BROWSE` to enable directory listings.

```yaml
routes:
  /static/:
    dest: FILE-BROWSE /var/www/static   # directory listing enabled

  /assets/:
    dest: FILE /var/www/assets          # listing disabled (serves files + index.html only)
```

The route prefix is stripped and the remainder is mapped onto the directory:

| Request | Served from |
|---------|-------------|
| `GET /static/` | directory listing (FILE-BROWSE) or `index.html` |
| `GET /static/app.js` | `/var/www/static/app.js` |
| `GET /static/css/main.css` | `/var/www/static/css/main.css` |

### Listing behaviour

- **`FILE-BROWSE <dir>`** — directory listing is shown when no `index.html` is present.
- **`FILE <dir>`** — directory listing is disabled. A request for a directory returns `index.html` if present, otherwise `403 Forbidden`. Individual files are always served.

### Features

Directory serving uses Go's built-in file server, which provides:

- Automatic `Content-Type` detection
- `ETag` / `Last-Modified` headers and `304 Not Modified` responses for browser caching
- HTTP range requests (resumable downloads, media streaming)

### Notes

- A status code supplied with a directory path (e.g. `FILE-BROWSE 404 /dir`) is **ignored** and a warning is logged — the file server sets the status itself.
- `client-add-header`, `client-del-header`, and the `Via: RouteMUX` header apply to directory routes.
- Auth (`global-auth`, per-route `auth`, JWT) applies to directory routes.

### CLI

```bash
# Serve a directory with listing
routemux --route /static/ --dest "FILE-BROWSE /var/www/static"

# Serve a directory without listing
routemux --route /assets/ --dest "FILE /var/www/assets"
```


---

## Unix Domain Sockets

RouteMUX can listen on a Unix socket and forward to upstreams over Unix sockets.

### Listening on a Unix socket

Set `listen` to a `unix:` address (the `port` is ignored):

```yaml
global:
  listen: unix:/var/run/routemux.sock
```

Both `unix:/path.sock` and `unix:///path.sock` forms are accepted. A stale socket file from an unclean shutdown is removed automatically before binding.

### Upstreams over a Unix socket

Use a `unix://` (plain HTTP) or `unixs://` (TLS) dest. The socket path and the upstream HTTP path are separated by a colon:

```yaml
routes:
  /api/:
    dest: unix:///var/run/backend.sock:/v1/      # HTTP over the socket, upstream path /v1/

  /secure/:
    dest: unixs:///var/run/secure.sock:/api/     # TLS over the socket
```

The format is `unix://<socket-path>:<http-path>`; the HTTP path defaults to `/` if omitted. Unix-socket upstreams can be mixed with TCP upstreams and used in load-balanced routes.

**Note on TLS (`unixs://`):** because the connection targets a socket file rather than a hostname, the upstream certificate's hostname cannot be verified — the socket itself is the trust boundary. RouteMUX therefore skips hostname verification for `unixs://` upstreams.

### CLI

```bash
# Listen on a socket, forward to a TCP backend
routemux --listen unix:/var/run/routemux.sock --route / --dest http://localhost:3000/

# Listen on TCP, forward to a socket backend
routemux --port 8080 --route /api/ --dest "unix:///var/run/backend.sock:/v1/"
```

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

The `refresh=` interval uses Go duration syntax: `30m`, `6h`, `24h`, etc. For file sources, RouteMUX polls the file's modification time — it only re-reads when the file has actually changed. For URL sources, RouteMUX re-fetches on the interval regardless. Timeout for URL fetch is 10s.

The `cache=` option (URL sources only) persists the fetched list to a local file. On startup, if cache exists, RouteMUX uses the cache without waiting for URL fetch, and URL is refreshed in background while server is ready. This prevents delay in startup if URL is slow or unavailable (e.g. no network). If no cache available on startup, then RouteMUX waits for the URL to be fetched before it starts listening. On every successful fetch, the cache file is updated atomically.

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

## Trusted Proxy Support

By default, RouteMUX treats itself as the public entry point and does not trust `X-Forwarded-*` headers sent by clients. This is the safe default — a client could forge `X-Forwarded-For: 1.1.1.1` to spoof their IP or `X-Forwarded-Proto: https` to lie about the connection type.

RouteMUX offers two ways to enable trusted proxy behaviour:

### Option 1 — `trust-client-headers: true` (global)

Trusts `X-Forwarded-*` from **all** connecting clients. Use this only when RouteMUX is always behind a single trusted proxy such as a CDN or load balancer.

```yaml
global:
  trust-client-headers: true
```

### Option 2 — `trusted-proxies` (per-IP)

Trusts `X-Forwarded-*` only from specific IP addresses or ranges. Connections from other IPs are treated as untrusted — their forwarded headers are discarded. This is the safer choice when the proxy IP is known.

```yaml
global:
  trusted-proxies:
    - 10.0.0.0/8                        # internal load balancer range
    - 172.16.0.0/12
    - https://example.com/proxy-ips refresh=12h cache=/tmp/proxies.txt
```

CLI equivalent (repeatable, same entry formats as `--ip-filter-allow`):

```bash
routemux   --trusted-proxy 10.0.0.0/8   --trusted-proxy 172.16.0.0/12   --route / --dest http://localhost:3000/
```

The `trusted-proxies` list supports the same entry formats as `ip-filter`: bare IPs, CIDRs, local files, and remote URLs with optional `refresh=` and `cache=` options.

### <a name="trusted-proxy-behavior"></a>Behaviour comparison

| Header | Default (untrusted) | Trusted (`trust-client-headers` or `trusted-proxies` match) |
|--------|---------------------|--------------------------------------------------------------|
| `X-Forwarded-For` | Discard client chain — set to connecting IP only | Append connecting IP to existing chain |
| `X-Forwarded-Host` | Set to original client `Host` header | Leave untouched |
| `X-Forwarded-Proto` | Set from actual TLS state of connection | Leave untouched |

> **Security note:** `trust-client-headers: true` trusts every connecting client unconditionally. Prefer `trusted-proxies` with explicit IP ranges when possible, so spoofed `X-Forwarded-*` headers from direct clients are always discarded.

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
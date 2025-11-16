## acl-proxy — Minimal Path‑ and IP‑Aware URL Filter Proxy

Small HTTP/HTTPS proxy that enforces allow/deny rules on full URLs (scheme + host + path) and optional ingress client IP subnets (IPv4). HTTPS interception is supported transparently or via CONNECT. Uses a self-signed CA certificate to generate a certificate for the target domain.

### Features
- Path‑aware URL policy with ordered rules (first match wins)
- Ingress client subnet rules (IPv4 CIDR) for source-based allow/deny
- HTTP and HTTPS support; optional transparent HTTPS listener
- Auto‑reloads config on SIGHUP or file change
- Structured policy‑decision logging (allows/denies)
- Built‑in CA generation and per‑host certs via SNI

### Limitations
- No HTTP/2 streaming support today (HTTP/1.1 only)
- No body/content filtering (URL and headers only)
- No WebSocket or CONNECT tunneling beyond HTTPS MITM
- No native IPv6 policy or subnet support yet (client matching is IPv4-only)

### Roadmap
- HTTP/2 streaming and upgrade handling
- Pluggable content filtering rules (body inspection)
- IPv6 support for client and upstream connections (including IPv6-aware subnet rules)

## Quick Start
- Install dependencies: `npm install`
- Start the proxy: `npm start`
- Defaults: HTTP `0.0.0.0:8881`, HTTPS `0.0.0.0:8889` (transparent TLS listener enabled when `httpsPort` is set)

## Configuration
- File: `config/acl-proxy.json`
- Default action + ordered rules; first match wins
- Optional HTTPS listener for client‑>proxy TLS: set `proxy.httpsPort` (uses auto‑generated CA certs)
- Patterns support simple globs across the full URL:
  - `https://example.com/**`
  - `https://*.example.com/**`
  - `https://example.com/group/*/project`

Each rule can match on URL pattern, client subnet, or both:
- `pattern`: glob-style match on the normalized full URL (`https://host/path?query`)
- `subnets`: list of IPv4 CIDR blocks (e.g. `"10.0.0.0/8"`, `"192.168.1.0/24"`)
  - When only `pattern` is set, the rule ignores client IP (existing behavior).
  - When only `subnets` is set, the rule applies to any URL from clients in those subnets.
  - When both are set, the URL and client IP must both match for the rule to apply.
  - At least one of `pattern` or `subnets` must be provided for each rule; invalid IPv4 CIDR values cause config load to fail.

Examples:

```json
{
  "policy": {
    "default": "deny",
    "rules": [
      // Allow only from an internal subnet regardless of URL
      { "action": "allow", "subnets": ["10.0.0.0/8"] },

      // Deny a sensitive API for a specific office range
      { "action": "deny", "pattern": "https://api.internal.example.com/**", "subnets": ["192.168.10.0/24"] },

      // Allow two subnets for all GitHub traffic
      { "action": "allow", "pattern": "https://github.com/**", "subnets": ["10.1.0.0/16", "10.2.0.0/16"] }
    ]
  }
}
```

### Macro Rulesets (templated rules)
You can define reusable rule templates and expand them with lists of values. This is useful when you have many similar allow/deny rules that vary by a parameter (e.g., GitLab repositories).

- Define `policy.macros` as named lists (e.g., `repo`)
- Define `policy.rulesets` as arrays of rule templates using placeholders like `{repo}`
- In `policy.rules`, include a ruleset. Placeholders auto-bind to macros of the same name (use `with` only to override or inject custom values)

Encoding variants:
- `{name}` – raw value in templates
- `addUrlEncVariants`: controls URL-encoded duplicates during expansion
  - `true` – for every placeholder used in the rule/ruleset include, generate both raw and URL-encoded variants
  - `["repo", ...]` – generate encoded duplicates only for the listed placeholders
  - Example: `user/ts-test-1` also expands to `user%2Fts-test-1`

Example:

```json
{
  "policy": {
    "default": "deny",
    "macros": {
      "repo": ["user/ts-test-1", "user/ts-test-2"]
    },
    "rulesets": {
      "gitlabRepo": [
        { "action": "allow", "pattern": "https://gitlab.internal/api/v4/projects/{repo}?**" },
        { "action": "allow", "pattern": "https://gitlab.internal/api/v4/projects/{repo}/**" },
        { "action": "allow", "pattern": "https://gitlab.internal/api/v4/projects/{repo}" },
        { "action": "allow", "pattern": "https://gitlab.internal/{repo}/**" },
        { "action": "allow", "pattern": "https://gitlab.internal/{repo}.git/**" }
      ]
    },
    "rules": [
      { "include": "gitlabRepo", "addUrlEncVariants": true }
    ]
  }
}
```

Updating the `repo` list automatically expands all templates in the `gitlabRepo` ruleset for each repo value.

### Direct Rule Interpolation
Placeholders can also be used directly in `policy.rules` without using a ruleset. Placeholders auto-bind to macros of the same name, and you can still use `addUrlEncVariants` at the rule level.

```json
{
  "policy": {
    "default": "deny",
    "macros": {
      "gitlab_prefix": "https://gitlab.internal",
      "repo": ["user/ts-test-1", "user/ts-test-2"]
    },
    "rules": [
      { "action": "allow", "pattern": "{gitlab_prefix}/api/v4/projects/{repo}?**", "addUrlEncVariants": ["repo"] },
      { "action": "allow", "pattern": "{gitlab_prefix}/{repo}.git/**" }
    ]
  }
}
```

Notes:
- Macros can be a single string (e.g., `gitlab_prefix`) or a list (e.g., `repo`).
- When a macro is a list, rules expand across all values (cartesian product across multiple placeholders).
- Strict validation: Every placeholder used in a rule or ruleset must be provided via `with` or exist in `policy.macros`. If a required macro is missing, the configuration fails to load. On live reload, the proxy keeps the previous working policy and logs an error.

### URL-Encoding Variant Expansion (2^N)
When `addUrlEncVariants` is enabled, the proxy produces both raw and URL-encoded variants for the selected placeholders. If you enable it for N placeholders, the expansion produces up to 2^N combinations (raw/encoded for each). Use this to cover APIs that expect encoded identifiers (e.g., GitLab project paths) without duplicating templates.

Example configuration (default deny, then allow specific paths; HTTPS listener enabled):

```json
{
  "proxy": {
    "bindAddress": "0.0.0.0",
    "port": 8881,
    "httpsBindAddress": "0.0.0.0",
    "httpsPort": 8889
  },
  "policy": {
    "default": "deny",
    "rules": [
      { "action": "allow", "pattern": "https://example.com/**" }
    ]
  },
  "logging": { "level": "info", "directory": "./logs" },
  "certificates": { "certsDir": "./certs" }
}
```

### Config Reload
The proxy automatically reloads configuration without restarting:
- On `SIGHUP` to the process
- When the config file changes on disk (e.g., editing `config/acl-proxy.json`)

On reload:
- Logging configuration is re‑applied (levels, destinations, policy decision logging)
- URL policy configuration is rebuilt and takes effect for new requests
- The proxy logs a summary of the compiled URL policy (default action and rules count) at info level, and the full expanded rule list at debug level

### Policy Decision Logging (allows/denies)
Configure under `logging.policyDecisions`:

```json
"logging": {
  "level": "info",
  "directory": "./logs",
  "policyDecisions": {
    "logAllows": false,
    "logDenies": true,
    "levelAllows": "info",
    "levelDenies": "warn"
  }
}
```

When enabled, the proxy logs a structured entry for each decision, including URL, method, client IP, matched rule action/pattern, and the default action used if no rule matched.

### Capture Logging (requests/responses)
Use the top-level `capture` section to write full request/response payloads (between client and proxy) as individual JSON files:

```json
"capture": {
  "allowed_request": false,
  "allowed_response": false,
  "denied_request": false,
  "denied_response": false
}
```

Behavior:
- All flags default to `false` (no capture).
- When enabled, each relevant event generates a JSON file under the capture/logging directory (default `./logs`, or `logging.directory`, or `capture.directory` if set).
- Default filenames are `<requestId>-req.json` for requests and `<requestId>-res.json` for responses. You can override via `capture.filename` with placeholders `{requestId}`, `{kind}`, and `{suffix}` (where `{suffix}` is `req` or `res`).
- Each JSON file contains: `timestamp`, `requestId`, `kind` (`request`/`response`), `decision` (`allow`/`deny`), `mode` (`http_proxy`/`https_connect`/`https_transparent`), full URL, method, HTTP version, client host/port, optional target host/port, headers, status code (for responses), and body encoded as base64 (`encoding`, `length`, `data`, and `contentType`).

### Capture CLI: extract-capture-body

This repo includes a small helper CLI to extract and decode captured bodies from a single JSON capture file produced by the proxy:

- Source: `src/cli/extract-capture-body.ts`
- Built output: `dist/cli/extract-capture-body.js`

The CLI:
- Accepts a single argument: the path to a JSON capture file (e.g. `logs-capture/<request-id>-res.json`)
- Parses the JSON, looks for a `body` with `encoding: "base64"` and decodes `data` to bytes
- Writes the raw decoded bytes to stdout

Example usage after building:

```bash
npm run build
node dist/cli/extract-capture-body.js logs-capture/<request-id>-res.json > body.bin
```

There is also a `bin` entry in `package.json`:

```json
"bin": {
  "extract-capture-body": "dist/cli/extract-capture-body.js"
}
```

This entry tells npm that the package exposes a command named `extract-capture-body`. After running `npm install` in this repo, you can invoke it via the local binary:

```bash
npm run build
npx extract-capture-body logs-capture/<request-id>-res.json > body.bin
```

If the package is installed globally or published, the same `bin` entry allows running `extract-capture-body` directly from the shell.

### Loop Protection
Use `loopProtection` to detect and prevent proxy request loops by tagging outbound requests with a header and rejecting any request that already carries that header:

```json
"loopProtection": {
  "enabled": true,
  "addHeader": true,
  "headerName": "x-acl-proxy-request-id"
}
```

Behavior:
- When `enabled` (default `true`) and `addHeader` is `true` (default), the proxy adds `headerName` with the current request ID to all outbound HTTP and HTTPS requests (`http_proxy`, `https_connect`, and `https_transparent` paths).
- If an incoming request already contains `headerName`, the proxy treats it as a loop and immediately responds with HTTP `508 Loop Detected` and a JSON body:
  - `{"error": "LoopDetected", "message": "Proxy loop detected via loop protection header"}`
- Loop detection is always disabled when `enabled` is explicitly set to `false`. Setting `addHeader` to `false` keeps detection enabled but stops adding the header to outbound requests (useful when another proxy in the chain is responsible for tagging).

### Environment Overrides
- `PROXY_PORT` – override listen port
- `PROXY_HOST` – override bind address
- `LOG_LEVEL` – logging level
- `ACL_PROXY_CONFIG` – custom config file path

## Certificates and HTTPS
Configure via the `certificates` section in the config file:
- `certsDir`: Directory for certificates (defaults to `./certs`)
- `caKeyPath`: Optional path to CA private key (if specified, must exist)
- `caCertPath`: Optional path to CA certificate (if specified, must exist)

Behavior:
- If CA paths are not specified: The proxy auto‑generates a CA on first run in `certsDir`
- If CA paths are specified but missing: The proxy fails fast with an error (no auto‑generation)
- Dynamic per‑domain certificates are stored in `<certsDir>/dynamic/`

Example with custom CA location:

```json
{
  "certificates": {
    "certsDir": "/data/certs",
    "caKeyPath": "/etc/ssl/private/my-ca-key.pem",
    "caCertPath": "/etc/ssl/certs/my-ca-cert.pem"
  }
}
```

### HTTPS Notes
- One CA certificate is used for all HTTPS interception (MITM + HTTPS listeners)
- Egress MITM: Generates dynamic certs signed by the CA to inspect HTTPS paths via CONNECT
- Transparent HTTPS: If clients connect to `httpsPort`, the proxy uses SNI to generate per‑host certificates
- Install the CA certificate (`ca-cert.pem`) in client browsers/systems to trust the proxy

Some CLI tools and SDKs will not trust a self‑signed or locally generated CA by default. When running behind `acl-proxy`, you may need to point them at the proxy CA certificate or relax verification in test environments:

```bash
export NPM_CONFIG_CAFILE=/usr/local/share/ca-certificates/proxy-ca.crt
export REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/proxy-ca.crt
export NODE_TLS_REJECT_UNAUTHORIZED=0  # test/dev only
```

Notes:
- `NPM_CONFIG_CAFILE` helps Node/npm-based tooling trust the proxy CA.
- `REQUESTS_CA_BUNDLE` is honored by many Python tools using `requests`/`urllib3`.
- `NODE_TLS_REJECT_UNAUTHORIZED=0` disables TLS verification and should only be used temporarily in non-production environments.

## Client Usage
- Configure your HTTP/HTTPS proxy client as `http://<host>:8881`
- Requests are allowed or denied based on the full URL (including path)

For some HTTP clients that default to HTTP/2, forcing HTTP/1.1 can improve compatibility with `acl-proxy`. For example, Cursor’s CLI agent can be configured to use HTTP/1 when talking through the proxy by adding the following to `$HOME/.cursor/cli-config.json`:

```json
{
  "network.useHttp1ForAgent": true
}
```

## Running AI tools inside Podman/Docker

You can run tools like `cursor-agent`, `codex`, or `claude-code` inside a Podman (or Docker) container and transparently force all outbound HTTP/HTTPS traffic through `acl-proxy` using `iptables`.

At a high level:
- The proxy runs on the host (e.g. HTTP transparent listener `8880`, HTTPS transparent listener `8888`).
- The container:
  - Trusts the proxy’s CA certificate.
  - Uses an entrypoint script to install `iptables` rules that DNAT outbound port 80/443 to the proxy.
  - Is started with additional network capabilities so `iptables` can run (e.g. `--cap-add=NET_ADMIN` for Docker/Podman).

### Sample Dockerfile (Podman-compatible)

```dockerfile
FROM node:lts

# AI CLI tools
RUN npm install -g @openai/codex@latest
RUN npm install -g @anthropic-ai/claude-code@latest
RUN curl https://cursor.com/install -fsS | bash
RUN cp -r /root/.local/* /usr/local/
RUN ln -sfn "$(readlink -n /usr/local/bin/cursor-agent | sed 's#^/root/.local#/usr/local#')" /usr/local/bin/cursor-agent

# general
RUN apt update
RUN apt install --no-install-recommends jq vim curl tzdata sudo ripgrep ca-certificates iptables -y
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
ENV TZ=America/Chicago
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/timezone && echo $TZ > /etc/timezone
ENV TERM=xterm-256color

# for agents
RUN ln -sf /usr/bin/python3 /usr/bin/python

# needed to run iptables in entrypoint.sh
RUN echo "ALL ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/nopasswd \
    && chmod 440 /etc/sudoers.d/nopasswd

# acl-proxy certificates
COPY proxy-ca.crt /usr/local/share/ca-certificates/proxy-ca.crt
RUN update-ca-certificates

# default working directory
WORKDIR /workspace

# copy iptables script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
```

### Sample `entrypoint.sh`

```bash
#!/bin/bash

PROXY_IP=$(getent hosts host.containers.internal | awk '{print $1}')
PROXY_PORT=8880   # transparent MITM HTTP
PROXY_SPORT=8888  # transparent MITM HTTPS

#
# ===== NAT TABLE (redirect only 80/443 through your proxy) =====
#

# Safety: don’t nat loopback or proxy
sudo iptables -t nat -A OUTPUT -d 127.0.0.0/8 -j RETURN
sudo iptables -t nat -A OUTPUT -p tcp -d ${PROXY_IP} --dport ${PROXY_PORT} -j RETURN
sudo iptables -t nat -A OUTPUT -p tcp -d ${PROXY_IP} --dport ${PROXY_SPORT} -j RETURN

# Redirect outbound HTTP/HTTPS to proxy
sudo iptables -t nat -A OUTPUT -p tcp --dport 80  -j DNAT --to-destination ${PROXY_IP}:${PROXY_PORT}
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination ${PROXY_IP}:${PROXY_SPORT}

#
# ===== FILTER TABLE (actual accept/deny rules) =====
#

# Allow loopback
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Allow DNS (UDP + TCP port 53)
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow traffic to the proxy (after NAT)
sudo iptables -A OUTPUT -p tcp -d ${PROXY_IP} --dport ${PROXY_PORT} -j ACCEPT
sudo iptables -A OUTPUT -p tcp -d ${PROXY_IP} --dport ${PROXY_SPORT} -j ACCEPT

# Then deny everything else
sudo iptables -A OUTPUT -j DROP

# Remove sudo
sudo rm /etc/sudoers.d/nopasswd

# Run original command
exec "$@"
```

### Running with Podman or Docker

- Start `acl-proxy` on the host with transparent listeners matching `PROXY_PORT` / `PROXY_SPORT` used above.
- Build the image:
  - `podman build -t ai-tools .`
  - or `docker build -t ai-tools .`
- Run the container with the required network capability so `iptables` can update the `nat` and `filter` tables, for example:
  - Podman: `podman run --cap-add=NET_ADMIN --rm -it ai-tools bash`
  - Docker: `docker run --cap-add=NET_ADMIN --rm -it ai-tools bash`

Notes:
- The example uses `host.containers.internal` (Podman on Linux); for Docker you may need `host.docker.internal` or an explicit `--add-host` entry pointing at the proxy host.
- Once running, all outbound HTTP/HTTPS traffic from the container is forced through `acl-proxy` and subject to its URL and subnet rules.
- The Dockerfile and entrypoint are examples; you can adapt them to your tooling stack as long as the same NAT/filter pattern and capabilities are preserved.

### Matching `acl-proxy` configuration for transparent ports

To pair with the `PROXY_PORT=8880` / `PROXY_SPORT=8888` values used in the container `entrypoint.sh`, configure `acl-proxy` on the host with matching HTTP and transparent HTTPS listeners:

```json
{
  "proxy": {
    "bindAddress": "0.0.0.0",
    "port": 8880,
    "httpsBindAddress": "0.0.0.0",
    "httpsPort": 8888
  },
  "policy": {
    "default": "deny",
    "rules": [
      { "action": "allow", "pattern": "https://example.com/**" }
    ]
  },
  "logging": {
    "level": "info",
    "directory": "./logs"
  },
  "certificates": {
    "certsDir": "./certs"
  }
}
```

With this setup:
- Plain HTTP traffic DNATed to port `8880` is handled by the HTTP listener in transparent mode (the proxy reconstructs the full URL from `Host` and path).
- HTTPS traffic DNATed to port `8888` terminates on the transparent TLS listener (`httpsPort`), which uses SNI and the proxy CA to perform MITM and apply the same URL policy.

## License
MIT

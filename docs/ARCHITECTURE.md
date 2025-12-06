# ACL Proxy Architecture

This document provides a detailed technical overview of the acl-proxy codebase, including data flow diagrams, module relationships, and internal object structures.

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Module Organization](#module-organization)
3. [Request Processing Flow](#request-processing-flow)
4. [Configuration System](#configuration-system)
5. [Policy Engine](#policy-engine)
6. [Certificate Management](#certificate-management)
7. [External Authentication](#external-authentication)
8. [Capture System](#capture-system)

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ACL Proxy Server                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────┐     ┌─────────────────────┐                       │
│  │   HTTP Listener     │     │  HTTPS Transparent  │                       │
│  │   (port 8881)       │     │  Listener (8889)    │                       │
│  │                     │     │                     │                       │
│  │  • Plain HTTP proxy │     │  • TLS termination  │                       │
│  │  • CONNECT tunnels  │     │  • SNI-based certs  │                       │
│  └──────────┬──────────┘     └──────────┬──────────┘                       │
│             │                           │                                   │
│             └───────────┬───────────────┘                                   │
│                         │                                                   │
│                         ▼                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      SharedAppState (ArcSwap)                        │   │
│  │  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────────┐  │   │
│  │  │   Config    │ │ PolicyEngine │ │ CertManager  │ │ HttpClient  │  │   │
│  │  └─────────────┘ └──────────────┘ └──────────────┘ └─────────────┘  │   │
│  │  ┌─────────────┐ ┌──────────────┐ ┌──────────────────────────────┐  │   │
│  │  │   Logging   │ │ LoopProtect  │ │     ExternalAuthManager      │  │   │
│  │  └─────────────┘ └──────────────┘ └──────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                            ┌─────────────────┐
                            │ Upstream Server │
                            │  (Internet)     │
                            └─────────────────┘
```

---

## Module Organization

```
acl_proxy (lib.rs)
├── app.rs              # Application state management
│   ├── AppState        # Holds all runtime components
│   └── SharedAppState  # Arc<ArcSwap<AppState>> for hot reload
│
├── cli/mod.rs          # Command-line interface
│   ├── Cli             # Argument parsing (clap)
│   ├── run()           # Entry point
│   └── Commands        # run, config validate/init, policy dump
│
├── config/mod.rs       # Configuration parsing & validation
│   ├── Config          # Root configuration struct
│   ├── ProxyConfig     # Bind addresses, ports
│   ├── PolicyConfig    # Rules, macros, rulesets
│   ├── CaptureConfig   # Request/response capture flags
│   └── TlsConfig       # Upstream TLS settings
│
├── proxy/              # HTTP/HTTPS proxy implementations
│   ├── http.rs         # HTTP proxy + CONNECT handling
│   ├── https_connect.rs    # MITM for CONNECT tunnels
│   └── https_transparent.rs # TLS-terminating transparent proxy
│
├── policy/mod.rs       # URL policy engine
│   ├── PolicyEngine    # Compiled rules, evaluation
│   ├── CompiledRule    # Parsed rule with regex
│   └── EffectivePolicy # Expanded rules for debugging
│
├── certs/mod.rs        # Certificate management
│   ├── CertManager     # CA + per-host cert generation
│   └── SniResolver     # SNI-based cert selection
│
├── external_auth.rs    # External approval workflows
│   ├── ExternalAuthManager  # Pending request tracking
│   ├── PendingRequest      # State for awaiting approval
│   └── StatusWebhook       # Terminal event notifications
│
├── capture/mod.rs      # Request/response capture
│   ├── CaptureRecord   # Serializable capture format
│   └── BodyCaptureBuffer # Bounded body buffering
│
├── logging/mod.rs      # Structured logging
│   ├── LoggingSettings # Tracing configuration
│   └── PolicyDecisionLogContext # Policy event logging
│
└── loop_protection/mod.rs # Proxy loop detection
    └── LoopProtectionSettings # Header-based detection
```

---

## Request Processing Flow

### HTTP Proxy Request Flow

```
┌──────────┐                                                              ┌──────────┐
│  Client  │                                                              │ Upstream │
└────┬─────┘                                                              └────▲─────┘
     │                                                                         │
     │ HTTP Request                                                            │
     │ GET http://example.com/path                                            │
     ▼                                                                         │
┌─────────────────────────────────────────────────────────────────────────────┐│
│                            HTTP Proxy Handler                               ││
│ ┌─────────────────────────────────────────────────────────────────────────┐ ││
│ │ 1. Parse Request                                                        │ ││
│ │    • Extract method, URL, headers                                       │ ││
│ │    • Generate request_id                                                │ ││
│ │    • Build full_url from absolute-form URI                              │ ││
│ └─────────────────────────────────────────────────────────────────────────┘ ││
│                                    │                                        ││
│                                    ▼                                        ││
│ ┌─────────────────────────────────────────────────────────────────────────┐ ││
│ │ 2. Loop Protection Check                                                │ ││
│ │    • Check for x-acl-proxy-request-id header                            │ ││
│ │    • If present → 508 Loop Detected                                     │ ││
│ └─────────────────────────────────────────────────────────────────────────┘ ││
│                                    │                                        ││
│                                    ▼                                        ││
│ ┌─────────────────────────────────────────────────────────────────────────┐ ││
│ │ 3. Policy Evaluation                                                    │ ││
│ │    PolicyEngine::evaluate(url, client_ip, method)                       │ ││
│ │    ┌──────────────────────────────────────────────────────────────────┐ │ ││
│ │    │ For each compiled rule:                                          │ │ ││
│ │    │   • Match regex against normalized URL                           │ │ ││
│ │    │   • Check client IP against subnets                              │ │ ││
│ │    │   • Check method against allowed methods                         │ │ ││
│ │    │   • First match wins → return decision                           │ │ ││
│ │    │ No match → use default_action (allow/deny)                       │ │ ││
│ │    └──────────────────────────────────────────────────────────────────┘ │ ││
│ └─────────────────────────────────────────────────────────────────────────┘ ││
│                                    │                                        ││
│                         ┌──────────┴──────────┐                             ││
│                         │                     │                             ││
│                    Denied               Allowed                             ││
│                         │                     │                             ││
│                         ▼                     ▼                             ││
│               ┌─────────────────┐  ┌─────────────────────────────────────┐  ││
│               │ 403 Forbidden   │  │ 4. External Auth Check (optional)  │  ││
│               │ + Capture       │  │    • If rule has external_auth_profile │ ││
│               │   (if enabled)  │  │    • Send webhook, await decision     │ ││
│               └─────────────────┘  │    • Timeout → 504 Gateway Timeout    │ ││
│                                    └───────────────┬─────────────────────┘  ││
│                                                    │                        ││
│                                    ┌───────────────┴───────────────┐        ││
│                                    │                               │        ││
│                              Approved                         Denied        ││
│                                    │                               │        ││
│                                    ▼                               ▼        ││
│ ┌─────────────────────────────────────────────────────────────┐   │        ││
│ │ 5. Proxy Request                                            │   │        ││
│ │    • Apply request header_actions (set/add/remove/replace) │   │        ││
│ │    • Add loop protection header                            │   │        ││
│ │    • Forward to upstream                                    │   │        ││
│ │    • Apply response header_actions                          │   │        ││
│ │    • Capture bodies (if enabled)                           │   │        ││
│ │    • Return response to client                              │───┼────────┼┘
│ └─────────────────────────────────────────────────────────────┘   │        │
└───────────────────────────────────────────────────────────────────┼────────┘
                                                                    │
                                                            403 Forbidden
```

### HTTPS CONNECT Flow (MITM Mode)

```
┌──────────┐                                                              ┌──────────┐
│  Client  │                                                              │ Upstream │
└────┬─────┘                                                              └────▲─────┘
     │                                                                         │
     │ CONNECT example.com:443                                                │
     ▼                                                                         │
┌──────────────────────────────────────────────────────────────────────────────┤
│                         CONNECT Handler                                      │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │ 1. Parse CONNECT target (host:port)                                      │ │
│ │ 2. Check loop protection header                                          │ │
│ │ 3. Generate per-host TLS certificate (cached)                            │ │
│ │ 4. Return 200 OK to client                                               │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                         │
│                                    ▼                                         │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │ 5. Upgrade connection to TLS                                             │ │
│ │    • Client performs TLS handshake with proxy                            │ │
│ │    • Proxy presents generated cert for example.com                       │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                         │
│                                    ▼                                         │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │ 6. Run HTTP/1.1 server over TLS tunnel                                   │ │
│ │    • Parse decrypted HTTP requests                                       │ │
│ │    • Apply policy to each request                                        │ │
│ │    • Proxy allowed requests to upstream HTTPS                            │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                         │
└────────────────────────────────────┼─────────────────────────────────────────┘
                                     │
                          (Same as HTTP flow from step 3)
```

### HTTPS Transparent Proxy Flow

```
┌──────────┐                                                              ┌──────────┐
│  Client  │                                                              │ Upstream │
└────┬─────┘                                                              └────▲─────┘
     │                                                                         │
     │ TLS ClientHello with SNI: example.com                                  │
     │ (Traffic redirected via iptables/firewall)                             │
     ▼                                                                         │
┌──────────────────────────────────────────────────────────────────────────────┤
│                    HTTPS Transparent Handler                                 │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │ 1. Accept TLS connection                                                 │ │
│ │    • Extract SNI hostname from ClientHello                               │ │
│ │    • Use SniResolver to select/generate certificate                      │ │
│ │    • Complete TLS handshake (ALPN: h2, http/1.1)                         │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                         │
│                                    ▼                                         │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │ 2. Build URL from Host header + request path                             │ │
│ │    • URL = https://{Host header}{path}                                   │ │
│ │    • Apply policy evaluation                                             │ │
│ │    • Proxy allowed requests to upstream                                  │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                         │
└────────────────────────────────────┼─────────────────────────────────────────┘
                                     │
                          (Same as HTTP flow from step 3)
```

---

## Configuration System

### Configuration Loading Flow

```
┌───────────────────────────────────────────────────────────────────────────┐
│                        Configuration Resolution                           │
└───────────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  --config     │         │ ACL_PROXY_CONFIG│         │    Default      │
│  CLI argument │         │ Environment Var │         │ config/acl-     │
│  (highest)    │         │                 │         │ proxy.toml      │
└───────┬───────┘         └────────┬────────┘         └────────┬────────┘
        │                          │                           │
        └──────────────────────────┼───────────────────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │     Read TOML file          │
                    │     Parse into Config       │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │  Apply Environment Overrides│
                    │  • PROXY_PORT → http_port   │
                    │  • PROXY_HOST → bind_address│
                    │  • LOG_LEVEL → logging.level│
                    └──────────────┬──────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │     Validate Configuration  │
                    │  • Schema version check     │
                    │  • Policy rule validation   │
                    │  • Certificate path check   │
                    │  • Logging level validation │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │   Build AppState            │
                    │  • Compile PolicyEngine     │
                    │  • Initialize CertManager   │
                    │  • Create HTTP client       │
                    │  • Setup ExternalAuthManager│
                    └─────────────────────────────┘
```

### Configuration Struct Relationships

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                Config                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ schema_version: String ("1")                                                │
│                                                                             │
│ ┌───────────────────────┐  ┌────────────────────────┐                      │
│ │     ProxyConfig       │  │     LoggingConfig      │                      │
│ │ • bind_address        │  │ • directory            │                      │
│ │ • http_port (8881)    │  │ • level                │                      │
│ │ • https_bind_address  │  │ ┌────────────────────┐ │                      │
│ │ • https_port (8889)   │  │ │PolicyDecisionsConf │ │                      │
│ └───────────────────────┘  │ │• log_allows: bool  │ │                      │
│                            │ │• log_denies: bool  │ │                      │
│ ┌───────────────────────┐  │ │• level_allows      │ │                      │
│ │     CaptureConfig     │  │ │• level_denies      │ │                      │
│ │ • allowed_request     │  │ └────────────────────┘ │                      │
│ │ • allowed_response    │  └────────────────────────┘                      │
│ │ • denied_request      │                                                   │
│ │ • denied_response     │  ┌────────────────────────┐                      │
│ │ • directory           │  │  LoopProtectionConfig  │                      │
│ │ • filename            │  │ • enabled: bool        │                      │
│ └───────────────────────┘  │ • add_header: bool     │                      │
│                            │ • header_name          │                      │
│ ┌───────────────────────┐  └────────────────────────┘                      │
│ │  CertificatesConfig   │                                                   │
│ │ • certs_dir           │  ┌────────────────────────┐                      │
│ │ • ca_key_path         │  │      TlsConfig         │                      │
│ │ • ca_cert_path        │  │ • verify_upstream      │                      │
│ └───────────────────────┘  │ • enable_http2_upstream│                      │
│                            └────────────────────────┘                      │
│                                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │                           PolicyConfig                                  │ │
│ │ ┌─────────────┐  ┌──────────────────┐  ┌──────────────────────────────┐ │ │
│ │ │  default    │  │     macros       │  │         rulesets             │ │ │
│ │ │ Allow|Deny  │  │ BTreeMap<String, │  │ BTreeMap<String,             │ │ │
│ │ └─────────────┘  │   MacroValues>   │  │   Vec<PolicyRuleTemplate>>   │ │ │
│ │                  └──────────────────┘  └──────────────────────────────┘ │ │
│ │ ┌──────────────────────────────────────────────────────────────────────┐│ │
│ │ │                     rules: Vec<PolicyRuleConfig>                     ││ │
│ │ │  ┌──────────────────────────┐  ┌──────────────────────────┐         ││ │
│ │ │  │   PolicyRuleDirectConfig │  │ PolicyRuleIncludeConfig  │         ││ │
│ │ │  │ • action: Allow|Deny     │  │ • include: String        │         ││ │
│ │ │  │ • pattern: Option<String>│  │ • with: MacroOverrideMap │         ││ │
│ │ │  │ • methods: Option<...>   │  │ • add_url_enc_variants   │         ││ │
│ │ │  │ • subnets: Vec<Ipv4Net>  │  │ • methods: Option<...>   │         ││ │
│ │ │  │ • header_actions: Vec    │  │ • subnets: Vec<Ipv4Net>  │         ││ │
│ │ │  │ • external_auth_profile  │  └──────────────────────────┘         ││ │
│ │ │  │ • rule_id: Option<String>│                                       ││ │
│ │ │  └──────────────────────────┘                                       ││ │
│ │ └──────────────────────────────────────────────────────────────────────┘│ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Policy Engine

### Policy Compilation Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Policy Expansion Pipeline                            │
└─────────────────────────────────────────────────────────────────────────────┘

PolicyConfig                    ExpandedPolicy                 PolicyEngine
     │                               │                              │
     │  ┌────────────────────────────┼────────────────────────────┐ │
     │  │        expand_policy()     │                            │ │
     │  │                            │                            │ │
     ▼  ▼                            │                            │ │
┌────────────────┐                   │                            │ │
│ Direct Rule    │───────────────────┼────────────────────────────┼─┤
│ {pattern, ...} │                   │                            │ │
└────────────────┘                   │                            │ │
        │                            │                            │ │
        ▼                            │                            │ │
┌────────────────────────────────┐   │                            │ │
│ collect_placeholders()         │   │                            │ │
│ Find {name} in pattern/desc    │   │                            │ │
└────────────────────────────────┘   │                            │ │
        │                            │                            │ │
        ▼                            │                            │ │
┌────────────────────────────────┐   │                            │ │
│ resolve_placeholders()         │   │                            │ │
│ Look up in: with > macros      │   │                            │ │
└────────────────────────────────┘   │                            │ │
        │                            │                            │ │
        ▼                            │                            │ │
┌────────────────────────────────┐   │                            │ │
│ cartesian_product()            │   │                            │ │
│ Expand multi-value macros      │   │                            │ │
│ [{repo: "a/b"}, {repo: "c/d"}] │   │                            │ │
└────────────────────────────────┘   │                            │ │
        │                            │                            │ │
        ▼                            │                            │ │
┌────────────────────────────────┐   │                            │ │
│ add_url_encoded_variants()     │   │                            │ │
│ If add_url_enc_variants=true   │   │                            │ │
│ Add "a%2Fb" alongside "a/b"    │   │                            │ │
└────────────────────────────────┘   │                            │ │
        │                            │                            │ │
        ▼                            │                            │ │
┌────────────────────────────────┐   │                            │ │
│ interpolate_template()         │   │    ┌──────────────────┐   │ │
│ Replace {name} with values     │───┼───▶│  ExpandedRule    │   │ │
└────────────────────────────────┘   │    │ (one per combo)  │   │ │
                                     │    └────────┬─────────┘   │ │
                                     │             │             │ │
┌────────────────┐                   │             │             │ │
│ Include Rule   │                   │             │             │ │
│ {include: ...} │───────────────────┼─────────────┼─────────────┼─┤
└────────────────┘                   │             │             │ │
        │                            │             │             │ │
        ▼                            │             │             │ │
┌────────────────────────────────┐   │             │             │ │
│ Lookup ruleset by name         │   │             │             │ │
│ Iterate template rules         │   │             │             │ │
│ (Same expansion as Direct)     │   │             │             │ │
└────────────────────────────────┘   │             │             │ │
                                     │             │             │ │
                                     │             ▼             │ │
                                     │    ┌──────────────────┐   │ │
                                     └───▶│ ExpandedPolicy   │───┼─┘
                                          │ rules: Vec<...>  │   │
                                          └────────┬─────────┘   │
                                                   │             │
                                                   ▼             │
                                          ┌──────────────────┐   │
                                          │ pattern_to_regex │   │
                                          │ "https://x.com/**"│   │
                                          │   → ^https?://    │   │
                                          │     x\.com/.*$   │   │
                                          └────────┬─────────┘   │
                                                   │             │
                                                   ▼             │
                                          ┌──────────────────┐   │
                                          │ CompiledRule     │   │
                                          │ • index          │   │
                                          │ • regex: Regex   │───┘
                                          │ • header_actions │
                                          └──────────────────┘
```

### Policy Evaluation Algorithm

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      PolicyEngine::evaluate()                               │
│                                                                             │
│  Input: (url: &str, client_ip: Option<&str>, method: Option<&str>)         │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 1. Normalize URL                                                    │   │
│  │    • Parse with url::Url                                            │   │
│  │    • Reconstruct: scheme://host:port/path?query                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 2. Normalize Client IP                                              │   │
│  │    • Strip zone ID (fe80::1%eth0 → fe80::1)                         │   │
│  │    • Convert IPv4-mapped IPv6 (::ffff:1.2.3.4 → 1.2.3.4)            │   │
│  │    • Treat ::1 as 127.0.0.1                                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 3. Iterate compiled rules (first match wins)                        │   │
│  │                                                                     │   │
│  │    for rule in &self.rules {                                        │   │
│  │        ┌─────────────────────────────────────────────────────────┐  │   │
│  │        │ a. Pattern Match (if rule has regex)                    │  │   │
│  │        │    if !rule.regex.is_match(&normalized_url) { continue }│  │   │
│  │        └─────────────────────────────────────────────────────────┘  │   │
│  │                                │                                    │   │
│  │                                ▼                                    │   │
│  │        ┌─────────────────────────────────────────────────────────┐  │   │
│  │        │ b. Subnet Match (if rule has subnets)                   │  │   │
│  │        │    if !client_in_any_subnet(ip, &rule.subnets)          │  │   │
│  │        │       { continue }                                      │  │   │
│  │        └─────────────────────────────────────────────────────────┘  │   │
│  │                                │                                    │   │
│  │                                ▼                                    │   │
│  │        ┌─────────────────────────────────────────────────────────┐  │   │
│  │        │ c. Method Match (if rule has methods)                   │  │   │
│  │        │    if !rule.methods.contains(method) { continue }       │  │   │
│  │        └─────────────────────────────────────────────────────────┘  │   │
│  │                                │                                    │   │
│  │                                ▼                                    │   │
│  │        ┌─────────────────────────────────────────────────────────┐  │   │
│  │        │ d. Match Found!                                         │  │   │
│  │        │    return PolicyDecision {                              │  │   │
│  │        │        allowed: rule.action == Allow,                   │  │   │
│  │        │        matched: Some(MatchedRule { ... })               │  │   │
│  │        │    }                                                    │  │   │
│  │        └─────────────────────────────────────────────────────────┘  │   │
│  │    }                                                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 4. No match - use default action                                    │   │
│  │    return PolicyDecision {                                          │   │
│  │        allowed: self.default_action == Allow,                       │   │
│  │        matched: None                                                │   │
│  │    }                                                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Certificate Management

### Certificate Generation Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CertManager Initialization                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │ Resolve CA paths              │
                    │ • Explicit: ca_key_path,      │
                    │   ca_cert_path from config    │
                    │ • Default: certs/ca-key.pem,  │
                    │   certs/ca-cert.pem           │
                    └───────────────┬───────────────┘
                                    │
                         ┌──────────┴──────────┐
                         │                     │
                   Paths exist            Paths missing
                         │                     │
                         ▼                     ▼
              ┌─────────────────────┐  ┌─────────────────────┐
              │ Load existing CA    │  │ Generate new CA     │
              │ • Parse PEM key     │  │ • rcgen::KeyPair    │
              │ • Parse PEM cert    │  │ • Self-signed cert  │
              │ • Rebuild rcgen obj │  │ • Write to disk     │
              └──────────┬──────────┘  └──────────┬──────────┘
                         │                        │
                         └───────────┬────────────┘
                                     │
                                     ▼
                      ┌─────────────────────────────┐
                      │        CertManager          │
                      │ • ca_cert: RcgenCertificate │
                      │ • ca_key: KeyPair           │
                      │ • server_configs: Cache     │
                      └─────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────────────┐
│                      Per-Host Certificate Generation                        │
└─────────────────────────────────────────────────────────────────────────────┘

Client TLS Handshake                    CertManager
        │                                   │
        │  SNI: example.com                 │
        ▼                                   │
┌───────────────────┐                       │
│  SniResolver      │                       │
│  ::resolve()      │                       │
└────────┬──────────┘                       │
         │                                  │
         │  Check cache                     │
         ▼                                  │
┌────────────────────────────────────┐      │
│ self.keys.get("example.com")       │      │
│                                    │      │
│  Cache hit?                        │      │
│  ├─ Yes → return Arc<CertifiedKey> │      │
│  └─ No  → generate_host_certificate│      │
└────────┬───────────────────────────┘      │
         │ Cache miss                       │
         ▼                                  │
┌────────────────────────────────────┐      │
│ generate_host_certificate()        │      │
│                                    │      │
│ 1. CertificateParams::new(["example.com"])
│ 2. leaf_key = KeyPair::generate()  │      │
│ 3. leaf_cert = params.signed_by(   │      │
│       leaf_key, ca_cert, ca_key)   │      │
│                                    │      │
│ 4. Build chain: [leaf, ca]         │      │
│                                    │      │
│ 5. Write to certs/dynamic/:        │      │
│    • example.com.crt  (leaf)       │      │
│    • example.com.key  (private)    │      │
│    • example.com-chain.crt (full)  │      │
│                                    │      │
│ 6. Cache and return                │      │
└────────────────────────────────────┘      │

                    ┌─────────────────────────────────┐
                    │      Filesystem Layout          │
                    ├─────────────────────────────────┤
                    │ certs/                          │
                    │ ├── ca-key.pem                  │
                    │ ├── ca-cert.pem                 │
                    │ └── dynamic/                    │
                    │     ├── example.com.crt         │
                    │     ├── example.com.key         │
                    │     ├── example.com-chain.crt   │
                    │     ├── api.github.com.crt      │
                    │     └── ...                     │
                    └─────────────────────────────────┘
```

---

## External Authentication

### External Auth Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    External Authentication Workflow                         │
└─────────────────────────────────────────────────────────────────────────────┘

Client                 acl-proxy               External Auth      Upstream
   │                      │                    Webhook Server         │
   │  Request             │                         │                 │
   │─────────────────────▶│                         │                 │
   │                      │                         │                 │
   │                      │ 1. Policy matches rule  │                 │
   │                      │    with external_auth   │                 │
   │                      │                         │                 │
   │                      │ 2. start_pending()      │                 │
   │                      │    Store PendingRequest │                 │
   │                      │    in DashMap           │                 │
   │                      │                         │                 │
   │                      │ 3. POST initial webhook │                 │
   │                      │────────────────────────▶│                 │
   │                      │   {                     │                 │
   │                      │     "requestId": "...", │                 │
   │                      │     "status": "pending",│                 │
   │                      │     "url": "...",       │                 │
   │                      │     "method": "GET",    │                 │
   │                      │     "clientIp": "...",  │                 │
   │                      │     "terminal": false   │                 │
   │                      │   }                     │                 │
   │                      │◀────────────────────────│                 │
   │                      │   200 OK                │                 │
   │                      │                         │                 │
   │                      │ 4. Wait for callback    │                 │
   │                      │    (or timeout)         │                 │
   │                      │                         │                 │
   │                      │   POST callback ────────┤                 │
   │                      │◀───────────────────────│                  │
   │                      │   {                     │                 │
   │                      │     "requestId": "...", │                 │
   │                      │     "decision": "allow" │                 │
   │                      │   }                     │                 │
   │                      │                         │                 │
   │                      │ 5a. Decision: Allow     │                 │
   │                      │─────────────────────────┼────────────────▶│
   │                      │                         │                 │
   │◀─────────────────────│                         │   Response      │
   │  Response            │◀────────────────────────┼─────────────────│
   │                      │                         │                 │

Alternative outcomes:

   │                      │ 5b. Decision: Deny      │                 │
   │◀─────────────────────│                         │                 │
   │  403 Forbidden       │                         │                 │
   │                      │                         │                 │

   │                      │ 5c. Timeout (no callback)                 │
   │◀─────────────────────│                         │                 │
   │  504 Gateway Timeout │                         │                 │
   │                      │                         │                 │
   │                      │ 6. Status webhook       │                 │
   │                      │    (terminal event)     │                 │
   │                      │────────────────────────▶│                 │
   │                      │   {                     │                 │
   │                      │     "status": "timed_out",                │
   │                      │     "terminal": true    │                 │
   │                      │   }                     │                 │
```

### External Auth Manager Internals

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       ExternalAuthManager                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ pending: Arc<DashMap<String, PendingRequest>>                       │   │
│  │                                                                     │   │
│  │  "req-12345" ──▶ PendingRequest {                                   │   │
│  │                    rule_index: 0,                                   │   │
│  │                    rule_id: Some("api-access"),                     │   │
│  │                    profile_name: "approval-flow",                   │   │
│  │                    created_at: Instant,                             │   │
│  │                    deadline_at: Instant,                            │   │
│  │                    decision_tx: oneshot::Sender<ExternalDecision>,  │   │
│  │                    url: "https://api.example.com/...",              │   │
│  │                    method: Some("POST"),                            │   │
│  │                    client_ip: Some("192.168.1.100"),                │   │
│  │                  }                                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ profiles: Arc<BTreeMap<String, ExternalAuthProfile>>                │   │
│  │                                                                     │   │
│  │  "approval-flow" ──▶ ExternalAuthProfile {                          │   │
│  │                        webhook_url: "https://auth.internal/...",    │   │
│  │                        timeout: Duration(5000ms),                   │   │
│  │                        webhook_timeout: Some(Duration(1000ms)),     │   │
│  │                        on_webhook_failure: WebhookFailureMode::Deny │   │
│  │                      }                                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ status_tx/status_rx: mpsc::channel<StatusWebhookEvent>              │   │
│  │                                                                     │   │
│  │  Background worker sends terminal status webhooks:                  │   │
│  │  • webhook_failed (initial webhook delivery failed)                 │   │
│  │  • timed_out (no callback within timeout)                           │   │
│  │  • error (internal error)                                           │   │
│  │  • cancelled (client disconnected)                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Capture System

### Capture Decision Matrix

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Capture Configuration                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [capture]                                                                  │
│  allowed_request = true/false    │ Capture request body for allowed reqs   │
│  allowed_response = true/false   │ Capture response body for allowed reqs  │
│  denied_request = true/false     │ Capture request body for denied reqs    │
│  denied_response = true/false    │ Capture response body for denied reqs   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │              should_capture(decision, kind) matrix                  │   │
│  │                                                                     │   │
│  │                    │  Request          │  Response                  │   │
│  │  ──────────────────┼───────────────────┼────────────────────────    │   │
│  │  Allow (proxied)   │ allowed_request   │ allowed_response           │   │
│  │  Deny (blocked)    │ denied_request    │ denied_response            │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Capture Record Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CaptureRecord (JSON)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  {                                                                          │
│    "timestamp": "2024-01-01T12:00:00.000Z",                                 │
│    "requestId": "req-1704110400000-1",                                      │
│    "kind": "request" | "response",                                          │
│    "decision": "allow" | "deny",                                            │
│    "mode": "http_proxy" | "https_connect" | "https_transparent",            │
│    "url": "https://api.example.com/v1/users",                               │
│    "method": "POST",                                                        │
│    "statusCode": 200,              // response only                         │
│    "statusMessage": "OK",          // response only                         │
│    "client": {                                                              │
│      "address": "192.168.1.100",                                            │
│      "port": 54321                                                          │
│    },                                                                       │
│    "target": {                                                              │
│      "address": "api.example.com",                                          │
│      "port": 443                                                            │
│    },                                                                       │
│    "httpVersion": "1.1",                                                    │
│    "headers": {                                                             │
│      "content-type": "application/json",                                    │
│      "authorization": "Bearer ...",                                         │
│      "x-custom": ["value1", "value2"]  // multi-value headers               │
│    },                                                                       │
│    "body": {                                                                │
│      "encoding": "base64",                                                  │
│      "length": 1234,               // full original length                  │
│      "data": "eyJmb28iOi...",      // base64, max 64KB captured             │
│      "contentType": "application/json"                                      │
│    }                                                                        │
│  }                                                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           Filesystem Layout                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  logs-capture/                                                              │
│  ├── req-1704110400000-1-req.json    # Request capture                      │
│  ├── req-1704110400000-1-res.json    # Response capture                     │
│  ├── req-1704110400001-2-req.json                                           │
│  ├── req-1704110400001-2-res.json                                           │
│  └── ...                                                                    │
│                                                                             │
│  Filename template: {requestId}-{suffix}.json                               │
│    • {requestId} - sanitized request ID (no path chars)                     │
│    • {suffix}    - "req" or "res"                                           │
│    • {kind}      - "request" or "response"                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Body Capture Buffer

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      BodyCaptureBuffer Operation                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;  // 64KB                  │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ BodyCaptureBuffer::new(max_bytes)                                   │   │
│  │                                                                     │   │
│  │  max_bytes: 65536                                                   │   │
│  │  captured: Vec<u8>                                                  │   │
│  │  total_len: 0                                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  push(chunk: &[u8])                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  total_len += chunk.len()     // Always count full length           │   │
│  │                                                                     │   │
│  │  if captured.len() < max_bytes {                                    │   │
│  │      let remaining = max_bytes - captured.len();                    │   │
│  │      let to_take = min(remaining, chunk.len());                     │   │
│  │      captured.extend_from_slice(&chunk[..to_take]);                 │   │
│  │  }                                                                  │   │
│  │  // Bytes beyond max_bytes are counted but not stored               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Example: 100KB body with 64KB limit                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Result:                                                            │   │
│  │    captured: [first 64KB of data]                                   │   │
│  │    total_len: 102400                                                │   │
│  │                                                                     │   │
│  │  JSON body field:                                                   │   │
│  │    "encoding": "base64",                                            │   │
│  │    "length": 102400,      // Original full size                     │   │
│  │    "data": "..."          // Base64 of first 64KB only              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Hot Reload Mechanism

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Configuration Hot Reload                             │
└─────────────────────────────────────────────────────────────────────────────┘

                     SIGHUP signal
                          │
                          ▼
            ┌─────────────────────────────┐
            │  reload_from_sources()      │
            │                             │
            │  1. Config::load_from_sources()
            │     (re-read TOML file)     │
            │                             │
            │  2. AppState::from_config() │
            │     (rebuild all components)│
            └──────────────┬──────────────┘
                           │
                           ▼
            ┌─────────────────────────────┐
            │ AppState::reload_shared_    │
            │   from_config()             │
            │                             │
            │ shared.store(Arc::new(      │
            │   new_state))               │
            │                             │
            │ ArcSwap atomically swaps    │
            │ the pointer                 │
            └──────────────┬──────────────┘
                           │
                ┌──────────┴──────────┐
                │                     │
                ▼                     ▼
    ┌─────────────────────┐  ┌─────────────────────┐
    │ New Connections     │  │ In-flight Requests  │
    │                     │  │                     │
    │ state.load_full()   │  │ Hold Arc to old     │
    │ → new AppState      │  │ AppState until      │
    │                     │  │ request completes   │
    └─────────────────────┘  └─────────────────────┘


SharedAppState = Arc<ArcSwap<AppState>>
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ArcSwap Diagram                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Before reload:                                                             │
│                                                                             │
│  SharedAppState ──▶ ArcSwap ──▶ Arc<AppState v1>                           │
│                                        │                                    │
│  Request A ────────────────────────────┘ (holds reference)                  │
│  Request B ────────────────────────────┘                                    │
│                                                                             │
│  After reload (atomic swap):                                                │
│                                                                             │
│  SharedAppState ──▶ ArcSwap ──▶ Arc<AppState v2>  ◀── New request C        │
│                                                                             │
│  Request A ────────────────────▶ Arc<AppState v1> (still valid until done) │
│  Request B ────────────────────▶ Arc<AppState v1>                          │
│                                                                             │
│  When A and B complete, v1 is dropped automatically                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Header Actions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Header Action Types                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  action: "remove"                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ direction: request | response | both                                │   │
│  │ name: "x-internal-header"                                           │   │
│  │ when: always | if_present | if_absent                               │   │
│  │                                                                     │   │
│  │ Effect: Remove all values of the named header                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  action: "set"                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ direction: request | response | both                                │   │
│  │ name: "x-custom-header"                                             │   │
│  │ value: "single-value"  OR  values: ["val1", "val2"]                 │   │
│  │ when: always | if_present | if_absent                               │   │
│  │                                                                     │   │
│  │ Effect: Remove existing, then add new value(s)                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  action: "add"                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ direction: request | response | both                                │   │
│  │ name: "x-custom-header"                                             │   │
│  │ value: "additional-value"  OR  values: [...]                        │   │
│  │ when: always | if_present | if_absent                               │   │
│  │                                                                     │   │
│  │ Effect: Append value(s) without removing existing                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  action: "replace_substring"                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ direction: request | response | both                                │   │
│  │ name: "authorization"                                               │   │
│  │ search: "old-token"                                                 │   │
│  │ replace: "new-token"                                                │   │
│  │ when: always | if_present | if_absent                               │   │
│  │                                                                     │   │
│  │ Effect: Replace substring in all values of header                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  "when" conditions:                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ always     - Apply unconditionally (default)                        │   │
│  │ if_present - Only if header existed in original message             │   │
│  │ if_absent  - Only if header did NOT exist in original message       │   │
│  │                                                                     │   │
│  │ Note: "original" = before any header actions for this rule          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Error Handling

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Error Type Hierarchy                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  CliError                                                                   │
│  ├── Config(ConfigError)                                                    │
│  ├── AppState(AppStateError)                                                │
│  ├── Runtime(String)                                                        │
│  ├── Proxy(HttpProxyError)                                                  │
│  └── HttpsTransparent(HttpsTransparentError)                                │
│                                                                             │
│  AppStateError                                                              │
│  ├── Logging(LoggingError)                                                  │
│  ├── Policy(PolicyError)                                                    │
│  ├── LoopProtection(LoopProtectionError)                                    │
│  └── Certs(CertError)                                                       │
│                                                                             │
│  ConfigError                                                                │
│  ├── Io { path, source }                                                    │
│  ├── ParseToml { path, source }                                             │
│  └── Invalid(String)                                                        │
│                                                                             │
│  PolicyError                                                                │
│  ├── MacroNotFound { name, context }                                        │
│  ├── RulesetNotFound { name }                                               │
│  ├── RuleInvalid { index, reason }                                          │
│  ├── PatternCompile { index, source }                                       │
│  └── UrlParse(String)                                                       │
│                                                                             │
│  CertError                                                                  │
│  ├── CreateDir { path, source }                                             │
│  ├── ReadCaKey { path, source }                                             │
│  ├── ReadCaCert { path, source }                                            │
│  ├── ParseCaKey(String)                                                     │
│  ├── ParseCaCert(String)                                                    │
│  ├── BuildServerConfig(String)                                              │
│  └── WriteFile { path, source }                                             │
│                                                                             │
│  HttpProxyError                                                             │
│  ├── BindAddress { address, source }                                        │
│  ├── BindListener { addr, source }                                          │
│  ├── FromTcp(io::Error)                                                     │
│  └── Hyper(hyper::Error)                                                    │
│                                                                             │
│  HttpsTransparentError                                                      │
│  ├── BindAddress { address, source }                                        │
│  ├── BindListener { addr, source }                                          │
│  ├── FromStd(io::Error)                                                     │
│  ├── TlsConfig(CertError)                                                   │
│  ├── Accept(io::Error)                                                      │
│  ├── TlsHandshake(io::Error)                                                │
│  └── Hyper(hyper::Error)                                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Summary

The ACL Proxy is a Rust-based HTTP/HTTPS proxy with:

1. **Dual Listener Architecture**: HTTP proxy (with CONNECT MITM) and HTTPS transparent termination
2. **Flexible Policy Engine**: Pattern matching with wildcards, macros, rulesets, subnets, and methods
3. **Dynamic Certificate Generation**: SNI-based per-host TLS certificates signed by a local CA
4. **External Authentication**: Webhook-based approval workflows with configurable timeouts
5. **Request/Response Capture**: Bounded body buffering with configurable capture flags
6. **Hot Reload**: SIGHUP-triggered configuration reload without dropping in-flight requests
7. **Loop Protection**: Header-based detection to prevent proxy loops

All components are designed for safe concurrent access using `Arc`, `ArcSwap`, `DashMap`, and Tokio's async primitives.

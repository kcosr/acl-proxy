# acl-proxy
Small HTTP/HTTPS proxy that enforces allow/deny rules on full URLs (scheme + host + path) and optional ingress client IP subnets (IPv4). HTTPS interception is supported transparently or via CONNECT. Uses a self-signed CA certificate to generate a certificate for the target domain.

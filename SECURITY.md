# Security

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/dkruyt/privacy-llm-gateway/security/advisories/new),
not in a public issue. Include the version or commit, the config (with secrets
removed) and steps to reproduce. You will get a reply within a week.

A leak path counts as a vulnerability: any way a request that should go local can
reach the public provider.

## Threat model

### What the gateway guarantees

- **Fail closed.** Public routing needs a valid classifier answer with no reason
  against it. Every error goes local: classifier timeout or invalid answer, Redis
  unreachable, oversized state, unsupported content, or any exception. Nothing
  retries on, or falls back to, the public provider.
- **Egress guard.** `upstream.py` is the only module that talks to model servers.
  The public client re-checks an HMAC stamp over the exact body it sends. The local
  client and the classifier only connect to hosts in `upstreams.local_hosts`.
  Redirects, retries and proxy environment variables are disabled.
- **Clients cannot choose the route.** They cannot pick the public provider, its
  model, a base URL or a key. Client headers (including `Authorization`) are never
  forwarded upstream.
- **No content in logs or metrics.** Logs hold rule ids, codes and hashes only.
  Metric labels are fixed sets plus the configured key id.
- **Keys.** Only SHA-256 hashes of client keys are stored, and they are compared in
  constant time. Secrets come from environment variables or files, never from the
  YAML.
- **Transport.** The public upstream must use `https://`. Plain `http://` to local
  hosts is only accepted for loopback, private IPs and single-label names, unless
  `upstreams.allow_insecure_http` is set.

### What you must provide

- **A trusted path to the local model and the classifier.** Every classified
  request is sent to the classifier in full, and every sensitive request to the
  local model. Use TLS, or keep them on a network you control. The egress guard
  checks host names, not where DNS resolves them.
- **TLS for clients.** The gateway serves plain HTTP. Put a TLS reverse proxy in
  front of it before exposing it beyond the host (`BIND_ADDR` in `.env` defaults
  to 127.0.0.1).
- **Secrets set in `.env`.** Compose refuses to start without the required ones.
  Redis needs a password; Open WebUI sits on a separate network from Redis and the
  metrics listener.

### Known limits

- **Classification is probabilistic.** Detectors and the classifier lower the
  risk of sensitive data reaching the public provider; they do not remove it.
  Calibrate the thresholds on your own traffic.
- **Document parsing has no CPU or memory limit.** PDFs are parsed in-process with
  pypdf, capped by size and page count only. A malicious PDF from an authenticated
  client can use a lot of CPU or memory. Keep pypdf patched and set
  `server.request_max_bytes` and container limits to fit your load.
- **Detector cost grows with body size.** Detectors scan the whole request
  (up to `server.request_max_bytes`) before the classifier size check.
- **Sticky sessions are a convenience, not a boundary.** A client can send a new
  `x-session-id` per request to avoid a pin.
- **Prefix cache (opt-in) in delta mode** classifies only new messages. Sensitive
  content split across turns can pass where a full classification would catch it.
- **`x-privacy-reasons`** tells the client which rule fired. That helps legitimate
  users and also someone probing for detector gaps.
- **Images** always route local and are forwarded as-is. If they are `http(s)` URLs,
  the local model server may fetch them.
- **Opaque reasoning blobs** are removed from requests, which breaks tool loops with
  Anthropic models on the public route.

## Supported versions

Only the latest release gets security fixes.

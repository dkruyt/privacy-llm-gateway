# Changelog

## 0.1.0 (unreleased)

First public release.

- OpenAI-compatible gateway with local classification: detectors, a local classifier
  model and a pure decision table route each `auto` request to the local or public
  upstream. Every failure routes local.
- Egress guard with HMAC stamps; no retries or fallback to the public provider.
- Sticky sessions in Redis, PDF/text attachment conversion, opaque reasoning removal,
  opt-in classification cache per conversation prefix.
- Prometheus metrics, JSON logs, Grafana dashboard and alert rules.
- Docker image, compose stack with Open WebUI, Prometheus and Grafana, and an
  integration suite on an internal network.
- Config validation requires `https://` for the public upstream and rejects plain
  `http://` to non-private local hosts unless `upstreams.allow_insecure_http` is set.
  `redis.password` is supported.

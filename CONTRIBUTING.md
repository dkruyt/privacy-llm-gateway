# Contributing

Issues and pull requests are welcome. For security problems, see [SECURITY.md](SECURITY.md).

## Setup

Python 3.12:

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[test]'
```

The lock files (`requirements.lock`, `requirements-test.lock`) are resolved with
hashes for linux/x86_64 and are what the Docker image and CI use (see the README
for installing from them). If hash checking fails on your platform, install from
`pyproject.toml` as above.

## Tests

```bash
.venv/bin/python -m pytest -q          # unit tests
tests/integration/run.sh               # docker compose integration suite (no internet)
```

Live tests against a real classifier are opt-in; see [README.md](README.md#testing).

## Guidelines

- Keep the fail-closed rule: any new error path routes local and never falls back to
  the public provider. Add a test for it.
- Never log or label metrics with request content, keys or user identifiers.
- Pin new dependencies exactly in `pyproject.toml` and regenerate the lock files
  (`uv pip compile --generate-hashes`).
- The Grafana dashboard JSON is generated: edit `grafana/build_dashboard.py` and run
  it, don't edit the JSON by hand.
- By contributing you agree that your contribution is licensed under the
  AGPL-3.0-or-later, like the rest of the project.

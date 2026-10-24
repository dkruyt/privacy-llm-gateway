# syntax=docker/dockerfile:1
# privacy-gateway: non-root, slim, read-only-root-fs friendly.
#   docker build -t privacy-gateway:0.1.0 .
#   docker run --read-only --tmpfs /tmp -v ./config.yaml:/etc/privacy-gateway/config.yaml:ro ...

FROM python:3.12.14-slim-trixie AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ---------------------------------------------------------------- dependencies
FROM base AS deps
RUN python -m venv /opt/venv
COPY requirements.lock /tmp/requirements.lock
RUN /opt/venv/bin/pip install --require-hashes --only-binary=:all: -r /tmp/requirements.lock

# ---------------------------------------------------------------- runtime
FROM base AS runtime
RUN groupadd --system --gid 10001 gateway \
 && useradd --system --uid 10001 --gid gateway --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gateway
COPY --from=deps /opt/venv /opt/venv
COPY privacy_gateway /app/privacy_gateway
# Pre-compile bytecode: the root filesystem is read-only at runtime.
RUN /opt/venv/bin/python -m compileall -q /app /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app \
    TMPDIR=/tmp
WORKDIR /app
USER 10001:10001
EXPOSE 8080 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]
ENTRYPOINT ["python", "-m", "privacy_gateway"]
CMD ["serve", "--config", "/etc/privacy-gateway/config.yaml"]

# ---------------------------------------------------------------- tests (compose profile "test")
FROM runtime AS test
USER root
COPY requirements-test.lock /tmp/requirements-test.lock
RUN /opt/venv/bin/pip install --require-hashes --only-binary=:all: -r /tmp/requirements-test.lock
COPY pyproject.toml /app/pyproject.toml
COPY tests /app/tests
COPY config.example.yaml /app/config.example.yaml
RUN /opt/venv/bin/python -m compileall -q /app/tests
USER 10001:10001
ENTRYPOINT []
CMD ["python", "-m", "pytest", "-p", "no:cacheprovider", "-m", "integration", "tests/integration", "-v"]

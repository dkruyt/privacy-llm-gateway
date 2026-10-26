#!/usr/bin/env python3
"""Install or update the Privacy LLM Gateway pipe function in Open WebUI (stdlib only).

    python3 openwebui/install.py [--url http://localhost:3000]

Auth: env OPENWEBUI_TOKEN (an admin session token), else prompts for the admin e-mail
and password. Idempotent. Steps:

1. create or update function `privacy_gateway` from privacy_llm_gateway_pipe.py and enable it;
2. disable the direct OpenAI connection (it would list a second, status-less auto/local);
3. task model (titles, tags, follow-ups) → privacy_gateway.local;
4. default model → privacy_gateway.auto.

Open WebUI keeps these settings in its database, so the compose env vars only apply
to a fresh install; this script changes an existing one.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

FUNCTION_ID = "privacy_gateway"
SOURCE = Path(__file__).with_name("privacy_llm_gateway_pipe.py")


class Client:
    def __init__(self, base: str, token: str | None = None):
        self.base = base.rstrip("/")
        self.token = token

    def call(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("content-type", "application/json")
        if self.token:
            req.add_header("authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else None


def login(client: Client) -> None:
    token = os.environ.get("OPENWEBUI_TOKEN")
    if not token:
        email = input("Open WebUI admin e-mail: ").strip()
        password = getpass.getpass("Password: ")
        token = client.call("POST", "/api/v1/auths/signin", {"email": email, "password": password})["token"]
    client.token = token


def install_function(client: Client) -> None:
    form = {
        "id": FUNCTION_ID,
        "name": "Privacy LLM Gateway",
        "content": SOURCE.read_text(),
        "meta": {"description": "auto/local via the privacy gateway, with a local/public status per answer."},
    }
    # Look it up in the list: a missing id answers 401, not 404.
    existing = {f["id"] for f in client.call("GET", "/api/v1/functions/")}
    if FUNCTION_ID in existing:
        fn = client.call("POST", f"/api/v1/functions/id/{FUNCTION_ID}/update", form)
        print(f"updated function {FUNCTION_ID}")
    else:
        fn = client.call("POST", "/api/v1/functions/create", form)
        print(f"created function {FUNCTION_ID}")
    if not fn.get("is_active"):
        client.call("POST", f"/api/v1/functions/id/{FUNCTION_ID}/toggle")
        print("enabled function")


def disable_openai_connection(client: Client) -> None:
    cfg = client.call("GET", "/openai/config")
    if not cfg.get("ENABLE_OPENAI_API"):
        return
    cfg["ENABLE_OPENAI_API"] = False
    client.call("POST", "/openai/config/update", cfg)
    print("disabled the direct OpenAI connection")


def set_task_model(client: Client) -> None:
    cfg = client.call("GET", "/api/v1/tasks/config")
    model = f"{FUNCTION_ID}.local"
    if cfg.get("TASK_MODEL_EXTERNAL") != model:
        cfg["TASK_MODEL_EXTERNAL"] = model
        client.call("POST", "/api/v1/tasks/config/update", cfg)
        print(f"task model → {model}")


def set_default_model(client: Client) -> None:
    cfg = client.call("GET", "/api/v1/configs/models")
    model = f"{FUNCTION_ID}.auto"
    if cfg.get("DEFAULT_MODELS") != model:
        cfg["DEFAULT_MODELS"] = model
        client.call("POST", "/api/v1/configs/models", cfg)
        print(f"default model → {model}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default=os.environ.get("OPENWEBUI_URL", "http://localhost:3000"))
    args = ap.parse_args()
    parts = urllib.parse.urlsplit(args.url)
    if parts.scheme == "http" and parts.hostname not in ("localhost", "127.0.0.1", "::1"):
        print(f"warning: {args.url} is plain http; the password and token travel unencrypted.", file=sys.stderr)
    client = Client(args.url)
    try:
        login(client)
        install_function(client)
        disable_openai_connection(client)
        set_task_model(client)
        set_default_model(client)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        print(f"error: {exc.url} → HTTP {exc.code}: {detail}", file=sys.stderr)
        return 1
    print("done. Make sure the openwebui container has PRIVACY_GATEWAY_KEY set (see compose.yml).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

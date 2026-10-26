#!/usr/bin/env bash
# Integration suite: gateway + mocks + Redis on an internal network (no internet).
#   tests/integration/run.sh [extra pytest args]
set -uo pipefail
cd "$(dirname "$0")/../.."
# compose.yml requires these for the production services; the test profile never starts
# them, but compose interpolates the whole file.
export REDIS_PASSWORD="${REDIS_PASSWORD:-unused}" WEBUI_SECRET_KEY="${WEBUI_SECRET_KEY:-unused}" \
  OPENWEBUI_GATEWAY_KEY="${OPENWEBUI_GATEWAY_KEY:-unused}" GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-unused}"
P=(docker compose -p privacy-llm-gateway-it --profile test)
SERVICES=(redis-test mock-public mock-local mock-classifier gateway-test gateway-noredis)

cleanup() { "${P[@]}" down -v --remove-orphans >/dev/null 2>&1; }
trap cleanup EXIT

"${P[@]}" build gateway-test mock-public || exit 1
"${P[@]}" up -d "${SERVICES[@]}" || exit 1

echo "== internal network has no internet access"
if "${P[@]}" run --rm --no-deps test-runner python -c "import socket; socket.create_connection(('1.1.1.1', 443), timeout=3)" 2>/dev/null; then
  echo "FAIL: test network can reach the internet"; exit 1
else
  echo "ok: no route to the internet"
fi

echo "== pytest"
"${P[@]}" run --rm test-runner python -m pytest -p no:cacheprovider -m integration tests/integration -v "$@"
rc=$?

echo "== log hygiene: grep gateway logs for every planted value"
"${P[@]}" logs --no-color gateway-test gateway-noredis > /tmp/privacy-llm-gateway-it.log 2>&1
python3 - /tmp/privacy-llm-gateway-it.log <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("planted", "tests/integration/planted.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
log = open(sys.argv[1], encoding="utf-8", errors="replace").read()
lines = log.count("\n")
found = [p for p in mod.PLANTED if p in log or p.lower() in log.lower()]
decisions = log.count('"event": "decision"')
print(f"scanned {lines} log lines ({decisions} decision lines) for {len(mod.PLANTED)} planted values")
if found:
    print("FAIL: planted values found in logs:", [f[:6] + "…" for f in found]); sys.exit(1)
if decisions == 0:
    print("FAIL: no decision lines logged"); sys.exit(1)
print("ok: none found")
PY
hyg=$?
rm -f /tmp/privacy-llm-gateway-it.log
[ $rc -eq 0 ] && [ $hyg -eq 0 ]

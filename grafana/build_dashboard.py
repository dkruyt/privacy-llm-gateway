"""Generate grafana/dashboards/privacy-gateway.json (run: python3 grafana/build_dashboard.py)."""

from __future__ import annotations

import json
from pathlib import Path

DS = {"type": "prometheus", "uid": "prometheus"}
KEY = 'key_id=~"$key_id"'
_id = 0
_y = 0
panels: list[dict] = []


def nid() -> int:
    global _id
    _id += 1
    return _id


def target(expr: str, legend: str = "", ref: str = "A", fmt: str | None = None, instant: bool = False) -> dict:
    t = {"datasource": DS, "expr": expr, "legendFormat": legend or "__auto", "refId": ref, "range": not instant, "instant": instant}
    if fmt:
        t["format"] = fmt
    return t


def row(title: str) -> None:
    global _y
    panels.append({"type": "row", "title": title, "id": nid(), "collapsed": False, "gridPos": {"h": 1, "w": 24, "x": 0, "y": _y}, "panels": []})
    _y += 1


def place(panel: dict, x: int, w: int, h: int, y: int) -> dict:
    panel.update(id=nid(), datasource=DS, gridPos={"h": h, "w": w, "x": x, "y": y})
    panels.append(panel)
    return panel


def stat(title, expr, x, w, y, unit="short", thresholds=None, desc="", decimals=None, mappings=None, legend=""):
    steps = thresholds or [{"color": "green", "value": None}]
    p = {
        "type": "stat", "title": title, "description": desc,
        "targets": [target(expr, legend, instant=True)],
        "fieldConfig": {"defaults": {"unit": unit, "thresholds": {"mode": "absolute", "steps": steps},
                                     "mappings": mappings or [], "noValue": "–",
                                     **({"decimals": decimals} if decimals is not None else {})},
                        "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "colorMode": "background", "graphMode": "none", "textMode": "auto", "justifyMode": "center"},
    }
    return place(p, x, w, 4, y)


def ts(title, targets, x, w, y, unit="short", stack=False, desc="", h=8, overrides=None, min0=True):
    p = {
        "type": "timeseries", "title": title, "description": desc, "targets": targets,
        "fieldConfig": {"defaults": {"unit": unit, **({"min": 0} if min0 else {}),
                                     "custom": {"drawStyle": "line", "lineWidth": 1, "fillOpacity": 20 if stack else 8,
                                                "showPoints": "never", "spanNulls": True,
                                                "stacking": {"mode": "normal" if stack else "none", "group": "A"}}},
                        "overrides": overrides or []},
        "options": {"legend": {"displayMode": "table", "placement": "right", "calcs": ["mean", "lastNotNull"]},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    }
    return place(p, x, w, h, y)


def hist(title, metric, x, w, y, desc, threshold=None, threshold_label=""):
    p = {
        "type": "bargauge", "title": title, "description": desc,
        "targets": [target(f"sum by (le) (increase({metric}_bucket[$__range]))", "{{le}}", fmt="heatmap", instant=True)],
        "fieldConfig": {"defaults": {"unit": "short", "color": {"mode": "continuous-BlYlRd"},
                                     "thresholds": {"mode": "absolute", "steps": [{"color": "blue", "value": None}]}},
                        "overrides": []},
        "options": {"orientation": "vertical", "displayMode": "gradient", "showUnfilled": False, "valueMode": "text",
                    "namePlacement": "auto", "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
    }
    return place(p, x, w, 8, y)


def table(title, expr, x, w, y, desc="", label="reason", h=8):
    p = {
        "type": "table", "title": title, "description": desc,
        "targets": [target(expr, fmt="table", instant=True)],
        "fieldConfig": {"defaults": {"custom": {"align": "auto"}}, "overrides": [
            {"matcher": {"id": "byName", "options": "Value"}, "properties": [
                {"id": "displayName", "value": "requests (range)"}, {"id": "decimals", "value": 0},
                {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic"}}]}]},
        "options": {"showHeader": True, "sortBy": [{"displayName": "requests (range)", "desc": True}]},
        "transformations": [{"id": "organize", "options": {"excludeByName": {"Time": True}}}],
    }
    return place(p, x, w, h, y)


RED_IF_POSITIVE = [{"color": "green", "value": None}, {"color": "red", "value": 1}]
UPDOWN = [{"options": {"0": {"text": "DOWN", "color": "red"}, "1": {"text": "UP", "color": "green"}}, "type": "value"}]

# ---------------------------------------------------------------- overview
row("Overview")
y = _y
stat("Requests / s", f"sum(rate(privacy_requests_total{{{KEY}}}[$__rate_interval]))", 0, 3, y, "reqps", decimals=2)
stat("Public share (auto)",
     f'sum(increase(privacy_requests_total{{{KEY},requested="auto",route="public"}}[$__range])) / '
     f'sum(increase(privacy_requests_total{{{KEY},requested="auto"}}[$__range]))',
     3, 3, y, "percentunit", [{"color": "blue", "value": None}],
     "Share of model=auto requests sent to the public provider over the selected range.", 1)
stat("Sensitive (range)", f'sum(increase(privacy_requests_total{{{KEY},verdict="sensitive"}}[$__range]))', 6, 3, y,
     thresholds=[{"color": "purple", "value": None}], decimals=0)
stat("Egress blocked", 'sum(privacy_egress_total{result="blocked"})', 9, 3, y, thresholds=RED_IF_POSITIVE,
     desc="Outbound calls refused by the egress guard. Must stay 0 — anything else is a bug.", decimals=0)
stat("Classifier error ratio",
     'sum(rate(privacy_classifier_calls_total{result!="ok"}[$__rate_interval])) / sum(rate(privacy_classifier_calls_total[$__rate_interval]))',
     12, 3, y, "percentunit", [{"color": "green", "value": None}, {"color": "orange", "value": 0.05}, {"color": "red", "value": 0.2}], decimals=1,
     desc="Share of classifier calls that failed (timeout, transport, HTTP, invalid answer). Empty when there were no calls.")
stat("Redis", 'max(privacy_up{dependency="redis"})', 15, 2, y, mappings=UPDOWN,
     thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}])
stat("Classifier", 'max(privacy_up{dependency="classifier"})', 17, 2, y, mappings=UPDOWN,
     thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}])
stat("Local model", 'max(privacy_up{dependency="local"})', 19, 2, y, mappings=UPDOWN,
     thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}])
stat("In flight", "sum(privacy_inflight_requests)", 21, 3, y, thresholds=[{"color": "blue", "value": None}], decimals=0)
_y = y + 4

# ---------------------------------------------------------------- routing
row("Routing")
y = _y
ts("Requests by route", [target(f'sum by (route) (rate(privacy_requests_total{{{KEY}}}[$__rate_interval]))', "{{route}}")],
   0, 8, y, "reqps", stack=True, overrides=[
       {"matcher": {"id": "byName", "options": "public"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}]},
       {"matcher": {"id": "byName", "options": "local"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}]}])
ts("Requests by verdict", [target(f'sum by (verdict) (rate(privacy_requests_total{{{KEY}}}[$__rate_interval]))', "{{verdict}}")],
   8, 8, y, "reqps", stack=True, overrides=[
       {"matcher": {"id": "byName", "options": "public"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}]},
       {"matcher": {"id": "byName", "options": "sensitive"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "purple"}}]},
       {"matcher": {"id": "byName", "options": "uncertain"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}}]}])
ts("Requests by client key", [target(f'sum by (key_id, requested) (rate(privacy_requests_total{{{KEY}}}[$__rate_interval]))',
                                     "{{key_id}} · {{requested}}")], 16, 8, y, "reqps", stack=True)
_y = y + 8
y = _y
table("Top routing reasons (range)", "topk(20, sum by (reason) (increase(privacy_route_reasons_total[$__range])) > 0)", 0, 12, y,
      "Why requests were routed local. Codes: detector:*, classifier_choice:*, classifier_category:*, classifier_error:*, unsupported:*, session_*, document_attached:* …", h=9)
ts("Routing reasons over time", [target("sum by (reason) (rate(privacy_route_reasons_total[$__rate_interval])) > 0", "{{reason}}")],
   12, 12, y, "reqps", stack=True, h=9)
_y = y + 9

# ---------------------------------------------------------------- classifier
row("Classifier")
y = _y
ts("Classifier calls by result", [target("sum by (result) (rate(privacy_classifier_calls_total[$__rate_interval]))", "{{result}}")],
   0, 8, y, "reqps", stack=True)
ts("Classifier skipped (why)", [target("sum by (why) (rate(privacy_classifier_skipped_total[$__rate_interval]))", "{{why}}")],
   8, 8, y, "reqps", stack=True)
ts("Latency: classifier call & whole classification", [
    target("histogram_quantile(0.5, sum by (le) (rate(privacy_classifier_seconds_bucket[$__rate_interval])))", "classifier p50", "A"),
    target("histogram_quantile(0.95, sum by (le) (rate(privacy_classifier_seconds_bucket[$__rate_interval])))", "classifier p95", "B"),
    target("histogram_quantile(0.95, sum by (le) (rate(privacy_classification_seconds_bucket[$__rate_interval])))", "pipeline p95", "C"),
], 16, 8, y, "s")
_y = y + 8
y = _y
hist("p(public) distribution (range)", "privacy_classifier_p_public", 0, 6, y,
     "Bucketed p(verdict=public). Threshold policy.thresholds.public_min_prob (default 0.80): below it → local.")
hist("Confidence distribution (range)", "privacy_classifier_confidence", 6, 6, y,
     "Bucketed verdict confidence. Threshold min_confidence (default 0.60).")
hist("Max category probability (range)", "privacy_classifier_category_max_prob", 12, 6, y,
     "Highest has_<category> probability per call. Threshold category_max_prob (default 0.30): above it → local.")
hist("Manipulation probability (range)", "privacy_classifier_manipulation_prob", 18, 6, y,
     "Threshold manipulation_max_prob (default 0.30): above it → local.")
_y = y + 8
y = _y
ts("Classifier input tokens", [
    target("histogram_quantile(0.5, sum by (le) (rate(privacy_classifier_input_tokens_bucket[$__rate_interval])))", "p50", "A"),
    target("histogram_quantile(0.95, sum by (le) (rate(privacy_classifier_input_tokens_bucket[$__rate_interval])))", "p95", "B"),
], 0, 12, y, "short", desc="Large states approach classifier.max_state_chars → too_large_for_classifier (routed local).")
ts("Sessions", [target("sum by (event) (rate(privacy_session_events_total[$__rate_interval]))", "{{event}}")],
   12, 12, y, "reqps", stack=True, desc="hit = request routed local by a sticky session; pinned = session flagged sensitive.")
_y = y + 8

# ---------------------------------------------------------------- upstreams
row("Upstreams & egress")
y = _y
ts("Upstream time to first byte", [
    target("histogram_quantile(0.5, sum by (le, route) (rate(privacy_upstream_ttfb_seconds_bucket[$__rate_interval])))", "{{route}} p50", "A"),
    target("histogram_quantile(0.95, sum by (le, route) (rate(privacy_upstream_ttfb_seconds_bucket[$__rate_interval])))", "{{route}} p95", "B"),
], 0, 8, y, "s")
ts("Request duration (p95)", [
    target("histogram_quantile(0.95, sum by (le, route, stream) (rate(privacy_request_seconds_bucket[$__rate_interval])))",
           "{{route}} stream={{stream}}")], 8, 8, y, "s")
ts("Upstream errors", [target("sum by (route, kind) (rate(privacy_upstream_errors_total[$__rate_interval]))", "{{route}} {{kind}}")],
   16, 8, y, "reqps", stack=True)
_y = y + 8
y = _y
ts("Egress by route & result", [target("sum by (route, result) (rate(privacy_egress_total[$__rate_interval]))", "{{route}} {{result}}")],
   0, 8, y, "reqps", desc="result=blocked must always be 0.", overrides=[
       {"matcher": {"id": "byRegexp", "options": ".*blocked"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}]}])
ts("In-flight requests", [target("sum by (route) (privacy_inflight_requests)", "{{route}}")], 8, 8, y, "short")
ts("Documents", [target("sum by (type, result) (rate(privacy_documents_total[$__rate_interval]))", "{{type}} {{result}}")],
   16, 8, y, "reqps", stack=True)
_y = y + 8

# ---------------------------------------------------------------- errors & config
row("Client errors & config")
y = _y
ts("Client errors by code", [target("sum by (code) (rate(privacy_client_errors_total[$__rate_interval]))", "{{code}}")],
   0, 12, y, "reqps", stack=True)
ts("Config reloads", [target("sum by (result) (increase(privacy_config_reloads_total[$__rate_interval]))", "{{result}}")],
   12, 6, y, "short", overrides=[
       {"matcher": {"id": "byName", "options": "failed"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}]}])
place({"type": "table", "title": "Active config & build",
       "targets": [target("privacy_config_info == 1", fmt="table", instant=True, ref="A"),
                   target("privacy_build_info", fmt="table", instant=True, ref="B")],
       "transformations": [{"id": "merge", "options": {}},
                           {"id": "organize", "options": {"excludeByName": {"Time": True, "Value #A": True, "Value #B": True,
                                                                             "__name__": True, "job": True, "instance": True}}}],
       "fieldConfig": {"defaults": {}, "overrides": []}, "options": {"showHeader": True}}, 18, 6, 8, y)
_y = y + 8

dashboard = {
    "uid": "privacy-gateway",
    "title": "Privacy Gateway",
    "description": "Routing, classifier, upstream and egress health of privacy-gateway. Content-free metrics only.",
    "tags": ["privacy-gateway", "llm"],
    "timezone": "browser",
    "editable": False,
    "graphTooltip": 1,
    "refresh": "30s",
    "time": {"from": "now-6h", "to": "now"},
    "schemaVersion": 41,
    "version": 1,
    "templating": {"list": [{
        "name": "key_id", "label": "Client key", "type": "query", "datasource": DS,
        "query": {"query": "label_values(privacy_requests_total, key_id)", "refId": "keys"},
        "definition": "label_values(privacy_requests_total, key_id)",
        "includeAll": True, "multi": True, "allValue": ".*", "refresh": 2, "sort": 1,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
    }]},
    "annotations": {"list": [{
        "name": "Config reloads", "datasource": DS, "enable": True, "iconColor": "orange",
        "expr": "changes(privacy_config_reloads_total[1m]) > 0", "titleFormat": "config reload {{result}}", "step": "60s",
    }]},
    "links": [],
    "panels": panels,
}

out = Path(__file__).resolve().parent / "dashboards" / "privacy-gateway.json"
out.write_text(json.dumps(dashboard, indent=2) + "\n")
print(f"wrote {out} ({len([p for p in panels if p['type'] != 'row'])} panels)")

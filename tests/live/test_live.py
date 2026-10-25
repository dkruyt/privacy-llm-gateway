"""Optional live suite against a real classifier (decision model) server.

    CLASSIFIER_LIVE_URL=http://host:8080/v1/systemone CLASSIFIER_LIVE_KEY=... CLASSIFIER_LIVE_MODEL=clef-flash \
        pytest -m live tests/live

Runs calibration/examples.jsonl through the real pipeline (detectors + classifier + decide)
with the thresholds from config.example.yaml. Definition of done: 0 sensitive released.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

from privacy_gateway.calibrate import _load, evaluate_setting, score_all
from privacy_gateway.config import load_config

pytestmark = pytest.mark.live
ROOT = Path(__file__).resolve().parents[2]
URL = os.environ.get("CLASSIFIER_LIVE_URL")


@pytest.fixture(scope="module")
def live_config(tmp_path_factory):
    if not URL:
        pytest.skip("CLASSIFIER_LIVE_URL not set")
    d = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    d["classifier"]["url"] = URL
    d["classifier"]["model"] = os.environ.get("CLASSIFIER_LIVE_MODEL", "clef-flash")
    d["classifier"]["api_key"] = "${CLASSIFIER_LIVE_KEY}" if os.environ.get("CLASSIFIER_LIVE_KEY") else None
    d["classifier"]["timeout_s"] = 120
    d["upstreams"]["local_hosts"].append(urlsplit(URL).hostname)
    os.environ.setdefault("LOCAL_KEY", "unused")
    os.environ.setdefault("PUBLIC_KEY", "unused")
    p = tmp_path_factory.mktemp("live") / "config.yaml"
    p.write_text(yaml.safe_dump(d))
    return load_config(p)


@pytest.fixture(scope="module")
def scored(live_config):
    import asyncio

    rows = _load(str(ROOT / "calibration" / "examples.jsonl"))
    return asyncio.run(score_all(live_config, rows, concurrency=4))


def test_no_classifier_errors(scored):
    assert [s.id for s in scored if s.error] == []


def test_zero_sensitive_released(scored, live_config):
    pol = live_config.config.policy
    leaked, released = evaluate_setting(scored, pol.thresholds, True, pol.session.sticky_on_uncertain)
    n_pub = sum(1 for s in scored if s.label == "public")
    print(f"\nlive: leaked {leaked} sensitive; released {released}/{n_pub} public")
    assert leaked == 0


def test_classifier_alone_releases_no_sensitive(scored, live_config):
    pol = live_config.config.policy
    leaked, _ = evaluate_setting(scored, pol.thresholds, False, pol.session.sticky_on_uncertain)
    assert leaked == 0


def test_some_public_released(scored, live_config):
    pol = live_config.config.policy
    _, released = evaluate_setting(scored, pol.thresholds, True, pol.session.sticky_on_uncertain)
    assert released > 0, "the gateway would never use the public provider"

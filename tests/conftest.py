from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "config.example.yaml"

TEST_KEY = "test-key-openwebui-0123456789abcdef"
TEST_KEY2 = "test-key-n8n-0123456789abcdef012345"


def example_dict() -> dict:
    return yaml.safe_load(EXAMPLE.read_text())


@pytest.fixture
def secret_env(monkeypatch):
    monkeypatch.setenv("LOCAL_KEY", "local-secret-value")
    monkeypatch.setenv("PUBLIC_KEY", "public-secret-value")
    monkeypatch.setenv("CLASSIFIER_KEY", "classifier-secret-value")


@pytest.fixture
def cfg_dict() -> dict:
    d = example_dict()
    d["auth"]["keys"] = [
        {"id": "openwebui", "sha256": hashlib.sha256(TEST_KEY.encode()).hexdigest()},
        {"id": "n8n", "sha256": hashlib.sha256(TEST_KEY2.encode()).hexdigest()},
    ]
    return d


@pytest.fixture
def write_cfg(tmp_path, secret_env):
    def _write(d: dict, name: str = "config.yaml") -> Path:
        p = tmp_path / name
        p.write_text(yaml.safe_dump(d, sort_keys=False))
        return p

    return _write


@pytest.fixture
def loaded(cfg_dict, write_cfg):
    from privacy_llm_gateway.config import load_config

    return load_config(write_cfg(cfg_dict))


@pytest.fixture
def example_copy(tmp_path):
    p = tmp_path / "config.yaml"
    shutil.copy(EXAMPLE, p)
    return p

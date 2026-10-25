from __future__ import annotations

import copy

import pytest

from privacy_gateway.config import ConfigError, ConfigHolder, load_config


def test_example_config_is_valid(example_copy, secret_env):
    lc = load_config(example_copy)
    cfg = lc.config
    assert cfg.upstreams.local.api_key == "local-secret-value"
    assert cfg.upstreams.public.api_key == "public-secret-value"
    assert cfg.classifier.api_key == "classifier-secret-value"
    assert cfg.policy.sensitive_categories == [
        "personal_data",
        "credentials_secrets",
        "private_document",
        "confidential_business",
        "proprietary_code",
    ]
    assert len(lc.sha256) == 64
    assert lc.stamp_key is None


def test_unknown_key_rejected_with_path(cfg_dict, write_cfg):
    cfg_dict["policy"]["thresholds"]["public_min_probability"] = 0.9
    with pytest.raises(ConfigError) as ei:
        load_config(write_cfg(cfg_dict))
    assert "policy.thresholds.public_min_probability" in str(ei.value)


def test_unknown_top_level_key_rejected(cfg_dict, write_cfg):
    cfg_dict["admin_api"] = {"enabled": True}
    with pytest.raises(ConfigError, match="admin_api"):
        load_config(write_cfg(cfg_dict))


def test_missing_env_secret_rejected(cfg_dict, write_cfg, monkeypatch):
    monkeypatch.delenv("PUBLIC_KEY")
    with pytest.raises(ConfigError) as ei:
        load_config(write_cfg(cfg_dict))
    msg = str(ei.value)
    assert "upstreams.public.api_key" in msg and "PUBLIC_KEY" in msg


def test_missing_file_secret_rejected(cfg_dict, write_cfg, tmp_path):
    cfg_dict["upstreams"]["public"]["api_key"] = {"file": str(tmp_path / "nope")}
    with pytest.raises(ConfigError, match="upstreams.public.api_key"):
        load_config(write_cfg(cfg_dict))


def test_file_secret_resolved(cfg_dict, write_cfg, tmp_path):
    f = tmp_path / "pub"
    f.write_text("file-secret\n")
    cfg_dict["upstreams"]["public"]["api_key"] = {"file": str(f)}
    assert load_config(write_cfg(cfg_dict)).config.upstreams.public.api_key == "file-secret"


def test_literal_secret_rejected_and_not_echoed(cfg_dict, write_cfg):
    cfg_dict["upstreams"]["public"]["api_key"] = "sk-or-v1-literalsecretdonotprint"
    with pytest.raises(ConfigError) as ei:
        load_config(write_cfg(cfg_dict))
    assert "upstreams.public.api_key" in str(ei.value)
    assert "literalsecret" not in str(ei.value)


def test_workers_require_stamp_key(cfg_dict, write_cfg):
    cfg_dict["server"]["workers"] = 2
    with pytest.raises(ConfigError, match="stamp.key_file"):
        load_config(write_cfg(cfg_dict))


def test_stamp_key_file(cfg_dict, write_cfg, tmp_path):
    k = tmp_path / "stamp"
    k.write_bytes(b"x" * 40)
    cfg_dict["server"]["workers"] = 2
    cfg_dict["stamp"]["key_file"] = str(k)
    assert load_config(write_cfg(cfg_dict)).stamp_key == b"x" * 40


def test_local_upstream_must_be_local_host(cfg_dict, write_cfg):
    cfg_dict["upstreams"]["local"]["base_url"] = "https://api.example.com/v1"
    with pytest.raises(ConfigError, match="local_hosts"):
        load_config(write_cfg(cfg_dict))


def test_classifier_must_be_local_host(cfg_dict, write_cfg):
    cfg_dict["classifier"]["url"] = "https://classifier.example.com/v1/systemone"
    with pytest.raises(ConfigError, match="classifier.url"):
        load_config(write_cfg(cfg_dict))


def test_invalid_custom_regex_is_config_error(cfg_dict, write_cfg):
    cfg_dict["policy"]["detectors"]["custom_patterns"] = {"bad": "("}
    with pytest.raises(ConfigError, match="policy.detectors.custom_patterns"):
        load_config(write_cfg(cfg_dict))


def test_sensitive_category_needs_question(cfg_dict, write_cfg):
    del cfg_dict["policy"]["categories"]["personal_data"]["question"]
    with pytest.raises(ConfigError, match="personal_data"):
        load_config(write_cfg(cfg_dict))


def test_required_categories(cfg_dict, write_cfg):
    del cfg_dict["policy"]["categories"]["uncertain"]
    with pytest.raises(ConfigError, match="uncertain"):
        load_config(write_cfg(cfg_dict))


def test_unknown_disabled_rule(cfg_dict, write_cfg):
    cfg_dict["policy"]["detectors"]["disabled"] = ["emial"]
    with pytest.raises(ConfigError, match="emial"):
        load_config(write_cfg(cfg_dict))


def test_invalid_yaml(tmp_path, secret_env):
    p = tmp_path / "c.yaml"
    p.write_text("server: [unclosed\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(p)


def test_bad_listen(cfg_dict, write_cfg):
    cfg_dict["server"]["listen"] = "0.0.0.0"
    with pytest.raises(ConfigError, match="server.listen"):
        load_config(write_cfg(cfg_dict))


class _Log:
    def __init__(self):
        self.events = []

    def event(self, name, level=None, **kw):
        self.events.append((name, kw))


def test_sighup_bad_file_keeps_old_config(cfg_dict, write_cfg):
    path = write_cfg(cfg_dict)
    results = []
    log = _Log()
    holder = ConfigHolder(load_config(path), on_reload=lambda ok, _: results.append(ok), logger=log)
    before = holder.current

    path.write_text("policy: [broken")
    assert holder.reload() is False
    assert holder.current is before
    assert results == [False]
    assert log.events[-1][0] == "config_reload" and log.events[-1][1]["result"] == "failed"

    bad = copy.deepcopy(cfg_dict)
    bad["policy"]["thresholds"]["public_min_prob"] = 7
    write_cfg(bad)
    assert holder.reload() is False
    assert holder.current is before


def test_sighup_good_file_swaps(cfg_dict, write_cfg):
    path = write_cfg(cfg_dict)
    log = _Log()
    holder = ConfigHolder(load_config(path), logger=log)
    cfg_dict["policy"]["thresholds"]["public_min_prob"] = 0.95
    cfg_dict["server"]["listen"] = "0.0.0.0:9999"
    write_cfg(cfg_dict)
    assert holder.reload() is True
    cfg = holder.current.config
    assert cfg.policy.thresholds.public_min_prob == 0.95
    assert cfg.server.listen == "0.0.0.0:8080"  # needs a restart
    assert log.events[-1][1]["result"] == "ok"
    assert log.events[-1][1]["restart_required_for"] == ["server.listen"]


def test_reload_build_failure_keeps_old(cfg_dict, write_cfg):
    path = write_cfg(cfg_dict)
    calls = {"n": 0}

    def build(lc):
        calls["n"] += 1
        if calls["n"] > 1:
            raise RuntimeError("boom")
        return lc

    holder = ConfigHolder(load_config(path), build=build)
    before = holder.current
    assert holder.reload() is False
    assert holder.current is before


def test_prefix_cache_defaults_and_bounds(cfg_dict, write_cfg):
    from privacy_gateway.config import ConfigError, load_config

    pc = load_config(write_cfg(cfg_dict)).config.policy.session.prefix_cache
    assert (pc.enabled, pc.borderline_margin, pc.ttl_seconds) == (False, 0.10, 86_400)
    for bad in ({"borderline_margin": 0.6}, {"borderline_margin": -0.1}, {"ttl_seconds": 10}, {"unknown": 1}):
        cfg_dict["policy"]["session"]["prefix_cache"] = bad
        with pytest.raises(ConfigError):
            load_config(write_cfg(cfg_dict))

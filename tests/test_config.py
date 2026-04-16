"""Tests for configuration management."""

from __future__ import annotations

from pathlib import Path

from cti_graph.config import TLP_LEVELS, Config, load_config


def test_tlp_ordering():
    assert TLP_LEVELS["white"] < TLP_LEVELS["green"]
    assert TLP_LEVELS["green"] < TLP_LEVELS["amber"]
    assert TLP_LEVELS["amber"] < TLP_LEVELS["red"]


def test_default_config():
    cfg = Config()
    assert cfg.api.host == "127.0.0.1"
    assert cfg.api.port == 8080
    assert cfg.stix.tlp_max == "amber"
    assert cfg.database.path == ""


def test_db_path_default():
    cfg = Config()
    assert cfg.db_path == Path.home() / ".local" / "share" / "cti-graph" / "graph.db"


def test_db_path_custom():
    cfg = Config(database={"path": "/tmp/test.db"})
    assert cfg.db_path == Path("/tmp/test.db")


def test_stix_dir_default():
    cfg = Config()
    assert cfg.stix_dir == Path.home() / ".local" / "share" / "cti-graph" / "stix"


def test_stix_dir_custom():
    cfg = Config(stix={"landing_dir": "/tmp/stix"})
    assert cfg.stix_dir == Path("/tmp/stix")


def test_api_auth_token_from_env(monkeypatch):
    monkeypatch.setenv("CTI_GRAPH_API_TOKEN", "test-token-123")
    cfg = Config()
    assert cfg.api_auth_token == "test-token-123"


def test_api_auth_token_empty():
    cfg = Config()
    # Don't rely on env state; just check property returns a string
    assert isinstance(cfg.api_auth_token, str)


def test_load_config_missing_file():
    cfg = load_config(Path("/nonexistent/config.toml"))
    # Should fall back to defaults
    assert cfg.api.port == 8080


def test_load_config_from_toml(tmp_path):
    toml_content = """\
[database]
path = "/tmp/custom.db"

[api]
port = 9090
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)

    cfg = load_config(config_file)
    assert cfg.db_path == Path("/tmp/custom.db")
    assert cfg.api.port == 9090
    # Other fields keep defaults
    assert cfg.stix.tlp_max == "amber"


def test_load_config_env_var(tmp_path, monkeypatch):
    toml_content = "[api]\nport = 7070\n"
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)

    monkeypatch.setenv("CTI_GRAPH_CONFIG", str(config_file))
    cfg = load_config()
    assert cfg.api.port == 7070

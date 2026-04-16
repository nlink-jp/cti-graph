"""Configuration management for cti-graph.

Priority: env vars > config.toml > defaults.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel

_TOOL_NAME = "cti-graph"
_ENV_PREFIX = "CTI_GRAPH_"

# TLP level ordering (higher = more restrictive)
TLP_LEVELS: dict[str, int] = {"white": 0, "green": 1, "amber": 2, "red": 3}

_DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / _TOOL_NAME


class DatabaseConfig(BaseModel):
    path: str = ""  # resolved to default at runtime


class StixConfig(BaseModel):
    landing_dir: str = ""
    tlp_max: str = "amber"


class OpenCTIConfig(BaseModel):
    url: str = ""
    token_env: str = "OPENCTI_TOKEN"


class CalderaConfig(BaseModel):
    url: str = ""
    api_key_env: str = "CALDERA_API_KEY"


class NotificationConfig(BaseModel):
    slack_webhook_env: str = "SLACK_WEBHOOK_URL"
    choke_point_threshold: float = 0.1


class GitHubConfig(BaseModel):
    host: str = ""
    token_env: str = "GITHUB_TOKEN"
    repo: str = ""


class APIConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080
    token_env: str = "CTI_GRAPH_API_TOKEN"


class Config(BaseModel):
    database: DatabaseConfig = DatabaseConfig()
    stix: StixConfig = StixConfig()
    opencti: OpenCTIConfig = OpenCTIConfig()
    caldera: CalderaConfig = CalderaConfig()
    notification: NotificationConfig = NotificationConfig()
    github: GitHubConfig = GitHubConfig()
    api: APIConfig = APIConfig()

    @property
    def db_path(self) -> Path:
        if self.database.path:
            return Path(self.database.path)
        return _DEFAULT_DATA_DIR / "graph.db"

    @property
    def stix_dir(self) -> Path:
        if self.stix.landing_dir:
            return Path(self.stix.landing_dir)
        return _DEFAULT_DATA_DIR / "stix"

    @property
    def api_auth_token(self) -> str:
        return os.environ.get(self.api.token_env, "")

    @property
    def caldera_api_key(self) -> str:
        return os.environ.get(self.caldera.api_key_env, "")

    @property
    def opencti_token(self) -> str:
        return os.environ.get(self.opencti.token_env, "")

    @property
    def slack_webhook_url(self) -> str:
        return os.environ.get(self.notification.slack_webhook_env, "")

    @property
    def github_token(self) -> str:
        return os.environ.get(self.github.token_env, "")


def _load_toml(path: Path | None = None) -> dict[str, Any]:
    if path is None:
        path = Path.home() / ".config" / _TOOL_NAME / "config.toml"
    if not path.is_file():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


def load_config(path: Path | None = None) -> Config:
    if path is None:
        env_path = os.environ.get(f"{_ENV_PREFIX}CONFIG")
        if env_path:
            path = Path(env_path)

    data = _load_toml(path)
    return Config(
        database=DatabaseConfig(**data.get("database", {})),
        stix=StixConfig(**data.get("stix", {})),
        opencti=OpenCTIConfig(**data.get("opencti", {})),
        caldera=CalderaConfig(**data.get("caldera", {})),
        notification=NotificationConfig(**data.get("notification", {})),
        github=GitHubConfig(**data.get("github", {})),
        api=APIConfig(**data.get("api", {})),
    )

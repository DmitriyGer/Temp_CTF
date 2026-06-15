from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import read_json


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class OracleSettings:
    hosts: tuple[str, ...]
    port: int
    services: tuple[str, ...]
    username: str
    password: str
    retries: int
    retry_delay: float
    connect_timeout: int
    datafile_dir: str


@dataclass(frozen=True)
class LlmSettings:
    enabled: bool
    optional: bool
    api_type: str
    base_url: str
    model: str
    api_key: str | None
    timeout: int
    explain_errors: bool
    search_steps: int
    query_row_limit: int


@dataclass(frozen=True)
class SearchSettings:
    object_limit: int
    row_limit: int
    column_limit: int
    name_markers: tuple[str, ...]
    credential_markers: tuple[str, ...]
    excluded_owners: frozenset[str]
    allowed_types: frozenset[str]


@dataclass(frozen=True)
class AppSettings:
    oracle: OracleSettings
    llm: LlmSettings
    search: SearchSettings
    task_dir: Path
    trajectory_dir: Path
    final_result: Path
    task_name: str | None
    allow_resource_limit: bool
    policy: dict[str, Any]

    @classmethod
    def load(cls) -> "AppSettings":
        config_path = Path(os.getenv("AGENT_CONFIG_PATH", "/app/settings.json"))
        policy_path = Path(os.getenv("AGENT_POLICY_PATH", "/app/policy.json"))
        raw = read_json(config_path)
        policy = read_json(policy_path)
        oracle = raw["oracle"]
        llm = raw.get("llm", {})
        search = raw.get("search", {})

        env_host = os.getenv("ORACLE_HOST")
        hosts = [env_host] if env_host else list(oracle.get("hosts", ["oracle-free"]))
        env_service = os.getenv("ORACLE_SERVICE")
        services = [env_service] if env_service else list(oracle.get("services", ["FREEPDB1"]))

        return cls(
            oracle=OracleSettings(
                hosts=tuple(hosts),
                port=int(os.getenv("ORACLE_PORT", oracle.get("port", 1521))),
                services=tuple(services),
                username=os.getenv("ORACLE_USER", oracle.get("username", "system")),
                password=os.getenv("ORACLE_PASSWORD", oracle.get("password", "oracle")),
                retries=int(os.getenv("ORACLE_RETRIES", oracle.get("retries", 12))),
                retry_delay=float(os.getenv("ORACLE_RETRY_DELAY", oracle.get("retry_delay", 5))),
                connect_timeout=int(oracle.get("connect_timeout", 10)),
                datafile_dir=os.getenv("ORACLE_DATAFILE_DIR", oracle.get("datafile_dir", "")),
            ),
            llm=LlmSettings(
                enabled=_env_bool("LLM_ENABLED", bool(llm.get("enabled", True))),
                optional=_env_bool("LLM_OPTIONAL", bool(llm.get("optional", True))),
                api_type=os.getenv("LLM_API_TYPE", llm.get("api_type", "ollama")),
                base_url=os.getenv("LLM_URL", llm.get("base_url", "")).rstrip("/"),
                model=os.getenv("LLM_MODEL", llm.get("model", "")),
                api_key=os.getenv("LLM_API_KEY") or llm.get("api_key") or None,
                timeout=int(os.getenv("LLM_TIMEOUT", llm.get("timeout", 120))),
                explain_errors=_env_bool(
                    "LLM_EXPLAIN_ERRORS", bool(llm.get("explain_errors", True))
                ),
                search_steps=int(
                    os.getenv("LLM_SEARCH_STEPS", llm.get("search_steps", 10))
                ),
                query_row_limit=int(
                    os.getenv("LLM_QUERY_ROW_LIMIT", llm.get("query_row_limit", 30))
                ),
            ),
            search=SearchSettings(
                object_limit=int(search.get("object_limit", 120)),
                row_limit=int(search.get("row_limit", 20)),
                column_limit=int(search.get("column_limit", 16)),
                name_markers=tuple(search.get("name_markers", [])),
                credential_markers=tuple(search.get("credential_markers", [])),
                excluded_owners=frozenset(item.upper() for item in search.get("excluded_owners", [])),
                allowed_types=frozenset(item.upper() for item in search.get("allowed_types", [])),
            ),
            task_dir=Path(os.getenv("AGENT_TASK_DIR", raw["paths"]["task_dir"])),
            trajectory_dir=Path(
                os.getenv("AGENT_TRAJECTORY_DIR", raw["paths"]["trajectory_dir"])
            ),
            final_result=Path(
                os.getenv("AGENT_FINAL_RESULT", raw["paths"]["final_result"])
            ),
            task_name=os.getenv("TASK_NAME") or None,
            allow_resource_limit=_env_bool(
                "ALLOW_RESOURCE_LIMIT", bool(raw.get("allow_resource_limit", False))
            ),
            policy=policy,
        )

    def safe_snapshot(self) -> dict[str, Any]:
        return {
            "oracle": {
                "hosts": self.oracle.hosts,
                "port": self.oracle.port,
                "services": self.oracle.services,
                "username": self.oracle.username,
                "password": "***",
                "retries": self.oracle.retries,
            },
            "llm": {
                "enabled": self.llm.enabled,
                "optional": self.llm.optional,
                "api_type": self.llm.api_type,
                "base_url": self.llm.base_url,
                "model": self.llm.model,
            },
            "task_dir": str(self.task_dir),
            "trajectory_dir": str(self.trajectory_dir),
            "task_name": self.task_name,
        }

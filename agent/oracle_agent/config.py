from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path

from dotenv import load_dotenv


def _as_bool(value: str | bool | None, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    ollama_url: str
    ollama_model: str
    llm_api_type: str
    llm_api_key: str | None
    oracle_host: str
    oracle_port: int
    oracle_service: str
    oracle_user: str
    oracle_password: str
    task_file: str
    playbook_dir: Path
    trajectory_dir: Path
    max_steps: int
    dry_run: bool
    collect_trajectories: bool
    trajectory_target_count: int
    allow_alter_system: bool
    request_timeout: int
    ollama_num_ctx: int
    ollama_num_predict: int
    log_level: str

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        settings = cls(
            ollama_url=os.getenv(
                "OLLAMA_URL", "http://192.168.10.65:8901/v1"
            ).rstrip("/"),
            ollama_model=os.getenv("OLLAMA_MODEL", "Qwen/Qwen3.6-27B"),
            llm_api_type=os.getenv("LLM_API_TYPE", "auto").strip().lower(),
            llm_api_key=os.getenv("LLM_API_KEY") or None,
            oracle_host=os.getenv("ORACLE_HOST", "oracle-free"),
            oracle_port=int(os.getenv("ORACLE_PORT", "1521")),
            oracle_service=os.getenv("ORACLE_SERVICE", "FREEPDB1"),
            oracle_user=os.getenv("ORACLE_USER", "system"),
            oracle_password=os.getenv("ORACLE_PASSWORD", "oracle"),
            task_file=os.getenv("TASK_FILE", "oracle_ctf_case_a.txt"),
            playbook_dir=Path(os.getenv("PLAYBOOK_DIR", "/app/oracle_ctf_playbook")),
            trajectory_dir=Path(os.getenv("TRAJECTORY_DIR", "/app/trajectories")),
            max_steps=int(os.getenv("MAX_STEPS", "40")),
            dry_run=_as_bool(os.getenv("DRY_RUN"), False),
            collect_trajectories=_as_bool(os.getenv("COLLECT_TRAJECTORIES"), False),
            trajectory_target_count=int(os.getenv("TRAJECTORY_TARGET_COUNT", "1000")),
            allow_alter_system=_as_bool(os.getenv("ALLOW_ALTER_SYSTEM"), False),
            request_timeout=int(os.getenv("REQUEST_TIMEOUT", "600")),
            ollama_num_ctx=int(os.getenv("OLLAMA_NUM_CTX", "4096")),
            ollama_num_predict=int(os.getenv("OLLAMA_NUM_PREDICT", "256")),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        for name in (
            "ollama_url",
            "ollama_model",
            "oracle_host",
            "oracle_service",
            "oracle_user",
            "oracle_password",
            "task_file",
        ):
            if not getattr(self, name):
                raise ValueError(f"Required setting {name.upper()} is empty")
        if self.max_steps < 1:
            raise ValueError("MAX_STEPS must be at least 1")
        if self.trajectory_target_count < 1:
            raise ValueError("TRAJECTORY_TARGET_COUNT must be at least 1")
        if self.ollama_num_ctx < 2048:
            raise ValueError("OLLAMA_NUM_CTX must be at least 2048")
        if self.ollama_num_predict < 64:
            raise ValueError("OLLAMA_NUM_PREDICT must be at least 64")
        if self.llm_api_type not in {"auto", "ollama", "openai"}:
            raise ValueError("LLM_API_TYPE must be auto, ollama or openai")

    def with_overrides(self, **changes: object) -> "Settings":
        return replace(self, **changes)

    def safe_summary(self) -> dict[str, object]:
        return {
            "ollama_url": self.ollama_url,
            "ollama_model": self.ollama_model,
            "llm_api_type": self.llm_api_type,
            "oracle_host": self.oracle_host,
            "oracle_port": self.oracle_port,
            "oracle_service": self.oracle_service,
            "oracle_user": self.oracle_user,
            "oracle_password": mask_secret(self.oracle_password),
            "task_file": self.task_file,
            "dry_run": self.dry_run,
            "ollama_num_ctx": self.ollama_num_ctx,
            "ollama_num_predict": self.ollama_num_predict,
        }


def mask_secret(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + ("*" * (len(value) - 2)) + value[-1]

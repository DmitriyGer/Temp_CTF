from __future__ import annotations

import hashlib
import json
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PASSWORD_SQL = re.compile(r"(?i)(IDENTIFIED\s+BY\s+)(\"[^\"]*\"|'[^']*'|\S+)")
PASSWORD_KEY = re.compile(r"(?i)(password|passwd|pwd|secret|credential)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def prompt_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def mask_sql(sql: str | None) -> str | None:
    if sql is None:
        return None
    return PASSWORD_SQL.sub(r"\1***", sql)


def sanitize(value: Any, secrets: list[str] | None = None, key: str = "") -> Any:
    secrets = [secret for secret in (secrets or []) if secret]
    if PASSWORD_KEY.search(key):
        return "***"
    if isinstance(value, dict):
        return {str(k): sanitize(v, secrets, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(item, secrets, key) for item in value]
    if isinstance(value, tuple):
        return [sanitize(item, secrets, key) for item in value]
    if isinstance(value, str):
        masked = mask_sql(value) or ""
        for secret in secrets:
            masked = masked.replace(secret, "***")
        return masked
    return value


class TrajectoryRecorder:
    def __init__(
        self,
        directory: Path | str,
        model: str,
        task_file: str,
        mode: str,
        trace_id: str | None = None,
        filename_prefix: str = "trajectory_openinference",
    ) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.model = model
        self.task_file = task_file
        self.mode = mode
        self.trace_id = trace_id or uuid.uuid4().hex
        self.root_span_id = uuid.uuid4().hex[:16]
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.jsonl_path = self.directory / f"{filename_prefix}_{stamp}_{self.trace_id[:8]}.jsonl"
        self.summary_path = self.directory / f"{filename_prefix}_{stamp}_{self.trace_id[:8]}_summary.json"
        self.steps: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def record_step(self, **data: Any) -> dict[str, Any]:
        timestamp = data.pop("timestamp", utc_now())
        duration_ms = int(data.pop("duration_ms", 0))
        step = {
            "trace_id": self.trace_id,
            "span_id": data.pop("span_id", uuid.uuid4().hex[:16]),
            "parent_span_id": data.pop("parent_span_id", self.root_span_id),
            "timestamp": timestamp,
            "step_number": data.pop("step_number", len(self.steps) + 1),
            "action_type": data.pop("action_type", "unknown"),
            "model": data.pop("model", self.model),
            "prompt_hash": data.pop("prompt_hash", None),
            "input_context_summary": data.pop("input_context_summary", {}),
            "proposed_action": data.pop("proposed_action", {}),
            "executed_sql_masked": mask_sql(data.pop("executed_sql_masked", None)),
            "sql_allowed": data.pop("sql_allowed", None),
            "result_status": data.pop("result_status", "unknown"),
            "result_preview": data.pop("result_preview", None),
            "error_code": data.pop("error_code", None),
            "error_message": data.pop("error_message", None),
            "verification_sql": mask_sql(data.pop("verification_sql", None)),
            "verification_result": data.pop("verification_result", None),
            "next_goal": data.pop("next_goal", None),
            "duration_ms": duration_ms,
            "mode": data.pop("mode", self.mode),
            "name": data.pop("name", "agent_step"),
            "attributes": data.pop("attributes", {}),
            **data,
        }
        safe_step = sanitize(step)
        with self._lock:
            with self.jsonl_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(safe_step, ensure_ascii=False, default=str) + "\n")
            self.steps.append(safe_step)
        return safe_step

    def finalize(self, status: str, flag: str | None, reason: str | None = None) -> dict[str, Any]:
        summary = {
            "trace_id": self.trace_id,
            "status": status,
            "mode": self.mode,
            "task_file": self.task_file,
            "model": self.model,
            "flag": flag,
            "reason": reason,
            "step_count": len(self.steps),
            "successful_steps": sum(step["result_status"] == "success" for step in self.steps),
            "failed_steps": sum(step["result_status"] == "failed" for step in self.steps),
            "trajectory_file": str(self.jsonl_path),
            "created_at": utc_now(),
        }
        self.summary_path.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return summary

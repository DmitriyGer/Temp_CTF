from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from .common import compact, file_stamp, scrub, utc_now, write_json


LOGGER = logging.getLogger("dba_agent")


class RunJournal:
    def __init__(self, directory: Path, config_snapshot: dict[str, Any]) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.trace_id = uuid.uuid4().hex
        self.path = directory / f"trajectory_{file_stamp()}_{self.trace_id[:8]}.json"
        self.started_at = utc_now()
        self.finished_at: str | None = None
        self.status = "running"
        self.events: list[dict[str, Any]] = []
        self.spans: list[dict[str, Any]] = []
        self.config_snapshot = scrub(config_snapshot)
        self.secrets: list[str] = []
        self.save()

    def add_secret(self, value: str | None) -> None:
        if value and value not in self.secrets:
            self.secrets.append(value)

    def event(
        self,
        stage: str,
        status: str,
        details: dict[str, Any] | None = None,
        level: int = logging.INFO,
    ) -> None:
        safe = scrub(details or {}, secrets=self.secrets)
        event = {
            "timestamp": utc_now(),
            "stage": stage,
            "status": status,
            "details": safe,
        }
        self.events.append(event)
        LOGGER.log(level, "stage=%s status=%s details=%s", stage, status, compact(safe, 500))
        self.save()

    def span(
        self,
        name: str,
        kind: str,
        status: str,
        started: float,
        input_data: dict[str, Any] | None = None,
        output_data: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        self.spans.append(
            {
                "trace_id": self.trace_id,
                "span_id": uuid.uuid4().hex[:16],
                "name": name,
                "kind": kind,
                "status": status,
                "timestamp": utc_now(),
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "input": scrub(input_data or {}, secrets=self.secrets),
                "output": scrub(output_data or {}, secrets=self.secrets),
                "error": scrub(error, secrets=self.secrets),
                "attributes": {"openinference.span.kind": kind},
            }
        )
        self.save()

    def finish(self, status: str, message: str, flag: str | None = None) -> None:
        self.status = status
        self.finished_at = utc_now()
        self.event(
            "run_finished",
            status,
            {"message": message, "flag": flag, "trajectory": str(self.path)},
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "events": self.events,
            "spans": self.spans,
            "config_snapshot": self.config_snapshot,
        }

    def save(self) -> None:
        write_json(self.path, self.as_dict())

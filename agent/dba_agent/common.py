from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SECRET_KEYS = ("password", "passwd", "pwd", "secret", "token", "credential", "api_key")
IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_$#]{0,127}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_$#]{1,128}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def read_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return value


def write_json(path: str | Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


def oracle_identifier(value: str, label: str = "identifier") -> str:
    clean = value.strip()
    if not IDENTIFIER_RE.fullmatch(clean):
        raise ValueError(f"Unsafe Oracle {label}: {value!r}")
    return clean.upper()


def qualified_name(value: str) -> tuple[str, str]:
    parts = value.split(".")
    if len(parts) != 2:
        raise ValueError(f"Expected OWNER.OBJECT, got {value!r}")
    return oracle_identifier(parts[0], "owner"), oracle_identifier(parts[1], "object")


def oracle_password(value: str, label: str = "password") -> str:
    if not PASSWORD_RE.fullmatch(value):
        raise ValueError(f"Unsafe Oracle {label}")
    return value


def mask_sql(sql: str | None) -> str | None:
    if not sql:
        return sql
    safe = re.sub(
        r"(?i)(IDENTIFIED\s+BY\s+)(\"[^\"]*\"|'[^']*'|\S+)",
        r"\1***",
        sql,
    )
    return safe


def scrub(value: Any, key: str = "", secrets: list[str] | None = None) -> Any:
    secrets = [item for item in (secrets or []) if item]
    if any(part in key.lower() for part in SECRET_KEYS):
        return "***"
    if isinstance(value, dict):
        return {str(k): scrub(v, str(k), secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(item, key, secrets) for item in value]
    if isinstance(value, str):
        result = mask_sql(value) or ""
        for secret in secrets:
            result = result.replace(secret, "***")
        return result
    return value


def compact(value: Any, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", str(value)).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."

from __future__ import annotations

import re
from typing import Any


class FlagMatcher:
    CONTEXT_MARKERS = ("FLAG", "CTF_FLAG")

    def __init__(self) -> None:
        self.patterns = [
            re.compile(r"CTF\{[^{}\r\n]{1,300}\}", re.IGNORECASE),
            re.compile(r"FLAG\{[^{}\r\n]{1,300}\}", re.IGNORECASE),
        ]

    def scan_rows(
        self,
        rows: list[dict[str, Any]],
        trusted_context: str | None = None,
    ) -> dict[str, Any] | None:
        for row_number, row in enumerate(rows):
            for column, value in row.items():
                text = str(value)[:1000] if value is not None else ""
                for pattern in self.patterns:
                    match = pattern.search(text)
                    if match:
                        return {
                            "flag": match.group(0),
                            "column": column,
                            "row_number": row_number,
                        }
        if not self._is_flag_context(trusted_context, rows):
            return None
        flag_columns = {
            str(column)
            for row in rows
            for column in row
            if "FLAG" in str(column).upper()
        }
        if flag_columns:
            found = self._first_plain_candidate(rows, flag_columns)
            if found:
                return found
        context_upper = (trusted_context or "").upper()
        if not any(marker in context_upper for marker in self.CONTEXT_MARKERS):
            return None
        return self._first_plain_candidate(rows)

    @classmethod
    def _first_plain_candidate(
        cls,
        rows: list[dict[str, Any]],
        allowed_columns: set[str] | None = None,
    ) -> dict[str, Any] | None:
        for row_number, row in enumerate(rows):
            for column, value in row.items():
                if allowed_columns is not None and str(column) not in allowed_columns:
                    continue
                candidate = str(value).strip() if value is not None else ""
                if cls._is_plain_flag_candidate(candidate):
                    return {
                        "flag": candidate,
                        "column": column,
                        "row_number": row_number,
                    }
        return None

    @classmethod
    def _is_flag_context(
        cls,
        context: str | None,
        rows: list[dict[str, Any]],
    ) -> bool:
        context_upper = (context or "").upper()
        if any(marker in context_upper for marker in cls.CONTEXT_MARKERS):
            return True
        return any(
            "FLAG" in str(column).upper()
            for row in rows
            for column in row
        )

    @staticmethod
    def _is_plain_flag_candidate(value: str) -> bool:
        return (
            3 <= len(value) <= 300
            and "\n" not in value
            and "\r" not in value
            and value.upper() not in {"NULL", "NONE", "N/A", "NOT_FOUND"}
        )

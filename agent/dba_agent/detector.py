from __future__ import annotations

import re
from typing import Any


class FlagMatcher:
    """
    Детектор контрольных значений для учебного Oracle CTF.

    Работает в два этапа:
    1. Сначала ищет явные шаблоны: CTF{...}, FLAG{...}, CVE-YYYY-NNNN...
    2. Если явного шаблона нет, принимает непустое значение из доверенного
       контекста: таблица/колонка с признаками FLAG, CTF, SECRET, TOKEN,
       ANSWER, RESULT, KEY, VALUE, INDICATOR, EVIDENCE.
    """

    CONTEXT_MARKERS = (
        "FLAG",
        "CTF",
        "SECRET",
        "TOKEN",
        "ANSWER",
        "RESULT",
        "KEY",
        "VALUE",
        "INDICATOR",
        "EVIDENCE",
        "INCIDENT",
    )

    LOW_VALUE_COLUMNS = {
        "ID",
        "EVIDENCE_ID",
        "CREATED_AT",
        "UPDATED_AT",
        "DATE",
        "CATEGORY",
        "TYPE",
        "STATUS",
    }

    def __init__(self) -> None:
        self.patterns = [
            re.compile(r"CTF\{[^{}\r\n]{1,300}\}", re.IGNORECASE),
            re.compile(r"FLAG\{[^{}\r\n]{1,300}\}", re.IGNORECASE),
            re.compile(
                r"\bCVE-\d{4}-\d{4,7}(?:-[A-Z0-9][A-Z0-9_-]{0,120})?\b",
                re.IGNORECASE,
            ),
        ]

    def scan_rows(
        self,
        rows: list[dict[str, Any]],
        trusted_context: str | None = None,
    ) -> dict[str, Any] | None:
        if not rows:
            return None

        # 1. Явные шаблоны ищем в любом результате.
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

        # 2. Если явного шаблона нет, принимаем plain-value только
        # из доверенного CTF-контекста.
        if not self._is_flag_context(trusted_context, rows):
            return None

        interesting_columns = self._interesting_columns(rows)

        if interesting_columns:
            found = self._first_plain_candidate(rows, interesting_columns)
            if found:
                return found

        return self._first_plain_candidate(rows)

    @classmethod
    def _interesting_columns(cls, rows: list[dict[str, Any]]) -> set[str]:
        result: set[str] = set()

        for row in rows:
            for column in row:
                column_name = str(column).upper()

                if column_name in cls.LOW_VALUE_COLUMNS:
                    continue

                if any(marker in column_name for marker in cls.CONTEXT_MARKERS):
                    result.add(str(column))

        return result

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

                column_name = str(column).upper()
                if column_name in cls.LOW_VALUE_COLUMNS:
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
            any(marker in str(column).upper() for marker in cls.CONTEXT_MARKERS)
            for row in rows
            for column in row
        )

    @staticmethod
    def _is_plain_flag_candidate(value: str) -> bool:
        if not (3 <= len(value) <= 300):
            return False

        if "\n" in value or "\r" in value:
            return False

        if value.upper() in {"NULL", "NONE", "N/A", "NOT_FOUND"}:
            return False

        # Отсекаем слишком обычные служебные значения.
        if value.isdigit():
            return False

        return True
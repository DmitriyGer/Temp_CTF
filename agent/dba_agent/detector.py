from __future__ import annotations

import re
from typing import Any


class FlagMatcher:
    def __init__(self) -> None:
        self.patterns = [
            re.compile(r"CTF\{[^{}\r\n]{1,300}\}", re.IGNORECASE),
            re.compile(r"FLAG\{[^{}\r\n]{1,300}\}", re.IGNORECASE),
        ]

    def scan_rows(self, rows: list[dict[str, Any]]) -> dict[str, Any] | None:
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
        return None

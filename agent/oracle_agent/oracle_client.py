from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import oracledb

from .config import mask_secret


@dataclass
class OracleResult:
    success: bool
    status: str
    rows: list[dict[str, Any]]
    row_count: int
    error_code: str | None = None
    error_message: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "status": self.status,
            "rows": self.rows,
            "row_count": self.row_count,
            "error_code": self.error_code,
            "error_message": self.error_message,
        }


class OracleClient:
    def __init__(self, host: str, port: int, service: str) -> None:
        self.dsn = oracledb.makedsn(host, port, service_name=service)
        self.connection: oracledb.Connection | None = None
        self.current_user: str | None = None

    def connect(self, username: str, password: str) -> OracleResult:
        self.close()
        try:
            self.connection = oracledb.connect(user=username, password=password, dsn=self.dsn)
            self.current_user = username
            return OracleResult(True, "connected", [], 0)
        except oracledb.Error as exc:
            return self._error_result(exc)

    def reconnect_as_user(self, username: str, password: str) -> OracleResult:
        return self.connect(username, password)

    def execute(self, sql: str) -> OracleResult:
        if self.connection is None:
            return OracleResult(False, "error", [], 0, "NOT_CONNECTED", "Oracle is not connected")
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(sql)
            self.connection.commit()
            return OracleResult(True, "executed", [], 0)
        except oracledb.Error as exc:
            return self._error_result(exc)

    def query(self, sql: str) -> OracleResult:
        if self.connection is None:
            return OracleResult(False, "error", [], 0, "NOT_CONNECTED", "Oracle is not connected")
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(sql)
                columns = [item[0].lower() for item in cursor.description or []]
                rows = [
                    {column: self._json_value(value) for column, value in zip(columns, row)}
                    for row in cursor.fetchmany(100)
                ]
            return OracleResult(True, "queried", rows, len(rows))
        except oracledb.Error as exc:
            return self._error_result(exc)

    def close(self) -> None:
        if self.connection is not None:
            try:
                self.connection.close()
            finally:
                self.connection = None
                self.current_user = None

    @staticmethod
    def mask_secret(value: str | None) -> str | None:
        return mask_secret(value)

    @staticmethod
    def _json_value(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return str(value)

    @staticmethod
    def _error_result(exc: oracledb.Error) -> OracleResult:
        error = exc.args[0] if exc.args else exc
        code_value = getattr(error, "code", None)
        code = f"ORA-{int(code_value):05d}" if code_value else "ORACLE_ERROR"
        message = getattr(error, "message", str(error))
        message = re.sub(r"(?i)(identified\s+by\s+)(\S+)", r"\1***", message)
        return OracleResult(False, "error", [], 0, code, message)

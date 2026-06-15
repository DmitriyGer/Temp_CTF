from __future__ import annotations

import re
import time
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import oracledb

from .common import mask_sql
from .journal import RunJournal
from .settings import OracleSettings


@dataclass
class DbResult:
    ok: bool
    rows: list[dict[str, Any]]
    row_count: int
    error_code: str | None = None
    error_message: str | None = None


class OracleGateway:
    FORBIDDEN = re.compile(
        r"\b(DROP|TRUNCATE|DELETE|UPDATE|MERGE|INSERT|SHUTDOWN|STARTUP|HOST|SPOOL)\b",
        re.IGNORECASE,
    )

    def __init__(self, settings: OracleSettings, journal: RunJournal) -> None:
        self.settings = settings
        self.journal = journal
        self.connection: oracledb.Connection | None = None
        self.host: str | None = None
        self.service: str | None = None

    def connect_admin(self) -> None:
        last_error = "not attempted"
        for attempt in range(1, self.settings.retries + 1):
            self.journal.event(
                "oracle_connect_attempt",
                "running",
                {"attempt": attempt, "max_attempts": self.settings.retries},
            )
            for host in self.settings.hosts:
                for service in self.settings.services:
                    dsn = oracledb.makedsn(
                        host, self.settings.port, service_name=service
                    )
                    try:
                        self.connection = oracledb.connect(
                            user=self.settings.username,
                            password=self.settings.password,
                            dsn=dsn,
                            tcp_connect_timeout=self.settings.connect_timeout,
                        )
                        self.connection.autocommit = True
                        self.host, self.service = host, service
                        context = self.query(
                            "SELECT USER AS CURRENT_USER, "
                            "SYS_CONTEXT('USERENV','CON_NAME') AS CONTAINER_NAME FROM DUAL"
                        )
                        self.journal.event(
                            "oracle_connected",
                            "success",
                            {
                                "host": host,
                                "port": self.settings.port,
                                "service": service,
                                "context": context.rows,
                            },
                        )
                        return
                    except oracledb.Error as exc:
                        last_error = self._error(exc)[1]
                        self.journal.event(
                            "oracle_connect_candidate",
                            "failed",
                            {"host": host, "service": service, "error": last_error},
                            logging.WARNING,
                        )
            if attempt < self.settings.retries:
                time.sleep(self.settings.retry_delay)
        raise RuntimeError(f"Cannot connect to Oracle: {last_error}")

    def open_user(self, username: str, password: str) -> oracledb.Connection:
        if not self.host or not self.service:
            raise RuntimeError("Administrative connection has not been established")
        dsn = oracledb.makedsn(
            self.host, self.settings.port, service_name=self.service
        )
        connection = oracledb.connect(user=username, password=password, dsn=dsn)
        connection.autocommit = True
        return connection

    def query(
        self,
        sql: str,
        binds: dict[str, Any] | None = None,
        max_rows: int = 100,
    ) -> DbResult:
        return self._run(sql, binds, max_rows, expect_rows=True)

    def execute(self, sql: str, binds: dict[str, Any] | None = None) -> DbResult:
        return self._run(sql, binds, 0, expect_rows=False)

    def _run(
        self,
        sql: str,
        binds: dict[str, Any] | None,
        max_rows: int,
        expect_rows: bool,
    ) -> DbResult:
        if self.connection is None:
            return DbResult(False, [], 0, "NOT_CONNECTED", "Oracle is not connected")
        started = time.perf_counter()
        safe_sql = mask_sql(sql)
        try:
            self._check_sql(sql)
            with self.connection.cursor() as cursor:
                cursor.execute(sql, binds or {})
                if expect_rows and cursor.description:
                    columns = [item[0].lower() for item in cursor.description]
                    rows = [
                        {
                            column: self._json_value(value)
                            for column, value in zip(columns, raw)
                        }
                        for raw in cursor.fetchmany(max_rows)
                    ]
                    result = DbResult(True, rows, len(rows))
                else:
                    result = DbResult(True, [], max(cursor.rowcount or 0, 0))
            self.journal.span(
                "oracle.query" if expect_rows else "oracle.execute",
                "TOOL",
                "OK",
                started,
                {"sql": safe_sql, "binds": binds or {}},
                {"row_count": result.row_count},
            )
            return result
        except (oracledb.Error, ValueError) as exc:
            code, message = self._error(exc)
            self.journal.span(
                "oracle.query" if expect_rows else "oracle.execute",
                "TOOL",
                "ERROR",
                started,
                {"sql": safe_sql, "binds": binds or {}},
                error=message,
            )
            return DbResult(False, [], 0, code, message)

    def close(self) -> None:
        if self.connection:
            self.connection.close()
            self.connection = None

    def json_value(self, value: Any) -> Any:
        return self._json_value(value)

    def omf_destination(self) -> str:
        result = self.query(
            "SELECT VALUE FROM V$PARAMETER WHERE NAME = 'db_create_file_dest'",
            max_rows=1,
        )
        return str(result.rows[0].get("value") or "").strip() if result.ok and result.rows else ""

    def _check_sql(self, sql: str) -> None:
        normalized = re.sub(r"\s+", " ", sql).strip()
        if ";" in normalized.rstrip(";"):
            raise ValueError("Multiple SQL statements are not allowed")
        if self.FORBIDDEN.search(normalized):
            raise ValueError("Destructive or data-changing SQL is blocked")

    @staticmethod
    def _error(exc: Exception) -> tuple[str, str]:
        if isinstance(exc, oracledb.Error) and exc.args:
            error = exc.args[0]
            code_value = getattr(error, "code", None)
            code = f"ORA-{int(code_value):05d}" if code_value else "ORACLE_ERROR"
            message = getattr(error, "message", str(error))
        else:
            code, message = type(exc).__name__, str(exc)
        return code, re.sub(r"(?i)(IDENTIFIED\s+BY\s+)\S+", r"\1***", message)

    @staticmethod
    def _json_value(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value if not isinstance(value, str) else value[:1000]
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, bytes):
            return value.decode(errors="replace")[:1000]
        if hasattr(value, "read"):
            try:
                return str(value.read())[:1000]
            except Exception:
                pass
        return str(value)[:1000]

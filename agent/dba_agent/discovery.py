from __future__ import annotations

from typing import Any

from .common import oracle_identifier
from .database import OracleGateway
from .detector import FlagMatcher
from .journal import RunJournal
from .settings import SearchSettings


class DatabaseDiscovery:
    USER_COLUMNS = ("USERNAME", "USER_NAME", "LOGIN", "USER")
    PASSWORD_COLUMNS = ("PASSWORD", "PASS", "PASSWD", "PWD", "SECRET")

    def __init__(
        self,
        database: OracleGateway,
        settings: SearchSettings,
        journal: RunJournal,
        matcher: FlagMatcher,
    ) -> None:
        self.database = database
        self.settings = settings
        self.journal = journal
        self.matcher = matcher
        self.checked_objects: list[dict[str, Any]] = []

    def find_credentials(self, exact_hint: str) -> dict[str, str] | None:
        tables = self._credential_tables(exact_hint)
        self.journal.event(
            "credential_candidates",
            "success",
            {"count": len(tables), "objects": tables[:20]},
        )
        for item in tables:
            credentials = self._read_credentials(item["owner"], item["table_name"])
            if credentials:
                self.journal.add_secret(credentials["password"])
                self.journal.event(
                    "credentials_found",
                    "success",
                    {
                        "username": credentials["username"],
                        "password": credentials["password"],
                        "source": credentials["source"],
                    },
                )
                return credentials
        self.journal.event(
            "credentials_found",
            "skipped",
            {"reason": "No readable username/password pair"},
        )
        return None

    def search_flag(self) -> dict[str, Any] | None:
        candidates = self._flag_candidates()
        self.journal.event(
            "fallback_candidates",
            "success",
            {"count": len(candidates)},
        )
        for candidate in candidates[: self.settings.object_limit]:
            owner = candidate["owner"]
            object_name = candidate["object_name"]
            columns = self._safe_columns(owner, object_name)
            if not columns:
                continue
            full_name = f"{owner}.{object_name}"
            sql = (
                f"SELECT {', '.join(columns)} FROM {full_name} "
                f"FETCH FIRST {self.settings.row_limit} ROWS ONLY"
            )
            result = self.database.query(sql, max_rows=self.settings.row_limit)
            self.checked_objects.append(
                {"object": full_name, "sql": sql, "source": candidate.get("source")}
            )
            if not result.ok:
                continue
            found = self.matcher.scan_rows(
                result.rows,
                trusted_context=full_name,
            )
            if found:
                return {
                    "flag": found["flag"],
                    "source": f"{full_name}.{found['column']}",
                    "sql": sql,
                    "strategy": "metadata_search",
                }
        return None

    def _credential_tables(self, hint: str) -> list[dict[str, str]]:
        exact = self.database.query(
            "SELECT OWNER, TABLE_NAME FROM ALL_TABLES WHERE TABLE_NAME = :name",
            {"name": oracle_identifier(hint, "credential table hint")},
            max_rows=100,
        )
        candidates = exact.rows if exact.ok else []
        markers = self.settings.credential_markers
        if markers:
            conditions = " OR ".join(
                f"UPPER(TABLE_NAME) LIKE :m{index}" for index in range(len(markers))
            )
            binds = {
                f"m{index}": f"%{marker.upper()}%"
                for index, marker in enumerate(markers)
            }
            fuzzy = self.database.query(
                f"SELECT OWNER, TABLE_NAME FROM ALL_TABLES WHERE ({conditions}) "
                "ORDER BY OWNER, TABLE_NAME",
                binds,
                max_rows=150,
            )
            if fuzzy.ok:
                candidates.extend(fuzzy.rows)
        unique: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for row in candidates:
            owner = str(row["owner"]).upper()
            table = str(row["table_name"]).upper()
            key = owner, table
            if owner not in self.settings.excluded_owners and key not in seen:
                seen.add(key)
                unique.append({"owner": owner, "table_name": table})
        return unique

    def _read_credentials(self, owner: str, table_name: str) -> dict[str, str] | None:
        owner = oracle_identifier(owner, "owner")
        table_name = oracle_identifier(table_name, "table")
        metadata = self.database.query(
            "SELECT COLUMN_NAME FROM ALL_TAB_COLUMNS "
            "WHERE OWNER = :owner AND TABLE_NAME = :table ORDER BY COLUMN_ID",
            {"owner": owner, "table": table_name},
            max_rows=100,
        )
        if not metadata.ok:
            return None
        columns = [str(row["column_name"]).upper() for row in metadata.rows]
        user_columns = [
            column
            for column in columns
            if any(marker in column for marker in self.USER_COLUMNS)
        ]
        password_columns = [
            column
            for column in columns
            if any(marker in column for marker in self.PASSWORD_COLUMNS)
        ]
        if not user_columns or not password_columns:
            return None
        full_name = f"{owner}.{table_name}"
        rows = self.database.query(
            f"SELECT * FROM {full_name} FETCH FIRST 20 ROWS ONLY",
            max_rows=20,
        )
        if not rows.ok:
            return None
        for row in rows.rows:
            for user_column in user_columns:
                for password_column in password_columns:
                    username = row.get(user_column.lower())
                    password = row.get(password_column.lower())
                    if username and password:
                        return {
                            "username": str(username),
                            "password": str(password),
                            "source": full_name,
                        }
        return None

    def _flag_candidates(self) -> list[dict[str, str]]:
        markers = self.settings.name_markers
        binds = {
            f"m{index}": f"%{marker.upper()}%"
            for index, marker in enumerate(markers)
        }
        object_conditions = " OR ".join(
            f"UPPER(OBJECT_NAME) LIKE :m{index}" for index in range(len(markers))
        )
        column_conditions = " OR ".join(
            f"UPPER(COLUMN_NAME) LIKE :m{index}" for index in range(len(markers))
        )
        items: list[dict[str, str]] = []
        if object_conditions:
            objects = self.database.query(
                "SELECT OWNER, OBJECT_NAME, OBJECT_TYPE FROM ALL_OBJECTS "
                "WHERE OBJECT_TYPE IN ('TABLE','VIEW') "
                f"AND ({object_conditions}) ORDER BY OWNER, OBJECT_NAME",
                binds,
                max_rows=500,
            )
            if objects.ok:
                items.extend(
                    {
                        "owner": str(row["owner"]).upper(),
                        "object_name": str(row["object_name"]).upper(),
                        "source": "object_name",
                    }
                    for row in objects.rows
                )
        if column_conditions:
            columns = self.database.query(
                "SELECT OWNER, TABLE_NAME, COLUMN_NAME FROM ALL_TAB_COLUMNS "
                f"WHERE ({column_conditions}) ORDER BY OWNER, TABLE_NAME, COLUMN_ID",
                binds,
                max_rows=500,
            )
            if columns.ok:
                items.extend(
                    {
                        "owner": str(row["owner"]).upper(),
                        "object_name": str(row["table_name"]).upper(),
                        "source": f"column:{row['column_name']}",
                    }
                    for row in columns.rows
                )
        unique: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in items:
            key = item["owner"], item["object_name"]
            if item["owner"] not in self.settings.excluded_owners and key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    def _safe_columns(self, owner: str, object_name: str) -> list[str]:
        metadata = self.database.query(
            "SELECT COLUMN_NAME, DATA_TYPE FROM ALL_TAB_COLUMNS "
            "WHERE OWNER = :owner AND TABLE_NAME = :table ORDER BY COLUMN_ID",
            {"owner": owner, "table": object_name},
            max_rows=200,
        )
        if not metadata.ok:
            return []
        columns: list[str] = []
        for row in metadata.rows:
            if str(row["data_type"]).upper() not in self.settings.allowed_types:
                continue
            try:
                columns.append(oracle_identifier(str(row["column_name"]), "column"))
            except ValueError:
                continue
            if len(columns) >= self.settings.column_limit:
                break
        return columns

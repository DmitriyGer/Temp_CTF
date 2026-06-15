from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class GuardResult:
    allowed: bool
    normalized_sql: str
    reason: str


FORBIDDEN = re.compile(
    r"\b(DROP|TRUNCATE|DELETE|UPDATE|MERGE|INSERT|SHUTDOWN|STARTUP)\b",
    re.IGNORECASE,
)
FORBIDDEN_GRANTS = re.compile(
    r"\b(DBA|ALL(?:\s+PRIVILEGES)?|SELECT\s+ANY\s+TABLE|"
    r"(?:CREATE|ALTER|DROP|INSERT|UPDATE|DELETE)\s+ANY)\b",
    re.IGNORECASE,
)
ALLOWED_SELECT_OBJECT = re.compile(
    r"^(?:"
    r"(?:[A-Z][A-Z0-9_$#]*\.)?CREDENTIALS|"
    r"CTF\.CTF_FLAG|DUAL|SESSION_ROLES|SESSION_PRIVS|"
    r"(?:DBA|ALL|USER)_[A-Z0-9_$#]+|"
    r"V_\$[A-Z0-9_$#]+|V\$[A-Z0-9_$#]+"
    r")$"
)


def normalize_sql(sql: str) -> str:
    without_comments = re.sub(r"/\*.*?\*/|--[^\r\n]*", " ", sql, flags=re.DOTALL)
    return re.sub(r"\s+", " ", without_comments).strip().rstrip(";").strip()


class SQLGuard:
    def __init__(self, allow_alter_system: bool = False) -> None:
        self.allow_alter_system = allow_alter_system

    def check(self, sql: str | None) -> GuardResult:
        if not sql or not sql.strip():
            return GuardResult(False, "", "SQL is empty")
        normalized = normalize_sql(sql)
        upper = normalized.upper()

        if ";" in normalized:
            return GuardResult(False, normalized, "Multiple SQL statements are not allowed")
        if FORBIDDEN.search(upper):
            return GuardResult(False, normalized, "Destructive or data-changing SQL is forbidden")
        if FORBIDDEN_GRANTS.search(upper):
            return GuardResult(False, normalized, "DBA, ALL and ANY privileges are forbidden")

        if upper == "ALTER SYSTEM SET RESOURCE_LIMIT=TRUE":
            return GuardResult(
                self.allow_alter_system,
                normalized,
                "Allowed by ALLOW_ALTER_SYSTEM" if self.allow_alter_system
                else "ALTER SYSTEM requires ALLOW_ALTER_SYSTEM=true",
            )
        if upper.startswith("ALTER SYSTEM"):
            return GuardResult(False, normalized, "ALTER SYSTEM is outside the CTF scope")

        if upper.startswith("SELECT "):
            return self._check_select(normalized)
        if re.fullmatch(r"CREATE TABLESPACE CTF_TABLESPACE\b.+", upper):
            return GuardResult(True, normalized, "Allowed CTF tablespace operation")
        if re.fullmatch(r"ALTER TABLESPACE CTF_TABLESPACE\b.+", upper):
            return GuardResult(True, normalized, "Allowed CTF tablespace operation")
        if re.fullmatch(r"CREATE PROFILE CTF_PROFILE LIMIT\b.+", upper):
            return GuardResult(True, normalized, "Allowed CTF profile operation")
        if re.fullmatch(r"ALTER PROFILE CTF_PROFILE LIMIT\b.+", upper):
            return GuardResult(True, normalized, "Allowed CTF profile operation")
        if re.fullmatch(r"CREATE ROLE CTF_ROLE IDENTIFIED BY .+", upper):
            return GuardResult(True, normalized, "Allowed protected CTF role creation")
        if re.fullmatch(r"ALTER ROLE CTF_ROLE IDENTIFIED BY .+", upper):
            return GuardResult(True, normalized, "Allowed protected CTF role change")
        if re.fullmatch(r"CREATE USER CTF_STUDENT\b.+", upper):
            return GuardResult(True, normalized, "Allowed CTF student creation")
        if re.fullmatch(r"ALTER USER COMPROMISED_USER ACCOUNT UNLOCK", upper):
            return GuardResult(True, normalized, "Allowed scenario account unlock")
        if re.fullmatch(r"ALTER USER CTF_STUDENT DEFAULT ROLE NONE", upper):
            return GuardResult(True, normalized, "Allowed default-role restriction")
        if re.fullmatch(r"ALTER USER CTF_STUDENT\b.+", upper):
            return GuardResult(True, normalized, "Allowed CTF student change")
        if upper == "GRANT CREATE SESSION TO CTF_STUDENT":
            return GuardResult(True, normalized, "Allowed minimal system privilege")
        if upper == "GRANT CTF_ROLE TO CTF_STUDENT":
            return GuardResult(True, normalized, "Allowed CTF role assignment")
        if upper == "GRANT SELECT ON CTF.CTF_FLAG TO CTF_ROLE":
            return GuardResult(True, normalized, "Allowed object privilege through role")
        if upper == "GRANT SELECT ON CTF.CTF_FLAG TO CTF_STUDENT":
            return GuardResult(False, normalized, "Direct flag access for CTF_STUDENT is forbidden")
        if re.fullmatch(r"SET ROLE CTF_ROLE IDENTIFIED BY .+", upper):
            return GuardResult(True, normalized, "Allowed protected role activation")

        return GuardResult(False, normalized, "SQL is outside the explicit Oracle CTF allowlist")

    def _check_select(self, sql: str) -> GuardResult:
        upper = sql.upper()
        objects = re.findall(r"\b(?:FROM|JOIN)\s+([A-Z0-9_$#.]+)", upper)
        if not objects:
            return GuardResult(False, sql, "SELECT must name an allowed object")
        blocked = [obj for obj in objects if not ALLOWED_SELECT_OBJECT.fullmatch(obj)]
        if blocked:
            return GuardResult(False, sql, f"SELECT object is outside CTF scope: {blocked[0]}")
        return GuardResult(True, sql, "Read-only query on an allowed CTF or metadata object")

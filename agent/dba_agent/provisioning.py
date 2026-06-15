from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from .common import oracle_identifier, oracle_password, qualified_name
from .database import DbResult, OracleGateway
from .detector import FlagMatcher
from .journal import RunJournal


class CtfProvisioner:
    def __init__(
        self,
        database: OracleGateway,
        journal: RunJournal,
        matcher: FlagMatcher,
    ) -> None:
        self.database = database
        self.journal = journal
        self.matcher = matcher

    def unlock_if_present(self, username: str) -> bool:
        username = oracle_identifier(username, "username")
        current = self.database.query(
            "SELECT USERNAME, ACCOUNT_STATUS FROM DBA_USERS WHERE USERNAME = :username",
            {"username": username},
        )
        if not current.ok or not current.rows:
            self.journal.event("unlock_compromised_user", "skipped", {"username": username})
            return False
        result = self.database.execute(f"ALTER USER {username} ACCOUNT UNLOCK")
        self._require(result, "unlock_compromised_user")
        verify = self.database.query(
            "SELECT USERNAME, ACCOUNT_STATUS FROM DBA_USERS WHERE USERNAME = :username",
            {"username": username},
        )
        self.journal.event(
            "unlock_compromised_user",
            "success",
            {"username": username, "verification": verify.rows},
        )
        return True

    def verify_login(self, username: str, password: str) -> bool:
        try:
            connection = self.database.open_user(username, password)
            with connection.cursor() as cursor:
                cursor.execute("SELECT USER FROM DUAL")
                current_user = cursor.fetchone()[0]
            connection.close()
            self.journal.event(
                "credential_login",
                "success",
                {"username": username, "current_user": current_user},
            )
            return True
        except Exception as exc:
            self.journal.event(
                "credential_login",
                "failed",
                {"username": username, "error": str(exc)},
            )
            return False

    def ensure_tablespace(self, spec: dict[str, Any]) -> None:
        name = oracle_identifier(spec["name"], "tablespace")
        exists = self.database.query(
            "SELECT TABLESPACE_NAME FROM DBA_TABLESPACES WHERE TABLESPACE_NAME = :name",
            {"name": name},
        )
        if exists.ok and exists.rows:
            self.journal.event("tablespace", "exists", {"name": name})
            return
        size = int(spec["size_mb"])
        next_size = int(spec.get("next_mb", 50))
        max_size = int(spec.get("max_size_mb", 1024))
        autoextend = (
            f"AUTOEXTEND ON NEXT {next_size}M MAXSIZE {max_size}M"
            if spec.get("autoextend", True)
            else "AUTOEXTEND OFF"
        )
        if self.database.omf_destination():
            sql = f"CREATE TABLESPACE {name} DATAFILE SIZE {size}M {autoextend}"
        else:
            datafile = self._datafile_path(name)
            sql = (
                f"CREATE TABLESPACE {name} DATAFILE '{datafile}' "
                f"SIZE {size}M {autoextend}"
            )
        self._require(self.database.execute(sql), "create_tablespace")
        verify = self.database.query(
            "SELECT TABLESPACE_NAME FROM DBA_TABLESPACES WHERE TABLESPACE_NAME = :name",
            {"name": name},
        )
        if not verify.ok or not verify.rows:
            raise RuntimeError(f"Tablespace {name} was not found after CREATE")
        self.journal.event("tablespace", "ready", {"name": name, "size_mb": size})

    def ensure_profile(self, spec: dict[str, Any]) -> None:
        name = oracle_identifier(spec["name"], "profile")
        limits = " ".join(
            f"{oracle_identifier(key, 'profile limit')} {self._limit_value(value)}"
            for key, value in spec["limits"].items()
        )
        exists = self.database.query(
            "SELECT DISTINCT PROFILE FROM DBA_PROFILES WHERE PROFILE = :name",
            {"name": name},
        )
        verb = "ALTER" if exists.ok and exists.rows else "CREATE"
        self._require(
            self.database.execute(f"{verb} PROFILE {name} LIMIT {limits}"),
            f"{verb.lower()}_profile",
        )
        verify = self.database.query(
            "SELECT RESOURCE_NAME, LIMIT FROM DBA_PROFILES "
            "WHERE PROFILE = :name ORDER BY RESOURCE_NAME",
            {"name": name},
        )
        self.journal.event(
            "profile",
            "ready",
            {"name": name, "limits": spec["limits"], "verified_rows": len(verify.rows)},
        )

    def ensure_role(self, spec: dict[str, Any]) -> None:
        name = oracle_identifier(spec["name"], "role")
        password = oracle_password(str(spec["password"]), "role password")
        self.journal.add_secret(password)
        exists = self.database.query(
            "SELECT ROLE FROM DBA_ROLES WHERE ROLE = :name", {"name": name}
        )
        verb = "ALTER" if exists.ok and exists.rows else "CREATE"
        self._require(
            self.database.execute(f"{verb} ROLE {name} IDENTIFIED BY {password}"),
            f"{verb.lower()}_role",
        )
        self.journal.event("role", "ready", {"name": name})

    def ensure_student(self, spec: dict[str, Any]) -> None:
        username = oracle_identifier(spec["username"], "student username")
        password = oracle_password(str(spec["password"]), "student password")
        tablespace = oracle_identifier(spec["default_tablespace"], "tablespace")
        temporary = oracle_identifier(spec.get("temporary_tablespace", "TEMP"), "temporary")
        profile = oracle_identifier(spec["profile"], "profile")
        quota = int(spec["quota_mb"])
        self.journal.add_secret(password)
        exists = self.database.query(
            "SELECT USERNAME FROM DBA_USERS WHERE USERNAME = :username",
            {"username": username},
        )
        if exists.ok and exists.rows:
            statements = [
                f"ALTER USER {username} IDENTIFIED BY {password}",
                f"ALTER USER {username} DEFAULT TABLESPACE {tablespace}",
                f"ALTER USER {username} TEMPORARY TABLESPACE {temporary}",
                f"ALTER USER {username} QUOTA {quota}M ON {tablespace}",
                f"ALTER USER {username} PROFILE {profile}",
                f"ALTER USER {username} ACCOUNT UNLOCK",
            ]
            for index, sql in enumerate(statements):
                result = self.database.execute(sql)
                if not result.ok and not (
                    index == 0 and result.error_code == "ORA-28007"
                ):
                    self._require(result, "alter_student")
        else:
            self._require(
                self.database.execute(
                    f"CREATE USER {username} IDENTIFIED BY {password} "
                    f"DEFAULT TABLESPACE {tablespace} TEMPORARY TABLESPACE {temporary} "
                    f"QUOTA {quota}M ON {tablespace} PROFILE {profile} ACCOUNT UNLOCK"
                ),
                "create_student",
            )
        verify = self.database.query(
            "SELECT USERNAME, DEFAULT_TABLESPACE, TEMPORARY_TABLESPACE, "
            "PROFILE, ACCOUNT_STATUS FROM DBA_USERS WHERE USERNAME = :username",
            {"username": username},
        )
        if not verify.ok or not verify.rows:
            raise RuntimeError(f"Student user {username} is not ready")
        self.journal.event("student_user", "ready", {"username": username, "quota_mb": quota})

    def apply_grants(self, task: dict[str, Any]) -> None:
        username = oracle_identifier(task["student"]["username"], "student")
        role = oracle_identifier(task["role"]["name"], "role")
        owner, object_name = qualified_name(task["flag_object"])
        flag_object = self.database.query(
            "SELECT OWNER, OBJECT_NAME, OBJECT_TYPE FROM ALL_OBJECTS "
            "WHERE OWNER = :owner AND OBJECT_NAME = :object_name "
            "AND OBJECT_TYPE IN ('TABLE','VIEW')",
            {"owner": owner, "object_name": object_name},
        )
        if not flag_object.ok or not flag_object.rows:
            raise RuntimeError(f"Flag object {owner}.{object_name} is unavailable")
        self._require(
            self.database.execute(f"GRANT CREATE SESSION TO {username}"),
            "grant_create_session",
        )
        self._require(
            self.database.execute(f"GRANT {role} TO {username}"),
            "grant_role",
        )
        self._require(
            self.database.execute(f"ALTER USER {username} DEFAULT ROLE NONE"),
            "disable_default_role",
        )
        self._require(
            self.database.execute(
                f"GRANT SELECT ON {owner}.{object_name} TO {role}"
            ),
            "grant_flag_select",
        )
        verify = self.database.query(
            "SELECT GRANTEE, GRANTED_ROLE, DEFAULT_ROLE FROM DBA_ROLE_PRIVS "
            "WHERE GRANTEE = :username AND GRANTED_ROLE = :role",
            {"username": username, "role": role},
        )
        self.journal.event("grants", "ready", {"role_assignment": verify.rows})

    def read_flag(self, task: dict[str, Any], strategy: str) -> dict[str, Any] | None:
        username = oracle_identifier(task["student"]["username"], "student")
        student_password = oracle_password(
            str(task["student"]["password"]), "student password"
        )
        role = oracle_identifier(task["role"]["name"], "role")
        role_password = oracle_password(str(task["role"]["password"]), "role password")
        owner, object_name = qualified_name(task["flag_object"])
        sql = f"SELECT * FROM {owner}.{object_name} FETCH FIRST 25 ROWS ONLY"
        try:
            connection = self.database.open_user(username, student_password)
            with connection.cursor() as cursor:
                cursor.execute(f"SET ROLE {role} IDENTIFIED BY {role_password}")
                cursor.execute(sql)
                columns = [item[0].lower() for item in cursor.description]
                rows = [
                    {
                        column: self.database.json_value(value)
                        for column, value in zip(columns, row)
                    }
                    for row in cursor.fetchmany(25)
                ]
            connection.close()
            found = self.matcher.scan_rows(rows)
            if found:
                self.journal.event(
                    "flag_read",
                    "success",
                    {"source": f"{owner}.{object_name}.{found['column']}"},
                )
                return {
                    "flag": found["flag"],
                    "source": f"{owner}.{object_name}.{found['column']}",
                    "sql": sql,
                    "strategy": strategy,
                }
            self.journal.event("flag_read", "not_found", {"object": f"{owner}.{object_name}"})
        except Exception as exc:
            self.journal.event(
                "flag_read",
                "failed",
                {"object": f"{owner}.{object_name}", "error": str(exc)},
            )
        return None

    def _datafile_path(self, tablespace: str) -> str:
        configured = self.database.settings.datafile_dir.strip()
        if configured:
            if any(char in configured for char in ("'", ";", "\n", "\r")):
                raise ValueError("Unsafe ORACLE_DATAFILE_DIR")
            return f"{configured.rstrip('/')}/{tablespace.lower()}01.dbf"
        users_file = self.database.query(
            "SELECT FILE_NAME FROM DBA_DATA_FILES "
            "WHERE TABLESPACE_NAME = 'USERS' FETCH FIRST 1 ROWS ONLY",
            max_rows=1,
        )
        if not users_file.ok or not users_file.rows:
            raise RuntimeError("OMF is disabled and USERS datafile directory is unavailable")
        parent = PurePosixPath(str(users_file.rows[0]["file_name"])).parent
        return str(parent / f"{tablespace.lower()}01.dbf")

    @staticmethod
    def _limit_value(value: Any) -> str:
        if isinstance(value, int):
            return str(value)
        clean = str(value).strip().upper()
        if not clean or any(char in clean for char in (";", "'", '"')):
            raise ValueError(f"Unsafe profile limit value: {value!r}")
        return clean

    @staticmethod
    def _require(result: DbResult, stage: str) -> None:
        if not result.ok:
            raise RuntimeError(
                f"{stage} failed: {result.error_code or ''} {result.error_message or ''}".strip()
            )

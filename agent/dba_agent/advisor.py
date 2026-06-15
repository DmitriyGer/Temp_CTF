from __future__ import annotations

import json
import re
import time
from typing import Any

import requests

from .common import compact
from .database import OracleGateway
from .detector import FlagMatcher
from .journal import RunJournal
from .settings import LlmSettings


class OptionalAdvisor:
    BLOCKED_SQL = re.compile(
        r"\b(ALTER|ANALYZE|AUDIT|BEGIN|CALL|COMMENT|COMMIT|CREATE|DELETE|DROP|"
        r"EXECUTE|GRANT|INSERT|LOCK|MERGE|RENAME|REVOKE|ROLLBACK|SET|SHUTDOWN|"
        r"STARTUP|TRUNCATE|UPDATE|DBMS_|UTL_)\b",
        re.IGNORECASE,
    )
    SYSTEM_OWNERS = {
        "ANONYMOUS",
        "AUDSYS",
        "CTXSYS",
        "DBSFWUSER",
        "DBSNMP",
        "DIP",
        "DVF",
        "DVSYS",
        "GGSYS",
        "GSMADMIN_INTERNAL",
        "GSMCATUSER",
        "GSMUSER",
        "LBACSYS",
        "MDSYS",
        "OJVMSYS",
        "OLAPSYS",
        "ORACLE_OCM",
        "ORDDATA",
        "ORDPLUGINS",
        "ORDSYS",
        "OUTLN",
        "REMOTE_SCHEDULER_AGENT",
        "SYS",
        "SYSBACKUP",
        "SYSDG",
        "SYSKM",
        "SYSRAC",
        "SYSTEM",
        "WMSYS",
        "XDB",
        "XS$NULL",
    }

    def __init__(self, settings: LlmSettings, policy: dict[str, Any], journal: RunJournal) -> None:
        self.settings = settings
        self.policy = policy
        self.journal = journal

    def explain(self, stage: str, error: str) -> str | None:
        if not self.settings.enabled or not self.settings.explain_errors:
            return None
        prompt = (
            "Ты консультант по локальной учебной Oracle CTF. "
            "Не создавай SQL и не предлагай обход прав. "
            "Кратко объясни ошибку и назови безопасную проверку.\n"
            f"Этап: {stage}\nОшибка: {compact(error, 1000)}\n"
            f"Правила: {json.dumps(self.policy.get('advisor_rules', []), ensure_ascii=False)}"
        )
        started = time.perf_counter()
        try:
            answer = self._request(prompt)
            self.journal.span(
                "llm.explain_error",
                "LLM",
                "OK",
                started,
                {"stage": stage, "error": error},
                {"answer": compact(answer, 1000)},
            )
            self.journal.event(
                "llm_advice",
                "success",
                {"stage": stage, "answer": compact(answer, 500)},
            )
            return answer
        except Exception as exc:
            self.journal.span(
                "llm.explain_error",
                "LLM",
                "ERROR",
                started,
                {"stage": stage},
                error=str(exc),
            )
            if self.settings.optional:
                self.journal.event(
                    "llm_advice",
                    "skipped",
                    {"reason": str(exc)},
                )
                return None
            raise

    def search_flag(
        self,
        database: OracleGateway,
        matcher: FlagMatcher,
        failed_tasks: list[str],
    ) -> dict[str, Any] | None:
        if not self.settings.enabled:
            self.journal.event(
                "llm_search",
                "skipped",
                {"reason": "LLM is disabled"},
            )
            return None

        self.journal.event(
            "llm_search_started",
            "running",
            {
                "model": self.settings.model,
                "max_steps": self.settings.search_steps,
                "failed_tasks": failed_tasks,
            },
        )
        grounding = self._collect_grounding(database)
        observation: dict[str, Any] = {
            "status": "start",
            "failed_tasks": failed_tasks,
            "known_flag_object": "CTF.CTF_FLAG was checked and did not contain a flag",
            "database_map": grounding,
            "instruction": (
                "Choose a promising non-system object from database_map. "
                "Inspect its columns or read a small number of rows."
            ),
        }
        attempted_sql: set[str] = set()
        history: list[dict[str, Any]] = []

        for step in range(1, self.settings.search_steps + 1):
            prompt = self._search_prompt(step, observation, history)
            self.journal.event(
                "llm_thinking",
                "running",
                {"step": step, "model": self.settings.model},
            )
            started = time.perf_counter()
            try:
                raw_answer = self._request(prompt, max_tokens=700, json_mode=True)
            except Exception as exc:
                self.journal.span(
                    "llm.search_action",
                    "LLM",
                    "ERROR",
                    started,
                    {"step": step},
                    error=str(exc),
                )
                self.journal.event(
                    "llm_action",
                    "failed",
                    {"step": step, "error": str(exc)},
                )
                if self.settings.optional:
                    return None
                raise

            try:
                action = self._parse_action(raw_answer)
                self.journal.span(
                    "llm.search_action",
                    "LLM",
                    "OK",
                    started,
                    {"step": step, "observation": observation},
                    {"action": action, "raw_answer": compact(raw_answer, 1500)},
                )
                self.journal.event(
                    "llm_action",
                    "success",
                    {
                        "step": step,
                        "action": action.get("action"),
                        "reason": compact(action.get("reason", ""), 500),
                        "sql": action.get("sql"),
                    },
                )
            except Exception as exc:
                self.journal.span(
                    "llm.search_action",
                    "LLM",
                    "ERROR",
                    started,
                    {"step": step},
                    error=str(exc),
                )
                self.journal.event(
                    "llm_action",
                    "rejected",
                    {
                        "step": step,
                        "error": str(exc),
                        "response": compact(raw_answer, 1000),
                    },
                )
                observation = {
                    "status": "invalid_llm_response",
                    "error": str(exc),
                    "response": compact(raw_answer, 1000),
                    "instruction": "Return only a valid JSON object matching the schema.",
                }
                continue

            if action["action"] == "finish":
                self.journal.event(
                    "llm_search_finished",
                    "not_found",
                    {"step": step, "reason": action.get("reason", "")},
                )
                return None

            sql = str(action.get("sql") or "").strip()
            try:
                sql = self._validate_read_only_sql(sql)
                normalized_sql = re.sub(r"\s+", " ", sql).upper()
                if re.search(
                    r"\bSELECT \* FROM ALL_(OBJECTS|TABLES|VIEWS|TAB_COLUMNS)\b",
                    normalized_sql,
                ):
                    raise ValueError(
                        "Broad data-dictionary scans are unnecessary; use database_map"
                    )
                if normalized_sql in attempted_sql:
                    raise ValueError("This SQL query was already executed")
                direct_owner = self._direct_system_owner(sql)
                if direct_owner:
                    raise ValueError(
                        f"Direct reads from Oracle-maintained schema {direct_owner} are not useful"
                    )
                attempted_sql.add(normalized_sql)
            except ValueError as exc:
                observation = {
                    "status": "rejected",
                    "error": str(exc),
                    "database_map": grounding,
                    "instruction": (
                        "Choose a different read-only query against a non-system object "
                        "from database_map."
                    ),
                }
                self.journal.event(
                    "llm_query",
                    "rejected",
                    {"step": step, "sql": sql, "error": str(exc)},
                )
                continue

            self.journal.event(
                "llm_query",
                "running",
                {"step": step, "sql": sql},
            )
            result = database.query(sql, max_rows=self.settings.query_row_limit)
            if not result.ok:
                observation = {
                    "status": "oracle_error",
                    "sql": sql,
                    "error_code": result.error_code,
                    "error": result.error_message,
                    "database_map": grounding,
                }
                history.append(
                    {
                        "step": step,
                        "sql": sql,
                        "status": "oracle_error",
                        "error": compact(result.error_message, 300),
                    }
                )
                self.journal.event(
                    "llm_query",
                    "failed",
                    {"step": step, **observation},
                )
                continue

            found = matcher.scan_rows(result.rows, trusted_context=sql)
            self.journal.event(
                "llm_query",
                "success",
                {
                    "step": step,
                    "sql": sql,
                    "row_count": result.row_count,
                    "rows_preview": result.rows[:5],
                },
            )
            if found:
                source = f"LLM query result column {found['column']}"
                self.journal.event(
                    "llm_flag_found",
                    "success",
                    {"step": step, "source": source, "sql": sql},
                )
                return {
                    "flag": found["flag"],
                    "source": source,
                    "sql": sql,
                    "strategy": "llm_search",
                }

            rows_for_model = self._compact_rows(result.rows)
            history.append(
                {
                    "step": step,
                    "sql": sql,
                    "status": "empty" if not result.rows else "no_flag",
                    "row_count": result.row_count,
                }
            )
            observation = {
                "status": "query_success",
                "sql": sql,
                "row_count": result.row_count,
                "rows": rows_for_model,
                "database_map": grounding,
                "instruction": (
                    "No flag matched. Do not query this empty object again. "
                    "Choose another promising non-system object or inspect its columns."
                ),
            }

        self.journal.event(
            "llm_search_finished",
            "not_found",
            {"reason": "step limit reached", "steps": self.settings.search_steps},
        )
        return None

    def _search_prompt(
        self,
        step: int,
        observation: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> str:
        return (
            "Ты LLM-агент для локальной учебной Oracle CTF. "
            "Три известных варианта уже не нашли флаг. Самостоятельно исследуй БД "
            "последовательными read-only SELECT-запросами. "
            "Карта пользовательских объектов уже передана в database_map. "
            "Сначала используй database_map, не делай широкий SELECT * из ALL_OBJECTS. "
            "Игнорируй Oracle-maintained схемы вроде SYS, SYSTEM, GSMADMIN_INTERNAL, "
            "LBACSYS, XDB и MDSYS. "

            "Важно: контрольное значение может быть не только CTF{...} или FLAG{...}. "
            "Оно может выглядеть как CVE-YYYY-NNNN, token, secret, answer, result, key, "
            "indicator_value или другое нестандартное значение в пользовательской таблице. "
            "Если ты уже получил строку из подозрительной пользовательской таблицы и видишь "
            "в ней CVE-like, token-like или явно контрольное значение, не продолжай искать "
            "CTF{...}; выбирай следующий запрос только если текущая таблица пустая или "
            "в ней нет полезных строк. "

            "Не используй DDL, DML, PL/SQL, DBMS_* и UTL_*. "
            "Не повторяй запросы. Если запрос уже был отклонён как повторный, выбери другой. "
            "Если объект пуст, сразу переходи к другому кандидату. "

            "За один шаг верни ровно один JSON-объект без markdown:\n"
            '{"action":"query","sql":"SELECT ...","reason":"кратко"}\n'
            "Когда разумные варианты исчерпаны:\n"
            '{"action":"finish","sql":null,"reason":"кратко"}\n'

            f"Шаг: {step}/{self.settings.search_steps}\n"
            "История уже выполненных запросов:\n"
            f"{json.dumps(history[-8:], ensure_ascii=False, default=str)}\n"
            "Последнее наблюдение:\n"
            f"{json.dumps(observation, ensure_ascii=False, default=str)[:9000]}"
        )

    def _collect_grounding(self, database: OracleGateway) -> dict[str, Any]:
        owners_result = database.query(
            "SELECT USERNAME FROM ALL_USERS "
            "WHERE ORACLE_MAINTAINED = 'N' ORDER BY USERNAME",
            max_rows=80,
        )
        owners = [
            str(row.get("username"))
            for row in owners_result.rows
            if row.get("username")
        ] if owners_result.ok else []

        objects_result = database.query(
            "SELECT O.OWNER, O.OBJECT_NAME, O.OBJECT_TYPE "
            "FROM ALL_OBJECTS O JOIN ALL_USERS U ON U.USERNAME = O.OWNER "
            "WHERE U.ORACLE_MAINTAINED = 'N' "
            "AND O.OBJECT_TYPE IN ('TABLE','VIEW') "
            "ORDER BY O.OWNER, O.OBJECT_NAME",
            max_rows=160,
        )
        objects = self._compact_rows(objects_result.rows) if objects_result.ok else []

        columns_result = database.query(
            "SELECT C.OWNER, C.TABLE_NAME, C.COLUMN_NAME, C.DATA_TYPE "
            "FROM ALL_TAB_COLUMNS C JOIN ALL_USERS U ON U.USERNAME = C.OWNER "
            "WHERE U.ORACLE_MAINTAINED = 'N' "
            "AND (UPPER(C.TABLE_NAME) LIKE '%FLAG%' "
            "OR UPPER(C.TABLE_NAME) LIKE '%CTF%' "
            "OR UPPER(C.TABLE_NAME) LIKE '%SECRET%' "
            "OR UPPER(C.TABLE_NAME) LIKE '%TOKEN%' "
            "OR UPPER(C.COLUMN_NAME) LIKE '%FLAG%' "
            "OR UPPER(C.COLUMN_NAME) LIKE '%SECRET%' "
            "OR UPPER(C.COLUMN_NAME) LIKE '%TOKEN%' "
            "OR UPPER(C.COLUMN_NAME) LIKE '%VALUE%' "
            "OR UPPER(C.COLUMN_NAME) LIKE '%DATA%') "
            "ORDER BY C.OWNER, C.TABLE_NAME, C.COLUMN_ID",
            max_rows=160,
        )
        columns = self._compact_rows(columns_result.rows) if columns_result.ok else []
        context = {
            "non_system_owners": owners,
            "objects": objects,
            "interesting_columns": columns,
        }
        self.journal.event(
            "llm_grounding",
            "success",
            {
                "owner_count": len(owners),
                "object_count": len(objects),
                "interesting_column_count": len(columns),
            },
        )
        return context

    @staticmethod
    def _compact_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        compacted: list[dict[str, Any]] = []
        for row in rows[:40]:
            compacted.append(
                {
                    str(key): value
                    for index, (key, value) in enumerate(row.items())
                    if index < 10
                }
            )
        return compacted

    @classmethod
    def _direct_system_owner(cls, sql: str) -> str | None:
        references = re.findall(
            r"\b(?:FROM|JOIN)\s+([A-Z][A-Z0-9_$#]*)\.",
            sql.upper(),
        )
        return next((owner for owner in references if owner in cls.SYSTEM_OWNERS), None)

    @staticmethod
    def _parse_action(answer: str) -> dict[str, Any]:
        text = answer.strip()
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced:
            text = fenced.group(1)
        else:
            start, end = text.find("{"), text.rfind("}")
            if start >= 0 and end > start:
                text = text[start : end + 1]
        value = json.loads(text)
        if not isinstance(value, dict):
            raise ValueError("LLM response is not a JSON object")
        action = str(value.get("action", "")).lower()
        if action not in {"query", "finish"}:
            raise ValueError(f"Unsupported LLM action: {action!r}")
        if action == "query" and not value.get("sql"):
            raise ValueError("LLM query action has no SQL")
        value["action"] = action
        return value

    @classmethod
    def _validate_read_only_sql(cls, sql: str) -> str:
        clean = sql.strip()
        if clean.endswith(";"):
            clean = clean[:-1].rstrip()
        if not clean or not re.match(r"^(SELECT|WITH)\b", clean, re.IGNORECASE):
            raise ValueError("Only SELECT or WITH queries are allowed")
        if ";" in clean or "--" in clean or "/*" in clean:
            raise ValueError("Comments and multiple SQL statements are not allowed")
        if cls.BLOCKED_SQL.search(clean):
            raise ValueError("The query contains a blocked SQL operation")
        if len(clean) > 5000:
            raise ValueError("The query is too long")
        return clean

    def _request(
        self,
        prompt: str,
        max_tokens: int = 180,
        json_mode: bool = False,
    ) -> str:
        headers = {"Content-Type": "application/json"}
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"
        if self.settings.api_type == "openai":
            response = requests.post(
                f"{self.settings.base_url}/chat/completions",
                headers=headers,
                json={
                    "model": self.settings.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0,
                    "max_tokens": max_tokens,
                    **({"response_format": {"type": "json_object"}} if json_mode else {}),
                },
                timeout=self.settings.timeout,
            )
            response.raise_for_status()
            choices = response.json().get("choices") or []
            return str(choices[0]["message"]["content"]) if choices else ""
        payload: dict[str, Any] = {
            "model": self.settings.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0, "num_predict": max_tokens},
        }
        if json_mode:
            payload["format"] = "json"
        response = requests.post(
            f"{self.settings.base_url}/api/generate",
            json=payload,
            timeout=self.settings.timeout,
        )
        response.raise_for_status()
        return str(response.json().get("response", ""))

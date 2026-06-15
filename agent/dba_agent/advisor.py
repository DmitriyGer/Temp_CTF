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
        observation: dict[str, Any] = {
            "status": "start",
            "failed_tasks": failed_tasks,
            "known_flag_object": "CTF.CTF_FLAG was checked and did not contain a flag",
        }

        for step in range(1, self.settings.search_steps + 1):
            prompt = self._search_prompt(step, observation)
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
            except ValueError as exc:
                observation = {
                    "status": "rejected",
                    "error": str(exc),
                    "instruction": "Return one read-only SELECT or WITH query.",
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
                }
                self.journal.event(
                    "llm_query",
                    "failed",
                    {"step": step, **observation},
                )
                continue

            found = matcher.scan_rows(result.rows)
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

            observation = {
                "status": "query_success",
                "sql": sql,
                "row_count": result.row_count,
                "rows": result.rows[:10],
                "instruction": "No flag matched. Analyze these rows and choose the next query.",
            }

        self.journal.event(
            "llm_search_finished",
            "not_found",
            {"reason": "step limit reached", "steps": self.settings.search_steps},
        )
        return None

    def _search_prompt(self, step: int, observation: dict[str, Any]) -> str:
        return (
            "Ты LLM-агент для локальной учебной Oracle CTF. "
            "Три известных варианта уже не нашли флаг. Самостоятельно исследуй БД "
            "последовательными read-only запросами. Сначала изучай ALL_OBJECTS, "
            "ALL_TABLES, ALL_VIEWS и ALL_TAB_COLUMNS, затем читай подходящие "
            "пользовательские таблицы или представления. Ищи значения вида "
            "CTF{...} или FLAG{...}. Не используй DDL, DML, PL/SQL, DBMS_* и UTL_*. "
            "За один шаг верни ровно один JSON-объект без markdown:\n"
            '{"action":"query","sql":"SELECT ...","reason":"кратко"}\n'
            "Когда разумные варианты исчерпаны:\n"
            '{"action":"finish","sql":null,"reason":"кратко"}\n'
            f"Шаг: {step}/{self.settings.search_steps}\n"
            "Последнее наблюдение:\n"
            f"{json.dumps(observation, ensure_ascii=False, default=str)[:12000]}"
        )

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

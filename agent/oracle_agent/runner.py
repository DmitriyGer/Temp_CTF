from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Any

from .action_schema import ActionType, AgentAction
from .config import Settings
from .ollama_client import OllamaClient, OllamaError
from .oracle_client import OracleClient, OracleResult
from .playbook_loader import PlaybookContext, load_playbook
from .prompts import initial_prompt, next_prompt
from .report import build_completion_report
from .sql_guard import SQLGuard
from .trajectory import TrajectoryRecorder, mask_sql, prompt_hash, sanitize


LOGGER = logging.getLogger(__name__)
FLAG_PATTERN = re.compile(r"(?:CTF|FLAG)\{[^}\r\n]{1,500}\}", re.IGNORECASE)


class AgentRunner:
    def __init__(
        self,
        settings: Settings,
        ollama: OllamaClient | None = None,
        oracle: OracleClient | None = None,
    ) -> None:
        self.settings = settings
        self.context = load_playbook(settings.playbook_dir, settings.task_file)
        self.ollama = ollama or OllamaClient(
            settings.ollama_url, settings.ollama_model, settings.request_timeout
        )
        self.oracle = oracle or OracleClient(
            settings.oracle_host, settings.oracle_port, settings.oracle_service
        )
        self.guard = SQLGuard(settings.allow_alter_system)
        self.recorder = TrajectoryRecorder(
            settings.trajectory_dir,
            settings.ollama_model,
            settings.task_file,
            "dry_run" if settings.dry_run else "live",
        )
        self.history: list[dict[str, Any]] = []
        self.known_secrets = [settings.oracle_password, "ctf_student", "ctf_role"]
        self.discovered_credentials: tuple[str, str] | None = None
        self.flag: str | None = None
        self.failed_sql_counts: dict[str, int] = {}

    def run(self) -> dict[str, Any]:
        LOGGER.info("Configuration: %s", self.settings.safe_summary())
        LOGGER.info("Playbook: %s", self.context.summary())
        if not self.settings.dry_run:
            self.ollama.ensure_available()
            connect_result = self.oracle.connect(
                self.settings.oracle_user, self.settings.oracle_password
            )
            if not connect_result.success:
                return self._finish("failed", connect_result.error_message)
            self._append_history("connect", connect_result.as_dict())
        else:
            self.ollama.ensure_available()
            self._append_history("connect", {"status": "dry_run", "success": True})

        prompt = initial_prompt(self.context)
        try:
            for step_number in range(1, self.settings.max_steps + 1):
                started = time.perf_counter()
                action, prompt = self._request_action(prompt)
                outcome = self._execute_action(action)
                duration_ms = int((time.perf_counter() - started) * 1000)
                self._record(step_number, prompt, action, outcome, duration_ms)
                self._append_history(action.action_type.value, outcome)

                if self.flag:
                    return self._finish("success", "Flag was returned by Oracle")
                if action.action_type in {ActionType.FINAL_REPORT, ActionType.STOP}:
                    return self._finish("failed", "Model stopped before a verified flag was returned")
                prompt = next_prompt(self.context, self.history)
            return self._finish("failed", f"MAX_STEPS={self.settings.max_steps} reached")
        except Exception as exc:
            LOGGER.exception("Agent failed")
            return self._finish("failed", str(exc))
        finally:
            self.oracle.close()

    def _request_action(self, prompt: str) -> tuple[AgentAction, str]:
        current_prompt = prompt
        for attempt in range(3):
            try:
                return self.ollama.next_action(current_prompt), current_prompt
            except OllamaError as exc:
                if attempt == 2:
                    raise
                current_prompt = next_prompt(
                    self.context,
                    self.history,
                    f"Предыдущий ответ невалиден: {exc}. Верни строгий JSON.",
                )
        raise RuntimeError("Unreachable action retry state")

    def _execute_action(self, action: AgentAction) -> dict[str, Any]:
        if action.action_type == ActionType.CONNECT:
            return self._connect_action(action)
        if action.action_type in {ActionType.SQL, ActionType.VERIFY, ActionType.SET_ROLE}:
            return self._sql_action(action)
        if action.action_type == ActionType.ASK_HUMAN:
            return {
                "success": False,
                "status": "failed",
                "error_code": "HUMAN_INPUT_REQUIRED",
                "error_message": action.reason,
                "sql_allowed": None,
            }
        return {
            "success": False,
            "status": "stopped",
            "error_code": None,
            "error_message": action.reason,
            "sql_allowed": None,
        }

    def _connect_action(self, action: AgentAction) -> dict[str, Any]:
        username = action.username
        password = action.password
        if not username and self.discovered_credentials:
            username, password = self.discovered_credentials
        if username and username.upper() == "CTF_STUDENT" and not password:
            password = "ctf_student"
        if username and username.upper() == self.settings.oracle_user.upper() and not password:
            password = self.settings.oracle_password
        if not username or not password:
            return {
                "success": False,
                "status": "failed",
                "error_code": "MISSING_CREDENTIALS",
                "error_message": "connect requires credentials obtained from the scenario",
                "sql_allowed": None,
            }
        self.known_secrets.append(password)
        if self.settings.dry_run:
            return {
                "success": True,
                "status": "success",
                "result": {"mode": "dry_run", "user": username},
                "sql_allowed": None,
            }
        result = self.oracle.reconnect_as_user(username, password)
        return {
            "success": result.success,
            "status": "success" if result.success else "failed",
            "result": sanitize(result.as_dict(), self.known_secrets),
            "error_code": result.error_code,
            "error_message": result.error_message,
            "sql_allowed": None,
        }

    def _sql_action(self, action: AgentAction) -> dict[str, Any]:
        guard = self.guard.check(action.sql)
        if not guard.allowed:
            return {
                "success": False,
                "status": "failed",
                "sql_allowed": False,
                "guard_reason": guard.reason,
                "error_code": "SQL_BLOCKED",
                "error_message": guard.reason,
            }
        if self.failed_sql_counts.get(guard.normalized_sql, 0) >= 2:
            return {
                "success": False,
                "status": "failed",
                "sql_allowed": False,
                "guard_reason": "The same SQL already failed twice",
                "error_code": "REPEATED_SQL_BLOCKED",
                "error_message": "The same failed SQL cannot be executed a third time",
            }
        if self.settings.dry_run:
            return {
                "success": True,
                "status": "success",
                "sql_allowed": True,
                "result": {"mode": "dry_run", "message": "SQL was validated but not executed"},
                "verification": self._dry_verification(action.verification_sql),
            }

        result = self._run_sql(guard.normalized_sql)
        if result.success:
            self.failed_sql_counts.pop(guard.normalized_sql, None)
        else:
            self.failed_sql_counts[guard.normalized_sql] = (
                self.failed_sql_counts.get(guard.normalized_sql, 0) + 1
            )
        if result.success:
            self._capture_credentials(result)
            self._capture_flag(result, guard.normalized_sql)
        verification = None
        if result.success and action.verification_sql:
            verification_guard = self.guard.check(action.verification_sql)
            if verification_guard.allowed:
                verification = self._run_sql(verification_guard.normalized_sql).as_dict()
            else:
                verification = {
                    "success": False,
                    "error_code": "VERIFICATION_SQL_BLOCKED",
                    "error_message": verification_guard.reason,
                }
        success = result.success and (verification is None or verification.get("success", False))
        return {
            "success": success,
            "status": "success" if result.success else "failed",
            "sql_allowed": True,
            "result": sanitize(result.as_dict(), self.known_secrets),
            "verification": sanitize(verification, self.known_secrets),
            "error_code": result.error_code if result.error_code else (
                "VERIFICATION_FAILED" if not success else None
            ),
            "error_message": result.error_message if result.error_message else (
                "Verification SQL failed or was blocked" if not success else None
            ),
        }

    def _run_sql(self, sql: str) -> OracleResult:
        return self.oracle.query(sql) if sql.upper().startswith("SELECT ") else self.oracle.execute(sql)

    def _capture_credentials(self, result: OracleResult) -> None:
        for row in result.rows:
            lowered = {str(key).lower(): value for key, value in row.items()}
            username = next(
                (lowered[key] for key in ("username", "user_name", "login", "user") if lowered.get(key)),
                None,
            )
            password = next(
                (lowered[key] for key in ("password", "passwd", "pwd") if lowered.get(key)),
                None,
            )
            if username and password:
                self.discovered_credentials = (str(username), str(password))
                self.known_secrets.append(str(password))
                return

    def _capture_flag(self, result: OracleResult, sql: str) -> None:
        if "CTF.CTF_FLAG" not in sql.upper():
            return
        for row in result.rows:
            for value in row.values():
                match = FLAG_PATTERN.search(str(value))
                if match:
                    self.flag = match.group(0)
                    return

    def _dry_verification(self, sql: str | None) -> dict[str, Any] | None:
        if not sql:
            return None
        check = self.guard.check(sql)
        return {
            "success": check.allowed,
            "mode": "dry_run",
            "message": check.reason,
        }

    def _record(
        self,
        step_number: int,
        prompt: str,
        action: AgentAction,
        outcome: dict[str, Any],
        duration_ms: int,
    ) -> None:
        safe_action = sanitize(action.model_dump(mode="json"), self.known_secrets)
        result = outcome.get("result")
        verification = outcome.get("verification")
        self.recorder.record_step(
            step_number=step_number,
            action_type=action.action_type.value,
            prompt_hash=prompt_hash(prompt),
            input_context_summary=self.context.summary(),
            proposed_action=safe_action,
            executed_sql_masked=mask_sql(action.sql),
            sql_allowed=outcome.get("sql_allowed"),
            result_status="success" if outcome.get("success") else "failed",
            result_preview=result,
            error_code=outcome.get("error_code"),
            error_message=outcome.get("error_message"),
            verification_sql=action.verification_sql,
            verification_result=verification,
            next_goal=action.next_goal,
            duration_ms=duration_ms,
            attributes={
                "openinference.span.kind": "TOOL",
                "tool.name": action.action_type.value,
                "input.value": safe_action,
                "output.value": sanitize(outcome, self.known_secrets),
            },
        )

    def _append_history(self, action: str, result: dict[str, Any]) -> None:
        self.history.append(
            {
                "action": action,
                "observation": sanitize(result, self.known_secrets),
            }
        )

    def _finish(self, status: str, reason: str | None) -> dict[str, Any]:
        summary = self.recorder.finalize(status, self.flag, reason)
        build_completion_report(self.settings.trajectory_dir, summary, self.recorder.steps)
        return summary


def collect_trajectories(settings: Settings, target: int) -> dict[str, Any]:
    context = load_playbook(settings.playbook_dir, settings.task_file)
    recorder = TrajectoryRecorder(
        settings.trajectory_dir,
        settings.ollama_model,
        settings.task_file,
        "dry_run",
        filename_prefix="trajectory_collection",
    )
    guard = SQLGuard(settings.allow_alter_system)
    corpus = [
        "SELECT * FROM CTF.CTF_FLAG",
        "GRANT CREATE SESSION TO CTF_STUDENT",
        "GRANT CTF_ROLE TO CTF_STUDENT",
        "ALTER USER CTF_STUDENT DEFAULT ROLE NONE",
        "GRANT SELECT ON CTF.CTF_FLAG TO CTF_ROLE",
        "SET ROLE CTF_ROLE IDENTIFIED BY ctf_role",
        "DROP USER CTF_STUDENT CASCADE",
        "GRANT DBA TO CTF_STUDENT",
        "GRANT SELECT ON CTF.CTF_FLAG TO CTF_STUDENT",
        "UPDATE CTF.CTF_FLAG SET FLAG='fake'",
    ]
    for index in range(target):
        sql = corpus[index % len(corpus)]
        checked = guard.check(sql)
        recorder.record_step(
            trace_id=uuid.uuid4().hex,
            parent_span_id=None,
            step_number=index + 1,
            action_type="sql_guard_test",
            prompt_hash=None,
            input_context_summary=context.summary(),
            proposed_action={"action_type": "sql", "sql": mask_sql(sql)},
            executed_sql_masked=sql,
            sql_allowed=checked.allowed,
            result_status="success" if checked.allowed else "failed",
            result_preview={
                "mode": "dry_run",
                "meaning": "safety-layer test only; Oracle SQL was not executed",
                "guard_reason": checked.reason,
            },
            error_code=None if checked.allowed else "SQL_BLOCKED",
            error_message=None if checked.allowed else checked.reason,
            duration_ms=0,
            mode="dry_run",
            attributes={
                "openinference.span.kind": "TOOL",
                "tool.name": "sql_guard",
            },
        )
    summary = recorder.finalize(
        "dataset_collected",
        None,
        f"Collected {target} dry-run safety trajectories; no CTF success was claimed",
    )
    return summary

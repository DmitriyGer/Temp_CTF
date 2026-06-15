from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .advisor import OptionalAdvisor
from .common import read_json
from .database import OracleGateway
from .detector import FlagMatcher
from .discovery import DatabaseDiscovery
from .journal import RunJournal
from .provisioning import CtfProvisioner
from .settings import AppSettings


LOGGER = logging.getLogger("dba_agent.workflow")


class OracleCtfWorkflow:
    def __init__(self, settings: AppSettings, journal: RunJournal) -> None:
        self.settings = settings
        self.journal = journal
        self.database = OracleGateway(settings.oracle, journal)
        self.matcher = FlagMatcher()
        self.discovery = DatabaseDiscovery(
            self.database, settings.search, journal, self.matcher
        )
        self.provisioner = CtfProvisioner(self.database, journal, self.matcher)
        self.advisor = OptionalAdvisor(settings.llm, settings.policy, journal)

    def run(self) -> dict[str, Any]:
        self.journal.add_secret(self.settings.oracle.password)
        self.journal.event(
            "run_started",
            "running",
            {
                "trace_id": self.journal.trace_id,
                "selected_task": self.settings.task_name or "all",
            },
        )
        try:
            self.database.connect_admin()
            self._enable_resource_limits()
            tasks = self._load_tasks()
            for task in tasks:
                result = self._run_task(task)
                if result:
                    return self._success(result)
            self.journal.event("metadata_search", "running")
            fallback = self.discovery.search_flag()
            if fallback:
                return self._success(fallback)
            return self._failure(
                "Флаг не найден после известных вариантов и ограниченного metadata search."
            )
        finally:
            self.database.close()

    def _run_task(self, task: dict[str, Any]) -> dict[str, Any] | None:
        name = str(task["name"])
        self.journal.event("task_started", "running", {"task": name})
        try:
            self.provisioner.unlock_if_present(task["compromised_user"])
            credentials = self.discovery.find_credentials(task["credentials_table"])
            if credentials:
                self.provisioner.verify_login(
                    credentials["username"], credentials["password"]
                )
            self.provisioner.ensure_tablespace(task["tablespace"])
            self.provisioner.ensure_profile(task["profile"])
            self.provisioner.ensure_role(task["role"])
            self.provisioner.ensure_student(task["student"])
            self.provisioner.apply_grants(task)
            found = self.provisioner.read_flag(task, name)
            if found:
                return found
            self.journal.event("task_finished", "not_found", {"task": name})
        except Exception as exc:
            LOGGER.exception("Task %s failed", name)
            self.journal.event(
                "task_failed",
                "failed",
                {"task": name, "error": str(exc)},
                logging.ERROR,
            )
            self.advisor.explain(name, str(exc))
        return None

    def _load_tasks(self) -> list[dict[str, Any]]:
        tasks = []
        for path in sorted(self.settings.task_dir.glob("*.json")):
            task = read_json(path)
            task["_source"] = str(path)
            tasks.append(task)
        if self.settings.task_name:
            tasks = [
                task
                for task in tasks
                if task.get("name") == self.settings.task_name
                or Path(task["_source"]).stem == self.settings.task_name
            ]
            if not tasks:
                raise FileNotFoundError(
                    f"TASK_NAME={self.settings.task_name!r} was not found in "
                    f"{self.settings.task_dir}"
                )
        tasks.sort(key=lambda task: int(task.get("priority", 999)))
        self.journal.event(
            "tasks_loaded",
            "success",
            {"tasks": [task["name"] for task in tasks]},
        )
        return tasks

    def _enable_resource_limits(self) -> None:
        if not self.settings.allow_resource_limit:
            self.journal.event(
                "resource_limit",
                "skipped",
                {"reason": "ALLOW_RESOURCE_LIMIT is false"},
            )
            return
        result = self.database.execute("ALTER SYSTEM SET RESOURCE_LIMIT=TRUE")
        if result.ok:
            self.journal.event("resource_limit", "success")
        else:
            self.journal.event(
                "resource_limit",
                "failed",
                {
                    "code": result.error_code,
                    "error": result.error_message,
                },
            )

    def _success(self, found: dict[str, Any]) -> dict[str, Any]:
        result = {
            "status": "success",
            "flag": found["flag"],
            "source": found["source"],
            "sql": found["sql"],
            "successful_strategy": found["strategy"],
            "trajectory_file": str(self.journal.path),
            "checked_objects": self.discovery.checked_objects,
            "final_message": "Флаг получен из Oracle Database.",
        }
        self.journal.finish(
            "success",
            result["final_message"],
            flag=result["flag"],
        )
        return result

    def _failure(self, message: str) -> dict[str, Any]:
        result = {
            "status": "fail",
            "flag": None,
            "source": None,
            "sql": None,
            "successful_strategy": None,
            "trajectory_file": str(self.journal.path),
            "checked_objects": self.discovery.checked_objects,
            "final_message": message,
        }
        self.journal.finish("fail", message)
        return result

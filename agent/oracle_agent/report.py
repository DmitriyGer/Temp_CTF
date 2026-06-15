from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def build_completion_report(
    directory: Path | str,
    summary: dict[str, Any],
    steps: list[dict[str, Any]],
) -> tuple[Path, Path]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    operations = [
        step.get("executed_sql_masked")
        for step in steps
        if step.get("executed_sql_masked")
    ]
    checks = [
        {
            "sql": step.get("verification_sql"),
            "result": step.get("verification_result"),
        }
        for step in steps
        if step.get("verification_sql")
    ]
    errors = [
        {
            "step": step.get("step_number"),
            "code": step.get("error_code"),
            "message": step.get("error_message"),
        }
        for step in steps
        if step.get("result_status") == "failed"
    ]
    report = {
        "status": summary.get("status", "failed"),
        "task_file": summary.get("task_file"),
        "model": summary.get("model"),
        "step_count": summary.get("step_count", len(steps)),
        "successful_steps": summary.get("successful_steps", 0),
        "error_count": len(errors),
        "oracle_operations": operations,
        "verifications": checks,
        "errors": errors,
        "flag_received": bool(summary.get("flag")),
        "flag": summary.get("flag"),
        "trajectory_file": summary.get("trajectory_file"),
        "architecture": (
            "Playbook loader -> Ollama JSON action -> Pydantic validation -> "
            "SQL allowlist -> python-oracledb -> verification -> OpenInference-like JSONL."
        ),
        "practice_report_usage": (
            "Use this file together with the source code and README as evidence of "
            "the agent pipeline, Oracle integration, safety checks and trajectories."
        ),
    }
    json_path = root / "completion_report.json"
    md_path = root / "completion_report.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    status_ru = "успешно" if report["status"] == "success" else "не выполнено полностью"
    flag_text = report["flag"] if report["flag_received"] else "не найден"
    md = f"""# Completion report

- Статус: {status_ru}
- Вариант: `{report["task_file"]}`
- Модель: `{report["model"]}`
- Шагов: {report["step_count"]}
- Успешных шагов: {report["successful_steps"]}
- Ошибок: {report["error_count"]}
- Флаг получен: {"да" if report["flag_received"] else "нет"}
- FLAG: `{flag_text}`
- Траектория: `{report["trajectory_file"]}`

## Выполненные Oracle-операции

{_markdown_list(operations)}

## Проверки

{_markdown_list([item["sql"] for item in checks])}

## Ошибки

{_markdown_list([f'{item["code"] or "ERROR"}: {item["message"]}' for item in errors])}

## Архитектура

{report["architecture"]}

## Использование в отчёте по практике

{report["practice_report_usage"]}
"""
    md_path.write_text(md, encoding="utf-8")
    return md_path, json_path


def rebuild_latest_report(directory: Path | str) -> tuple[Path, Path]:
    root = Path(directory)
    summaries = sorted(root.glob("trajectory_openinference_*_summary.json"))
    if not summaries:
        raise FileNotFoundError(f"No trajectory summaries found in {root}")
    summary = json.loads(summaries[-1].read_text(encoding="utf-8"))
    trajectory_path = Path(summary["trajectory_file"])
    steps = [
        json.loads(line)
        for line in trajectory_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return build_completion_report(root, summary, steps)


def _markdown_list(items: list[Any]) -> str:
    clean = [str(item) for item in items if item]
    return "\n".join(f"- `{item}`" for item in clean) if clean else "- Нет"

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


SUPPORTED_SUFFIXES = {".md", ".txt", ".json"}
SPECIAL_FILES = {
    "master_playbook": "oracle_agent_master_playbook.md",
    "safety_boundaries": "sql_safety_boundaries.md",
    "telemetry_rules": "execution_telemetry_rules.md",
    "report_schema": "completion_report_schema.md",
}
CONTEXT_FILES = [
    "agent_identity_and_scope.md",
    "oracle_variant_runbook.md",
    "adaptive_flag_discovery.md",
    "sql_safety_boundaries.md",
    "execution_telemetry_rules.md",
    "completion_report_schema.md",
]


@dataclass(frozen=True)
class PlaybookContext:
    directory: Path
    task_path: Path
    task_text: str
    files: dict[str, str]
    special: dict[str, str]
    full_context: str

    def summary(self) -> dict[str, object]:
        return {
            "directory": str(self.directory),
            "task_file": self.task_path.name,
            "loaded_files": sorted(self.files),
            "character_count": len(self.full_context),
        }


def _read(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        try:
            return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in playbook file {path}: {exc}") from exc
    return text


def load_playbook(directory: Path | str, task_file: str) -> PlaybookContext:
    root = Path(directory)
    if not root.is_dir():
        raise FileNotFoundError(f"Playbook directory not found: {root}")

    task_candidate = Path(task_file)
    task_path = task_candidate if task_candidate.is_absolute() else root / task_candidate
    if not task_path.is_file():
        available = ", ".join(path.name for path in sorted(root.glob("*.txt")))
        raise FileNotFoundError(
            f"Task file not found: {task_path}. Available task files: {available or 'none'}"
        )

    paths = sorted(
        path for path in root.iterdir()
        if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES
    )
    if task_path.resolve() not in {path.resolve() for path in paths}:
        paths.append(task_path)
        paths.sort()

    files = {path.name: _read(path) for path in paths}
    special = {
        key: files.get(filename, "")
        for key, filename in SPECIAL_FILES.items()
    }
    task_text = _read(task_path)
    sections = [
        f"\n===== FILE: {name} =====\n{files[name].strip()}"
        for name in CONTEXT_FILES
        if files.get(name)
    ]
    sections.append(f"\n===== SELECTED TASK: {task_path.name} =====\n{task_text.strip()}")

    return PlaybookContext(
        directory=root,
        task_path=task_path,
        task_text=task_text,
        files=files,
        special=special,
        full_context="\n".join(sections),
    )

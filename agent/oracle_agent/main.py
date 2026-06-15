from __future__ import annotations

import argparse
import json
import logging
import sys

from .config import Settings
from .report import rebuild_latest_report
from .runner import AgentRunner, collect_trajectories


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local Oracle CTF AI agent")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("run", help="Run the live agent")
    subparsers.add_parser("dry-run", help="Validate model actions without executing SQL")
    collect = subparsers.add_parser(
        "collect-trajectories",
        help="Create an honest dry-run safety evaluation dataset",
    )
    collect.add_argument("--target", type=int, default=None)
    subparsers.add_parser("report", help="Rebuild report from the latest trajectory")
    return parser


def main(argv: list[str] | None = None) -> int:
    settings = None
    try:
        settings = Settings.from_env()
    except Exception:
        pass
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO) if settings else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )
    args = build_parser().parse_args(argv)
    command = args.command or "run"
    try:
        settings = settings or Settings.from_env()
        if command == "dry-run":
            settings = settings.with_overrides(dry_run=True)
            summary = AgentRunner(settings).run()
        elif command == "collect-trajectories":
            target = args.target or settings.trajectory_target_count
            if target < 1:
                raise ValueError("--target must be at least 1")
            summary = collect_trajectories(settings, target)
        elif command == "report":
            md_path, json_path = rebuild_latest_report(settings.trajectory_dir)
            summary = {"completion_report_md": str(md_path), "completion_report_json": str(json_path)}
        else:
            if settings.collect_trajectories:
                summary = collect_trajectories(settings, settings.trajectory_target_count)
            else:
                summary = AgentRunner(settings).run()
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary.get("status") in {"success", "dataset_collected"} or command == "report" else 1
    except Exception as exc:
        logging.getLogger(__name__).exception("Command failed")
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())

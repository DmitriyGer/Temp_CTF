from __future__ import annotations

import json
import logging
import os
import sys
import traceback

from .common import scrub, utc_now, write_json
from .journal import RunJournal
from .settings import AppSettings
from .workflow import OracleCtfWorkflow


def main() -> int:
    logging.basicConfig(
        level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )
    settings = AppSettings.load()
    journal = RunJournal(settings.trajectory_dir, settings.safe_snapshot())
    try:
        result = OracleCtfWorkflow(settings, journal).run()
        result["finished_at"] = utc_now()
        write_json(settings.final_result, result)
        print(json.dumps(scrub(result), ensure_ascii=False, indent=2))
        return 0 if result["status"] == "success" else 2
    except Exception as exc:
        logging.getLogger(__name__).exception("Agent stopped with a critical error")
        message = f"{type(exc).__name__}: {exc}"
        journal.event(
            "critical_error",
            "failed",
            {"error": message, "traceback": traceback.format_exc()},
            logging.ERROR,
        )
        journal.finish("fail", message)
        result = {
            "status": "fail",
            "flag": None,
            "source": None,
            "successful_strategy": None,
            "trajectory_file": str(journal.path),
            "final_message": message,
            "finished_at": utc_now(),
        }
        write_json(settings.final_result, result)
        print(json.dumps(scrub(result), ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())

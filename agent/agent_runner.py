
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import oracledb
import requests

BASE_DIR = Path(__file__).resolve().parent


def find_instruction_dir(cfg: dict | None = None) -> Path | None:
    """Find folder with agent instruction files.

    Main project folder is intentionally named differently from example projects:
    oracle_ctf_playbook.
    Legacy names are supported only as fallback so old local runs do not break.
    """
    configured = None
    if cfg:
        configured = cfg.get("agent", {}).get("instruction_dir")
    candidates = []
    if configured:
        configured_path = Path(configured)
        candidates.append(configured_path if configured_path.is_absolute() else BASE_DIR / configured)

    candidates.extend([
        BASE_DIR / "oracle_ctf_playbook",
        BASE_DIR / "ctf_oracle_ruleset",
        BASE_DIR / "db_agent_playbook",
        BASE_DIR / "Instruction",
        BASE_DIR / "Instructions",
        BASE_DIR / "Instrucrion",
        BASE_DIR / "instructions",
    ])
    seen = set()
    for candidate in candidates:
        key = str(candidate.resolve()) if candidate.exists() else str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.exists() and candidate.is_dir():
            return candidate
    return None


def read_instruction_file(directory: Path, filename: str) -> str:
    path = directory / filename
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def load_agent_instructions(cfg: dict | None = None) -> dict:
    """Load project-specific text instructions for the planner.

    The loaded text is used in system_prompt. The trajectory stores only a
    compact summary, not the full instruction text, so docker logs and traces
    stay readable.
    """
    directory = find_instruction_dir(cfg)
    if directory is None:
        return {
            "loaded": False,
            "directory": None,
            "full_text": "",
            "files": {},
        }

    configured_files = []
    if cfg:
        configured_files = cfg.get("agent", {}).get("instruction_files") or []
    filenames = configured_files or [
        "agent_identity_and_scope.md",
        "oracle_variant_runbook.md",
        "adaptive_flag_discovery.md",
        "sql_safety_boundaries.md",
        "execution_telemetry_rules.md",
        "completion_report_schema.md",
    ]

    legacy_filenames = [
        "01_system_prompt_main.md",
        "02_task_execution_rules.md",
        "03_universal_search_rules.md",
        "04_safety_rules.md",
        "05_trace_rules_openinference.md",
        "06_final_report_format.md",
    ]

    loaded_files = {}
    parts = []
    for filename in filenames:
        content = read_instruction_file(directory, filename)
        loaded_files[filename] = bool(content.strip())
        if content.strip():
            parts.append(f"\n\n# FILE: {filename}\n{content.strip()}")

    if not parts:
        for filename in legacy_filenames:
            content = read_instruction_file(directory, filename)
            loaded_files[filename] = bool(content.strip())
            if content.strip():
                parts.append(f"\n\n# FILE: {filename}\n{content.strip()}")

    if not parts:
        combined = None
        if cfg:
            combined = cfg.get("agent", {}).get("combined_instruction_file")
        for filename in [combined, "oracle_agent_master_playbook.md", "agent_full_instruction.md"]:
            if not filename:
                continue
            content = read_instruction_file(directory, filename)
            loaded_files[filename] = bool(content.strip())
            if content.strip():
                parts.append(content.strip())
                break

    return {
        "loaded": bool(parts),
        "directory": str(directory),
        "full_text": "\n".join(parts),
        "files": loaded_files,
    }


def instruction_trace_summary(instructions: dict) -> dict:
    return {
        "loaded": instructions.get("loaded"),
        "directory": instructions.get("directory"),
        "files": instructions.get("files", {}),
        "chars": len(instructions.get("full_text") or ""),
    }

def build_system_prompt(instructions: dict) -> str:
    base_prompt = SYSTEM_PROMPT.strip()
    if not instructions.get("loaded"):
        return base_prompt + "\n\nВНИМАНИЕ: внешние instruction-файлы не найдены. Используется встроенный минимальный промпт."
    return (
        base_prompt
        + "\n\nНиже подключены внешние инструкции агента. Они имеют приоритет над кратким встроенным промптом, если не противоречат правилам безопасности."
        + instructions["full_text"]
    )


SYSTEM_PROMPT = """
Ты ИИ-агент для учебного администрирования Oracle Database.
Твоя задача — выбирать следующий безопасный шаг для получения флага.
Важно: варианты 1–3 являются примерными. На реальной проверке структура задания может быть похожей, но не совпадать 1 в 1.
Если известные варианты не дали флаг, нужно перейти в адаптивный режим: анализировать доступные метаданные Oracle, предлагать безопасную стратегию поиска похожих CTF-объектов, ключевые слова и приоритеты проверки.
SQL напрямую ты не выполняешь. Ты выбираешь только tool/action из списка allowed_actions.
Python-инструментальный слой выполнит действие, проверит безопасность, вернёт observation и запишет траекторию.

Возвращай только JSON:
{
  "thought": "кратко почему выбран этот шаг",
  "action": "одно значение из allowed_actions"
}

Правила:
- Не придумывай SQL.
- Не придумывай пароли и флаг.
- Если предыдущее действие завершилось ошибкой, выбери следующий безопасный шаг или переход к следующему варианту.
- Если флаг найден, выбери finish_success.
- Если все варианты не дали флаг, выбери universal_search.
"""

VARIANTS = {
    1: {
        "tablespace_size_mb": 150,
        "quota_mb": 80,
        "profile_limits": {
            "SESSIONS_PER_USER": 4,
            "IDLE_TIME": 30,
            "FAILED_LOGIN_ATTEMPTS": 3,
            "PASSWORD_REUSE_TIME": 60,
            "PASSWORD_REUSE_MAX": 4,
        },
    },
    2: {
        "tablespace_size_mb": 520,
        "quota_mb": 260,
        "profile_limits": {
            "SESSIONS_PER_USER": 3,
            "LOGICAL_READS_PER_SESSION": 130000,
            "CPU_PER_CALL": 6500,
            "CONNECT_TIME": 80,
            "PASSWORD_LIFE_TIME": 28,
            "PASSWORD_GRACE_TIME": 4,
        },
    },
    3: {
        "tablespace_size_mb": 560,
        "quota_mb": 280,
        "profile_limits": {
            "IDLE_TIME": 20,
            "LOGICAL_READS_PER_CALL": 11000,
            "CPU_PER_SESSION": 32000,
            "FAILED_LOGIN_ATTEMPTS": 3,
            "PASSWORD_LOCK_TIME": 1,
            "SESSIONS_PER_USER": 2,
        },
    },
}

SYSTEM_SCHEMAS = {
    "SYS", "SYSTEM", "XDB", "CTXSYS", "MDSYS", "ORDSYS", "ORDDATA", "OUTLN",
    "WMSYS", "DBSNMP", "APPQOSSYS", "GSMADMIN_INTERNAL", "OJVMSYS", "DVSYS",
    "AUDSYS", "LBACSYS", "OLAPSYS", "MDDATA", "REMOTE_SCHEDULER_AGENT", "SYSBACKUP",
    "SYSDG", "SYSKM", "SYSRAC", "ANONYMOUS"
}

FLAG_RE = re.compile(r"(?:CTF|FLAG)\{[^}\r\n]{1,200}\}", re.IGNORECASE)
SECRET_KEYS = ["FLAG", "CTF", "SECRET", "TOKEN", "KEY", "ANSWER", "VALUE", "RESULT", "RESULTS", "SOLUTION", "TASK", "LAB", "CHALLENGE"]

ORDERED_ACTIONS = [
    "check_connection",
    "check_pdb",
    "unlock_compromised_user",
    "find_credentials",
    "test_credentials",
    "ensure_tablespace",
    "ensure_profile",
    "ensure_role",
    "ensure_student_user",
    "grant_create_session",
    "grant_role",
    "disable_default_role",
    "grant_select_flag",
    "connect_student",
    "activate_role",
    "read_known_flag",
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def now_ms() -> int:
    return int(time.time() * 1000)


def live_log(message: str) -> None:
    """Print a short live message to Docker logs.

    Trajectory keeps the full OpenInference JSON. Docker logs should stay compact:
    only stage/action/result/error are printed here.
    """
    stamp = time.strftime("%H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)


def compact_value(value: Any, max_len: int = 220) -> str:
    """Build short one-line representation for live logs."""
    value = mask_data(value)
    if isinstance(value, dict):
        if value.get("flag"):
            return f"flag={value.get('flag')}"
        if value.get("message"):
            return str(value.get("message"))[:max_len]
        if value.get("status"):
            return str(value.get("status"))[:max_len]
        if value.get("error"):
            return str(value.get("error"))[:max_len]
        if value.get("ok") is not None:
            return f"ok={value.get('ok')}"
    try:
        text = json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        text = str(value)
    text = text.replace("\n", " ")
    return text[:max_len] + ("..." if len(text) > max_len else "")



def mask_string(value: str) -> str:
    value = re.sub(r"(?i)(IDENTIFIED\s+BY\s+)(\"?)[^\s;\"]+(\"?)", r"\1***", value)
    value = re.sub(r"(?i)(PASSWORD\s*[:=]\s*)([^,}\s]+)", r"\1***", value)
    value = re.sub(r"(?i)(admin_password\s*[:=]\s*)([^,}\s]+)", r"\1***", value)
    return value


def mask_data(data: Any) -> Any:
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if any(s in k.lower() for s in ["password", "pwd", "secret", "token"]):
                result[k] = "***"
            else:
                result[k] = mask_data(v)
        return result
    if isinstance(data, list):
        return [mask_data(x) for x in data]
    if isinstance(data, str):
        return mask_string(data)
    return data


class TraceWriter:
    def __init__(self, trajectories_dir: str):
        self.dir = Path(trajectories_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

        # Every agent run must have its own trace file.
        # The old implementation always appended into trajectory_openinference.jsonl,
        # therefore different launches were mixed in one file.
        self.trace_id = uuid.uuid4().hex
        self.started_at = time.strftime("%Y%m%d_%H%M%S")
        self.run_id = f"{self.started_at}_{self.trace_id[:8]}"

        self.path = self.dir / f"trajectory_openinference_{self.run_id}.jsonl"
        self.final_path = self.dir / f"final_result_{self.run_id}.json"

        # Convenience pointers to the most recent run. These files are overwritten
        # on each launch and are not used for accumulating trajectories.
        self.latest_trace_path = self.dir / "trajectory_openinference_latest.jsonl"
        self.latest_final_path = self.dir / "final_result.json"
        self.latest_trace_path.write_text("", encoding="utf-8")
        live_log(f"RUN START run_id={self.run_id} trace_id={self.trace_id} trajectory={self.path.name}")

    def span(self, name: str, kind: str, input_value: Any, output_value: Any, parent_span_id: str | None = None, attrs: dict | None = None) -> str:
        span_id = uuid.uuid4().hex[:16]
        record = {
            "trace_id": self.trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "name": name,
            "start_time_unix_ms": now_ms(),
            "end_time_unix_ms": now_ms(),
            "attributes": {
                "openinference.span.kind": kind,
                "input.value": json.dumps(mask_data(input_value), ensure_ascii=False, default=str),
                "output.value": json.dumps(mask_data(output_value), ensure_ascii=False, default=str),
            }
        }
        if attrs:
            record["attributes"].update(mask_data(attrs))
        line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line)
        with self.latest_trace_path.open("a", encoding="utf-8") as f:
            f.write(line)

        # Compact live output for `docker logs`.
        if name == "load_instructions":
            if isinstance(output_value, dict):
                live_log(f"INSTRUCTIONS loaded={output_value.get('loaded')} dir={output_value.get('directory')}")
        elif name == "agent_start":
            live_log("AGENT started")
        elif name == "start_variant":
            if isinstance(input_value, dict):
                live_log(f"VARIANT {input_value.get('variant_id')} started")
        elif name == "planner_decision":
            if isinstance(output_value, dict):
                live_log(f"PLAN action={output_value.get('action')} thought={str(output_value.get('thought', ''))[:120]}")
        elif name == "llm_choose_action_failed":
            live_log(f"LLM unavailable/error: {compact_value(output_value)}")
        elif name == "variant_without_flag":
            if isinstance(input_value, dict):
                live_log(f"VARIANT {input_value.get('variant_id')} finished without flag")
        elif name == "start_universal_search":
            live_log("UNIVERSAL SEARCH started")
        elif name == "agent_finish":
            status = output_value.get("status") if isinstance(output_value, dict) else None
            mode = output_value.get("mode") if isinstance(output_value, dict) else None
            flag = output_value.get("flag") if isinstance(output_value, dict) else None
            live_log(f"AGENT finished status={status} mode={mode} flag={'yes' if flag else 'no'}")
        elif kind == "TOOL":
            ok = output_value.get("ok") if isinstance(output_value, dict) else None
            if isinstance(output_value, dict) and output_value.get("flag"):
                live_log(f"TOOL {name}: OK flag={output_value.get('flag')}")
            elif ok is False:
                live_log(f"TOOL {name}: ERROR {compact_value(output_value)}")
            else:
                live_log(f"TOOL {name}: OK {compact_value(output_value)}")
        return span_id

    def final(self, result: dict) -> None:
        result = dict(result)
        result["trace_id"] = self.trace_id
        result["run_id"] = self.run_id
        result["trajectory_file"] = str(self.path)
        result["final_result_file"] = str(self.final_path)
        payload = json.dumps(mask_data(result), ensure_ascii=False, indent=2, default=str)
        self.final_path.write_text(payload, encoding="utf-8")
        self.latest_final_path.write_text(payload, encoding="utf-8")


@dataclass
class AgentState:
    variant_id: int | None = None
    completed: set[str] = field(default_factory=set)
    history: list[dict] = field(default_factory=list)
    flag: str | None = None
    flag_source: dict | None = None
    credentials: dict | None = None
    ctf_student_connected: bool = False
    role_activated: bool = False
    pdb_name: str | None = None
    errors: list[dict] = field(default_factory=list)

    def public(self) -> dict:
        return {
            "variant_id": self.variant_id,
            "completed": sorted(self.completed),
            "flag_found": self.flag is not None,
            "flag_source": self.flag_source,
            "credentials_found": self.credentials is not None,
            "ctf_student_connected": self.ctf_student_connected,
            "role_activated": self.role_activated,
            "pdb_name": self.pdb_name,
            "recent_history": self.history[-8:],
            "recent_errors": self.errors[-5:],
        }


class OracleAgent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.instructions = load_agent_instructions(cfg)
        self.system_prompt = build_system_prompt(self.instructions)
        self.trace = TraceWriter(cfg["agent"]["trajectories_dir"])
        self.trace.span("load_instructions", "CHAIN", {"base_dir": str(BASE_DIR)}, instruction_trace_summary(self.instructions))
        self.admin_conn = None
        self.credentials_conn = None
        self.student_conn = None
        self.state = AgentState()
        self.adaptive_strategy = None

    def connect(self, username: str, password: str):
        oracle = self.cfg["oracle"]
        hosts = oracle.get("hosts") or [oracle.get("host", "localhost")]
        last_error = None
        for host in hosts:
            try:
                dsn = oracledb.makedsn(host, int(oracle["port"]), service_name=oracle["service_name"])
                conn = oracledb.connect(user=username, password=password, dsn=dsn)
                live_log(f"ORACLE connected {host}:{oracle['port']}/{oracle['service_name']} as {username}")
                return conn
            except Exception as e:
                live_log(f"ORACLE connection failed {host}:{oracle['port']} as {username}: {e}")
                last_error = e
        raise RuntimeError(f"Cannot connect to Oracle as {username}: {last_error}")

    def sql(self, conn, sql: str, params: dict | None = None, allow_error: bool = True) -> dict:
        cur = conn.cursor()
        try:
            cur.execute(sql, params or {})
            if cur.description:
                cols = [c[0] for c in cur.description]
                rows = [list(r) for r in cur.fetchall()]
                return {"ok": True, "columns": cols, "rows": rows, "sql": sql}
            conn.commit()
            return {"ok": True, "message": "committed", "sql": sql}
        except Exception as e:
            if not allow_error:
                raise
            return {"ok": False, "error": str(e), "sql": sql}
        finally:
            cur.close()

    def pick_connection(self):
        return self.credentials_conn or self.admin_conn

    def parse_llm_json(self, text: str) -> dict:
        cleaned = text.strip()
        cleaned = re.sub(r"^```json\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"^```\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        m = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if not m:
            raise ValueError(f"LLM did not return JSON: {text}")
        return json.loads(m.group(0))

    def ask_llm_milestone(self, milestone: str, context: dict) -> dict:
        """Call LLM only at meaningful checkpoints.

        This keeps the SQL execution deterministic and fast, but leaves real LLM
        participation in the trajectory. The result is advisory only: Python still
        executes the safe toolchain and never runs SQL generated by the model.
        """
        agent_cfg = self.cfg.get("agent", {})
        if not agent_cfg.get("use_llm_milestones", False):
            return {"ok": True, "skipped": True, "reason": "use_llm_milestones=false"}

        ocfg = self.cfg.get("ollama", {})
        urls = ocfg.get("api_urls") or [ocfg.get("base_url", "").rstrip("/") + "/api/generate"]
        timeout = int(ocfg.get("milestone_timeout_seconds", ocfg.get("timeout_seconds", 20)))
        prompt = {
            "milestone": milestone,
            "role": "Ты ИИ-компонент Oracle CTF агента. Проанализируй состояние кратко. SQL не генерируй и не выполняй.",
            "instructions_summary": instruction_trace_summary(self.instructions),
            "state": self.state.public(),
            "context": context,
            "required_json_schema": {
                "analysis": "краткий анализ текущего состояния",
                "strategy": "что агент должен делать дальше на уровне стратегии",
                "risk": "основной риск или none"
            }
        }
        full_prompt = self.system_prompt + "\n\nMILESTONE_CONTEXT:\n" + json.dumps(prompt, ensure_ascii=False, indent=2, default=str)
        last_error = None
        for url in urls:
            try:
                payload = {
                    "model": ocfg["model"],
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {
                        "temperature": ocfg.get("temperature", 0.0),
                        "num_ctx": ocfg.get("num_ctx", 2048),
                    },
                }
                response = requests.post(url, json=payload, timeout=timeout)
                response.raise_for_status()
                raw = response.json().get("response", "")
                parsed = None
                try:
                    parsed = self.parse_llm_json(raw)
                except Exception:
                    parsed = {"analysis": raw.strip()[:1000]}
                result = {"ok": True, "milestone": milestone, "raw": raw, "parsed": parsed}
                self.trace.span(
                    f"llm_milestone_{milestone}",
                    "LLM",
                    prompt,
                    result,
                    attrs={"llm.model_name": ocfg.get("model", "unknown")},
                )
                live_log(f"LLM milestone {milestone}: OK")
                return result
            except Exception as e:
                last_error = e
        result = {"ok": False, "milestone": milestone, "error": str(last_error)}
        self.trace.span(f"llm_milestone_{milestone}_failed", "LLM", prompt, result)
        live_log(f"LLM milestone {milestone}: ERROR {str(last_error)[:180]}")
        return result

    def ask_llm_adaptive_strategy(self, context: dict) -> dict:
        """Ask LLM for an adaptive search strategy after all known variants failed.

        This is the main AI-agent point for non-exact tasks. The model does not
        generate executable SQL. It returns search priorities: keywords, object
        name hints and reasoning. Python validates identifiers and performs only
        limited SELECT queries through universal_search().
        """
        agent_cfg = self.cfg.get("agent", {})
        default_strategy = {
            "ok": True,
            "source": "fallback_default_strategy",
            "analysis": "known variants failed; use metadata-driven universal search",
            "keywords": SECRET_KEYS,
            "priority_rules": [
                "check non-system owners first",
                "prioritize object or column names containing flag/ctf/secret/token/answer/result/value",
                "read only text columns with row limits",
                "detect only values matching CTF{...} or FLAG{...}",
            ],
            "max_objects": int(agent_cfg.get("universal_max_objects", 50)),
            "max_rows_per_object": int(agent_cfg.get("universal_max_rows_per_object", 20)),
        }

        if not agent_cfg.get("use_llm_milestones", False):
            self.trace.span("adaptive_strategy_fallback", "CHAIN", context, default_strategy)
            live_log("ADAPTIVE AGENT strategy: fallback, LLM milestones disabled")
            return default_strategy

        ocfg = self.cfg.get("ollama", {})
        urls = ocfg.get("api_urls") or [ocfg.get("base_url", "").rstrip("/") + "/api/generate"]
        timeout = int(ocfg.get("milestone_timeout_seconds", ocfg.get("timeout_seconds", 30)))

        # Keep the prompt intentionally short: large prompts caused timeouts on local Ollama.
        prompt = {
            "role": "Oracle CTF adaptive search agent",
            "task": "Known training variants failed. Propose a safe metadata-driven strategy to find a similar hidden CTF flag in Oracle.",
            "known_failures": context,
            "allowed": [
                "inspect Oracle metadata",
                "choose search keywords",
                "prioritize non-system tables/views and text columns",
                "use limited SELECT only",
                "detect CTF{...} or FLAG{...}",
            ],
            "forbidden": ["DROP", "DELETE", "TRUNCATE", "ALTER DATABASE", "SHUTDOWN", "execute generated SQL"],
            "return_json_schema": {
                "analysis": "why known variants failed",
                "keywords": ["FLAG", "CTF", "SECRET", "TOKEN", "ANSWER", "RESULT", "VALUE"],
                "priority_rules": ["short safe rules"],
                "risk": "main risk or none",
            },
        }
        full_prompt = (
            "Return only JSON. Do not generate SQL. "
            "The Python tool layer will execute safe limited metadata queries.\n"
            + json.dumps(prompt, ensure_ascii=False, default=str)
        )

        last_error = None
        for url in urls:
            try:
                payload = {
                    "model": ocfg["model"],
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {
                        "temperature": ocfg.get("temperature", 0.0),
                        "num_ctx": min(int(ocfg.get("num_ctx", 2048)), 2048),
                    },
                }
                response = requests.post(url, json=payload, timeout=timeout)
                response.raise_for_status()
                raw = response.json().get("response", "")
                parsed = self.parse_llm_json(raw)
                keywords = parsed.get("keywords") or []
                clean_keywords = []
                for item in keywords:
                    item = str(item).upper().strip()
                    if re.fullmatch(r"[A-Z0-9_]{2,30}", item):
                        clean_keywords.append(item)
                merged_keywords = []
                for item in clean_keywords + SECRET_KEYS:
                    if item not in merged_keywords:
                        merged_keywords.append(item)
                strategy = {
                    "ok": True,
                    "source": "llm_adaptive_strategy",
                    "analysis": str(parsed.get("analysis", ""))[:1000],
                    "keywords": merged_keywords,
                    "priority_rules": parsed.get("priority_rules") or default_strategy["priority_rules"],
                    "risk": str(parsed.get("risk", "none"))[:500],
                    "max_objects": default_strategy["max_objects"],
                    "max_rows_per_object": default_strategy["max_rows_per_object"],
                    "raw": raw[:2000],
                }
                self.trace.span(
                    "llm_adaptive_universal_search_strategy",
                    "LLM",
                    prompt,
                    mask_data(strategy),
                    attrs={"llm.model_name": ocfg.get("model", "unknown")},
                )
                live_log("ADAPTIVE AGENT strategy: OK llm_adaptive_strategy")
                return strategy
            except Exception as e:
                last_error = e

        fallback = dict(default_strategy)
        fallback["llm_error"] = str(last_error)
        self.trace.span("llm_adaptive_universal_search_strategy_failed", "LLM", prompt, mask_data(fallback))
        live_log(f"ADAPTIVE AGENT strategy: LLM ERROR, fallback used: {str(last_error)[:160]}")
        return fallback

    def ask_llm_next_action(self, allowed_actions: list[str], recommended_action: str, reason: str) -> dict:
        if not self.cfg.get("agent", {}).get("use_llm_planner", True):
            return {
                "thought": "LLM planner disabled; using safe recommended action",
                "action": recommended_action,
            }

        ocfg = self.cfg["ollama"]
        urls = ocfg.get("api_urls") or [ocfg["base_url"].rstrip("/") + "/api/generate"]
        prompt = {
            "allowed_actions": allowed_actions,
            "recommended_action": recommended_action,
            "reason": reason,
            "state": self.state.public(),
        }
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=False, indent=2, default=str)},
        ]
        full_prompt = "\n\n".join(f"{m['role'].upper()}:\n{m['content']}" for m in messages)
        last_error = None
        for url in urls:
            try:
                payload = {
                    "model": ocfg["model"],
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {"temperature": ocfg.get("temperature", 0.0), "num_ctx": ocfg.get("num_ctx", 4096)},
                }
                response = requests.post(url, json=payload, timeout=ocfg.get("timeout_seconds", 180))
                response.raise_for_status()
                raw = response.json().get("response", "")
                action = self.parse_llm_json(raw)
                self.trace.span("llm_choose_action", "LLM", prompt, {"raw": raw, "parsed": action}, attrs={"llm.model_name": ocfg["model"]})
                if action.get("action") not in allowed_actions:
                    return {"thought": "LLM returned invalid action; using safe recommended action", "action": recommended_action, "llm_invalid": action}
                return action
            except Exception as e:
                last_error = e
        self.trace.span("llm_choose_action_failed", "LLM", prompt, {"error": str(last_error)})
        return {"thought": "LLM unavailable; using safe recommended action", "action": recommended_action, "llm_error": str(last_error)}

    def observe(self, action: str, result: dict):
        entry = {"action": action, "result": mask_data(result)}
        self.state.history.append(entry)
        if not result.get("ok", False):
            self.state.errors.append(entry)
        print(json.dumps(entry, ensure_ascii=False, default=str))

    def tool(self, name: str, fn):
        try:
            result = fn()
        except Exception as e:
            result = {"ok": False, "error": str(e)}
        self.trace.span(name, "TOOL", {"variant_id": self.state.variant_id}, result, attrs={"tool.name": name})
        self.observe(name, result)
        if result.get("ok"):
            self.state.completed.add(name)
        return result

    def check_connection(self):
        if self.admin_conn is None:
            oracle = self.cfg["oracle"]
            password = os.environ.get("ORACLE_ADMIN_PASSWORD", oracle.get("admin_password", ""))
            self.admin_conn = self.connect(oracle["admin_user"], password)
        return self.sql(self.admin_conn, "SELECT sys_context('USERENV','CURRENT_USER') AS current_user FROM dual")

    def check_pdb(self):
        result = self.sql(self.admin_conn, "SELECT sys_context('USERENV','CON_NAME') AS con_name FROM dual")
        if result.get("ok") and result.get("rows"):
            self.state.pdb_name = result["rows"][0][0]
            if self.state.pdb_name == "CDB$ROOT":
                result["ok"] = False
                result["error"] = "Connected to CDB$ROOT, but target must be PDB"
        return result

    def unlock_compromised_user(self):
        exists = self.sql(self.admin_conn, "SELECT username FROM dba_users WHERE username = 'COMPROMISED_USER'")
        if not exists.get("ok") or not exists.get("rows"):
            return {"ok": True, "message": "compromised_user does not exist, skipping unlock"}
        return self.sql(self.admin_conn, "ALTER USER compromised_user ACCOUNT UNLOCK")

    def find_credentials(self):
        candidates_sql = """
            SELECT owner, table_name
            FROM dba_tables
            WHERE table_name = 'CREDENTIALS'
              AND owner NOT IN ('SYS','XDB','CTXSYS','MDSYS','ORDSYS','OUTLN')
            ORDER BY CASE WHEN owner = 'SYSTEM' THEN 0 ELSE 1 END, owner, table_name
            FETCH FIRST 20 ROWS ONLY
        """
        candidates = self.sql(self.admin_conn, candidates_sql)
        if not candidates.get("ok") or not candidates.get("rows"):
            return {"ok": True, "message": "credentials table not found"}

        for owner, table in candidates["rows"]:
            cols = self.sql(self.admin_conn, """
                SELECT column_name FROM dba_tab_columns
                WHERE owner = :owner AND table_name = :table_name
            """, {"owner": owner, "table_name": table})
            col_names = [r[0] for r in cols.get("rows", [])]
            username_col = next((c for c in col_names if c.upper() in ["USERNAME", "USER_NAME", "LOGIN", "USER"]), None)
            password_col = next((c for c in col_names if c.upper() in ["PASSWORD", "PASS", "PWD"]), None)
            if not username_col or not password_col:
                continue
            q = f'SELECT "{username_col}", "{password_col}" FROM "{owner}"."{table}" WHERE ROWNUM <= 1'
            row = self.sql(self.admin_conn, q)
            if row.get("ok") and row.get("rows"):
                username, password = row["rows"][0]
                self.state.credentials = {"username": username, "password": password, "owner": owner, "table": table}
                return {"ok": True, "message": "credentials found", "username": username, "source": f"{owner}.{table}"}
        return {"ok": True, "message": "credentials table found, but username/password columns were not found"}

    def test_credentials(self):
        if not self.state.credentials:
            return {"ok": True, "message": "credentials not found, continue as admin"}
        try:
            self.credentials_conn = self.connect(self.state.credentials["username"], self.state.credentials["password"])
            return {"ok": True, "message": "credentials login succeeded", "username": self.state.credentials["username"]}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def ensure_tablespace(self):
        v = VARIANTS[self.state.variant_id]
        exists = self.sql(self.admin_conn, "SELECT tablespace_name FROM dba_tablespaces WHERE tablespace_name = 'CTF_TABLESPACE'")
        if exists.get("ok") and exists.get("rows"):
            files = self.sql(self.admin_conn, """
                SELECT file_name, bytes/1024/1024 AS size_mb, autoextensible, maxbytes/1024/1024 AS max_mb
                FROM dba_data_files WHERE tablespace_name = 'CTF_TABLESPACE'
            """)
            return {"ok": True, "message": "CTF_TABLESPACE already exists", "datafiles": files.get("rows", [])}
        datafile_dir = self.cfg["oracle"].get("datafile_dir", "/opt/oracle/oradata/FREE/FREEPDB1")
        datafile = f"{datafile_dir}/ctf_tablespace01.dbf"
        sql = f"CREATE TABLESPACE CTF_TABLESPACE DATAFILE '{datafile}' SIZE {v['tablespace_size_mb']}M AUTOEXTEND ON NEXT 10M MAXSIZE 1G"
        return self.sql(self.admin_conn, sql)

    def ensure_profile(self):
        v = VARIANTS[self.state.variant_id]
        limit_sql = " ".join(f"{k} {val}" for k, val in v["profile_limits"].items())
        exists = self.sql(self.admin_conn, "SELECT profile FROM dba_profiles WHERE profile = 'CTF_PROFILE' FETCH FIRST 1 ROWS ONLY")
        if exists.get("ok") and exists.get("rows"):
            results = []
            for k, val in v["profile_limits"].items():
                results.append(self.sql(self.admin_conn, f"ALTER PROFILE CTF_PROFILE LIMIT {k} {val}"))
            return {"ok": all(r.get("ok") for r in results), "message": "CTF_PROFILE altered", "details": results}
        return self.sql(self.admin_conn, f"CREATE PROFILE CTF_PROFILE LIMIT {limit_sql}")

    def ensure_role(self):
        exists = self.sql(self.admin_conn, "SELECT role FROM dba_roles WHERE role = 'CTF_ROLE'")
        if exists.get("ok") and exists.get("rows"):
            return self.sql(self.admin_conn, 'ALTER ROLE CTF_ROLE IDENTIFIED BY "ctf_role"')
        return self.sql(self.admin_conn, 'CREATE ROLE CTF_ROLE IDENTIFIED BY "ctf_role"')

    def ensure_student_user(self):
        v = VARIANTS[self.state.variant_id]
        exists = self.sql(self.admin_conn, "SELECT username FROM dba_users WHERE username = 'CTF_STUDENT'")
        if not exists.get("ok"):
            return exists
        if exists.get("rows"):
            commands = [
                'ALTER USER CTF_STUDENT IDENTIFIED BY "ctf_student" ACCOUNT UNLOCK',
                'ALTER USER CTF_STUDENT DEFAULT TABLESPACE CTF_TABLESPACE TEMPORARY TABLESPACE TEMP PROFILE CTF_PROFILE',
                f'ALTER USER CTF_STUDENT QUOTA {v["quota_mb"]}M ON CTF_TABLESPACE',
            ]
        else:
            commands = [
                f'CREATE USER CTF_STUDENT IDENTIFIED BY "ctf_student" DEFAULT TABLESPACE CTF_TABLESPACE TEMPORARY TABLESPACE TEMP QUOTA {v["quota_mb"]}M ON CTF_TABLESPACE PROFILE CTF_PROFILE ACCOUNT UNLOCK'
            ]
        results = []
        for cmd in commands:
            r = self.sql(self.admin_conn, cmd)
            if not r.get("ok") and "ORA-28007" in r.get("error", ""):
                r = {"ok": True, "message": "password reuse blocked, password left unchanged", "sql": cmd}
            results.append(r)
        return {"ok": all(r.get("ok") for r in results), "details": results}

    def grant_create_session(self):
        return self.sql(self.admin_conn, "GRANT CREATE SESSION TO CTF_STUDENT")

    def grant_role(self):
        return self.sql(self.admin_conn, "GRANT CTF_ROLE TO CTF_STUDENT")

    def disable_default_role(self):
        return self.sql(self.admin_conn, "ALTER USER CTF_STUDENT DEFAULT ROLE NONE")

    def grant_select_flag(self):
        exists = self.sql(self.admin_conn, """
            SELECT owner, object_name, object_type FROM dba_objects
            WHERE owner = 'CTF' AND object_name = 'CTF_FLAG'
              AND object_type IN ('TABLE','VIEW')
        """)
        if not exists.get("ok") or not exists.get("rows"):
            return {"ok": True, "message": "CTF.CTF_FLAG not found, grant skipped"}
        return self.sql(self.admin_conn, "GRANT SELECT ON CTF.CTF_FLAG TO CTF_ROLE")

    def connect_student(self):
        try:
            self.student_conn = self.connect("CTF_STUDENT", "ctf_student")
            self.state.ctf_student_connected = True
            return {"ok": True, "message": "connected as CTF_STUDENT"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def activate_role(self):
        if not self.student_conn:
            r = self.connect_student()
            if not r.get("ok"):
                return r
        result = self.sql(self.student_conn, 'SET ROLE CTF_ROLE IDENTIFIED BY "ctf_role"')
        if result.get("ok"):
            self.state.role_activated = True
        return result

    def read_known_flag(self):
        if not self.student_conn:
            r = self.connect_student()
            if not r.get("ok"):
                return r
        if not self.state.role_activated:
            r = self.activate_role()
            if not r.get("ok"):
                return r
        result = self.sql(self.student_conn, "SELECT * FROM CTF.CTF_FLAG WHERE ROWNUM <= 20")
        flag = self.extract_flag_from_rows(result.get("rows", []))
        if flag:
            self.state.flag = flag
            self.state.flag_source = {"owner": "CTF", "table": "CTF_FLAG", "column": "*", "sql": "SELECT * FROM CTF.CTF_FLAG WHERE ROWNUM <= 20"}
            result["flag"] = flag
            result["flag_source"] = self.state.flag_source
        return result

    def extract_flag_from_rows(self, rows: list) -> str | None:
        for row in rows:
            for value in row:
                if value is None:
                    continue
                m = FLAG_RE.search(str(value))
                if m:
                    return m.group(0)
        return None

    def safe_ident(self, name: str) -> str | None:
        if re.fullmatch(r"[A-Z][A-Z0-9_$#]*", name or ""):
            return name
        return None

    def universal_search(self):
        strategy = self.adaptive_strategy or {}
        max_objects = int(strategy.get("max_objects") or self.cfg["agent"].get("universal_max_objects", 200))
        max_rows = int(strategy.get("max_rows_per_object") or self.cfg["agent"].get("universal_max_rows_per_object", 50))
        keywords = strategy.get("keywords") or SECRET_KEYS
        keywords = [str(k).upper().strip() for k in keywords if re.fullmatch(r"[A-Z0-9_]{2,30}", str(k).upper().strip())]
        if not keywords:
            keywords = SECRET_KEYS

        sys_list = ",".join(f"'{s}'" for s in sorted(SYSTEM_SCHEMAS))
        checked = 0
        skipped = []
        seen = set()
        candidates = []

        def add_candidates(rows, source: str):
            for owner, table, column, data_type in rows or []:
                key = (owner, table, column)
                if key in seen:
                    continue
                seen.add(key)
                score = 0
                combined = f"{owner}.{table}.{column}".upper()
                for kw in keywords:
                    if kw in combined:
                        score += 10
                if owner not in SYSTEM_SCHEMAS:
                    score += 1
                candidates.append({
                    "owner": owner,
                    "table": table,
                    "column": column,
                    "data_type": data_type,
                    "source": source,
                    "score": score,
                })

        # 1. LLM/default keyword-guided metadata search.
        key_condition = " OR ".join([
            f"owner LIKE '%{k}%' OR table_name LIKE '%{k}%' OR column_name LIKE '%{k}%'" for k in keywords
        ])
        keyword_sql = f"""
            SELECT owner, table_name, column_name, data_type
            FROM dba_tab_columns
            WHERE owner NOT IN ({sys_list})
              AND data_type IN ('CHAR','VARCHAR2','NCHAR','NVARCHAR2','CLOB')
              AND ({key_condition})
            FETCH FIRST {max_objects} ROWS ONLY
        """
        keyword_result = self.sql(self.admin_conn, keyword_sql)
        if keyword_result.get("ok"):
            add_candidates(keyword_result.get("rows", []), "keyword_metadata")
        else:
            skipped.append({"stage": "keyword_metadata", "reason": keyword_result.get("error")})

        # 2. Broader adaptive fallback. This handles similar tasks where names do
        # not contain FLAG/SECRET/etc., but the value itself contains CTF{...}.
        remaining = max(0, max_objects - len(candidates))
        if remaining > 0:
            broad_sql = f"""
                SELECT owner, table_name, column_name, data_type
                FROM dba_tab_columns
                WHERE owner NOT IN ({sys_list})
                  AND data_type IN ('CHAR','VARCHAR2','NCHAR','NVARCHAR2','CLOB')
                ORDER BY owner, table_name, column_id
                FETCH FIRST {remaining} ROWS ONLY
            """
            broad_result = self.sql(self.admin_conn, broad_sql)
            if broad_result.get("ok"):
                add_candidates(broad_result.get("rows", []), "broad_text_scan")
            else:
                skipped.append({"stage": "broad_text_scan", "reason": broad_result.get("error")})

        candidates.sort(key=lambda x: x["score"], reverse=True)
        self.trace.span(
            "adaptive_universal_candidates",
            "CHAIN",
            {"strategy": mask_data(strategy), "keywords": keywords, "max_objects": max_objects, "max_rows": max_rows},
            {"candidate_count": len(candidates), "top": candidates[:10]},
        )

        for item in candidates[:max_objects]:
            owner, table, column = item["owner"], item["table"], item["column"]
            if not all([self.safe_ident(owner), self.safe_ident(table), self.safe_ident(column)]):
                skipped.append({"owner": owner, "table": table, "column": column, "reason": "unsafe identifier"})
                continue
            if str(item.get("data_type", "")).upper() == "CLOB":
                query = f'SELECT DBMS_LOB.SUBSTR("{column}", 4000, 1) AS "{column}" FROM "{owner}"."{table}" WHERE "{column}" IS NOT NULL AND ROWNUM <= {max_rows}'
            else:
                query = f'SELECT "{column}" FROM "{owner}"."{table}" WHERE "{column}" IS NOT NULL AND ROWNUM <= {max_rows}'
            result = self.sql(self.admin_conn, query)
            checked += 1
            if not result.get("ok"):
                skipped.append({"owner": owner, "table": table, "column": column, "reason": result.get("error")})
                continue
            flag = self.extract_flag_from_rows(result.get("rows", []))
            if flag:
                self.state.flag = flag
                self.state.flag_source = {"owner": owner, "table": table, "column": column, "sql": query, "candidate_source": item.get("source")}
                return {
                    "ok": True,
                    "flag": flag,
                    "flag_source": self.state.flag_source,
                    "strategy_source": strategy.get("source", "none"),
                    "checked_objects": checked,
                    "candidate_count": len(candidates),
                    "skipped": skipped[:20],
                }
        return {
            "ok": True,
            "flag": None,
            "message": "flag was not found by adaptive universal search",
            "strategy_source": strategy.get("source", "none"),
            "candidate_count": len(candidates),
            "checked_objects": checked,
            "skipped": skipped[:20],
        }

    def recommended_next(self) -> tuple[str, list[str], str]:
        if self.state.flag:
            return "finish_success", ["finish_success"], "flag already found"
        for action in ORDERED_ACTIONS:
            if action not in self.state.completed:
                return action, [action, "universal_search"], f"next required action for variant {self.state.variant_id}"
        return "variant_done", ["variant_done", "universal_search"], "all variant actions were completed, but flag is absent"

    def execute_named_action(self, action: str) -> dict:
        tools = {
            "check_connection": self.check_connection,
            "check_pdb": self.check_pdb,
            "unlock_compromised_user": self.unlock_compromised_user,
            "find_credentials": self.find_credentials,
            "test_credentials": self.test_credentials,
            "ensure_tablespace": self.ensure_tablespace,
            "ensure_profile": self.ensure_profile,
            "ensure_role": self.ensure_role,
            "ensure_student_user": self.ensure_student_user,
            "grant_create_session": self.grant_create_session,
            "grant_role": self.grant_role,
            "disable_default_role": self.disable_default_role,
            "grant_select_flag": self.grant_select_flag,
            "connect_student": self.connect_student,
            "activate_role": self.activate_role,
            "read_known_flag": self.read_known_flag,
            "universal_search": self.universal_search,
        }
        if action not in tools:
            return {"ok": False, "error": f"unknown action {action}"}
        return self.tool(action, tools[action])

    def run_variant(self, variant_id: int) -> bool:
        self.state.variant_id = variant_id
        self.state.completed = set()
        self.state.ctf_student_connected = False
        self.state.role_activated = False
        if self.student_conn:
            try: self.student_conn.close()
            except Exception: pass
            self.student_conn = None
        self.trace.span("start_variant", "CHAIN", {"variant_id": variant_id, "params": VARIANTS[variant_id]}, {"status": "started"})
        for _ in range(40):
            recommended, allowed, reason = self.recommended_next()
            if recommended == "finish_success":
                return True
            if recommended == "variant_done":
                self.trace.span("variant_without_flag", "CHAIN", {"variant_id": variant_id}, {"status": "no_flag"})
                return False
            decision = self.ask_llm_next_action(allowed, recommended, reason)
            action = decision.get("action", recommended)
            self.trace.span("planner_decision", "CHAIN", {"allowed": allowed, "recommended": recommended}, decision)
            if action == "universal_search":
                # внутри варианта можно разрешить, но основной сценарий сначала проверяет все варианты
                action = recommended
            action_result = self.execute_named_action(action)
            if action == "grant_select_flag" and "not found" in str(action_result.get("message", "")).lower():
                # Standard object is absent. Do not waste time on connect_student,
                # activate_role and read_known_flag for this variant.
                self.state.completed.update({"connect_student", "activate_role", "read_known_flag"})
            if self.state.flag:
                return True
        return False

    def run_all(self) -> dict:
        root = self.trace.span("agent_start", "CHAIN", {"variants": list(VARIANTS)}, {"status": "started"})
        self.ask_llm_milestone("task_analysis", {"variants": list(VARIANTS), "goal": "start Oracle CTF task"})
        try:
            if self.cfg.get("agent", {}).get("skip_known_variants_before_universal", False):
                self.trace.span("skip_known_variants", "CHAIN", {"reason": "skip_known_variants_before_universal=true"}, {"status": "skipped"})
            else:
                for variant_id in [1, 2, 3]:
                    found = self.run_variant(variant_id)
                    if found:
                        result = {
                            "status": "success",
                            "mode": "known_variant",
                            "variant_id": variant_id,
                            "flag": self.state.flag,
                            "flag_source": self.state.flag_source,
                        }
                        self.ask_llm_milestone("final_summary", {"result": result})
                        self.trace.span("agent_finish", "CHAIN", {"root": root}, result)
                        self.trace.final(result)
                        return result

            # If known variants did not find the flag, start the adaptive AI-agent stage.
            # The LLM proposes search priorities for similar/non-exact tasks; Python
            # then performs only safe limited SELECT operations.
            failure_context = {
                "reason": "known variants did not return flag",
                "known_variants_checked": [1, 2, 3],
                "last_errors": self.state.errors[-10:],
                "history_tail": self.state.history[-15:],
                "standard_object": "CTF.CTF_FLAG",
                "next_stage": "adaptive_universal_search",
            }
            self.adaptive_strategy = self.ask_llm_adaptive_strategy(failure_context)
            self.trace.span("start_adaptive_universal_search", "CHAIN", failure_context, {"status": "started", "strategy": mask_data(self.adaptive_strategy)})
            live_log(f"UNIVERSAL SEARCH strategy_source={self.adaptive_strategy.get('source')}")
            self.execute_named_action("universal_search")
            if self.state.flag:
                result = {"status": "success", "mode": "universal_search", "flag": self.state.flag, "flag_source": self.state.flag_source}
            else:
                result = {"status": "failed", "mode": "universal_search", "flag": None, "message": "flag was not found"}
            self.ask_llm_milestone("final_summary", {"result": result})
            self.trace.span("agent_finish", "CHAIN", {"root": root}, result)
            self.trace.final(result)
            return result
        finally:
            for conn in [self.admin_conn, self.credentials_conn, self.student_conn]:
                try:
                    if conn:
                        conn.close()
                except Exception:
                    pass

def main():
    cfg = load_json(BASE_DIR / "config.json")
    agent = OracleAgent(cfg)
    result = agent.run_all()
    live_log("FINAL RESULT:\n" + json.dumps(mask_data(result), ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()

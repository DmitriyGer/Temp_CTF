
import argparse, json, re, time, uuid
from pathlib import Path
from typing import Any
import oracledb, requests

BASE_DIR = Path(__file__).resolve().parent

SYSTEM_PROMPT = """
Ты ИИ-агент для учебного администрирования Oracle Database.
Цель: выполнить текст задания и получить флаг из CTF.CTF_FLAG.
На каждом шаге возвращай только JSON.

Доступные действия:
1) run_sql:
{"thought":"почему выбран шаг","action":"run_sql","connect_as":"admin|credentials|ctf_student","sql":"SQL"}
2) set_credentials_connection:
{"thought":"почему","action":"set_credentials_connection","username":"USER","password":"PASSWORD"}
3) switch_connection:
{"thought":"почему","action":"switch_connection","connect_as":"credentials|ctf_student"}
4) finish:
{"thought":"почему","action":"finish","status":"success|failed","flag":"CTF{...}","summary":"итог"}

Обязательная логика:
проверить подключение; разблокировать compromised_user; найти credentials; если credentials найдены, сохранить их через set_credentials_connection; создать/проверить CTF_TABLESPACE; создать/изменить CTF_PROFILE; создать/изменить CTF_ROLE; создать/изменить CTF_STUDENT; выдать CREATE SESSION; назначить CTF_ROLE не по умолчанию; выдать SELECT ON CTF.CTF_FLAG TO CTF_ROLE; подключиться под CTF_STUDENT; выполнить SET ROLE CTF_ROLE IDENTIFIED BY ctf_role; выполнить SELECT * FROM CTF.CTF_FLAG; после получения флага вернуть finish.

Правила безопасности:
запрещены DROP, DELETE, TRUNCATE, UPDATE, MERGE, ALTER SYSTEM, SHUTDOWN, GRANT DBA, GRANT ALL PRIVILEGES.
CTF_STUDENT можно выдать только CREATE SESSION.
SELECT на CTF.CTF_FLAG выдаётся только CTF_ROLE.
Если объект уже существует, используй ALTER или переходи к проверке.
Если ошибка Oracle, проанализируй её и выбери исправляющее действие.
"""

def load_json(path): return json.loads(Path(path).read_text(encoding="utf-8"))
def read_text(path): return Path(path).read_text(encoding="utf-8")
def now_ms(): return int(time.time() * 1000)

class OITrace:
    def __init__(self, out_dir):
        self.dir = Path(out_dir); self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "openinference_traces.jsonl"
        self.trace_id = uuid.uuid4().hex
    def span(self, name, kind, input_value, output_value, parent_span_id=None, attributes=None):
        span_id = uuid.uuid4().hex[:16]
        rec = {
            "trace_id": self.trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "name": name,
            "start_time_unix_ms": now_ms(),
            "end_time_unix_ms": now_ms(),
            "attributes": {
                "openinference.span.kind": kind,
                "input.value": json.dumps(input_value, ensure_ascii=False, default=str),
                "output.value": json.dumps(output_value, ensure_ascii=False, default=str)
            }
        }
        if attributes: rec["attributes"].update(attributes)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        return span_id

def parse_model_json(text):
    cleaned = text.strip()
    cleaned = re.sub(r"^```json\s*", "", cleaned, flags=re.I)
    cleaned = re.sub(r"^```\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    m = re.search(r"\{.*\}", cleaned, flags=re.S)
    if not m: raise ValueError(f"LLM did not return JSON: {text}")
    return json.loads(m.group(0))

def ask_ollama(cfg, messages, trace):
    ocfg = cfg["ollama"]
    urls = ocfg.get("api_urls") or [ocfg["base_url"].rstrip("/") + "/api/generate"]
    prompt = "\n\n".join([f"{m['role'].upper()}:\n{m['content']}" for m in messages])
    last_error = None
    for url in urls:
        try:
            payload = {
                "model": ocfg["model"],
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": ocfg.get("temperature", 0.0), "num_ctx": ocfg.get("num_ctx", 4096)}
            }
            r = requests.post(url, json=payload, timeout=ocfg.get("timeout_seconds", 180))
            r.raise_for_status()
            raw = r.json().get("response", "")
            trace.span("ollama_generate", "LLM", {"url": url, "messages": messages}, {"raw_response": raw},
                       attributes={"llm.model_name": ocfg["model"]})
            return parse_model_json(raw)
        except Exception as e:
            last_error = e
    raise RuntimeError(f"Cannot call Ollama or parse JSON. Last error: {last_error}")

def connect_oracle(cfg, username, password):
    oracle = cfg["oracle"]
    hosts = oracle.get("hosts") or [oracle.get("host", "localhost")]
    last_error = None
    for host in hosts:
        try:
            dsn = oracledb.makedsn(host, oracle["port"], service_name=oracle["service_name"])
            conn = oracledb.connect(user=username, password=password, dsn=dsn)
            print(f"Connected to Oracle: {host}:{oracle['port']}/{oracle['service_name']} as {username}")
            return conn
        except Exception as e:
            print(f"Oracle connection failed: {host}:{oracle['port']} as {username} -> {e}")
            last_error = e
    raise RuntimeError(f"Cannot connect to Oracle. Last error: {last_error}")

def validate_sql(sql):
    up = re.sub(r"\s+", " ", sql.strip()).upper()
    forbidden = ["DROP ", "DELETE ", "TRUNCATE ", "UPDATE ", "MERGE ", "ALTER SYSTEM", "SHUTDOWN", "GRANT DBA", "GRANT ALL", "ALL PRIVILEGES"]
    for x in forbidden:
        if x in up: raise RuntimeError(f"Forbidden SQL command: {x.strip()}")
    allowed = ["SELECT ", "ALTER USER ", "CREATE TABLESPACE ", "ALTER TABLESPACE ", "CREATE PROFILE ", "ALTER PROFILE ",
               "CREATE ROLE ", "ALTER ROLE ", "CREATE USER ", "GRANT CREATE SESSION", "GRANT SELECT ON", "GRANT CTF_ROLE", "SET ROLE"]
    if not any(up.startswith(x) for x in allowed):
        raise RuntimeError(f"SQL command is not allowed: {sql}")
    if up.startswith("GRANT "):
        good = ("GRANT CREATE SESSION TO CTF_STUDENT" in up or
                "GRANT SELECT ON CTF.CTF_FLAG TO CTF_ROLE" in up or
                "GRANT CTF_ROLE TO CTF_STUDENT" in up)
        if not good: raise RuntimeError(f"GRANT command does not match task: {sql}")

def run_sql(conn, sql):
    cur = conn.cursor()
    try:
        cur.execute(sql)
        if cur.description:
            cols = [c[0] for c in cur.description]
            rows = [list(r) for r in cur.fetchall()]
            return {"ok": True, "columns": cols, "rows": rows}
        conn.commit()
        return {"ok": True, "message": "committed"}
    except Exception as e:
        return {"ok": False, "error": str(e), "sql": sql}
    finally:
        cur.close()

def execute_action(action, cfg, conns, trace):
    name = action.get("action")
    if name == "run_sql":
        sql = action.get("sql", "")
        connect_as = action.get("connect_as", "admin")
        validate_sql(sql)
        if connect_as not in conns or conns[connect_as] is None:
            return {"ok": False, "error": f"Connection {connect_as} is not initialized"}
        result = run_sql(conns[connect_as], sql)
        trace.span("run_sql", "TOOL", {"connect_as": connect_as, "sql": sql}, result, attributes={"tool.name": "run_sql"})
        return result
    if name == "set_credentials_connection":
        user, pwd = action.get("username"), action.get("password")
        if not user or not pwd: return {"ok": False, "error": "username/password required"}
        try:
            conns["credentials"] = connect_oracle(cfg, user, pwd)
            result = {"ok": True, "message": f"credentials connection initialized as {user}"}
        except Exception as e:
            result = {"ok": False, "error": str(e)}
        trace.span("set_credentials_connection", "TOOL", {"username": user, "password": "***"}, result)
        return result
    if name == "switch_connection":
        ca = action.get("connect_as")
        result = {"ok": ca in conns and conns.get(ca) is not None, "message": f"connection {ca} checked"}
        trace.span("switch_connection", "TOOL", action, result)
        return result
    if name == "finish":
        result = {"ok": True, "finished": True, "status": action.get("status"), "flag": action.get("flag"), "summary": action.get("summary")}
        trace.span("finish", "CHAIN", action, result)
        return result
    result = {"ok": False, "error": f"Unknown action: {name}"}
    trace.span("unknown_action", "TOOL", action, result)
    return result

def build_prompt(task_text, history):
    return "Текст задания:\n" + task_text + "\n\nИстория последних действий:\n" + json.dumps(history[-12:], ensure_ascii=False, indent=2, default=str) + "\n\nВыбери следующее действие. Верни только JSON."

def agent_loop(cfg, task_text, max_steps=45):
    trace = OITrace(cfg["agent"]["trajectories_dir"])
    conns = {"admin": connect_oracle(cfg, cfg["oracle"]["admin_user"], cfg["oracle"]["admin_password"]), "credentials": None, "ctf_student": None}
    history = []
    root = trace.span("agent_start", "CHAIN", {"task_text": task_text}, {"status": "started"})
    try:
        for step in range(1, max_steps + 1):
            messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": build_prompt(task_text, history)}]
            try:
                action = ask_ollama(cfg, messages, trace)
            except Exception as e:
                obs = {"ok": False, "error": f"LLM error: {e}"}
                history.append({"step": step, "action": None, "observation": obs})
                print(json.dumps(history[-1], ensure_ascii=False, default=str))
                continue
            if action.get("connect_as") == "ctf_student" and conns.get("ctf_student") is None:
                try:
                    conns["ctf_student"] = connect_oracle(cfg, "CTF_STUDENT", "ctf_student")
                except Exception as e:
                    history.append({"step": step, "action": action, "observation": {"ok": False, "error": f"Cannot init ctf_student connection: {e}"}})
                    continue
            try:
                obs = execute_action(action, cfg, conns, trace)
            except Exception as e:
                obs = {"ok": False, "error": str(e), "rejected_by_safety_layer": True}
                trace.span("safety_rejection", "TOOL", action, obs)
            history.append({"step": step, "action": action, "observation": obs})
            print(json.dumps(history[-1], ensure_ascii=False, default=str))
            if obs.get("ok") and obs.get("rows") and "CTF{" in json.dumps(obs.get("rows"), ensure_ascii=False):
                history.append({"system_hint": "Флаг найден. Следующим шагом верни finish со status=success и flag из observation."})
            if action.get("action") == "finish":
                trace.span("agent_finish", "CHAIN", {"history_size": len(history)}, obs, parent_span_id=root)
                return {"ok": True, "history": history, "result": obs, "trace_id": trace.trace_id}
        result = {"ok": False, "error": "max_steps exceeded", "trace_id": trace.trace_id, "history": history}
        trace.span("agent_finish", "CHAIN", {"history_size": len(history)}, result, parent_span_id=root)
        return result
    finally:
        for c in conns.values():
            try:
                if c: c.close()
            except Exception:
                pass

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--task", default=None)
    p.add_argument("--max-steps", type=int, default=45)
    args = p.parse_args()
    cfg = load_json(BASE_DIR / "config.json")
    task_file = Path(args.task) if args.task else BASE_DIR / cfg["agent"]["task_file"]
    result = agent_loop(cfg, read_text(task_file), args.max_steps)
    print(json.dumps(result.get("result", result), ensure_ascii=False, indent=2, default=str))

if __name__ == "__main__":
    main()

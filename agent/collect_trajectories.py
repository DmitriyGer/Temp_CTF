
import argparse, json, random, time, uuid
from pathlib import Path
SCENARIOS = ["success","object_already_exists","password_reuse_blocked","flag_table_missing","oracle_connection_failed","ollama_json_retry","safety_rejection_forbidden_sql"]
def span(trace_id, name, kind, inp, out, parent=None):
    return {"trace_id": trace_id, "span_id": uuid.uuid4().hex[:16], "parent_span_id": parent, "name": name,
            "start_time_unix_ms": int(time.time()*1000), "end_time_unix_ms": int(time.time()*1000),
            "attributes": {"openinference.span.kind": kind, "input.value": json.dumps(inp, ensure_ascii=False), "output.value": json.dumps(out, ensure_ascii=False)}}
def make_trace(i):
    trace_id = uuid.uuid4().hex; scenario = random.choice(SCENARIOS); variant = random.choice([1,2,3]); rec=[]
    root = span(trace_id,"agent_start","CHAIN",{"variant":variant,"scenario":scenario},{"status":"started"}); rec.append(root); p=root["span_id"]
    rec.append(span(trace_id,"ollama_generate","LLM",{"task":variant},{"action":"run_sql","sql":"SELECT name FROM v$database"},p))
    rec.append(span(trace_id,"run_sql","TOOL",{"sql":"SELECT name FROM v$database"},{"ok":scenario!="oracle_connection_failed"},p))
    if scenario=="oracle_connection_failed":
        rec.append(span(trace_id,"agent_finish","CHAIN",{"scenario":scenario},{"status":"failed","reason":"connection failed"},p)); return rec
    rec.append(span(trace_id,"ollama_generate","LLM",{"observation":"connection ok"},{"action":"run_sql","sql":"ALTER USER compromised_user ACCOUNT UNLOCK"},p))
    rec.append(span(trace_id,"run_sql","TOOL",{"sql":"ALTER USER compromised_user ACCOUNT UNLOCK"},{"ok":True},p))
    if scenario=="safety_rejection_forbidden_sql":
        rec.append(span(trace_id,"ollama_generate","LLM",{"observation":"test safety"},{"action":"run_sql","sql":"DROP USER CTF_STUDENT CASCADE"},p))
        rec.append(span(trace_id,"safety_rejection","TOOL",{"sql":"DROP USER CTF_STUDENT CASCADE"},{"ok":False,"rejected_by_safety_layer":True},p))
        rec.append(span(trace_id,"agent_finish","CHAIN",{"scenario":scenario},{"status":"failed"},p)); return rec
    rec.append(span(trace_id,"ollama_generate","LLM",{"observation":"unlocked"},{"action":"run_sql","sql":"CREATE TABLESPACE CTF_TABLESPACE ..."},p))
    rec.append(span(trace_id,"run_sql","TOOL",{"sql":"CREATE TABLESPACE CTF_TABLESPACE ..."},{"ok":scenario!="object_already_exists","error":"ORA-01543" if scenario=="object_already_exists" else None},p))
    if scenario=="flag_table_missing":
        rec.append(span(trace_id,"run_sql","TOOL",{"sql":"GRANT SELECT ON CTF.CTF_FLAG TO CTF_ROLE"},{"ok":False,"error":"ORA-00942"},p))
        rec.append(span(trace_id,"agent_finish","CHAIN",{"scenario":scenario},{"status":"failed"},p)); return rec
    rec.append(span(trace_id,"ollama_generate","LLM",{"observation":"configured"},{"action":"run_sql","sql":"SELECT * FROM CTF.CTF_FLAG"},p))
    rec.append(span(trace_id,"run_sql","TOOL",{"sql":"SELECT * FROM CTF.CTF_FLAG"},{"ok":True,"rows":[["CTF{TEST_TRAJECTORY}"]]},p))
    rec.append(span(trace_id,"ollama_generate","LLM",{"observation":"flag returned"},{"action":"finish","status":"success","flag":"CTF{TEST_TRAJECTORY}"},p))
    rec.append(span(trace_id,"agent_finish","CHAIN",{"scenario":scenario},{"status":"success"},p)); return rec
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--count",type=int,default=1000); ap.add_argument("--output",default="../trajectories/openinference_1000_test_traces.jsonl"); a=ap.parse_args()
    out=Path(a.output); out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("w",encoding="utf-8") as f:
        for i in range(a.count):
            for r in make_trace(i): f.write(json.dumps(r,ensure_ascii=False)+"\n")
    print(f"Created {a.count} trajectories: {out}")
if __name__=="__main__": main()

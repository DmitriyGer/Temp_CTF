
import argparse, json, random, time, uuid
from pathlib import Path
SCENARIOS = ["success_known_variant", "success_universal_search", "missing_flag_object", "oracle_error", "credentials_absent", "forbidden_sql_rejected"]
def span(tid, name, kind, inp, out, parent=None):
    return {"trace_id": tid, "span_id": uuid.uuid4().hex[:16], "parent_span_id": parent, "name": name,
            "start_time_unix_ms": int(time.time()*1000), "end_time_unix_ms": int(time.time()*1000),
            "attributes": {"openinference.span.kind": kind, "input.value": json.dumps(inp, ensure_ascii=False), "output.value": json.dumps(out, ensure_ascii=False)}}
def one():
    tid=uuid.uuid4().hex; sc=random.choice(SCENARIOS); v=random.choice([1,2,3]); rec=[]
    root=span(tid,"agent_start","CHAIN",{"scenario":sc},{"status":"started"}); rec.append(root); p=root["span_id"]
    for action in ["check_connection","check_pdb","unlock_compromised_user","find_credentials","test_credentials","ensure_tablespace","ensure_profile","ensure_role","ensure_student_user"]:
        rec.append(span(tid,"llm_choose_action","LLM",{"allowed_actions":[action]}, {"action":action}, p))
        ok = not (sc=="oracle_error" and action=="check_connection")
        rec.append(span(tid,action,"TOOL",{"variant":v},{"ok":ok},p))
        if not ok:
            rec.append(span(tid,"agent_finish","CHAIN",{}, {"status":"failed"},p)); return rec
    if sc == "forbidden_sql_rejected":
        rec.append(span(tid,"safety_layer","TOOL",{"sql":"DROP USER X"},{"ok":False,"rejected":True},p))
        rec.append(span(tid,"agent_finish","CHAIN",{}, {"status":"failed"},p)); return rec
    if sc == "success_known_variant":
        rec.append(span(tid,"read_known_flag","TOOL",{}, {"ok":True,"flag":"CTF{TEST_FLAG}"},p))
        rec.append(span(tid,"agent_finish","CHAIN",{}, {"status":"success","mode":"known_variant"},p)); return rec
    rec.append(span(tid,"read_known_flag","TOOL",{}, {"ok":False,"error":"not found"},p))
    rec.append(span(tid,"universal_search","TOOL",{}, {"ok": sc=="success_universal_search", "flag":"FLAG{UNIVERSAL}" if sc=="success_universal_search" else None},p))
    rec.append(span(tid,"agent_finish","CHAIN",{}, {"status":"success" if sc=="success_universal_search" else "failed"},p)); return rec
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--count',type=int,default=1000); ap.add_argument('--output',default='../trajectories/openinference_1000_test_traces.jsonl'); a=ap.parse_args()
    out=Path(a.output); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('w',encoding='utf-8') as f:
        for _ in range(a.count):
            for r in one(): f.write(json.dumps(r,ensure_ascii=False)+'\n')
    print(f'Created {a.count} trajectories: {out}')
if __name__=='__main__': main()

#!/bin/sh
set -eu

if [ "${1:-}" = "pytest" ] || [ "${1:-}" = "python" ] || [ "${1:-}" = "sh" ]; then
  exec "$@"
fi

command_name="${1:-run}"

if [ "$command_name" = "run" ] || [ "$command_name" = "dry-run" ]; then
  python - <<'PY'
import os
import time
import requests

url = os.getenv("OLLAMA_URL", "http://ollama:11434").rstrip("/") + "/api/tags"
for attempt in range(60):
    try:
        if requests.get(url, timeout=2).ok:
            break
    except requests.RequestException:
        pass
    time.sleep(2)
else:
    raise SystemExit(f"Ollama is unavailable at {url}")
PY
fi

if [ "$command_name" = "run" ]; then
  python - <<'PY'
import os
import socket
import time

host = os.getenv("ORACLE_HOST", "oracle-free")
port = int(os.getenv("ORACLE_PORT", "1521"))
for attempt in range(90):
    try:
        with socket.create_connection((host, port), timeout=2):
            break
    except OSError:
        time.sleep(2)
else:
    raise SystemExit(f"Oracle listener is unavailable at {host}:{port}")
PY
fi

exec python -m oracle_agent.main "$@"

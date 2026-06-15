# Oracle LLM Agent Full

LLM выбирает следующее действие, Python только проверяет безопасность и выполняет tool.

Запуск:
```powershell
docker compose -f docker-compose.agent.yaml up --build
```

1000 траекторий:
```powershell
python .\collect_trajectories.py --count 1000
```

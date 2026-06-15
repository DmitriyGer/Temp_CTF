# Tech-Practice Oracle LLM Agent v3

Версия v3 выполняет три заранее заданных варианта по очереди. Если `CTF.CTF_FLAG` не найден, запускается универсальный поиск по доступным объектам.

LLM через Ollama выбирает следующий tool/action. Python не даёт LLM выполнять SQL напрямую: SQL находится внутри безопасных инструментов.

## Запуск

```powershell
cd C:\Users\Taisiya\Documents\VSCode\University\Tech-Practice\agent
docker compose -f docker-compose.agent.yaml up --build
```

## Результаты

```powershell
Get-Content ..\trajectories\final_result.json
Get-Content ..\trajectories\trajectory_openinference.jsonl -Tail 20
```

## 1000 тестовых траекторий

```powershell
python .\collect_trajectories.py --count 1000
```

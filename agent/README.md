# Oracle CTF Agent

Агент выполняет Oracle CTF детерминированным Python-кодом. Языковая модель не
формирует и не выполняет SQL: она опционально объясняет ошибки Oracle. Если LLM
недоступна, основной сценарий продолжается.

## Запуск

Oracle Database и Ollama должны быть заранее подняты:

```bash
docker compose -f ./base/docker-compose.base.yml up -d
docker compose -f ./ollama/docker-compose.ollama.yml up -d
docker exec Temp-2 ollama pull qwen2.5-coder:7b
```

По умолчанию агент использует Oracle на порту `58002` и Ollama на порту
`58003`.

```bash
docker compose -f ./agent/docker-compose.yml build --no-cache oracle-agent
docker compose -f ./agent/docker-compose.yml run --rm oracle-agent
```

Траектории и `final_result.json` сохраняются в `agent/trajectories`.

## Один вариант

```bash
TASK_NAME=variant_a docker compose -f ./agent/docker-compose.yml run --rm oracle-agent
```

Без `TASK_NAME` агент проверяет варианты `A`, `B`, `C` по приоритету.

## Без LLM

```bash
LLM_ENABLED=false docker compose -f ./agent/docker-compose.yml run --rm oracle-agent
```

## Другие подключения

```bash
ORACLE_HOST=host.docker.internal \
ORACLE_PORT=1521 \
ORACLE_PASSWORD=oracle \
LLM_API_TYPE=ollama \
LLM_URL=http://host.docker.internal:58003 \
LLM_MODEL=qwen2.5-coder:7b \
docker compose -f ./agent/docker-compose.yml run --rm oracle-agent
```

## Пайплайн

1. Retry подключения к Oracle.
2. Загрузка JSON-вариантов.
3. Разблокировка `COMPROMISED_USER`.
4. Поиск `CREDENTIALS` и проверка найденного входа.
5. Проверка и создание tablespace, profile, role и student user.
6. Выдача минимальных привилегий и отключение default role.
7. Вход как `CTF_STUDENT`, активация роли и чтение флага.
8. Ограниченный metadata search, если известный объект не дал флаг.
9. Сохранение trajectory и финального результата.

Опасные DML/DDL-команды блокируются централизованно. Пароли маскируются в
консольных логах и trajectory.

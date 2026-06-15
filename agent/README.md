# Oracle CTF AI Agent

Агент запускается отдельно от Oracle Database и Ollama. База и Ollama должны быть уже подняты и доступны с хоста.

По умолчанию используются:

- Ollama: `http://host.docker.internal:58003`;
- Oracle: `host.docker.internal:58002`;
- service name: `FREEPDB1`;
- модель: `qwen2.5-coder:7b`;
- вариант: `oracle_ctf_case_a.txt`.

## Запуск

Из папки `agent`:

```bash
cd agent
docker compose build --no-cache oracle-agent
docker compose run --rm oracle-agent
```

После изменения Python-кода или Dockerfile пересоберите образ:

```bash
docker compose build oracle-agent
```

Если пароль Oracle отличается, передайте фактическое значение:

```bash
ORACLE_PASSWORD=другой_пароль docker compose run --rm oracle-agent
```

## Другой вариант

```bash
TASK_FILE=oracle_ctf_case_b.txt docker compose run --rm oracle-agent
```

## Другие адреса Oracle и Ollama

```bash
OLLAMA_URL=http://host.docker.internal:11434 \
ORACLE_HOST=host.docker.internal \
ORACLE_PORT=1521 \
ORACLE_PASSWORD=oracle \
docker compose run --rm oracle-agent
```

## Сбор 1000 траекторий

```bash
docker compose run --rm oracle-agent collect-trajectories --target 1000
```

Траектории и completion report сохраняются в `agent/trajectories`.

На сервере без GPU первый ответ модели может формироваться несколько минут.
Таймаут по умолчанию равен 600 секундам. При необходимости его можно изменить:

```bash
REQUEST_TIMEOUT=900 docker compose run --rm oracle-agent
```

## Как работает агент

Агент загружает инструкции из `oracle_ctf_playbook`, получает от Ollama один JSON-action, проверяет SQL через allowlist и только затем выполняет его в Oracle через `python-oracledb`. Пароли маскируются, опасные SQL-команды блокируются, флаг сохраняется только после реального результата Oracle.

Для работы модели используется краткий файл
`oracle_ctf_playbook/runtime_agent_guide.md`. Подробные исходные playbook-файлы
остаются в проекте как документация, но не отправляются модели на каждом шаге.

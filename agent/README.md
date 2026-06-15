# Oracle CTF AI Agent

Агент запускается отдельно от Oracle Database и Ollama. База и Ollama должны быть уже подняты и доступны с хоста.

По умолчанию используются:

- OpenAI-compatible llama.cpp API: `http://192.168.10.65:8901/v1`;
- Oracle: `host.docker.internal:58002`;
- service name: `FREEPDB1`;
- модель: `Qwen/Qwen3.6-27B`;
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

## Другие адреса Oracle и LLM

```bash
OLLAMA_URL=http://192.168.10.65:8901/v1 \
OLLAMA_MODEL=Qwen/Qwen3.6-27B \
LLM_API_TYPE=openai \
ORACLE_HOST=host.docker.internal \
ORACLE_PORT=1521 \
ORACLE_PASSWORD=oracle \
docker compose run --rm oracle-agent
```

Для прежнего Ollama:

```bash
OLLAMA_URL=http://host.docker.internal:58003 \
OLLAMA_MODEL=qwen2.5-coder:7b \
LLM_API_TYPE=ollama \
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

## Просмотр выполнения

Агент выводит в Docker logs текущий этап, номер шага, ожидание модели, выбранный
action, маскированный SQL, результат safety guard, результат Oracle,
verification и длительность. Пароли и полный prompt не выводятся.

```bash
docker compose run --rm oracle-agent
```

Чтобы после запуска использовать именно `docker compose logs`, запускайте
сервис без `run --rm`:

```bash
docker compose up -d --build oracle-agent
```

В другом терминале:

```bash
docker compose logs -f oracle-agent
```

Пример:

```text
stage=step_start step=3/40 current_user=system
stage=llm_wait step=3 attempt=1/3 prompt_chars=7200
stage=action_received step=3 type=sql sql=ALTER USER ...
stage=sql_guard allowed=True
stage=step_done step=3 status=success total_ms=17020
```

Более подробные диагностические сообщения:

```bash
LOG_LEVEL=DEBUG docker compose run --rm oracle-agent
```

Параметры производительности Ollama:

```bash
OLLAMA_NUM_CTX=4096 OLLAMA_NUM_PREDICT=192 \
docker compose run --rm oracle-agent
```

## Как работает агент

Агент загружает инструкции из `oracle_ctf_playbook`, получает от Ollama один JSON-action, проверяет SQL через allowlist и только затем выполняет его в Oracle через `python-oracledb`. Пароли маскируются, опасные SQL-команды блокируются, флаг сохраняется только после реального результата Oracle.

Для работы модели используется краткий файл
`oracle_ctf_playbook/runtime_agent_guide.md`. Подробные исходные playbook-файлы
остаются в проекте как документация, но не отправляются модели на каждом шаге.

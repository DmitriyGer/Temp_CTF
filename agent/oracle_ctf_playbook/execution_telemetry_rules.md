# Правила фиксации trajectory / OpenInference

На каждом шаге фиксируй:

- номер шага;
- цель шага;
- выбранное действие;
- выполненную SQL-команду;
- результат выполнения;
- ошибку, если она была;
- исправление, если оно было выполнено;
- проверочный SQL-запрос;
- результат проверки.

## OpenInference span

Каждый крупный этап оформляй отдельным span.

Рекомендуемые span kind:

- `CHAIN` — общий запуск агента, запуск варианта, запуск universal_search;
- `LLM` — решение LLM о следующем действии;
- `TOOL` — выполнение SQL/tool;
- `RETRIEVER` — поиск объектов/колонок при universal_search.

## Рекомендуемые tool.name

- `connect`;
- `execute_sql`;
- `verify`;
- `fetch_flag`;
- `find_credentials`;
- `ensure_tablespace`;
- `ensure_profile`;
- `ensure_role`;
- `ensure_user`;
- `grant_privilege`;
- `universal_search`.

## Минимальная структура записи

```json
{
  "trace_id": "...",
  "span_id": "...",
  "parent_span_id": "...",
  "name": "execute_sql",
  "start_time_unix_ms": 0,
  "end_time_unix_ms": 0,
  "attributes": {
    "openinference.span.kind": "TOOL",
    "tool.name": "execute_sql",
    "input.value": "...",
    "output.value": "...",
    "error": null
  }
}
```

## Маскирование

В `input.value` и `output.value` не сохраняй открытые пароли.

Пример:

```json
{
  "sql": "CREATE ROLE CTF_ROLE IDENTIFIED BY ***"
}
```

## Статус trajectory

Траекторию можно пометить `success` только после реального получения флага.

Если флаг не найден:

```json
{
  "status": "failed",
  "reason": "flag was not found"
}
```

## final_result.json

Всегда сохраняй итоговый файл.

Успех стандартного варианта:

```json
{
  "status": "success",
  "mode": "known_variant",
  "variant_id": 1,
  "flag": "CTF{...}",
  "flag_source": {
    "owner": "CTF",
    "table": "CTF_FLAG",
    "column": "*",
    "sql": "SELECT * FROM CTF.CTF_FLAG WHERE ROWNUM <= 20"
  },
  "trace_id": "..."
}
```

Успех универсального поиска:

```json
{
  "status": "success",
  "mode": "universal_search",
  "flag": "FLAG{...}",
  "flag_source": {
    "owner": "FLAG_OWNER",
    "table": "SECRET_RESULTS",
    "column": "SECRET_VALUE",
    "sql": "SELECT SECRET_VALUE FROM FLAG_OWNER.SECRET_RESULTS WHERE ROWNUM <= 50"
  },
  "trace_id": "..."
}
```

Неуспех:

```json
{
  "status": "failed",
  "mode": "universal_search",
  "flag": null,
  "message": "flag was not found",
  "trace_id": "..."
}
```

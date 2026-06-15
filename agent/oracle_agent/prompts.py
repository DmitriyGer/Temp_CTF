from __future__ import annotations

import json
from typing import Any

from .action_schema import OLLAMA_ACTION_SCHEMA
from .playbook_loader import PlaybookContext


SYSTEM_PROMPT = """\
Ты управляешь только локальной учебной Oracle CTF-базой.
Соблюдай подключенный playbook и SQL safety boundaries.
Верни ровно один следующий action, а не полный план.
Ответ должен быть единственным JSON-объектом без Markdown и пояснений вне JSON.
Используй поле action_type. Поля action, user, tool и command запрещены.
Используй минимальные привилегии. CTF_STUDENT получает только CREATE SESSION.
SELECT на CTF.CTF_FLAG выдавай только роли CTF_ROLE.
CTF_ROLE должна быть назначена CTF_STUDENT, но не быть default role.
Перед чтением флага подключись как CTF_STUDENT и активируй защищенную роль.
Не раскрывай пароли в reason, safety_notes, next_goal или финальном отчете.
Не выдумывай учетные данные, результаты SQL и флаг.
Если SQL заблокирован или завершился ошибкой, предложи исправимый безопасный шаг.
Для DDL и GRANT по возможности указывай verification_sql.
"""

RESPONSE_REMINDER = """\
ОБЯЗАТЕЛЬНЫЙ ФОРМАТ ОТВЕТА:
{
  "action_type": "sql",
  "reason": "Краткая причина",
  "sql": "ALTER USER compromised_user ACCOUNT UNLOCK",
  "verification_sql": "SELECT username, account_status FROM dba_users WHERE username = 'COMPROMISED_USER'",
  "next_goal": "Найти таблицу credentials"
}

Допустимые action_type: connect, sql, verify, set_role, final_report, stop, ask_human.
Не возвращай {"action": "unlock_user", "user": "..."}.
"""


def _static_prefix(context: PlaybookContext) -> str:
    schema = json.dumps(OLLAMA_ACTION_SCHEMA, ensure_ascii=False, indent=2)
    return (
        f"{SYSTEM_PROMPT}\n\n"
        f"JSON Schema ответа:\n{schema}\n\n"
        f"Инструкционный контекст:\n{context.full_context}\n\n"
        f"{RESPONSE_REMINDER}"
    )


def initial_prompt(context: PlaybookContext) -> str:
    return (
        f"{_static_prefix(context)}\n\n"
        "Последние наблюдения: подключение к Oracle выполнено.\n"
        "Начни с одного следующего безопасного действия."
    )


def next_prompt(
    context: PlaybookContext,
    history: list[dict[str, Any]],
    correction: str | None = None,
) -> str:
    compact_history = json.dumps(history[-4:], ensure_ascii=False, default=str, separators=(",", ":"))
    correction_text = f"\nИсправление формата/действия: {correction}\n" if correction else ""
    return (
        f"{_static_prefix(context)}\n\n"
        f"Последние наблюдения:\n{compact_history}\n"
        f"{correction_text}\n"
        "Верни только один следующий action по JSON Schema."
    )

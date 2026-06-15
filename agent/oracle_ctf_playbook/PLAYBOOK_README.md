# Инструкции для Oracle CTF Agent

Архив содержит готовые текстовые инструкции для ИИ-агента, который выполняет учебную CTF-задачу по администрированию Oracle Database.

## Файлы

- `01_system_prompt_main.md` — основной системный промпт агента.
- `02_task_execution_rules.md` — правила выполнения стандартных вариантов 1–3.
- `03_universal_search_rules.md` — усиленные правила универсального поиска флага.
- `04_safety_rules.md` — запреты и правила безопасности SQL.
- `05_trace_rules_openinference.md` — правила фиксации trajectory/OpenInference.
- `06_final_report_format.md` — формат финального ответа агента.
- `task_variant_1.txt` — текст задания варианта 1.
- `task_variant_2.txt` — текст задания варианта 2.
- `task_variant_3.txt` — текст задания варианта 3.
- `agent_full_instruction.md` — полный объединённый промпт, который можно использовать как одну инструкцию.
- `agent_instruction.json` — те же инструкции в JSON-структуре.

## Как использовать

Если агент принимает один системный промпт, используй файл:

```text
agent_full_instruction.md
```

Если агент поддерживает раздельные инструкции, подключай файлы по смыслу:

```text
01_system_prompt_main.md
02_task_execution_rules.md
03_universal_search_rules.md
04_safety_rules.md
05_trace_rules_openinference.md
06_final_report_format.md
```

## Главная логика

Агент должен:

1. Выполнить стандартный сценарий для варианта 1.
2. Если флаг не найден — выполнить вариант 2.
3. Если флаг не найден — выполнить вариант 3.
4. Если флаг не найден — запустить универсальный поиск по пользовательским объектам базы.
5. Сохранить trajectory-файл и `final_result.json`.

# Универсальный интеллектуальный поиск флага

Универсальный поиск запускается только если:

1. Вариант 1 не дал флаг.
2. Вариант 2 не дал флаг.
3. Вариант 3 не дал флаг.
4. Стандартный объект `CTF.CTF_FLAG` отсутствует, недоступен или не содержит значение, похожее на флаг.

## Цель

Найти флаг в нестандартных пользовательских объектах базы данных.

Примеры возможных объектов:

- `FLAG_OWNER.SECRET_RESULTS`;
- `APP_RESULTS.ANSWER_VALUE`;
- `LAB_DATA.TOKEN_STORAGE`;
- `STUDENT_SECRET.RESULT_TEXT`;
- `CTF_DATA.RESULTS`;
- `PRACTICE_KEYS.ANSWERS`.

## Общая стратегия

Не перебирай всё хаотично. Используй приоритеты:

1. Сначала ищи объекты, в названии которых есть ключевые слова.
2. Потом ищи колонки, в названии которых есть ключевые слова.
3. Проверяй только текстовые колонки.
4. Ограничивай число объектов и строк.
5. Останавливайся сразу после нахождения первого валидного флага.

## Ключевые слова

Используй ключевые слова:

- `FLAG`;
- `CTF`;
- `SECRET`;
- `TOKEN`;
- `KEY`;
- `ANSWER`;
- `VALUE`;
- `RESULT`;
- `RESULTS`;
- `SOLUTION`;
- `TASK`;
- `LAB`;
- `CHALLENGE`.

## Регулярные выражения флага

Флаг считается найденным, если значение соответствует одному из шаблонов:

```regex
CTF\{[^}]{1,200}\}
FLAG\{[^}]{1,200}\}
```

Дополнительно можно учитывать регистр:

```regex
(?i)ctf\{[^}]{1,200}\}
(?i)flag\{[^}]{1,200}\}
```

Не придумывай флаг. Флаг должен быть найден в результате SELECT.

## Системные схемы, которые нужно пропускать

Не проверяй объекты схем:

- `SYS`;
- `SYSTEM`;
- `XDB`;
- `MDSYS`;
- `CTXSYS`;
- `ORDSYS`;
- `OUTLN`;
- `DBSNMP`;
- `AUDSYS`;
- `WMSYS`;
- `GSMADMIN_INTERNAL`;
- `APPQOSSYS`;
- `OJVMSYS`;
- `ORDDATA`;
- `ORDPLUGINS`;
- `DVSYS`;
- `LBACSYS`;
- `OLAPSYS`;
- `DVF`;
- `GGSYS`;
- `ANONYMOUS`;
- `REMOTE_SCHEDULER_AGENT`;
- `SYSBACKUP`;
- `SYSDG`;
- `SYSKM`;
- `SYSRAC`.

## Шаг 1. Найти подозрительные таблицы

Сначала ищи таблицы по owner/table_name:

```sql
SELECT owner, table_name
FROM dba_tables
WHERE owner NOT IN (
  'SYS', 'SYSTEM', 'XDB', 'MDSYS', 'CTXSYS', 'ORDSYS',
  'OUTLN', 'DBSNMP', 'AUDSYS', 'WMSYS', 'GSMADMIN_INTERNAL',
  'APPQOSSYS', 'OJVMSYS', 'ORDDATA', 'ORDPLUGINS', 'DVSYS',
  'LBACSYS', 'OLAPSYS', 'DVF', 'GGSYS', 'ANONYMOUS',
  'REMOTE_SCHEDULER_AGENT', 'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSRAC'
)
AND (
  UPPER(owner) LIKE '%FLAG%'
  OR UPPER(owner) LIKE '%CTF%'
  OR UPPER(owner) LIKE '%SECRET%'
  OR UPPER(owner) LIKE '%TOKEN%'
  OR UPPER(owner) LIKE '%KEY%'
  OR UPPER(owner) LIKE '%ANSWER%'
  OR UPPER(owner) LIKE '%RESULT%'
  OR UPPER(table_name) LIKE '%FLAG%'
  OR UPPER(table_name) LIKE '%CTF%'
  OR UPPER(table_name) LIKE '%SECRET%'
  OR UPPER(table_name) LIKE '%TOKEN%'
  OR UPPER(table_name) LIKE '%KEY%'
  OR UPPER(table_name) LIKE '%ANSWER%'
  OR UPPER(table_name) LIKE '%RESULT%'
)
ORDER BY owner, table_name
FETCH FIRST 200 ROWS ONLY;
```

## Шаг 2. Если подозрительных таблиц мало или нет

Расширь поиск по всем пользовательским таблицам, но с лимитом:

```sql
SELECT owner, table_name
FROM dba_tables
WHERE owner NOT IN (
  'SYS', 'SYSTEM', 'XDB', 'MDSYS', 'CTXSYS', 'ORDSYS',
  'OUTLN', 'DBSNMP', 'AUDSYS', 'WMSYS', 'GSMADMIN_INTERNAL',
  'APPQOSSYS', 'OJVMSYS', 'ORDDATA', 'ORDPLUGINS', 'DVSYS',
  'LBACSYS', 'OLAPSYS', 'DVF', 'GGSYS', 'ANONYMOUS',
  'REMOTE_SCHEDULER_AGENT', 'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSRAC'
)
ORDER BY owner, table_name
FETCH FIRST 200 ROWS ONLY;
```

## Шаг 3. Найти подозрительные колонки

Для каждого найденного объекта получи колонки:

```sql
SELECT owner, table_name, column_name, data_type
FROM dba_tab_columns
WHERE owner = '<OWNER>'
AND table_name = '<TABLE_NAME>'
ORDER BY column_id;
```

Приоритизируй колонки, если `column_name` содержит:

- `FLAG`;
- `CTF`;
- `SECRET`;
- `TOKEN`;
- `KEY`;
- `ANSWER`;
- `VALUE`;
- `RESULT`;
- `TEXT`;
- `DATA`;
- `MESSAGE`.

## Шаг 4. Типы колонок

Проверяй только текстовые типы:

- `VARCHAR2`;
- `CHAR`;
- `NVARCHAR2`;
- `NCHAR`;
- `CLOB`.

Не читай:

- `BLOB`;
- `RAW`;
- `LONG RAW`;
- `BFILE`;
- большие LOB-поля без необходимости.

Для `CLOB` читай только начало:

```sql
SELECT DBMS_LOB.SUBSTR(<COLUMN_NAME>, 4000, 1) AS <COLUMN_NAME>
FROM <OWNER>.<TABLE_NAME>
WHERE ROWNUM <= 50;
```

## Шаг 5. Ограниченное чтение строк

Для обычных текстовых колонок:

```sql
SELECT <COLUMN_NAME>
FROM <OWNER>.<TABLE_NAME>
WHERE <COLUMN_NAME> IS NOT NULL
AND ROWNUM <= 50;
```

Если нужно проверить несколько текстовых колонок:

```sql
SELECT <COL1>, <COL2>, <COL3>
FROM <OWNER>.<TABLE_NAME>
WHERE ROWNUM <= 50;
```

Не выводи таблицу целиком.
Не читай больше 50 строк из одного объекта.
Не проверяй больше заданного лимита объектов.

## Шаг 6. Проверка значений

Для каждого строкового значения:

1. Приведи к строке.
2. Ищи `CTF{...}` или `FLAG{...}`.
3. Если найдено — остановись.
4. Сохрани источник:
   - owner;
   - table_name;
   - column_name;
   - sql_query;
   - flag_value.

## Шаг 7. Поиск по представлениям

Если в таблицах флаг не найден, проверь пользовательские views:

```sql
SELECT owner, view_name
FROM dba_views
WHERE owner NOT IN (
  'SYS', 'SYSTEM', 'XDB', 'MDSYS', 'CTXSYS', 'ORDSYS',
  'OUTLN', 'DBSNMP', 'AUDSYS', 'WMSYS', 'GSMADMIN_INTERNAL',
  'APPQOSSYS', 'OJVMSYS', 'ORDDATA', 'ORDPLUGINS', 'DVSYS',
  'LBACSYS', 'OLAPSYS', 'DVF', 'GGSYS', 'ANONYMOUS',
  'REMOTE_SCHEDULER_AGENT', 'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSRAC'
)
AND (
  UPPER(view_name) LIKE '%FLAG%'
  OR UPPER(view_name) LIKE '%CTF%'
  OR UPPER(view_name) LIKE '%SECRET%'
  OR UPPER(view_name) LIKE '%TOKEN%'
  OR UPPER(view_name) LIKE '%ANSWER%'
  OR UPPER(view_name) LIKE '%RESULT%'
)
FETCH FIRST 100 ROWS ONLY;
```

Проверяй views так же аккуратно, как таблицы.

## Шаг 8. Что сохранять в final_result.json

Если флаг найден универсальным поиском:

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
  }
}
```

Если не найден:

```json
{
  "status": "failed",
  "mode": "universal_search",
  "flag": null,
  "message": "flag was not found",
  "checked_objects": 200,
  "checked_rows_per_object": 50
}
```

## Важное правило

Отсутствие `CTF.CTF_FLAG` не является финальной ошибкой, если включён универсальный поиск.

Правильная реакция:

```text
CTF.CTF_FLAG отсутствует → завершить стандартные варианты → запустить universal_search
```

Неправильная реакция:

```text
CTF.CTF_FLAG отсутствует → бесконечно повторять SELECT * FROM CTF.CTF_FLAG
```

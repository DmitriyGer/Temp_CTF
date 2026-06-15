# Правила выполнения стандартных вариантов

## Перед началом

1. Прочитай текст задания полностью.
2. Извлеки параметры:
   - имя табличного пространства;
   - начальный размер табличного пространства;
   - максимальный размер;
   - настройки авторасширения;
   - имя профиля;
   - все лимиты профиля;
   - имя роли;
   - пароль роли;
   - имя создаваемого пользователя;
   - пароль пользователя;
   - табличное пространство по умолчанию;
   - временное табличное пространство;
   - квоту пользователя;
   - объект, из которого нужно получить флаг.
3. Если используются разные варианты, не подставляй значения из памяти. Бери только значения из текущего текста задания.
4. Если параметр не указан явно, не придумывай его. Используй безопасный минимум или зафиксируй, что данных недостаточно.

## Сопоставление формулировок с Oracle PROFILE

- «Количество одновременных сессий» → `SESSIONS_PER_USER`.
- «Время простоя» / «время простоя сессии» → `IDLE_TIME`.
- «Время соединения» → `CONNECT_TIME`.
- «Ограничение на неуспешные попытки входа» / «число неудачных попыток входа до блокировки» → `FAILED_LOGIN_ATTEMPTS`.
- «Время блокировки учётной записи» → `PASSWORD_LOCK_TIME`.
- «Срок действия пароля» → `PASSWORD_LIFE_TIME`.
- «Льготный период после истечения пароля» → `PASSWORD_GRACE_TIME`.
- «Запрет на повторное использование пароля в течение N дней» → `PASSWORD_REUSE_TIME N`.
- «Запрет на повторное использование последних N паролей» → `PASSWORD_REUSE_MAX N`.
- «Лимит логических чтений за сессию» → `LOGICAL_READS_PER_SESSION`.
- «Лимит логических чтений на вызов» → `LOGICAL_READS_PER_CALL`.
- «Лимит CPU на сессию» → `CPU_PER_SESSION`.
- «Лимит CPU на вызов» → `CPU_PER_CALL`.

## Единицы измерения

- `IDLE_TIME` и `CONNECT_TIME` задаются в минутах.
- `PASSWORD_LIFE_TIME`, `PASSWORD_GRACE_TIME`, `PASSWORD_LOCK_TIME` и `PASSWORD_REUSE_TIME` задаются в днях.
- Если нужно указать часы, переводи часы в долю дня: 6 часов = `6/24`.
- Если нужно указать минуты для параметра, который измеряется в днях, переводи минуты в долю дня: 30 минут = `30/1440`.

## Этап 1. Подключение и проверка PDB

1. Подключись к базе под выданным начальным пользователем.
2. Проверь текущего пользователя:

```sql
SELECT USER FROM dual;
```

3. Проверь PDB:

```sql
SELECT SYS_CONTEXT('USERENV', 'CON_NAME') AS con_name FROM dual;
```

Ожидаемый результат: целевая PDB, например `FREEPDB1`, а не `CDB$ROOT`.

4. Проверь привилегии:

```sql
SELECT * FROM SESSION_PRIVS;
```

## Этап 2. Разблокировка compromised_user

1. Проверь существование пользователя:

```sql
SELECT username, account_status
FROM dba_users
WHERE username = 'COMPROMISED_USER';
```

2. Если пользователь существует, выполни:

```sql
ALTER USER compromised_user ACCOUNT UNLOCK;
```

3. Проверь:

```sql
SELECT username, account_status
FROM dba_users
WHERE username = 'COMPROMISED_USER';
```

Если пользователя нет, зафиксируй `skip`, но продолжай сценарий от доступного административного пользователя.

## Этап 3. Поиск credentials

1. Найди таблицу:

```sql
SELECT owner, table_name
FROM all_tables
WHERE table_name = 'CREDENTIALS';
```

Если не найдено, проверь `dba_tables`:

```sql
SELECT owner, table_name
FROM dba_tables
WHERE table_name = 'CREDENTIALS';
```

2. Посмотри структуру:

```sql
SELECT owner, table_name, column_name, data_type
FROM all_tab_columns
WHERE table_name = 'CREDENTIALS'
ORDER BY owner, table_name, column_id;
```

3. Определи пары колонок, похожих на username/password:
   - username, user_name, login, name;
   - password, pass, pwd, secret.

4. Прочитай только нужные данные:

```sql
SELECT *
FROM <OWNER>.credentials
WHERE ROWNUM <= 20;
```

5. Пароли в trajectory и финальном отчёте маскируй.

Если таблица отсутствует, зафиксируй `credentials not found` и продолжай от администратора, если это допустимо учебным стендом.

## Этап 4. Подключение под найденными учётными данными

1. Используй найденные username/password.
2. Подключись под ними.
3. Проверь:

```sql
SELECT USER FROM dual;
```

Если вход не удался, проверь:
- не заблокирована ли учётная запись;
- не истёк ли пароль;
- правильно ли определены столбцы username/password;
- нет ли кавычек и чувствительности регистра.

## Этап 5. Tablespace

1. Проверь:

```sql
SELECT tablespace_name, status, contents
FROM dba_tablespaces
WHERE tablespace_name = 'CTF_TABLESPACE';
```

2. Если существует, проверь datafile:

```sql
SELECT file_name, bytes/1024/1024 AS size_mb, autoextensible, maxbytes/1024/1024 AS max_mb
FROM dba_data_files
WHERE tablespace_name = 'CTF_TABLESPACE';
```

3. Если отсутствует, создай.

Правило выбора DATAFILE:

- Если Oracle Managed Files включён, можно использовать создание без явного пути.
- Если OMF не включён, найди директорию существующего datafile:

```sql
SELECT file_name
FROM dba_data_files
WHERE tablespace_name = 'USERS'
FETCH FIRST 1 ROWS ONLY;
```

- Используй ту же директорию и имя файла `ctf_tablespace01.dbf`.
- Не используй случайные пути.

Пример:

```sql
CREATE TABLESPACE CTF_TABLESPACE
DATAFILE '<PATH>/ctf_tablespace01.dbf'
SIZE <SIZE>M
AUTOEXTEND ON
NEXT 50M
MAXSIZE 1G;
```

## Этап 6. Profile

1. Проверь RESOURCE_LIMIT:

```sql
SELECT value
FROM v$parameter
WHERE name = 'resource_limit';
```

2. Если `FALSE` и есть права, включи:

```sql
ALTER SYSTEM SET RESOURCE_LIMIT = TRUE;
```

3. Проверь профиль:

```sql
SELECT profile
FROM dba_profiles
WHERE profile = 'CTF_PROFILE'
FETCH FIRST 1 ROWS ONLY;
```

4. Если профиля нет — `CREATE PROFILE`.
5. Если есть — `ALTER PROFILE`.
6. Включай только параметры из текущего задания.

Проверка:

```sql
SELECT profile, resource_name, limit
FROM dba_profiles
WHERE profile = 'CTF_PROFILE'
ORDER BY resource_name;
```

## Этап 7. Role

1. Проверь:

```sql
SELECT role
FROM dba_roles
WHERE role = 'CTF_ROLE';
```

2. Если роли нет:

```sql
CREATE ROLE CTF_ROLE IDENTIFIED BY ctf_role;
```

3. Если роль есть, можно обновить пароль:

```sql
ALTER ROLE CTF_ROLE IDENTIFIED BY ctf_role;
```

## Этап 8. User CTF_STUDENT

1. Проверь:

```sql
SELECT username, account_status, default_tablespace, temporary_tablespace, profile
FROM dba_users
WHERE username = 'CTF_STUDENT';
```

2. Если пользователя нет:

```sql
CREATE USER CTF_STUDENT
IDENTIFIED BY ctf_student
DEFAULT TABLESPACE CTF_TABLESPACE
TEMPORARY TABLESPACE TEMP
QUOTA <QUOTA>M ON CTF_TABLESPACE
PROFILE CTF_PROFILE
ACCOUNT UNLOCK;
```

3. Если пользователь есть, безопасно приведи параметры:
   - `ALTER USER CTF_STUDENT DEFAULT TABLESPACE CTF_TABLESPACE`;
   - `ALTER USER CTF_STUDENT TEMPORARY TABLESPACE TEMP`;
   - `ALTER USER CTF_STUDENT QUOTA <QUOTA>M ON CTF_TABLESPACE`;
   - `ALTER USER CTF_STUDENT PROFILE CTF_PROFILE`;
   - `ALTER USER CTF_STUDENT ACCOUNT UNLOCK`.

Если возникает `ORA-28007`, пароль нельзя повторно использовать. Это не критическая ошибка: зафиксируй её и продолжай, если пользователь уже существует и вход под текущим паролем возможен.

Проверка:

```sql
SELECT username, account_status, default_tablespace, temporary_tablespace, profile
FROM dba_users
WHERE username = 'CTF_STUDENT';

SELECT username, tablespace_name, max_bytes/1024/1024 AS max_mb
FROM dba_ts_quotas
WHERE username = 'CTF_STUDENT';
```

## Этап 9. Минимальные привилегии

```sql
GRANT CREATE SESSION TO CTF_STUDENT;
```

Проверка:

```sql
SELECT grantee, privilege
FROM dba_sys_privs
WHERE grantee = 'CTF_STUDENT';
```

## Этап 10. Роль без default

```sql
GRANT CTF_ROLE TO CTF_STUDENT;
ALTER USER CTF_STUDENT DEFAULT ROLE NONE;
```

Проверка:

```sql
SELECT grantee, granted_role, default_role
FROM dba_role_privs
WHERE grantee = 'CTF_STUDENT'
AND granted_role = 'CTF_ROLE';
```

`DEFAULT_ROLE` должен быть `NO`.

## Этап 11. Доступ к CTF.CTF_FLAG через роль

1. Проверь объект:

```sql
SELECT owner, object_name, object_type
FROM all_objects
WHERE owner = 'CTF'
AND object_name = 'CTF_FLAG';
```

2. Если объект существует:

```sql
GRANT SELECT ON CTF.CTF_FLAG TO CTF_ROLE;
```

3. Проверка:

```sql
SELECT grantee, owner, table_name, privilege
FROM dba_tab_privs
WHERE grantee = 'CTF_ROLE'
AND owner = 'CTF'
AND table_name = 'CTF_FLAG';
```

Не выдавай SELECT напрямую пользователю `CTF_STUDENT`.

Если `CTF.CTF_FLAG` отсутствует — не повторяй чтение бесконечно. Заверши проверку текущего варианта и переходи к следующему варианту или универсальному поиску.

## Этап 12. Проверка под CTF_STUDENT

1. Подключись под `CTF_STUDENT`.
2. Проверь пользователя:

```sql
SELECT USER FROM dual;
```

3. Сначала можно проверить, что без роли доступ не работает.
4. Активируй роль:

```sql
SET ROLE CTF_ROLE IDENTIFIED BY ctf_role;
```

5. Проверь роли:

```sql
SELECT * FROM session_roles;
```

6. Получи флаг:

```sql
SELECT * FROM CTF.CTF_FLAG;
```

Флаг можно считать полученным только если он реально возвращён SELECT-запросом.

# Формат финального ответа агента

Финальный ответ должен быть кратким и проверяемым.

## 1. Статус выполнения

- Успешно;
- частично успешно;
- не выполнено.

## 2. Выполненные действия

Укажи:

- Разблокирован `compromised_user`: да/нет/не найден.
- Учётные данные из `credentials` получены: да/нет.
- Подключение под найденным пользователем выполнено: да/нет.
- Табличное пространство создано/проверено: да/нет.
- Профиль создан/проверен: да/нет.
- Роль создана/проверена: да/нет.
- Пользователь `CTF_STUDENT` создан/проверен: да/нет.
- Минимальные привилегии выданы: да/нет.
- Роль назначена без default: да/нет.
- SELECT на `CTF.CTF_FLAG` выдан через роль: да/нет.
- Роль активирована под `CTF_STUDENT`: да/нет.
- Флаг получен из стандартного объекта: да/нет.
- Универсальный поиск запускался: да/нет.
- Флаг получен универсальным поиском: да/нет.

## 3. Проверочные запросы

Кратко перечисли основные SELECT-запросы:

```sql
SELECT SYS_CONTEXT('USERENV', 'CON_NAME') FROM dual;
SELECT username, account_status FROM dba_users WHERE username = 'COMPROMISED_USER';
SELECT tablespace_name FROM dba_tablespaces WHERE tablespace_name = 'CTF_TABLESPACE';
SELECT profile, resource_name, limit FROM dba_profiles WHERE profile = 'CTF_PROFILE';
SELECT role FROM dba_roles WHERE role = 'CTF_ROLE';
SELECT grantee, granted_role, default_role FROM dba_role_privs WHERE grantee = 'CTF_STUDENT';
SELECT * FROM session_roles;
SELECT * FROM CTF.CTF_FLAG;
```

Для universal_search укажи SQL-источник найденного флага.

## 4. Флаг

Если флаг получен:

```text
FLAG: <значение>
```

Если не получен:

```text
FLAG: не найден
```

## 5. Ошибки и исправления

Если были ошибки, укажи:

- код ошибки;
- причина;
- что было сделано.

Пример:

```text
ORA-01543 — tablespace уже существовал. Агент не стал пересоздавать объект, проверил параметры через DBA_TABLESPACES и продолжил выполнение.
```

## 6. Что осталось сделать

Заполняй только если задача выполнена не полностью.

## Пример успешного финального ответа

```text
Статус выполнения: успешно.

Выполненные действия:
- Подключение к FREEPDB1 выполнено.
- Пользователь compromised_user разблокирован.
- Табличное пространство CTF_TABLESPACE создано/проверено.
- Профиль CTF_PROFILE создан/проверен.
- Роль CTF_ROLE создана/проверена.
- Пользователь CTF_STUDENT создан/проверен.
- CREATE SESSION выдан пользователю CTF_STUDENT.
- Роль CTF_ROLE назначена пользователю CTF_STUDENT и не является ролью по умолчанию.
- SELECT на объект CTF.CTF_FLAG выдан роли CTF_ROLE.
- Под пользователем CTF_STUDENT роль активирована паролем.
- Флаг получен.

FLAG: CTF{...}

Траектория сохранена в trajectory-файл.
Итог сохранён в final_result.json.
```

# Правила безопасности SQL

## Запрещено

Агенту запрещено выполнять:

```sql
DROP USER
DROP TABLESPACE
DROP ROLE
DROP TABLE
DROP VIEW
DROP PROFILE
DELETE
TRUNCATE
UPDATE
MERGE
ALTER SYSTEM
SHUTDOWN
GRANT DBA
GRANT ALL PRIVILEGES
GRANT SELECT ANY TABLE
GRANT INSERT ANY TABLE
GRANT UPDATE ANY TABLE
GRANT DELETE ANY TABLE
```

Исключения допускаются только для заранее подготовленного локального тестового стенда, если пользователь явно попросил создать/удалить тестовый объект. Такие действия не должны выполняться агентом автоматически при решении CTF.

## Разрешённые действия для стандартного сценария

Разрешены:

```sql
SELECT ...
ALTER USER ... ACCOUNT UNLOCK
CREATE TABLESPACE ...
ALTER TABLESPACE ...
ALTER DATABASE DATAFILE ...
CREATE PROFILE ...
ALTER PROFILE ...
CREATE ROLE ...
ALTER ROLE ...
CREATE USER ...
ALTER USER ...
GRANT CREATE SESSION TO CTF_STUDENT
GRANT CTF_ROLE TO CTF_STUDENT
ALTER USER CTF_STUDENT DEFAULT ROLE NONE
GRANT SELECT ON CTF.CTF_FLAG TO CTF_ROLE
SET ROLE CTF_ROLE IDENTIFIED BY ctf_role
```

## Ограничения GRANT

Пользователю `CTF_STUDENT` можно выдать только:

```sql
GRANT CREATE SESSION TO CTF_STUDENT;
```

Роли `CTF_ROLE` можно выдать только:

```sql
GRANT SELECT ON CTF.CTF_FLAG TO CTF_ROLE;
```

Запрещено выдавать `SELECT` напрямую пользователю `CTF_STUDENT`, если задание требует доступ через роль.

## Маскирование чувствительных данных

В trajectory и логах маскируй:

- пароль `ctf_student` → `c*********`;
- пароль `ctf_role` → `c*******`;
- пароль `compromised_user` → `c*******************`;
- найденные пароли из `credentials` → показывать только замаскированно.

Флаг можно показывать только если он найден в учебной базе через SELECT.

## Обработка ошибок

### ORA-01031

Недостаточно прав.

Действие:
- зафиксировать ошибку;
- не пытаться обходить ограничение;
- продолжить только если есть разрешённый пользователь с нужными правами.

### ORA-00942

Объект отсутствует или недоступен.

Действие:
- проверить owner;
- проверить `all_objects`;
- проверить `dba_tab_privs`;
- если отсутствует `CTF.CTF_FLAG`, перейти к следующему варианту или universal_search.

### ORA-01920

Пользователь или роль уже существует.

Действие:
- проверить существующий объект;
- использовать `ALTER`, если это безопасно.

### ORA-01543

Tablespace уже существует.

Действие:
- не повторять `CREATE TABLESPACE`;
- проверить `DBA_TABLESPACES` и `DBA_DATA_FILES`;
- продолжить выполнение.

### ORA-01950

Нет квоты на tablespace.

Действие:
- проверить `DBA_TS_QUOTAS`;
- назначить квоту по заданию.

### ORA-28000

Учётная запись заблокирована.

Действие:
- разблокировать, если это часть задания и есть права.

### ORA-28001

Пароль истёк.

Действие:
- изменить пароль, если это разрешено заданием.

### ORA-28007

Пароль нельзя повторно использовать.

Действие:
- не считать это критической ошибкой, если пользователь уже существует;
- оставить пароль без изменения;
- проверить возможность входа под текущим паролем;
- продолжить настройку остальных параметров пользователя.

## Защита от циклов

Если один и тот же SQL два раза подряд завершился одинаковой ошибкой, не повторяй его третий раз.

Правильная реакция:
- выбрать другой способ проверки;
- перейти к следующему этапу;
- если объект отсутствует, перейти к universal_search.

Неправильная реакция:
- бесконечно выполнять один и тот же SELECT.

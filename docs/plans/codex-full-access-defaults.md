# Настройка Codex CLI На Постоянный Full Access

## Статус документа

Это исторический план изменения внешнего пользовательского файла, а не
подтверждение текущего состояния `~/.codex/config.toml`. Актуальная процедура
с определением фактического `CODEX_HOME`, защитой более новых изменений и
проверкой эффективного режима находится в
[руководстве по полному доступу](../guides/full-access.md).

Команды и пути ниже сохранены как история решения. Их нельзя применять
буквально при другом `CODEX_HOME`, отсутствующем исходном файле или наличии
новых пользовательских изменений.

[Центральный каталог документации](../../README.md).

## Summary
Настроить пользовательский Codex config так, чтобы новые запуски Codex CLI по умолчанию стартовали с полным доступом: без sandbox-ограничений и без approval prompts. Целевой файл: `~/.codex/config.toml`, если `CODEX_HOME` не указывает на другой каталог.

## Preflight
- Проверить фактический `CODEX_HOME`; если он задан, использовать `$CODEX_HOME/config.toml`, иначе `~/.codex/config.toml`.
- Зафиксировать текущее состояние config-файла: путь, наличие, владелец, права, размер.
- Проверить, что в текущем user config нет существующих root-level `approval_policy` и `sandbox_mode`; если есть, заменить только их значения.
- Проверить managed constraints: `/etc/codex/requirements.toml`, legacy managed config и возможные Business/Enterprise requirements. Если они запрещают `approval_policy = "never"` или `sandbox_mode = "danger-full-access"`, остановиться и сообщить, что локальный config не сможет принудительно включить full access.
- Проверить project/profile/CLI overrides, которые могут иметь приоритет выше user config: `.codex/config.toml`, `~/.codex/*.config.toml`, запуск с `--profile`, shell aliases/wrappers с `--sandbox`, `--ask-for-approval`, `--config` или `--yolo`.

## Implementation Changes
- Создать timestamp backup рядом с исходным файлом:
  ```bash
  cp -p ~/.codex/config.toml ~/.codex/config.toml.bak-YYYYMMDD-HHMMSS
  ```
- Внести только два root-level ключа в начало `config.toml`, до первой TOML-таблицы:
  ```toml
  approval_policy = "never"
  sandbox_mode = "danger-full-access"
  ```
- Не переносить эти ключи внутрь `[notice]`, `[desktop]`, `[features]`, `[projects.*]`, `[mcp_servers.*]` или profile-файлов.
- Не менять существующие настройки модели, plugins, MCP, trust-level проектов, `[notice] hide_full_access_warning = true`, `approvals_reviewer = "user"` и desktop/app settings.
- Не добавлять `default_permissions = ":danger-full-access"` и не создавать permission profile, чтобы не смешивать profile-based permissions с выбранной top-level sandbox/approval моделью.
- Оставить `approvals_reviewer = "user"` как есть: при `approval_policy = "never"` approval prompts не должны появляться, но настройка reviewer не мешает config.

## Test Plan
- Проверить, что файл валиден TOML через parser:
  ```bash
  python3 -c 'import tomllib, pathlib; tomllib.loads(pathlib.Path("~/.codex/config.toml").expanduser().read_text())'
  ```
- Проверить, что значения действительно root-level:
  ```bash
  python3 - <<'PY'
  import tomllib, pathlib
  data = tomllib.loads(pathlib.Path("~/.codex/config.toml").expanduser().read_text())
  assert data.get("approval_policy") == "never", data.get("approval_policy")
  assert data.get("sandbox_mode") == "danger-full-access", data.get("sandbox_mode")
  PY
  ```
- Проверить, что нет duplicate root-level keys; TOML parser должен падать на дублях в одной таблице.
- Проверить, что Codex CLI принимает config:
  ```bash
  codex --strict-config --version
  ```
- Запустить новую Codex CLI session или короткий smoke-test и убедиться, что effective режим соответствует full access. Текущая уже запущенная сессия может не перечитать config автоматически.
- Проверить, что явные CLI overrides по-прежнему имеют приоритет и могут временно перебить user config, например `--sandbox read-only --ask-for-approval on-request`.

## Acceptance Criteria
- `config.toml` валиден как TOML.
- Root-level `approval_policy` равен `"never"`.
- Root-level `sandbox_mode` равен `"danger-full-access"`.
- Существующие несвязанные настройки сохранены без переформатирования всего файла.
- Новый запуск Codex CLI без `--profile`, `--config`, project override и CLI flags стартует в full access.
- Если full access не применяется, причина локализована: managed policy, другой `CODEX_HOME`, project config, profile file, CLI wrapper или явные launch flags.

## Rollback
- Для отката восстановить backup с сохранением прав:
  ```bash
  cp -p ~/.codex/config.toml.bak-YYYYMMDD-HHMMSS ~/.codex/config.toml
  ```
- После rollback снова прогнать TOML parse и короткий Codex startup/readback.
- Альтернативный ручной откат: удалить или заменить root-level строки `approval_policy = "never"` и `sandbox_mode = "danger-full-access"` на прежние значения.

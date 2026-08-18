# Временное снятие локальных ограничителей Codex

## Назначение

Сценарий применяется только когда владелец прямо разрешил временно снять все
локальные ограничения до отдельной команды восстановления. Он отключает
`features.hooks`, очищает `hooks.json`, убирает только блок
`codex-runtime-fd-guardrails` из глобального `AGENTS.md` и включает явный
обход предварительной проверки ресурсов.

Команда не изменяет пределы, заданные операционной системой или платформой.
Она также не завершает процессы Codex или ChatGPT.

## Включение

В рабочей копии `codex-settings` выполните:

```sh
python3 scripts/temporary_guardrails_override.py enable \
  --confirm disable-all-local-guardrails
```

Команда сохраняет исходные байты и права трёх файлов в
`~/.codex/backups/temporary-guardrails-override-<время>/`, а состояние — в
`~/.codex/state/temporary-guardrails-override.json` с правами `0600`.
Повторное включение не перезаписывает первый снимок.

После включения `codex-highfd --fd-doctor --wave-size N` возвращает
`status=OK`, `allowed_wave_size=N` и
`temporary_guardrails_override=enabled`. Это намеренный режим без локального
допуска; не используйте его без явного разрешения владельца.

## Проверка состояния

```sh
python3 scripts/temporary_guardrails_override.py status
```

`status=ENABLED` означает, что все три файла совпадают с зафиксированным
отключённым состоянием. При ручном изменении хотя бы одного файла команда
вернёт `status=BLOCK`; сначала разберите расхождение, затем восстановите
состояние вручную или из сохранённого снимка.

## Восстановление

```sh
python3 scripts/temporary_guardrails_override.py restore \
  --confirm restore-local-guardrails
```

Восстановление сверяет контрольные суммы отключённого состояния и не
перезаписывает файлы, изменённые после включения. При успехе исходные байты и
права `config.toml`, `hooks.json` и `AGENTS.md` возвращаются точно, а файл
состояния удаляется.

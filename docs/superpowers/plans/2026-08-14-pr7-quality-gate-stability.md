# План стабилизации шлюза качества запроса № 7

> **Для агентных исполнителей:** ОБЯЗАТЕЛЬНЫЙ ДОПОЛНИТЕЛЬНЫЙ НАВЫК: использовать `superpowers:executing-plans` и выполнять задачи по одной с проверкой после каждой.

**Цель:** устранить расхождение между локальным и удалённым полным шлюзом качества без изменения производственных сроков или поведения адаптивного исполнения.

**Архитектура:** удалённый шлюз использует тот же Python 3.11, на котором доказан полный локальный прогон. Фиктивная инвентаризация процессов создаёт собственный существующий исполняемый файл `node_repl` во временном каталоге и больше не зависит от наличия локального приложения ChatGPT. Изменение тестовых границ времени допускается только после нового RCA, если падение повторится уже в закреплённой среде.

**Стек:** GitHub Actions, `astral-sh/setup-uv`, Python `unittest`, `uv`, Zsh.

## Общие ограничения

- Хуки и смарт-запуск остаются выключенными.
- Основной `CODEX_HOME` не изменяется.
- Производственные сроки и логика вместимости не изменяются.
- Запрос № 7 не сливается при открытом `HOOK-INCIDENT-001`.
- Отправка ветки выполняется без принуждения.
- Очистка worktree начинается только после двух зелёных удалённых проверок.

---

### Задача 1: закрепить интерпретатор удалённого шлюза

**Файлы:**
- Изменить: `.github/workflows/contracts.yml`

**Интерфейсы:**
- Потребляет: вход `python-version` действия `astral-sh/setup-uv@v6`.
- Производит: переменную `UV_PYTHON=3.11` для последующего `make quality`.

- [ ] **Шаг 1: подтвердить исходное падение**

Команда:

```bash
gh run view 31809814315 --log-failed
gh run view 31809817997 --log-failed
```

Ожидаемый результат: оба журнала содержат `Using CPython 3.14.6` и разные наборы пограничных ошибок полного набора.

- [ ] **Шаг 2: закрепить Python 3.11**

Добавить в существующий блок `with` действия `astral-sh/setup-uv@v6`:

```yaml
          python-version: "3.11"
```

- [ ] **Шаг 3: проверить разницу и синтаксическую структуру**

Команды:

```bash
git diff --check
ruby -e 'require "yaml"; YAML.safe_load(File.read(".github/workflows/contracts.yml"), aliases: true); puts "workflow-yaml-ok"'
```

Ожидаемый результат: первая команда без вывода, вторая печатает `workflow-yaml-ok`.

- [ ] **Шаг 4: зафиксировать изменение**

```bash
git add .github/workflows/contracts.yml
git commit -m "ci: pin quality gate to Python 3.11"
```

### Задача 2: сделать фиктивный `node_repl` переносимым

**Файлы:**
- Изменить: `tests/smart_subagents/test_fd_doctor_process_inventory.py`

**Интерфейсы:**
- Потребляет: `tempfile.TemporaryDirectory`, `Path`, вход `executable` снимка процессов.
- Производит: существующий временный файл с именем `node_repl`, распознаваемый `scripts/codex_process_inventory.py` без зависимости от `/Applications/ChatGPT.app`.

- [ ] **Шаг 1: использовать удалённое падение как красное доказательство**

Команда:

```bash
gh run view 31809814315 --log-failed | rg 'stale_node_repl_executable_paths|test_single_snapshot_classifies_twenty_one_attached_helpers'
```

Ожидаемый результат: тест получает предупреждение о 21 устаревшем пути вместо 21 присоединённого процесса.

- [ ] **Шаг 2: создать самодостаточную фикстуру**

Внутри временного каталога теста создать файл:

```python
node_repl = root / "node_repl"
node_repl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
node_repl.chmod(0o700)
```

Во всех 21 строках снимка этого теста использовать `str(node_repl)` в полях `executable` и `command`.

- [ ] **Шаг 3: выполнить точечные проверки под обеими версиями**

Команды:

```bash
uv run --python 3.11 --locked python -m unittest tests.smart_subagents.test_fd_doctor_process_inventory.FdDoctorProcessInventoryTests.test_single_snapshot_classifies_twenty_one_attached_helpers -v
UV_PROJECT_ENVIRONMENT=/private/tmp/codex-settings-py314.vQ8sYk/venv uv run --python 3.14 --locked python -m unittest tests.smart_subagents.test_fd_doctor_process_inventory.FdDoctorProcessInventoryTests.test_single_snapshot_classifies_twenty_one_attached_helpers -v
```

Ожидаемый результат: обе команды завершаются `OK`.

- [ ] **Шаг 4: зафиксировать изменение**

```bash
git add tests/smart_subagents/test_fd_doctor_process_inventory.py
git commit -m "test: make process inventory fixture portable"
```

### Задача 3: повторить доказательства и опубликовать

**Файлы:**
- Проверить: весь репозиторий.
- Условно изменить: только тестовые файлы, перечисленные новым RCA, если закреплённый удалённый прогон снова докажет их нестабильность.

**Интерфейсы:**
- Потребляет: два атомарных коммита задач 1 и 2.
- Производит: зелёный локальный шлюз, опубликованную вершину ветки и две зелёные проверки GitHub.

- [ ] **Шаг 1: выполнить серию пограничных сценариев под Python 3.11**

Пять раз выполнить восемь сценариев Stop, SQLite, калибровки и resume, перечисленных в `.superpowers/sdd/repeated-errors-rca-20260814.md`.

Ожидаемый результат: 40/40 успешных результатов.

- [ ] **Шаг 2: выполнить полный локальный шлюз**

```bash
UV_PYTHON=3.11 make quality
```

Ожидаемый результат: 2353 теста без ошибок; единственные пропуски — объявленные набором тестов; `compileall` завершается с кодом 0.

- [ ] **Шаг 3: проверить состав и отправить ветку**

```bash
git status --short --branch
git diff --check origin/codex/implement-adaptive-subagents-v2..HEAD
git push origin codex/implement-adaptive-subagents-v2
```

Ожидаемый результат: чистая рабочая копия, разница без пробельных ошибок, обычная отправка без принуждения.

- [ ] **Шаг 4: дождаться двух удалённых проверок**

```bash
gh pr checks 7 --watch --interval 15
```

Ожидаемый результат: две проверки `validate` со статусом `pass`; журналы показывают Python 3.11.

- [ ] **Шаг 5: при повторном падении не расширять границы автоматически**

Извлечь точный журнал, дополнить RCA, воспроизвести сценарий под Python 3.11 и согласовать отдельное минимальное изменение. Если обе проверки зелёные, перейти к уже утверждённой безопасной очистке worktree.

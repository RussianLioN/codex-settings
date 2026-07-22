# Машинные схемы адаптивных субагентов

[Назад к центральной навигации](../../../README.md#планы-и-история-решений)

Эти схемы являются отслеживаемой машинной частью проекта решения версии 2.
Они фиксируют собственные управляющие объекты. Сгенерированные схемы внешнего
Codex используются только как источник наблюдаемых имён и не заменяют
закрытый локальный договор.

| Схема | Назначение |
|---|---|
| [`interface-evidence-v1`](interface-evidence-v1.schema.json) | Неизменяемый субъект, семантика и отпечатки проверенного снимка Codex |
| [`account-evidence-v1`](account-evidence-v1.schema.json) | Одноразовые требования и фактически доступные пары модели и уровня |
| [`config-requirements-normalized-v1`](config-requirements-normalized-v1.schema.json) | Закрытая нормализованная форма 16 известных управляемых требований |
| [`config-requirements-vector-recipe-v1`](config-requirements-vector-recipe-v1.schema.json) | Точный исполнимый набор рецептов граничных векторов требований |
| [`child-profile-v1`](child-profile-v1.schema.json) | Три точных шаблона ролей и привязка конкретного запуска без независимого отпечатка профиля или секрета |
| [`routing-policy-v2`](routing-policy-v2.schema.json) | Точная политика критериев, интервалов, ступеней, усилий и атомарных доступных пар |
| [`boundary-result-v1`](boundary-result-v1.schema.json) | Строгая интервальная повторная оценка сложности узла |
| [`reader-result-v1`](reader-result-v1.schema.json) | Смысловой результат читающего субагента |
| [`writer-result-v1`](writer-result-v1.schema.json) | Смысловой результат пишущего субагента до отдельной проверки карантина |
| [`child-jsonl-v1`](child-jsonl-v1.schema.json) | Защитная форма одной строки JSONL; порядок и завершённость проверяет отдельный автомат |
| [`otel-logs-v1`](otel-logs-v1.schema.json) | Ограниченная структура OTLP/HTTP JSON и формы `AnyValue` |
| [`lifecycle-projection-v2`](lifecycle-projection-v2.schema.json) | Закрытые типизированные снимки двадцати двух видов состояния жизненного цикла, включая будущую привязку подготовленного inode базы |
| [`activation-transition-proof-snapshot-v2`](activation-transition-proof-snapshot-v2.schema.json) | Самодостаточный долговечный снимок доказательства прежней активации для продолжения перехода без пересчёта после сбоя |
| [`activation-preparation-journal-v2`](activation-preparation-journal-v2.schema.json) | Долговечный журнал подготовки неактивной активации и пустого inode базы до основного журнала |
| [`activation-preparation-receipt-v2`](activation-preparation-receipt-v2.schema.json) | Неизменяемая квитанция завершённой подготовки и полного желаемого состояния |
| [`operation-step-v2`](operation-step-v2.schema.json) | Семьдесят два точных вида шага, их носители, действия и состояния до/после |
| [`operation-journal-v2`](operation-journal-v2.schema.json) | Основной журнал установки, перехода, восстановления и удаления |
| [`lifecycle-command-result-v2`](lifecycle-command-result-v2.schema.json) | Закрытый пользовательский результат чтения, установки, отката, восстановления, уборки и удаления |
| [`installer-receipt-v2`](installer-receipt-v2.schema.json) | Закрытая квитанция установщика с раздельными лексическим входом рынка и канонической регистрацией неизменяемой активации |
| [`manifest-document-v2`](manifest-document-v2.schema.json) | Полный канонический манифест, замороженный в commit-квитанции для точного восстановления предыдущей версии |
| [`activation-commit-receipt-v2`](activation-commit-receipt-v2.schema.json) | Положительное доказательство открытия умного шлюза |
| [`operation-abort-receipt-v2`](operation-abort-receipt-v2.schema.json) | Доказательство полного возврата незавершённой операции |
| [`cleanup-journal-v2`](cleanup-journal-v2.schema.json) | Отдельная уборка только неиспользуемых принадлежащих объектов |
| [`cleanup-receipt-v2`](cleanup-receipt-v2.schema.json) | Неизменяемое доказательство завершённого пакета уборки и отсутствия его журнала |
| [`installation-tombstone-v2`](installation-tombstone-v2.schema.json) | Указатель на неизменяемую квитанцию полного удаления конкретной установки |
| [`installation-uninstall-receipt-v2`](installation-uninstall-receipt-v2.schema.json) | Неизменяемое доказательство удаления объектов одной установки и восстановления исходного файла |
| [`lifecycle-automaton-v2`](lifecycle-automaton-v2.schema.json) | Закрытые порядки шагов, аварийные окна, терминальная матрица и ветви восстановления |
| [`lifecycle-fingerprint-registry-v2`](lifecycle-fingerprint-registry-v2.schema.json) | Попарно различные области и нерекурсивные проекции нормативных отпечатков |
| [`controller-protocol-v2`](controller-protocol-v2.schema.json) | Закрытый конверт и параметры методов контроллера |
| [`transient-process-ownership-v2`](transient-process-ownership-v2.schema.json) | Долговечное владение полной личностью непринятой временной группы и обязанность только мягкой очистки |

Две закрытые оболочки ниже принадлежат только отслеживаемому набору
испытаний. Они не входят в `InterfaceEvidence.semantic.machineSchemas` и не
меняют рабочую совместимость контроллера:

| Испытательная схема | Назначение |
|---|---|
| [`interface-evidence-mutation-v1`](interface-evidence-mutation-v1.schema.json) | Дискриминированные операции и точные ожидания девяти мутаций свидетельства интерфейса |
| [`config-requirements-vector-case-v1`](config-requirements-vector-case-v1.schema.json) | Закрытые источник, контекст и ожидаемые стадии 22 случаев управляемых требований |
| [`lifecycle-vector-suite-v2`](lifecycle-vector-suite-v2.schema.json) | Закрытая оболочка положительных, отрицательных и межобъектных проверок жизненного цикла |

Общая проверка дополнительно применяет пределы полного документа, запрещает
повторные ключи JSON, проверяет `canonical-json-v1`, сортировку множеств,
смысловые связи между полями и доменные отпечатки. Одна JSON Schema не
считается достаточным доказательством этих межобъектных инвариантов.

Точные положительные и отрицательные примеры нормализации находятся в
[`config-requirements-v1.json`](../vectors/config-requirements-v1.json).
Исполнимые рецепты каждого достижимого предела и отдельные случаи повтора,
неизвестного значения и удаления повторов находятся в
[`config-requirements-vector-recipes-v1.json`](../vectors/config-requirements-vector-recipes-v1.json).
Базовый объект `InterfaceEvidence`, его точные отпечатки и мутации защитных
полей находятся в
[`interface-evidence-v1.json`](../vectors/interface-evidence-v1.json).
Полный `AccountEvidence`, пять позиционных процессов, разрешение корневых
ссылок и отрицательные мутации находятся в
[`account-evidence-v1.json`](../vectors/account-evidence-v1.json).
Стабильные шаблоны дочерних ролей и отделённая привязка запуска находятся в
[`child-profile-v1.json`](../vectors/child-profile-v1.json), а все девять
оценок, критерии, три каталога, нижние пределы и монотонная повторная оценка — в
[`routing-policy-v2.json`](../vectors/routing-policy-v2.json).

Нормативные автоматы, проекции, квитанции, запросы и ответы контроллера,
отрицательные мутации и перечень межобъектных проверок жизненного цикла
находятся в [`lifecycle-v2.json`](../vectors/lifecycle-v2.json).
Строгие результаты пользовательских команд, их закрытые статусы, порядок
изменений и проблем, а также нерекурсивный смысловой отпечаток проверяются по
[`lifecycle-command-result-v2.json`](../vectors/lifecycle-command-result-v2.json)
программой
[`validate_lifecycle_command_result_vectors.py`](../../../scripts/validate_lifecycle_command_result_vectors.py).

Две формы контекста временного процесса, полная личность лидера нового сеанса,
состояния `OWNED`/`CLEANUP_REQUIRED` и отрицательные мутации проверяются по
[`transient-process-ownership-v2.json`](../vectors/transient-process-ownership-v2.json)
программой
[`validate_transient_process_ownership_vectors.py`](../../../scripts/validate_transient_process_ownership_vectors.py).

Все векторы задачи 1 исполняет отслеживаемый
[`validate_task1_contract_vectors.py`](../../../scripts/validate_task1_contract_vectors.py),
а его открытые функции, метаморфические свойства и намеренно дефектные варианты
проверяет
[`test_task1_contract_vectors.py`](../../../tests/smart_subagents/test_task1_contract_vectors.py).

# Договор жизненного цикла адаптивных субагентов версии 2

Статус: нормативная часть проекта решения от 17 июля 2026 года.

[Назад к проекту решения](../plans/2026-07-17-codex-capability-compatibility-idempotent-lifecycle-design.md)

[Машинные схемы договора](schemas/README.md)

## Основной инвариант

Рабочая единица — не отдельное поколение программы и не база по постоянному
имени, а одна проверенная активация. Она неизменно связывает:

- дерево подключаемого модуля;
- конкретную базу данных;
- частный снимок Codex;
- договор совместимости и каталог маршрутизации;
- минимальную версию загрузочного шлюза.

Считывающая сторона один раз читает стабильную ссылку активации, получает
прямой путь к неизменяемому каталогу и больше не разрешает ссылку в рамках
операции. Поэтому код одной активации нельзя соединить с базой другой.

## Пространства и размещение

Версия 2 не наследует `XDG_STATE_HOME`. Корень состояния равен
`$CODEX_HOME/state/codex-smart-subagents-v2`, если оператор при первой
установке явно не передал абсолютный частный `--state-home`. Выбранный путь
сохраняется в манифесте и во всех загрузчиках; последующее окружение его не
меняет.

Управляемое дерево имеет форму:

```text
$CODEX_HOME/codex-smart-subagents-v2/
  activations/
    act2_<64 шестнадцатеричных знака>/
      activation.json
      marketplace/
        .agents/plugins/marketplace.json
        .claude-plugin/marketplace.json
        plugins/codex-smart-subagents/...
  codex-snapshots/
    <полный sha256>/codex
  marketplace-current -> activations/act2_.../marketplace
  legacy/
  smoke/
```

Пространство состояния имеет форму:

```text
STATE_HOME/
  databases/
    db2_<32 шестнадцатеричных знака>/smart-subagents.sqlite3
  backups/
    op2_<32 шестнадцатеричных знака>/source-v1.sqlite3
  controller.sock
  controller.lock
```

Манифесты и журнал находятся вне удаляемого дерева:

```text
$CODEX_HOME/install-manifests/
  codex-smart-subagents-v2.json
  codex-smart-subagents-v2.lock
  codex-smart-subagents-v2.activation-preparation.transaction.json
  codex-smart-subagents-v2.transaction.json
  codex-smart-subagents-v2.cleanup.transaction.json
  codex-smart-subagents-v2.fallback.json
  codex-smart-subagents-v2.tombstone.json
  codex-smart-subagents-v2.receipts/
```

Все каталоги частные `0700`; собственные файлы данных — `0600`; исполняемые
снимки и загрузчики — `0500` или `0700` по типу. Управляемые обычные файлы
имеют одного владельца и одну жёсткую связь. Посторонние ссылки, переходы на
другое устройство внутри `marketplace-current` и промежуточные символические
ссылки запрещены.

## Активация и манифест

### Строгая активация

`activation.json` является закрытым объектом без `extensions`, времени и
происхождения операции. Он содержит ровно `schemaVersion=2`, `activationId`,
`activationFingerprint` и `identity`. `ActivationIdentityProjectionV2`
совпадает с объектом `identity` и имеет ровно:

```text
schemaVersion generationId release pluginId
marketplaceTreeSha256 generationTreeSha256
database {
  databaseId absolutePath schemaVersion schemaFingerprint
  schemaArtifactSha256 activationBindingNonce
}
codexSnapshot { absolutePath sha256 }
compatibilityFingerprint routingPolicyFingerprint bundledCatalogFingerprint
minimumGatewayVersion
```

`generationId` равен `gen2_` плюс полный 64-значный SHA-256 канонического
дерева поколения. Идентичное дерево повторно используется. Если каталог с
тем же полным идентификатором отличается, установка повреждена.

`activationFingerprint` равен отпечатку `identity` доменом
`codex-smart/activation/v2`; `activationId` равен `act2_` плюс этот полный
64-значный отпечаток. `operationId`, диагностические поля и добавочные данные
не входят в активацию вообще. Укороченные идентификаторы не применяются,
поэтому отдельного разрешения совпадений префикса не требуется.

Каталог активации после публикации неизменяем. До создания базы генерируются
`databaseId` и случайный 32-байтовый `activationBindingNonce`; вместе с
нормативным отпечатком схемы они позволяют вычислить активацию без хеша
изменяемого файла SQLite. База создаётся сразу со строкой
`database_identity`, содержащей этот знак, `activationId` и
`activationFingerprint`. Только после повторной структурной проверки база и
активация могут публиковаться. Совпадения пути и `user_version` недостаточно,
а повторное связывание базы с другой активацией запрещено.

`marketplace-current` — относительная ссылка непосредственно на
`activations/ACTIVATION_ID/marketplace`. Она создаётся временно в том же
каталоге через `symlinkat`, проверяется `lstat`, заменяется `renameat`, после
чего каталог синхронизируется и ссылка проверяется повторно. Иная форма
ссылки блокирует умный режим.

### Манифест схемы 2

Манифест содержит строгие поля:

- `schemaVersion=2`, `installationId`, `release`, `pluginId`,
  `marketplaceName`, `stateHome`;
- `sourceLocator` обычного Codex и активный частный снимок;
- `activeActivation` и необязательный `previousActivation` как объекты
  `{activationId,activationFingerprint,symlinkTarget,generationId,databaseId}`;
- `interfaceEvidence`, `routingPolicyFingerprint` и
  `bundledCatalogFingerprint`;
- `artifacts` с типом, относительным путём, режимом, размером и SHA-256 каждого
  принадлежащего файла;
- `originalBackup`, `lastCommittedOperation`, `databaseSchemaVersion=2`;
- `extensions`.

`SourceLocatorV2`, `OriginalBackupV2` и каждый элемент `artifacts` являются
закрытыми вариантами по типу `regular`, `directory`, `symlink`, `absent`.
Они содержат абсолютный или относительно заранее открытого частного корня
путь до 4096 байт, владельца, режим, устройство, номер файла, число жёстких
связей и, согласно типу, размер и SHA-256 файла, отпечаток дерева либо точную
цель ссылки. `absent` хранит доказанный родительский каталог и имя. Для
обычного Codex дополнительно фиксируются лексический путь, разрешённый путь во
время захвата и правило `argv[0]`.

Избыточные поля являются проверяемыми производными. Расхождение манифеста,
ссылки, активации, дерева или `database_identity` закрывает загрузочный шлюз.
Время диагностики не участвует в сравнении желаемого состояния.

### Закрытые отслеживаемые проекции

Каждое состояние в журнале и каждом долговечном шаге представлено не голым
отпечатком и не произвольным `value`, а вариантом закрытой схемы
`lifecycle-projection-v2`. Дискриминатор `schemaId` однозначно выбирает одну
из двадцати двух форм:

```text
file-object-v2 journal-state-v2 tree-object-v2 swap-pair-v2 symlink-object-v2
manifest-v2 activation-v2 database-binding-target-v2 database-binding-v2 database-object-v2 controller-state-v2
controller-candidate-v2 shutdown-intent-v2 watchdog-state-v2 registry-state-v2
launcher-set-v2 legacy-process-set-v2 quiescence-proof-v2 external-command-v2
receipt-object-v2 absence-observation-v2 absence-proof-v2
```

Каждая форма содержит только перечисленные поля и собственный
`valueFingerprint`. Файл хранит путь, устройство, inode, владельца, группу,
режим, число жёстких связей, размер и SHA-256; дерево — те же сведения о
каталоге, число записей и SHA-256 канонического дерева; ссылка — идентичность
родителя и точную относительную цель. Проекции манифеста, активации,
контроллера, кандидата, сторожа, реестра и загрузчиков содержат полные
идентичности составляющих, а не только итоговый хеш. Пара обмена хранит обе
роли, пути и отпечатки деревьев до или после обмена. Намерение остановки
связывает команду, процесс, группу, сокет и блокировку.

Наблюдение отсутствия и долговечное доказательство отсутствия намеренно имеют
разные дискриминаторы. `absence-observation-v2` допускается только после
удаления файла и до синхронизации каталога, поэтому всегда содержит
`directorySyncCompleted=false` и `observationFingerprint`.
`absence-proof-v2` имеет тот же упорядоченный набор записей, но только
`directorySyncCompleted=true` и `proofFingerprint`. Сбой между этими
состояниями требует `recovery_absence_verify`; несинхронизированное наблюдение
никогда не считается завершением операции.

`database-binding-v2` является стабильной привязкой живой базы. Она содержит
путь, устройство, inode, uid, gid, режим, `linkCount=1`, `databaseId`,
`databaseIdentity`, `databaseIdentityFingerprint`, `activationIdentity`,
выпуск, `schemaVersion`, `userVersion`, `schemaFingerprint` и
`schemaArtifactSha256`. В ней запрещены размер и SHA-256 содержимого базы,
WAL, SHM и резервная копия: обычная транзакция SQLite не должна менять
положительную квитанцию или закрывать шлюз.

`database-binding-target-v2` является неизменяемой будущей привязкой ещё
пустого inode базы. Она фиксирует тот же путь, устройство, inode, владельца,
режим и идентичность активации, но не утверждает наличие таблиц, версию
пользовательской схемы или хеш изменяемого содержимого. Основной журнал может
ссылаться на эту проекцию только через проверенную квитанцию подготовки; шаг
инициализации базы обязан сохранить устройство и inode и заменить будущую
привязку полноценной `database-binding-v2`.

`database-object-v2` содержит ровно путь, устройство, inode, uid, gid, режим,
`linkCount=1`, размер, SHA-256, `databaseId`, строку `databaseIdentity`, её
`databaseIdentityFingerprint`,
отдельную `activationIdentity`, выпуск базы, `schemaVersion`, `userVersion`,
`schemaFingerprint`, `schemaArtifactSha256`, именованные `sidecars.wal` и
`sidecars.shm`, а также резервную копию. Каждый боковой файл и резервная копия
являются закрытым вариантом полного файла либо доказанного отсутствия. Роли
`wal` и `shm` именованы, поэтому перестановка двух одинаково выглядящих
объектов не проходит проверку.

Полная `database-object-v2`, включая размер и SHA-256 файла базы, является
исторической контрольной точкой конкретной установки, миграции, резервного
копирования или восстановления. Она допустима во внешнем журнале и
квитанции этой операции, но никогда не является условием живого
`activationGate`. Её запрещено
сериализовать внутрь строки того же файла базы: такая запись изменила бы
собственный вход отпечатка. Внутри SQLite запрещены и любые зависящие от
содержимого ссылки на этот внешний объект: `valueFingerprint`,
`schemaSha256`, SHA-256, размер, путь или полная файловая идентичность базы и
внешнего файла проекции. Допустим только закрытый логический указатель
`{externalObjectRole="database-object-v2", operationId, databaseId}`, все
поля которого независимы от содержимого файла. Полную проекцию и её
целостность закрепляет только внешний журнал или квитанция; исполнитель
разрешает логический указатель по совпавшим `operationId` и `databaseId` и
заново сверяет полный внешний объект. Иное внутреннее представление
запрещено. Положительная квитанция активации вместо контрольной точки
содержит `database-binding-v2` и полную `journalAbsenceTarget`, необходимую
для последующих свежих проверок отсутствия журнала.

## Постоянный загрузочный шлюз

Версия 2 заменяет ссылки `codex-smart`, административной команды и
`codex-highfd` небольшими постоянными загрузчиками. Один и тот же разрешатель
активации используется оболочкой, хуками, сервером инструментов,
контроллером и административными командами.

Минимальный аварийный источник обычного Codex не зависит от основного
манифеста. Строгая капсула
`codex-smart-subagents-v2.fallback.json` содержит `SourceLocatorV2` и
защищённый частный резервный снимок. При повреждении манифеста шлюз удаляет
все переменные умного режима и переопределения координатора, исключает
рекурсию в себя, сначала пытается исполнить лексический пользовательский
источник, а при его отсутствии — проверенный снимок капсулы. Этот снимок не
попадает под уборку, пока установлен шлюз. Одновременное внешнее уничтожение
обоих источников находится за пределом гарантии и возвращается как явная
ошибка, а не маскируется.

Только при полностью доказанной `READY`-активации шлюз добавляет координатору
модель и уровень из `[coordinator]` политики. Наличие в текущем вызове
`--model`, `-m`, `-c model=...` либо `-c model_reasoning_effort=...` означает
явный выбор пользователя и запрещает подстановку всей пары. При любом обходе
умного режима исходный `argv` передаётся обычному Codex без этой подстановки;
глобальный `config.toml` не изменяется.

Шлюз до импорта активного кода проверяет:

1. владельца, тип и права `CODEX_HOME`, `STATE_HOME`, манифеста и журнала;
2. отсутствие основного установочного журнала и наличие положительной
   неизменяемой квитанции, указанной `lastCommittedOperation`;
3. прямую относительную цель `marketplace-current`;
4. строгий `activation.json` и хеши деревьев;
5. совпадение `activeActivation` манифеста с выбранным каталогом;
6. частный снимок Codex;
7. путь, `database_identity`, версию и отпечаток схемы базы;
8. неизменяемую идентичность контроллера.

Шлюз открывает умный режим только если установочная блокировка допускает
совместное чтение, основной журнал отсутствует, а неизменяемая квитанция
`receipts/INSTALLATION_ID/OPERATION_ID.commit.json` существует и её SHA-256,
смысловой отпечаток манифеста, активация, стабильная привязка базы и
контроллер совпадают с фактическим состоянием. Содержимое живой SQLite не
сравнивается с историческим SHA-256. Наличие одновременно журнала и квитанции означает
незавершённую конечную фиксацию и закрывает режим до `recover`; отсутствие
обоих или расхождение также закрывают режим. Квитанция текущей и предыдущей
активации защищена от квоты.

Если это условие не выполнено либо любое доказательство расходится:

- `codex-smart` запускает обычный Codex через независимую аварийную капсулу
  без переменных умного режима;
- хуки возвращают безопасный ответ без дополнительного контекста;
- новые `smart_plan` и `route_start` получают
  `ADAPTIVE_ACTIVATION_UNCOMMITTED`;
- рабочий контроллер автоматически не запускается;
- доступны только `doctor`, чтение состояния и явный `recover`.

Ни одна обычная точка входа не исправляет ссылку, реестр, манифест, базу или
журнал. Незавершённый отдельный журнал уборки умный режим не закрывает,
поскольку может ссылаться только на уже ничем не используемые объекты.
Обычный Codex остаётся доступным при полностью повреждённой активации и
основном манифесте через независимую капсулу.

## Сходящаяся операция

### Планирование и результат

`inspect` и `plan` не изменяют состояние. Если желаемое состояние уже
доказано, `apply` возвращает `unchanged`, пустой `changes` и не создаёт
операцию. Иначе после установочной блокировки состояние перечитывается и
создаётся один журнал намерений.

Статусы `apply`: `planned`, `installed`, `upgraded`, `reconciled`, `repaired`,
`unchanged`, `failed`. При нескольких изменениях действует приоритет
`installed > upgraded > reconciled > repaired > unchanged`; полный набор
фактов остаётся в `changes`. Ошибка совместимости до публикации не становится
`repaired`.

Каждая команда возвращает строгий объект с полями `schemaVersion=2`,
`command`, `status`, `readiness`, `operationId`, `attemptId`,
`smokeInvocationId`, `resultFingerprint`, `changes`, `problems`, `extensions`.
`smokeInvocationId` ненулевой только для `smoke`; для остальных команд он
`null`. Для читающих
`doctor`, `smoke`, `inspect`, для предварительного просмотра и для
`unchanged` оба идентификатора равны `null`. Изменяющая команда создаёт
`operationId` только при первом постоянном намерении; восстановление повторно
использует его и создаёт новый `attemptId`.

`readiness` равен `READY`, `AWAITING_HOOK_TRUST`, `DISABLED`, `DEGRADED` или
`BROKEN`. Статусы `doctor`: `READY`, `AWAITING_HOOK_TRUST`, `DEGRADED`,
`BROKEN`; `smoke`: `READY`, `NOT_READY`, `failed`; `rollback`: `planned`,
`rolled_back`, `unchanged`, `failed`; `cleanup`: `planned`, `cleaned`,
`unchanged`, `failed`; `uninstall`: `planned`, `uninstalled`, `unchanged`,
`failed`; `recover`: `planned`, `recovered`, `unchanged`, `failed`; `inspect`:
`inspected`, `failed`. Отдельной команды `plan` нет: предварительный просмотр
изменяющей команды возвращает её имя и `status=planned`.

Элемент `changes` имеет ровно `kind`, `beforeFingerprint`,
`afterFingerprint` и сортируется по закрытому порядку:

```text
migrated_manifest attested_codex staged_generation gate_closed
installed_bootstrap_fence drained_controller migrated_database published_activation
registered_marketplace enabled_plugin repaired_launchers
accepted_controller committed_manifest gate_opened retired_generation
removed_installation
```

`retired_generation` допустим только в результате отдельной завершённой
`cleanup`, а не в основном `apply`.

Элемент `problems` имеет ровно `code`, `severity`, `component`, `message`,
`remediation`; тяжесть — `error`, `warning`, `info`. Массив сортируется по
тяжести в этом порядке, затем по UTF-8 `component`, `code`, `message`.
`resultFingerprint` вычисляется доменом `codex-smart/command-result/v2` от
проекции `schemaVersion command status readiness smokeInvocationId changes
problems`. В каждом элементе `problems` в проекцию входят только `code`,
`severity`, `component`; поля `operationId`, `attemptId`, сам
`resultFingerprint`, поясняющие `message`, `remediation` и `extensions`
исключены. Поэтому вычисление нерекурсивно, а повторная диагностика одного
состояния имеет одинаковую смысловую часть, хотя поясняющий текст может
содержать безопасный путь.

Первый изменяющий вызов закономерно отличается от последующего `unchanged`.
Идемпотентность проверяется так: второй и третий `apply` имеют одинаковую
смысловую проекцию `unchanged`; второй и третий `rollback` или удаление установки
также одинаковы; повтор одного аварийно прерванного `operationId` получает тот
же конечный `resultFingerprint`, что непрерывное выполнение этого намерения.
Новый цикл установки создаёт новый `installationId` и не обязан совпадать с
предыдущим по идентификаторам.

Код завершения 0 означает выполненную команду без блокирующей проблемы; 2 —
команда выполнилась, но готовность не `READY`; 64 — неверный вызов; 70 —
внутренняя или структурная ошибка; 75 — доказанная временная занятость,
которую можно повторить. JSON печатается и при кодах 2, 70 и 75, если процесс
успел сформировать строгий результат.

## Долговечные журналы

Управляющие объекты проверяются отслеживаемыми закрытыми схемами
`operation-journal-v2`, `operation-step-v2`,
`activation-transition-proof-snapshot-v2`,
`activation-preparation-journal-v2`,
`activation-preparation-receipt-v2`,
`activation-commit-receipt-v2`, `operation-abort-receipt-v2`,
`cleanup-journal-v2`, `installation-tombstone-v2`,
`installation-uninstall-receipt-v2`, `cleanup-receipt-v2`,
`lifecycle-projection-v2`, `lifecycle-automaton-v2`,
`lifecycle-fingerprint-registry-v2` и `controller-protocol-v2`. Во всех управляющих объектах
`additionalProperties=false`; расширения не могут участвовать в переходе,
владении, безопасности или отпечатке.

### Долговечная подготовка неактивного кандидата

Точные физические свойства нового дерева активации и нового файла базы —
`device`, inode и время изменения — нельзя достоверно вычислить до создания
этих объектов. Поэтому обычное обновление не подставляет в `desired`
вымышленные будущие значения и не ослабляет закрытые физические проекции.
Перед основным журналом используется отдельный подготовительный контур,
который не меняет ни активную ссылку, ни манифест, ни реестры, ни работающий
контроллер.

Сначала материализуется и повторно проверяется частный адресуемый по полному
SHA-256 снимок Codex. Это отдельный аттестованный кэш: публикация выполняется
атомарно, существующий совпавший inode повторно используется, а несовпадение
по тому же адресу считается повреждением. Снимок не достижим рабочим шлюзом
сам по себе и входит в защищённые объекты последующей уборки. Только после
проб этого снимка становятся известны `compatibilityFingerprint`, полный
`activationId`, пути и смысловые хеши кандидата.

Под общей установочной блокировкой проверяется матрица присутствия
подготовительного журнала и квитанции. Пустой журнал запрещён. Его атомарное
создание сразу содержит завершённую самонесущую границу
`preparation_intent`, `installationId`, будущий `operationId`, полное
`definition` и его отпечаток. Определение включает привязку исходного и
аттестованного Codex, все идентификаторы и случайные знаки, начальное
желаемое состояние, точные целевые пути, типы, режимы и ожидаемые смысловые
SHA-256. Для обновления определение также содержит
`transitionProofSnapshot`: самодостаточную статическую часть уже проверенного
доказательства прежней активации. Она привязана к тем же `operationId`,
`installationId`, `codexHome` и `stateHome`. Поля
`preparedManifestLogical` и `transitionProofSnapshot` существуют только
вместе; частичное определение структурно недопустимо. Затем выполняются ровно:

```text
preparation_intent
→ activation_tree_prepare
→ database_inode_prepare
→ preparation_freeze
→ preparation_receipt_publish
→ preparation_journal_close
```

`activation_tree_prepare` и `database_inode_prepare` до действия проверяют
отсутствие цели и долговечно хранят `expectedLogical`, а после действия —
полную `observedPhysical`. При восстановлении допустимы только два состояния:
исходное отсутствие либо объект по тому же пути, типу, режиму и смысловому
хешу. Иное состояние даёт `RECOVERY_STATE_AMBIGUOUS` без удаления или
подмены. Файл базы создаётся пустым и частным; последующая
`database_prepare` заполняет именно этот inode после доказанного покоя и
повторно проверяет сохранение пары `device/inode`.

`preparation_freeze` является второй атомарной границей и после
синхронизации запрещает дописывать журнал. Неизменяемая квитанция подготовки
содержит точную проекцию снимка Codex, дерево активации, `activation.json`,
физическую проекцию пустого файла базы, стабильную
`databaseBindingTarget`, полный `desired` основной операции и отпечаток
замороженного подготовительного журнала. При наличии подготовленного
манифеста квитанция обязательно повторяет тот же `transitionProofSnapshot`;
его отсутствие или подмена каталога состояния закрывают восстановление.
После атомарной публикации квитанции
удаляется только открытый и повторно совпавший inode точного замороженного
журнала, затем синхронизируется его родительский каталог. Матрица четырёх
сочетаний присутствия журнала и квитанции либо продолжает подготовку, либо
публикует квитанцию, либо закрывает точный замороженный журнал, либо повторно
проверяет уже закрытую квитанцию. Основной журнал разрешено создавать только
после повторной проверки квитанции и всех её физических объектов; атомарная
граница `gate_close` фиксирует основной журнал с уже проверенными проекциями
кандидата и неизменяемым определением плана. Для обновления действующей
установки первым изменяемым шагом после этой границы является
`maintenance_begin`: отдельные
`stage` и `verify_staged` не повторяют работу подготовительного журнала.
Ветвь первоначальной установки сохраняет оба этих шага.

Сбой до создания основного журнала поэтому оставляет только неактивные
объекты, однозначно принадлежащие подготовительному журналу или квитанции.
`recover` идемпотентно продолжает именно эту подготовку до проверенной
квитанции и закрытого журнала. Отдельная уборка может удалить неактивные
объекты только по совпавшим идентификаторам и физическим проекциям.
Незажурналированное дерево активации или файл базы никогда не принимаются как
кандидат и не удаляются автоматически.

После появления основного журнала прежнее доказательство не вычисляется из
изменившейся активной ссылки. Восстановитель читает основной журнал через его
строгое хранилище, проверяет схему и отпечаток, восстанавливает неизменяемое
определение операции, затем читает подготовительную квитанцию и повторно
проверяет её `transitionProofSnapshot`. Шаги принимаются только в фактическом
порядке, с `planId` исходного плана и надлежащим `recordCarrier`; допустимы
только сохранённые состояния до или после `activation_link` и
`manifest_commit`. Стабильные прежнее дерево, база и квитанции проверяются
заново, но завершённые эффекты не запускаются повторно.

### Основной журнал намерений

Журнал содержит ровно:

```text
schemaVersion kind installationId operationId operation phase recoveryPolicy
executionPlan abortPlan recoveryPlans discoveryBefore fencedBefore desired
attempts steps changes terminalDefinitionSnapshot terminalDeleteIntent
createdAt updatedAt journalFingerprint
```

`phase` принадлежит `DISCOVERED`, `FENCING`, `LEGACY_EXIT_PENDING`, `FENCED`, `APPLYING`,
`COMMITTING`, `ABORTING`, `FAILED`, `TERMINAL_FROZEN`;
`recoveryPolicy` может перейти только `REVERSIBLE → FORWARD_ONLY`. Снимки
`discoveryBefore`, `fencedBefore`, `desired` являются закрытыми наборами
предназначенных для полного состояния проекций: файлов, деревьев, ссылок,
манифеста, активации, базы, контроллера и его кандидатов, сторожей, реестра,
загрузчиков, старых процессов, покоя, внешних команд, квитанций и долговечных
доказательств отсутствия. Произвольный словарь и голый отпечаток вместо
проекции запрещены.

План выбирается один раз после обнаружения состояния и проверки квитанции
подготовки, но до первого изменения доступного рабочему шлюзу состояния.
До создания основного журнала вычисляются `planId`, `machineId`, выбранная ветвь,
источник выбора, вся составленная последовательность и отпечаток определения
плана. Они впервые становятся долговечными атомарно в создаваемом основном
журнале вместе со всеми определениями изменяемых шагов. Первый шаг
`gate_close` уже находится в состоянии `COMPLETED`, имеет носитель
`JOURNAL_ATOMIC_BOUNDARY`, глобальный и плановый номера 0; каждый последующий
изменяемый шаг уже записан как `PLANNED` с точными `action`, `before` и
`expectedAfter`. Тот же первый документ всегда содержит поле
`terminalDefinitionSnapshot`: `null` только для операции без терминального
определения, иначе полную статическую форму будущей заморозки, квитанции и
последующих действий. В `TERMINAL_FROZEN` значение обязательно ненулевое, а
последний `terminal_journal_freeze` обязан быть `COMPLETED`. Поэтому будущий
шаг нельзя незаметно пересчитать после
аварии, а его изменение при возобновлении отвергается до нового внешнего
эффекта. Старый корректный префиксный журнал разрешено только дочитать по
сохранённому определению плана и дополнить следующим точным шагом.
`firstIncompleteOrdinal` нового журнала не может быть меньше 1. Пустой
существующий основной журнал и курсор 0 структурно недопустимы.

`abortPlan` фиксирует точный завершённый префикс прямого плана до первого
обратного эффекта. `recoveryPlans` только дописываются; каждый новый план
ссылается на неизменяемый отпечаток исходного плана и точный первый
незавершённый шаг. Для состояния `PLANNED` курсор наложения равен 0, для
`ACTIVE` он меньше длины, для `COMPLETED` равен длине, а неоднозначная ветвь
не имеет исполняемого префикса.

Шаг содержит ровно:

```text
stepId ordinal planId planOrdinal recordCarrier kind state commandId
action actionFingerprint before expectedAfter observedAfter intentAt completedAt
```

`state` принадлежит только `PLANNED`, `INTENT_DURABLE`, `COMPLETED`. Для
каждого из 69 `kind` схема задаёт отдельный вариант и связывает его с точными
`action`, `before`, `expectedAfter`, типом `commandId` и допустимой
комбинацией `observedAfter/intentAt/completedAt`. Обратное действие никогда не
кодируется состоянием или флагом шага: `activation_link_restore`,
`legacy_bridge_swap_restore`, `registry_restore` и другие обратные действия —
самостоятельные прямые виды. Общий непрозрачный объект и произвольный `value`
запрещены.

Носитель шага закрыт тремя вариантами. Обычные действия используют
`JOURNAL_MUTABLE` и имеют два проверяемых аварийных окна. `gate_close` и
`terminal_journal_freeze` являются атомарными границами
`JOURNAL_ATOMIC_BOUNDARY` и всегда сразу `COMPLETED`. Публикация квитанций,
удаление замороженного журнала и окончательная синхронизация отсутствия
исполняются только `FROZEN_TERMINAL_EXECUTOR` из неизменяемого конечного
намерения или плана восстановления и никогда не дописываются в замороженный
журнал.

Журнал ограничен 16 МиБ, 128 шагами и 64 попытками; квитанция — 1 МиБ.
Повторные ключи JSON запрещены.

`operationId` равен `op2_` плюс 32 случайных шестнадцатеричных знака. Повтор
после аварии сохраняет его, но создаёт новый `attemptId`; завершённые шаги не
исполняются повторно.

Все долговечные действия используют один примитив. Частный корень обходится
через `openat(O_DIRECTORY|O_NOFOLLOW)`. Обычный временный файл создаётся в
целевом каталоге с `O_CREAT|O_EXCL|O_NOFOLLOW`, записывается, получает
`fsync` и на macOS `F_FULLFSYNC`, затем заменяется `renameat`; родительский
каталог синхронизируется, итог повторно открывается и проверяется. Ссылка
создаётся `symlinkat` под случайным именем, проверяется `lstat`, заменяется
`renameat` и синхронизируется. Удаление требует совпавшего файлового
идентификатора, `unlinkat` и синхронизации каталога. Межкаталожный перенос и
`RENAME_SWAP` синхронизируют оба каталога. Ошибка любого шага не позволяет
записать `COMPLETED`.

Перед внешним действием уже записанный шаг атомарно переводится из `PLANNED`
в `INTENT_DURABLE`; отпечаток аргументов и точные `before/expectedAfter` не
меняются. Для
детерминированного файлового действия `expectedAfter` является полной
проекцией результата. Для эффекта, который назначает PID, сокет, экземпляр
или позднее доказательство, `expectedAfter` является закрытым ограничением:
`EXPECTED_REGISTRATION`, `EXPECTED_MAINTENANCE`, `EXPECTED_ACCEPTING` либо
`EXPECTED_SHUTDOWN_PROOF`; неизвестные во время планирования поля в нём равны
`null`, а не заполнены фиктивными значениями. После действия состояние
читается заново и фактическая проекция целиком сохраняется в `observedAfter`.
Исполнитель принимает её только через отдельный для вида шага предикат,
который связывает все заранее известные поля с ограничением. При повторном
чтении завершённого шага живая проекция должна быть побайтно равна сохранённой
`observedAfter`. Точное `before` позволяет повторить действие; доказанная
цепочка `controller_recover` добавляет отдельный шаг; третье состояние даёт
`RECOVERY_STATE_AMBIGUOUS` без удаления. Для штатных команд Codex заранее
перечисляются и после команды синхронизируются все затронутые файлы и
каталоги реестра; неизвестная поверхность блокирует реальную установку.

Полная ветвь обновления действующей установки состоит ровно из 20 шагов:

```text
gate_close
→ maintenance_begin
→ wait_runtime_quiescent
→ maintenance_strengthen
→ controller_shutdown
→ shutdown_socket_cleanup
→ database_prepare
→ activation_link
→ recovery_forward_only
→ marketplace_registry
→ plugin_registry
→ launchers
→ controller_candidate_spawn
→ controller_accept
→ verify_candidate
→ manifest_commit
→ maintenance_resume
→ terminal_journal_freeze
→ commit_receipt_publish
→ gate_open
```

`gate_close` — первый внешний шаг обычного обновления версии 2, который
меняет состояние, доступное рабочему шлюзу: публикация уже синхронизированного
стабильного файла транзакции. До него разрешены чтение, расчёт плана,
аттестованный адресуемый кэш снимка и отдельная доказанная подготовка
неактивного кандидата; активная ссылка, манифест, реестры, загрузчики, живая
база и контроллер не меняются. Шлюз версии 2 с этого момента не создаёт новую
умную работу. Установщик
обязан фактически выполнить
`maintenance_begin → ожидание runtimeQuiescentV2 →
maintenance_strengthen(FREEZE) → shutdown`; одно сводное состояние не
заменяет эти команды. Перед первым изменением реестра долговечно фиксируется
`FORWARD_ONLY`. `verify_candidate` использует прямые пути
кандидата, проверяет ссылку, базу, реестр, загрузчики и контроллер в режиме
обслуживания. `lastCommittedOperation` появляется только в манифесте после
этой проверки. `shutdown` не удаляет сокет: его точная идентичность остаётся
в намерении, а отдельный `shutdown_socket_cleanup` после доказанной смерти
PID с тем же маркером и захвата исключительной блокировки удаляет только тот
же inode и синхронизирует родителя.

После `maintenance_resume` журнал выполняет `terminal_journal_freeze`: в нём
появляются намерение удаления, ожидаемый путь и вид квитанции, полный список
завершённых шагов, ожидаемое доказательство отсутствия и отпечаток
замороженной проекции. После синхронизации журнал больше никогда не
изменяется. Затем `commit_receipt_publish` создаёт через
`O_EXCL` неизменяемую квитанцию
`receipts/INSTALLATION_ID/OPERATION_ID.commit.json`. Она содержит фактический
SHA-256 и смысловой отпечаток уже готового манифеста, активации, базы и
неизменяемой идентичности контроллера, но не `controlEpoch`, `instanceId`,
`controllerStartId` или PID; затем файл и каталог синхронизируются и квитанция повторно
открывается. Манифест содержит только `lastCommittedOperation`, поэтому цикла
хешей нет. Квитанция связывает `frozenJournalFingerprint`. `gate_open` после
этого удаляет стабильный журнал и синхронизирует
каталог манифестов. Сбой при наличии обоих файлов оставляет режим закрытым;
`recover` проверяет квитанцию и завершает удаление. Уборка в эту операцию не
входит.

До `recovery_forward_only` восстановление может доказанно завершить переход
вперёд либо по закрытой таблице вернуть прежние ссылку, манифест, базу и новый
экземпляр прежнего контроллера. После неё оно идёт только вперёд. Произвольная
«последняя копия» никогда не выбирается.

### Закрытые автоматы жизненного цикла

`lifecycle-automaton-v2` является нормативным перечнем автоматов. Для каждого
автомата неизменяемы начальное состояние, последовательность видов шагов,
политика восстановления и терминальное состояние:

| Автомат | Начало | Упорядоченные шаги | Политика | Конец |
|---|---|---|---|---|
| `apply` | `DISCOVERED` | три префикса допуска, затем `database_prepare → activation_link → recovery_forward_only → marketplace_registry → plugin_registry → launchers → controller_candidate_spawn → controller_accept → verify_candidate → manifest_commit → maintenance_resume → terminal_journal_freeze → commit_receipt_publish → gate_open` | `REVERSIBLE_THEN_FORWARD_ONLY` | `JOURNAL_ABSENT_RECEIPT_PRESENT` |
| `abort` | `REVERSIBLE_FAILURE` | одна из 34 точных обратных ветвей, затем `terminal_journal_freeze → abort_receipt_publish → abort_journal_close` | `REVERSIBLE_ONLY` | `JOURNAL_ABSENT_RECEIPT_PRESENT` |
| `rollback` | `ACTIVE_CURRENT` | один из двух префиксов допуска, затем `activation_link_restore → recovery_forward_only → registry_restore → launchers_restore → controller_candidate_spawn → controller_previous_accept → verify_candidate → manifest_restore → maintenance_resume → terminal_journal_freeze → commit_receipt_publish → gate_open` | `REVERSIBLE_THEN_FORWARD_ONLY` | `JOURNAL_ABSENT_RECEIPT_PRESENT` |
| `uninstall` | `ACTIVE_OR_DISABLED` | один из трёх префиксов допуска, затем `recovery_forward_only → uninstall_plugin_remove → uninstall_marketplace_remove → uninstall_launchers_restore → uninstall_activation_link_remove → uninstall_activation_remove → uninstall_manifest_remove → terminal_journal_freeze → uninstall_receipt_publish → uninstall_tombstone_publish → uninstall_journal_close` | `REVERSIBLE_THEN_FORWARD_ONLY` | `JOURNAL_ABSENT_RECEIPT_TOMBSTONE_PRESENT` |
| `cleanup` | `PLANNED` | `cleanup_object_delete → terminal_journal_freeze → cleanup_receipt_publish → cleanup_journal_close` | `FORWARD_ONLY` | `JOURNAL_ABSENT_RECEIPT_PRESENT` |
| `recovery` | `FILESYSTEM_OBSERVED` | `recovery_inspect`, затем ровно одна ветвь из таблицы восстановления ниже | `MATCHED_STATE_ONLY` | `PRESENCE_MATRIX_DISPOSITION` |
| `legacyMigration` | `DISCOVERED_DESIRED_NULL` | `gate_close → legacy_gateway_fence → legacy_bridge_prepare → legacy_bridge_swap → legacy_marketplace_archive → watchdog_spawn → watchdog_arm → legacy_sigstop → legacy_quiescence → migration_forward_only → legacy_sigterm → legacy_sigcont → external_process_observe → watchdog_disarm → legacy_socket_cleanup → legacy_fenced_snapshot_commit → database_prepare → activation_link → marketplace_registry → plugin_registry → launchers → controller_candidate_spawn → controller_accept → verify_candidate → manifest_commit → maintenance_resume → terminal_journal_freeze → commit_receipt_publish → gate_open` | `REVERSIBLE_THEN_FORWARD_ONLY` | `JOURNAL_ABSENT_RECEIPT_PRESENT` |
| `legacyBridgeForward` | `LEGACY_ACTIVE` | `legacy_gateway_fence → legacy_bridge_prepare → legacy_bridge_swap → legacy_marketplace_archive` | `REVERSIBLE_ONLY` | `BRIDGE_ARCHIVED` |
| `legacyBridgeReverse` | `BRIDGE_ARCHIVED` | `legacy_marketplace_unarchive → legacy_bridge_swap_restore → legacy_bridge_remove → legacy_gateway_restore` | `REVERSIBLE_ONLY` | `LEGACY_ACTIVE` |
| `externalObserver` | `RUNNING` | `external_process_observe → external_exit_recheck` | `MATCHED_STATE_ONLY` | `EXITED_OR_DURABLE_STILL_RUNNING` |

У `apply`, `abort`, `rollback`, `uninstall` и `recovery` есть закрытые условные
ветви; у остальных пяти автоматов их нет. В первых четырёх автоматах только
решение `CONTINUE_COMMON_MACHINE` составляет выбранный префикс с общей
последовательностью, а `RECOVERY_STATE_AMBIGUOUS` ничего не исполняет.
`recovery` имеет 30 самостоятельных ветвей. Автоматы
`legacyBridgeForward` и `legacyBridgeReverse` являются вложенными частями
одного журнала `legacy-migration`, а не источниками самостоятельного
`operationId`.

### Терминальный протокол и восстановление

Операция считается завершённой только при наличии связанной неизменяемой
квитанции, всех обязательных итоговых указателей и синхронизированном
отсутствии журнала. Для `COMMIT`, `ABORT` и `CLEANUP` дополнительного
указателя нет; `UNINSTALL` требует совпавший `installation-tombstone-v2`.
Перед квитанцией шаг `terminal_journal_freeze` записывает
`terminalDeleteIntent` и переводит журнал в `TERMINAL_FROZEN`. После этого
байты журнала неизменяемы: разрешены только публикация квитанции и требуемого
надгробного указателя по уже замороженным намерениям, повторная проверка их
связи, удаление ровно этого замороженного журнала и синхронизация
родительского каталога.

Входной классификатор `terminalProtocol.presenceMatrix` рассматривает только
физическое присутствие файлов и содержит ровно четыре случая:

| Журнал | Квитанция | Решение |
|---|---|---|
| есть | нет | `INSPECT_PHASE_AND_RECOVER` |
| есть | есть | `VERIFY_TERMINAL_THEN_DELETE` |
| нет | есть | `VERIFY_COMPLETION_ARTIFACTS` |
| нет | нет | `INVALID_ABSENCE_WITHOUT_RECEIPT` |

Значения `INSPECT_PHASE_AND_RECOVER` и `VERIFY_TERMINAL_THEN_DELETE` являются
классификацией входа, а не разрешением немедленно изменить файлы. Для пары
«журнал есть, квитанции нет» восстановитель сначала читает `phase`: только
доказанный `TERMINAL_FROZEN` отображается в `PUBLISH_BOUND_RECEIPT`, а
нетерминальная фаза — в одну из трёх ветвей продолжения ниже. Для пары «оба
файла есть» он сначала доказывает `TERMINAL_FROZEN` и связь квитанции с
`frozenJournalFingerprint`: только после этого
`VERIFY_TERMINAL_THEN_DELETE` отображается в `DELETE_FROZEN_JOURNAL`;
квитанция при нетерминальной фазе даёт `INVALID_RECEIPT_BEFORE_FREEZE`.
Для пары «журнала нет, квитанция есть» классификатор требует проверить все
итоговые указатели: обычные виды переходят в `COMPLETE`, а удаление установки —
в `COMPLETE_UNINSTALL` только при совпавшем надгробном указателе.

Таким образом, наличие журнала без квитанции само по себе не разрешает её
публикацию. После проверки фазы, связи и состояния процессов автомат
`recovery` выбирает ровно одну закрытую ветвь:

| Условие | Решение | Шаги |
|---|---|---|
| нетерминальная фаза, внешний процесс с совпавшими PID, маркером старта и группой ещё жив | `REPROVE_EXTERNAL_EXIT_THEN_REEVALUATE` | `external_exit_recheck → recovery_inspect` |
| нетерминальная фаза, контроллер не нужен на первом незавершённом шаге | `RESUME_DECLARED_MACHINE` | `recovery_resume_operation` |
| нетерминальная фаза, совпавший контроллер жив | `RESUME_DECLARED_MACHINE` | `recovery_resume_operation` |
| нетерминальная фаза, совпавший контроллер отсутствует, остановка и свободная блокировка доказаны | `RECOVER_CONTROLLER_THEN_RESUME` | `controller_candidate_spawn → controller_recover → recovery_resume_operation` |
| нетерминальная фаза, точный текущий кандидат зарегистрирован | `ADOPT_CURRENT_CANDIDATE_THEN_RESUME` | `controller_accept → recovery_resume_operation` |
| нетерминальная фаза, точный прежний кандидат зарегистрирован | `ADOPT_PREVIOUS_CANDIDATE_THEN_RESUME` | `controller_previous_accept → recovery_resume_operation` |
| нетерминальная фаза, контроллер, сокет, блокировка или кандидат не совпали | `RECOVERY_STATE_AMBIGUOUS` | действий нет |
| нетерминальная фаза, квитанция уже есть | `INVALID_RECEIPT_BEFORE_FREEZE` | действий нет |
| `TERMINAL_FROZEN`, вид `COMMIT`, `ABORT` или `CLEANUP`, квитанции нет | `PUBLISH_BOUND_RECEIPT` | `recovery_receipt_publish → recovery_journal_close → recovery_absence_verify` |
| `TERMINAL_FROZEN`, вид `COMMIT`, `ABORT` или `CLEANUP`, связанная квитанция есть | `DELETE_FROZEN_JOURNAL` | `recovery_journal_close → recovery_absence_verify` |
| `TERMINAL_FROZEN`, квитанция не совпала или повреждена | `RECOVERY_STATE_AMBIGUOUS` | действий нет |
| журнал удалён, каталог ещё не синхронизирован, связанная обычная квитанция есть | `FINALIZE_SYNCHRONIZED_ABSENCE` | `recovery_absence_verify` |
| журнал синхронизированно отсутствует, связанная обычная квитанция есть | `COMPLETE` | действий нет |
| журнал отсутствует, обычная квитанция не совпала или повреждена | `RECOVERY_STATE_AMBIGUOUS` | действий нет |

Для `UNINSTALL` третьим обязательным предикатом является состояние
`tombstone.json`; его матрица полна:

| Журнал | Квитанция | Надгробный указатель | Решение | Шаги |
|---|---|---|---|---|
| есть, `TERMINAL_FROZEN` | нет | отсутствует | `PUBLISH_UNINSTALL_RECEIPT_AND_TOMBSTONE` | `recovery_receipt_publish → uninstall_tombstone_publish → recovery_journal_close → recovery_absence_verify` |
| есть, `TERMINAL_FROZEN` | нет | `STALE_PRIOR_INSTALLATION`, полностью доказан | `PUBLISH_UNINSTALL_RECEIPT_AND_REPLACE_TOMBSTONE` | `recovery_receipt_publish → uninstall_tombstone_publish → recovery_journal_close → recovery_absence_verify` |
| есть, `TERMINAL_FROZEN` | нет | заявляет текущую операцию при отсутствующей текущей квитанции | `RECOVERY_STATE_AMBIGUOUS` | действий нет |
| есть, `TERMINAL_FROZEN` | нет | не принадлежит договору или повреждён | `RECOVERY_STATE_AMBIGUOUS` | действий нет |
| есть, `TERMINAL_FROZEN` | есть | отсутствует | `PUBLISH_MISSING_UNINSTALL_TOMBSTONE` | `uninstall_tombstone_publish → recovery_journal_close → recovery_absence_verify` |
| есть, `TERMINAL_FROZEN` | есть | `STALE_PRIOR_INSTALLATION`, полностью доказан | `REPLACE_STALE_UNINSTALL_TOMBSTONE` | `uninstall_tombstone_publish → recovery_journal_close → recovery_absence_verify` |
| есть, `TERMINAL_FROZEN` | есть | совпадает | `DELETE_FROZEN_UNINSTALL_JOURNAL` | `recovery_journal_close → recovery_absence_verify` |
| есть, `TERMINAL_FROZEN` | есть | не принадлежит договору или повреждён | `RECOVERY_STATE_AMBIGUOUS` | действий нет |
| есть, `TERMINAL_FROZEN` | не совпала или повреждена | любое | `RECOVERY_STATE_AMBIGUOUS` | действий нет |
| удалён, каталог ещё не синхронизирован | есть | совпадает | `FINALIZE_SYNCHRONIZED_ABSENCE` | `recovery_absence_verify` |
| синхронизированно отсутствует | есть | совпадает | `COMPLETE_UNINSTALL` | действий нет |
| нет | есть | отсутствует | `INVALID_UNINSTALL_WITHOUT_TOMBSTONE` | действий нет; дописывать указатель без замороженного журнала запрещено |
| нет | есть | валиден, но относится к предыдущей установке | `INVALID_UNINSTALL_WITHOUT_CURRENT_TOMBSTONE` | действий нет; заменять указатель без замороженного журнала запрещено |
| нет | есть | не принадлежит договору или повреждён | `RECOVERY_STATE_AMBIGUOUS` | действий нет |
| нет | не совпала или повреждена | любое | `RECOVERY_STATE_AMBIGUOUS` | действий нет |
| нет | нет | отсутствует | `INVALID_ABSENCE_WITHOUT_RECEIPT` | действий нет |

Предикат `STALE_PRIOR_INSTALLATION` разрешает штатную замену только в двух
строках с замороженным текущим журналом и только при одновременном
доказательстве всех условий:

1. старый `installation-tombstone-v2` проходит свою схему и проверку
   `tombstoneFingerprint`; его вложенная `installation-uninstall` квитанция,
   её `receiptFingerprint` и полная неизменяемая файловая проекция квитанции
   также проверены и связаны с идентификаторами внутри старого указателя;
2. `installationId` старого указателя отличается от `installationId`
   текущего замороженного журнала;
3. `before` шага `uninstall_tombstone_publish` равен всей только что
   наблюдённой файловой проекции старого указателя — пути, устройству, номеру
   файла, владельцу и группе, режиму, числу связей, размеру и SHA-256; действие
   остаётся `write-replace`, а любое расхождение перед записью закрывает
   восстановление;
4. при отсутствующей текущей квитанции замороженное намерение точно задаёт
   ожидаемую квитанцию с `installationId`, `operationId` и
   `frozenJournalFingerprint` текущего журнала, которую
   `recovery_receipt_publish` обязан опубликовать первым; при уже существующей
   квитанции проверяется её фактическое совпадение с теми же тремя полями
   замороженного намерения.

Это не ослабление общего несовпадения. Указатель той же установки с иным
`operationId`, отпечатком квитанции или файловой проекцией, невалидный
указатель и чужой файл классифицируются как `UNOWNED_OR_CORRUPT` и дают
`RECOVERY_STATE_AMBIGUOUS`. Валидный указатель предыдущей установки без
текущего замороженного журнала также не переписывается: состояние остаётся
`INVALID_UNINSTALL_WITHOUT_CURRENT_TOMBSTONE`.

Если внешний процесс всё ещё работает, шлюз остаётся закрытым с проблемой
`EXTERNAL_PROCESS_STILL_RUNNING`. В этой ветви запрещены восстановление
контроллера, публикация квитанции, удаление журнала и `SIGKILL`: разрешены
только повторное доказательство выхода и новый `recovery_inspect`.

### Нормативные области отпечатков

Все отпечатки ниже вычисляются как SHA-256 от канонического JSON версии 1 с
указанной областью. Проекция содержит поля ровно в приведённом порядке;
исключённые поля не входят во вход хеша. Области попарно различны.

| Объект | Область | Проекция | Исключено |
|---|---|---|---|
| `executionPlan` | `codex-smart/execution-plan-definition/v2` | `planId machineId selectedBranchId selectionSource composedStepKinds` | `firstIncompleteOrdinal planDefinitionFingerprint` |
| `abortPlan` | `codex-smart/abort-plan-definition/v2` | `planId machineId selectedBranchId selectionSource sourceExecutionPlanDefinitionFingerprint sourceCompletedForwardStepKinds composedStepKinds` | `firstIncompleteOrdinal planDefinitionFingerprint` |
| `recoveryPlan` | `codex-smart/recovery-plan-definition/v2` | `planId selectedRecoveryBranchId selectionSource sourcePlanDefinitionFingerprint sourceStepState firstIncompleteOrdinal firstIncompleteKind firstIncompleteStepId firstIncompleteActionFingerprint controllerPrerequisite candidateId overlayStepKinds` | `status overlayCursorOrdinal planDefinitionFingerprint` |
| `cleanupPlan` | `codex-smart/cleanup-plan-definition/v2` | `planId selectionSource objectOrderIds terminalStepKind` | `firstIncompleteOrdinal planDefinitionFingerprint` |
| `stateBundle` | `codex-smart/state-bundle/v2` | `fileObjects treeObjects symlinks manifest activation database controller controllerCandidates watchdogs registry launchers legacyProcesses quiescence externalCommands receipts absenceProofs` | `bundleFingerprint` |
| `journalState` | `codex-smart/journal-state/v2` | `schemaId schemaSha256 value` | `valueFingerprint` |
| `operationJournal` | `codex-smart/operation-journal/v2` | `schemaVersion kind installationId operationId operation phase recoveryPolicy executionPlan abortPlan recoveryPlans discoveryBefore fencedBefore desired attempts steps changes terminalDeleteIntent createdAt updatedAt` | `journalFingerprint` |
| `cleanupJournal` | `codex-smart/cleanup-journal/v2` | `schemaVersion cleanupId installationId baseCommitReceipt phase cleanupPlan protectedObjects objects steps terminalDeleteIntent createdAt updatedAt` | `journalFingerprint` |
| `terminalState` | `codex-smart/terminal-state/v2` | `terminalKind receiptKind receiptPath completedStepIds postFreezeActionKinds receiptPayloadIntent tombstonePayloadIntent journalAbsenceTarget frozenAt` | `terminalStateFingerprint` |
| `activationPreparationDefinition` | `codex-smart/activation-preparation-definition/v2` | `journalPath receiptPath lockPath activationIntent desiredSeed snapshotFile activationTreeLogical activationFileLogical databaseEmptyFileLogical` | — |
| `activationPreparationIntent` | `codex-smart/activation-preparation-intent/v2` | `sourceRoot codexHome codexBinary stateHome socketPath controllerLockPath installationId operationId databaseId activationBindingNonce activationId activationFingerprint controllerIdentity compatibilityFingerprint routingPolicyFingerprint bundledCatalogFingerprint schemaFingerprint schemaArtifactSha256 activationDir snapshotPath databasePath bundledCatalogPath identity activationDocument sourceLocator snapshotLocator bundledCatalog interfaceEvidence completedAt` | `activationIntentFingerprint` |
| `preparationLogicalObject` | `codex-smart/preparation-logical-object/v2` | `path objectType mode contentSha256` | `logicalFingerprint` |
| `activationPreparationStep` | `codex-smart/activation-preparation-step/v2` | `stepId ordinal kind state expectedLogical observedPhysical observedCompanions intentAt completedAt` | `stepFingerprint` |
| `activationPreparationJournal` | `codex-smart/activation-preparation-journal/v2` | `schemaVersion journalKind installationId operationId phase definitionFingerprint definition intentBoundary steps contentGeneration createdAt updatedAt frozenAt frozenJournalFingerprint desired` | `journalFingerprint` |
| `activationPreparationFrozenJournal` | `codex-smart/activation-preparation-frozen-journal/v2` | те же поля подготовительного журнала, причём `frozenJournalFingerprint=null` во входе | `journalFingerprint` |
| `databaseBindingTarget` | `codex-smart/database-binding-target/v2` | `schemaId schemaSha256 value` | `valueFingerprint` |
| `activationPreparationReceipt` | `codex-smart/activation-preparation-receipt/v2` | `schemaVersion receiptKind installationId operationId activationIntent snapshotFile activationTree activationFile databaseEmptyFile databaseBindingTarget desired frozenJournalFingerprint completedAt` | `receiptFingerprint` |
| `databaseBinding` | `codex-smart/database-binding/v2` | `schemaId schemaSha256 value` | `valueFingerprint` |
| `activationCommitReceipt` | `codex-smart/activation-commit-receipt/v2` | `schemaVersion receiptKind installationId operationId frozenJournalFingerprint manifest manifestDocument transitionLineage activation databaseBinding journalAbsenceTarget controllerIdentity completedStepIds completedAt` | `receiptFingerprint` |
| `operationAbortReceipt` | `codex-smart/operation-abort-receipt/v2` | `schemaVersion receiptKind installationId operationId frozenJournalFingerprint restoredState journalAbsenceTarget reasonCode completedAt` | `receiptFingerprint` |
| `installationUninstallReceipt` | `codex-smart/installation-uninstall-receipt/v2` | `schemaVersion receiptKind installationId operationId frozenJournalFingerprint dataRetentionMode retainedData removedState restoredOriginalBackup absenceProof completedAt` | `receiptFingerprint` |
| `cleanupReceipt` | `codex-smart/cleanup-receipt/v2` | `schemaVersion receiptKind cleanupId installationId frozenJournalFingerprint baseCommitReceipt removedObjects absenceProof completedAt` | `receiptFingerprint` |
| `installationTombstone` | `codex-smart/installation-tombstone/v2` | `schemaVersion installationId operationId uninstallReceipt absenceProof completedAt` | `tombstoneFingerprint` |
| `absenceObservation` | `codex-smart/absence-observation/v2` | `observationId installationId operationId entries directorySyncCompleted` | `observationFingerprint` |
| `absenceProof` | `codex-smart/absence-proof/v2` | `proofId installationId operationId entries directorySyncCompleted` | `proofFingerprint` |
| `absenceProofProjection` | `codex-smart/absence-proof-projection/v2` | `schemaId schemaSha256 value` | `valueFingerprint` |
| `activationGate` | `codex-smart/activation-gate/v2` | `manifestSemanticFingerprint activationReceiptFingerprint journalAbsenceProof` | `gateFingerprint` |
| `controllerCandidate` | `codex-smart/controller-candidate/v2` | `schemaId schemaSha256 value` | `valueFingerprint` |
| `shutdownIntent` | `codex-smart/shutdown-intent/v2` | `schemaId schemaSha256 value` | `valueFingerprint` |
| `swapPair` | `codex-smart/swap-pair/v2` | `schemaId schemaSha256 value` | `valueFingerprint` |
| `watchdogState` | `codex-smart/watchdog-state/v2` | `schemaId schemaSha256 value` | `valueFingerprint` |
| `stepAction` | `codex-smart/step-action/v2` | `action` | `actionFingerprint` |
| `lifecycleCommandResult` | `codex-smart/command-result/v2` | `schemaVersion command status readiness smokeInvocationId changes problems` | `operationId attemptId resultFingerprint problems.message problems.remediation extensions` |
| `controllerRequest` | `codex-smart/controller-request/v2` | `messageType protocolVersion release codexHomeHash shellSessionId controllerIdentity instanceId controllerStartId commandId expectedControlEpoch operationId method params` | `requestFingerprint extensions` |
| `controllerCommandResult` | `codex-smart/controller-command-result/v2` | `method payload.status payload.previousControlEpoch payload.newControlEpoch payload.controllerIdentity payload.instanceId payload.controllerStartId payload.socketIntent` | `payload.commandReceipt responseFingerprint extensions` |
| `controllerResponse` | `codex-smart/controller-response/v2` | `messageType protocolVersion release method responseKind commandId requestFingerprint controlEpoch payload` | `responseFingerprint extensions` |

`terminalStateFingerprint` не входит в собственную проекцию. Сначала
вычисляется отдельный отпечаток терминального состояния, затем он включается в
`terminalDeleteIntent`, после чего вычисляется `frozenJournalFingerprint`, и
уже этот последний отпечаток связывается квитанцией. Поэтому цепочка не
рекурсивна и квитанция не может быть перенесена между видами операций.
Реестр содержит ровно 37 таких областей. Для вложенного доказательства
отсутствия сначала вычисляются два независимых отпечатка:

```text
proofProjection = {
  proofId, installationId, operationId, entries, directorySyncCompleted
}
proofFingerprint =
  SHA256(UTF8("codex-smart/absence-proof/v2") || 0x00 ||
         canonical-json-v1(proofProjection))

envelopeProjection = {schemaId, schemaSha256, value}
valueFingerprint =
  SHA256(UTF8("codex-smart/absence-proof-projection/v2") || 0x00 ||
         canonical-json-v1(envelopeProjection))
```

В `envelopeProjection.value` уже входит вычисленный `proofFingerprint`, а
собственный `valueFingerprint` исключён. Только после обоих пересчётов
`activationGate` вычисляется как

```text
SHA256(UTF8("codex-smart/activation-gate/v2") || 0x00 ||
       canonical-json-v1({
         manifestSemanticFingerprint,
         activationReceiptFingerprint,
         journalAbsenceProof
       }))
```

Поле `journalAbsenceProof` входит в проекцию шлюза целиком: `schemaId`,
`schemaSha256`, закрытые `value` и `valueFingerprint`; замена полной проекции
одним `proofFingerprint` запрещена. Собственный `gateFingerprint` исключён из
входа, поэтому вычисление не рекурсивно. В частности, смысловой результат
изменяющей команды контроллера не включает собственную квитанцию команды,
`responseFingerprint` или расширения, поэтому повтор ответа не создаёт
рекурсивный вход отпечатка.

Положительная квитанция активации хранит полную `journalAbsenceTarget` с
устойчивыми `proofId`, `installationId`, `operationId` и `entries`.
`frozenJournalFingerprint` не используется для реконструкции цели. Каждая
свежая проверка берёт цель только из проверенной квитанции, открывает каждый
родительский каталог без перехода по ссылкам и под общей установочной
блокировкой выполняет `fstatat(ENOENT) → fsync(dirfd) → fstatat(ENOENT)`.
Устройство, inode, путь и basename обязаны совпасть с целью. Поскольку время
наблюдения в доказательство не входит, повторная фактическая проверка создаёт
те же канонические байты и тот же `proofId`; повторное использование старого
JSON без файловых обращений запрещено.

Та же квитанция хранит канонический `manifestDocument`, из которого обязаны
точно пересчитываться размер и SHA-256 файла, все поля проекции `manifest` и
смысловой отпечаток. `transitionLineage` различает `initial`, `update` и
`rollback`: для первого перехода все ссылки на предшественника равны `null`,
а обновление и откат фиксируют точный путь, SHA-256 и отпечаток исходной
квитанции, отпечаток доказательства активации, три `commandId` остановки и
идентичность остановленного контроллера с эпохой. Собственный
`lineageFingerprint` пересчитывается без самого себя. Поэтому восстановление
не выбирает предшественника по повторяющемуся `activationId`.

## Реестр рынка и подключаемого модуля

Управляемый рынок всегда имеет имя `codex-settings-adaptive`. Команда
`plugin marketplace add` получает лексический стабильный путь
`.../marketplace-current`, но Codex `0.144.6` канонизирует его и в ответах
реестра возвращает разрешённый неизменяемый каталог
`.../activations/ACTIVATION_ID/marketplace`. Квитанция установщика версии 2
хранит обе стороны: `marketplacePath` как лексический вход и
`registeredMarketplacePath` как наблюдённую каноническую регистрацию.
Считать различие этих двух путей ошибкой запрещено; каждый из них обязан
совпадать со своей стороной договора. Поле `marketplacePath` внутри
`registry-state-v2` относится к каноническому наблюдению реестра, а не к
одноимённому лексическому полю квитанции установщика.

Будущие шаги реестра не подставляют ещё неизвестные inode, содержимое
`config.toml` или результаты списков. `marketplace_registry.before` и
`plugin_registry.before` являются закрытыми ограничениями со статусами
`EXPECTED_MARKETPLACE_REGISTERED` и `EXPECTED_PLUGIN_ENABLED`; динамические
поля в них равны `null`. После штатной команды исполнитель заново читает все
три представления, строит фактические `MARKETPLACE_REGISTERED` либо
`PLUGIN_ENABLED`, сохраняет их в `observedAfter` и принимает только при
точном совпадении всех стабильных полей с соответствующим ограничением.

Основным описанием состава и политики является
`.agents/plugins/marketplace.json`; совместимый
`.claude-plugin/marketplace.json` делает корень распознаваемым штатной
командой Codex и обязан совпадать с основным описанием по имени, источнику и
версии манифеста расширения. Регистрация расширения точно проверяется по
`name`, `version`, `installPolicy`, `authPolicy`, локальному `source` и
каноническому пути. Желаемое состояние доказывается тремя независимыми
представлениями:

1. `plugin marketplace list --json`;
2. `plugin list --json`;
3. разобранный `config.toml` с сохранением всех посторонних данных.

Перед изменением реального профиля изолированная проба в отдельном
`CODEX_HOME` обязана доказать удаление старого локального рынка, добавление
того же имени с другим путём, повторное добавление подключаемого модуля и
отсутствие дубликатов. Если штатные команды текущего Codex не обеспечивают
такой переход, реальная установка завершается до изменения профиля. Ручное
редактирование `config.toml` запрещено.

Переход реального профиля выполняется под закрытым шлюзом:

1. снять точный отпечаток старой записи рынка и подключаемого модуля;
2. `plugin remove` только принадлежащего расширения;
3. `plugin marketplace remove` только принадлежащего рынка;
4. `plugin marketplace add` стабильного пути `marketplace-current`;
5. `plugin add` полного `pluginId`;
6. повторно доказать единственность и все три представления.

Каждый шаг имеет `intent/completed`. Исчезновение целевого объекта перед
удалением считается `after` только при совпадении сохранённого отпечатка
владения; объект с тем же именем и другой идентичностью не удаляется.
Переустановка может вернуть хуки в `untrusted`; установщик никогда не выдаёт
доверие и возвращает готовность `AWAITING_HOOK_TRUST`.

## Протокол контроллера 2

### Общий конверт и здоровье

`controller-protocol-v2` является верхним закрытым `oneOf`, а не общим
конвертом с независимо выбранными `method` и `params`. Он содержит отдельный
вариант каждого из двенадцати запросов, отдельный `health`, отдельный успешный
ответ каждого метода, закрытую ошибку и квитанцию повтора. Во всех вариантах
`protocolVersion=2` и `release=0.2.0`; иной выпуск не принимается.

Каждый запрос является строгим объектом:

```text
messageType protocolVersion release codexHomeHash shellSessionId controllerIdentity
instanceId controllerStartId commandId expectedControlEpoch operationId
method params requestFingerprint extensions
```

Для первого `health` поля `controllerIdentity`, `instanceId`,
`controllerStartId`, `commandId`, `expectedControlEpoch`, `operationId` равны
`null`; остальные вызовы связывают ненулевые `controllerIdentity`,
`controllerStartId` и `expectedControlEpoch>=1` с точным ответом здоровья.
Метод действующего экземпляра требует ненулевой `instanceId`; только
`controller_accept` и `controller_recover` передают его как `null` и получают
новый. Изменяющий управляющий вызов требует `commandId=cc2_` плюс 32 случайных
hex и ненулевой `operationId`. Добавочное поле вне `extensions` запрещено.

В `controller_accept.params` поле `expectedOrphanOperationId` присутствует
всегда. Для обычной установки и обновления оно равно `null`. При откате оно
равно точной операции остановленного контроллера предыдущей базы; принять
кандидата разрешено только при совпадении этого значения с долговечным
состоянием базы. `controller_recover` это исключение не наследует и никогда
не перепривязывает остановленный orphan другой операции.

Ответы имеют строгие `messageType=response`, `method`, `responseKind`,
`commandId`, `requestFingerprint`, ненулевую известную `controlEpoch`, точный
`payload`, `responseFingerprint` и `extensions`. `responseKind` равен ровно
`HEALTH`, `SUCCESS`, `ERROR` или `REPLAY_RECEIPT`. Ошибка имеет закрытые код,
сообщение и признак повторимости. `REPLAY_RECEIPT.payload` содержит ровно
`commandReceipt`, `originalControlEpoch`, `originalPayload` и
`originalResponseFingerprint`. `originalPayload` является точной закрытой
копией исходного успешного результата соответствующего метода, включая ту же
квитанцию и `socketIntent` для `shutdown`; исходная эпоха совпадает с эпохой
квитанции и внешней эпохой ответа повтора. Клиент реконструирует исходный
конверт `SUCCESS` с пустыми `extensions`, заново вычисляет его
`responseFingerprint` и сравнивает с `originalResponseFingerprint`, после
чего прогоняет обычную проверку успешного ответа. Отсутствие или расхождение
любого поля даёт `REPLAY_PROOF_UNAVAILABLE`, а не новый изменяющий вызов.
Ответ `health`
содержит:

- `protocolVersion=2`, `release=0.2.0`, `namespace`;
- `controllerIdentity`, `instanceId`, `controllerStartId`, `pid`,
  `processStartMarker`;
- отдельные `state` из `ACCEPTING`, `DRAINING`, `MAINTENANCE`,
  `maintenanceMode` из `null`, `drain`, `freeze`, а также самостоятельные
  `operationId` и `controlEpoch`;
- `acceptingNewRoutes`, `quiescent`;
- `activationFingerprint`, `compatibilityFingerprint`,
  `routingPolicyFingerprint`, `bundledCatalogFingerprint`, `databaseId`,
  `databaseSchemaVersion=2`;
- строгий `workCounts`;
- `extensions` и отпечатки запроса и ответа.

`workCounts` содержит неотрицательные целые `nonterminalRoutes`,
`nonterminalNodes`, `activeAttempts`, `activeLeases`, `openIntents`,
`inflightLaunchPermits`, `activeRuntimeArtifacts`,
`pendingCandidatePublications`, `activeEvidenceJobs` и
`queuedEvidenceJobs`. `quiescent=true` только при нуле каждого из десяти
счётчиков и успешной проверке соответствующих запросов базы.

Проекция базы в ответ однозначна: `NONE → null`, `DRAIN → drain`,
`FREEZE → freeze`. Иное сочетание `state` и режима является повреждением и не
публикуется как здоровый ответ.

`controllerIdentity` вычисляется доменом
`codex-smart/controller-identity/v2` от точного объекта
`{protocolVersion,release,namespace,codexHomeHash,stateHome,
activationFingerprint,compatibilityFingerprint,routingPolicyFingerprint,
bundledCatalogFingerprint,
databaseId,databaseSchemaVersion}`. Процесс другой идентичности не
переиспользуется и не завершается автоматически.

`instanceId` имеет форму `ci2_` плюс 32 случайных строчных шестнадцатеричных
знака и назначается успешным `controller_accept` или `controller_recover`.
`controllerStartId` имеет форму `cs2_` плюс 32 случайных hex и создаётся до
запуска процесса. PID не используется как идентификатор экземпляра.

### Условные команды контроллера

Таблица квитанций команд задаётся договором базы. `requestFingerprint`
вычисляется доменом `codex-smart/controller-request/v2` от строгого запроса
без `requestFingerprint` и `extensions`; `responseFingerprint` — доменом
`codex-smart/controller-response/v2` от строгого ответа без
`responseFingerprint` и `extensions`. Ровно шесть методов изменяют управляющее
состояние, повышают `controlEpoch` на один и пишут долговечную квитанцию:
`maintenance_begin`, `maintenance_strengthen`, `shutdown`,
`controller_accept`, `controller_recover`, `maintenance_resume`. Только они
принимают ненулевые `commandId`, `operationId` и допускают
`REPLAY_RECEIPT`. Методы
действующего контроллера требуют его непустой `instanceId`.
`controller_accept` является единственным исключением: он приходит по
унаследованному частному каналу готовности только что запущенного кандидата,
передаёт `instanceId=null` и получает новый идентификатор в ответе. В одной
`BEGIN IMMEDIATE` транзакции контроллер:

1. ищет квитанцию по `commandId`;
2. при совпавшем отпечатке запроса возвращает прежний результат;
3. при другом отпечатке возвращает `COMMAND_REPLAY_CONFLICT`;
4. иначе сравнивает экземпляр, эпоху и допустимость перехода;
5. выполняет изменение, увеличивает эпоху и пишет квитанцию.

Квитанция проверяется до старой эпохи, поэтому потерянный ответ можно
повторить. Новый законный переход получает новый `commandId`.
`maintenance_status`, `admit_node`, `smart_status`,
`reserve_launch_permit`, `commit_launch_permit` используют живое ограждение и
ненулевую ожидаемую эпоху, но имеют `commandId=null`, `operationId=null`, не
повышают `controlEpoch` и не участвуют в повторе по квитанции управляющей
команды. Они читают состояние либо меняют только отдельные сущности допуска.
Ослабление `freeze` до `drain` запрещено. Конкурирующая операция получает
`CONTROLLER_OPERATION_CONFLICT`.

`controller_state` долговечно хранит состояние, режим, причину,
`operationId`, экземпляр, `controllerStartId`, PID, маркер, эпоху, активацию
и отпечатки. Каждый процесс получает новый `controllerStartId`, `instanceId`
и повышает эпоху; старый `instanceId` никогда не переиспользуется.

`controller_recover` сначала получает исключительную системную блокировку до
открытия SQLite, доказывает отсутствие прежнего PID с тем же маркером,
совпадение базы, активации и `controllerIdentity`, затем согласует
незавершённые допуски. Он сохраняет прежние `state`, `maintenanceMode`,
`operationId` и причину, назначает новый экземпляр, повышает эпоху на один и
только после фиксации публикует сокет. Обслуживание нельзя ослабить. При
открытом установочном журнале восстановление запускает только явный
`recover`; при корректной положительной квитанции и отсутствии журнала
разрешён штатный аварийный перезапуск.

### Допуск узла и граница `Popen`

Пятисекундный предел локального вызова не включает процессы сбора
свидетельства. Публичный `route_start` проверяет конверт, владельца маршрута
и общий закрытый `activationGate`, создаёт долговечный
`startRequestId=sr2_...` и ставит первый готовый узел в ограниченную очередь
`AccountEvidence`. До успешного свидетельства `admissionId` не существует,
разрешение запуска не резервируется и фактического допуска нет.

Для каждой фактической попытки запуска узла создаётся ровно одно отдельное
`evidenceJobId=aej2_...`: пять независимых процессов, один общий предел
180 секунд, без кэша и автоматического повтора. `smart_plan`, `direct`,
`clarify` и сам `route_start` дополнительных полных сборов не выполняют.
Маршрут из `N` запускаемых узлов выполняет ровно `N` полных сборов. Повторная
попытка является новым явным запуском с новым заданием, а не скрытым
повтором.

Очередь содержит не более 32 заданий, не более двух заданий одновременно
имеют состояние `RUNNING` и не более одного задания одного маршрута может
быть активным. Ожидающее задание отменяется без запуска процесса. Активная
отмена за пять секунд завершает текущую группу, доказывает отсутствие пяти
процессов и единожды фиксирует `CANCELLED`. `activeEvidenceJobs` и
`queuedEvidenceJobs` входят в `workCounts` и критерий покоя.

После успешного задания внутренний `admit_node` под общей стороной барьера и
одной `BEGIN IMMEDIATE` сверяет `ACCEPTING`, эпоху, маршрут, связанный
учётный контекст, стабильную привязку базы и тройку `activationGate`. Только
он создаёт `admissionId=adm2_...`. Последующие
`reserve_launch_permit` и `commit_launch_permit` не запускают новые полные
сборы, а проверяют тот же неизменяемый результат `evidenceJobId`, текущую
эпоху, фактический шлюз и идентичность снимка. Непосредственно перед передачей
миссии дочернему Codex контроллер требует `child-attestation-v2`; смена
учётной среды или фактической пары завершает попытку `STALE` до выполнения
задачи. Внутреннее `ACCEPTING` без этих доказательств никогда не означает
фактический допуск.

Один контроллер является единственным процессом, запускающим детей. Прямой
`Popen(Codex)` запрещён. Он запускает неизменяемый
`codex-child-launch-guard` с `permitId`, случайным одноразовым знаком,
частным каналом кадров и отдельным каналом ошибки с `CLOEXEC`. Кадр —
канонический JSON с 32-битной длиной, не более 16 КиБ. Автомат сторожа:

```text
CREATED → HELLO_SENT → GUARDED → COMMIT_AUTHORIZED → EXEC_CONFIRMED
                         ↘ ABORTED | CHANNEL_CLOSED | DEADLINE | PROTOCOL_ERROR
```

`HELLO` содержит версию, `permitId`, одноразовый знак, PID и маркер сторожа,
отпечаток аргументов и идентичность снимка. Он приходит не позднее двух
секунд. Контроллер проверяет его и фиксирует `GUARDED`; на решение отводится
восемь секунд. Удерживая общую сторону барьера, контроллер непосредственно
перед фиксацией повторяет дескрипторную проверку снимка, затем точный
`commit_launch_permit` одной транзакцией в третий раз сверяет эпоху,
совпавший фактический манифест, ту же неизменяемую квитанцию активации и свежую
проекцию отсутствия основного журнала. `activationGate` запросов
`admit_node`, `reserve_launch_permit` и `commit_launch_permit` обязан
быть побитно одинаков после канонизации; несовпадение закрывает допуск. Только
затем контроллер создаёт связанную попытку и
переводит допуск в `COMMIT_AUTHORIZED`. Только после фиксации он посылает
`COMMIT` с тем же знаком.

Сторож после `COMMIT` снова проверяет снимок, аргументы и знак и вызывает
`execve`. Успешный `exec` в течение одной секунды закрывает канал ошибки с
`CLOEXEC`; при отказе сторож пишет строгий `EXEC_ERROR`. Контроллер сверяет
тот же PID, маркер и образ процесса, переводит допуск в `STARTED` и только
тогда освобождает барьер. Весь критический участок ограничен десятью
секундами. Сбой до `COMMIT_AUTHORIZED` не запускает Codex; сбой после него
оставляет известные разрешение, попытку, PID и маркер, которые
`controller_recover` согласует без догадочного повтора.

`drain` запрещает новые `startRequestId`, задания доказательства и
`admissionId`. Ожидающие задания сразу отменяются, активные получают
`CANCEL_REQUESTED` и обязаны доказанно завершить свои группы процессов за
пять секунд; лишь затем контроллер ждёт остальные категории покоя.
`freeze` получает исключительную
сторону барьера, ждёт не более десяти секунд, повышает эпоху и помечает
`RESERVED`/`GUARDED` как `ABORTED_FREEZE`; критический
`COMMIT_AUTHORIZED → EXEC_CONFIRMED` либо полностью завершён до `freeze`, либо
не запускается после него. Отменённое или закончившееся после смены эпохи
`AccountEvidence` не может создать допуск.

### Осушение, остановка и принятие

`maintenance_begin` переводит `ACCEPTING → DRAINING`, сохраняет режим и
операцию. Установщик ждёт естественного покоя до 60 секунд; автоматическая
отмена маршрутов запрещена. При `ACTIVE_ROUTES` и неизменной старой активации
он обязан условно выполнить `maintenance_resume` той же операцией, но с новым
`commandId`, записать неизменяемую квитанцию отмены, удалить журнал и вернуть
ошибку. Следующий `apply` создаёт новый `operationId`. Если возврат не
завершён либо исходная активация уже изменилась, журнал остаётся только для
`recover`, а шлюз закрыт.

`maintenance_resume` проверяет свежий критерий покоя как предварительное
условие принятия кандидата, но при переходе в `ACCEPTING` всегда сохраняет
`quiescent=false`: открытие приёма новых маршрутов прекращает действие
положительного утверждения о покое. Ожидаемая проекция этого шага также
содержит `acceptingNewRoutes=true` и `quiescent=false`. Иначе первая новая
работа оставила бы в строке контроллера устаревшее `quiescent=true`.

`shutdown` допустим только при `quiescent=true` и полной проекции
`runtime-v2` покоя. Одна транзакция переводит `controller_state` из
`MAINTENANCE` в административную форму `STOPPED`, сохраняющую прежние
`instanceId`, PID, маркер старта и группу процесса для аудита, повышает
`controlEpoch` ровно на один и пишет квитанцию команды. Ответ и
`response_json` этой квитанции сохраняют один неизменяемый `socketIntent` с
путём, устройством, inode, владельцем, режимом, PID, маркером, группой и путём
блокировки. Эта транзакция ещё не создаёт конечную `shutdown-intent-v2`, так
как доказательств выхода процесса и исключительной блокировки ещё нет.

После фиксации процесс закрывает входы, потоки и базу, освобождает блокировку
и выходит, но не удаляет сокет. Внешний исполнитель шага
`controller_shutdown` по точной квитанции и её `socketIntent` доказывает
отсутствие прежнего PID с тем же маркером и получает исключительную
блокировку. Только после этого он строит неизменяемую конечную
`shutdown-intent-v2` со статусом
`SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN` и записывает её как фактическую
`observedAfter` завершённого шага. Неизменяемая `expectedAfter` этого шага
имеет статус `EXPECTED_SHUTDOWN_PROOF`, те же заранее известные поля и `null`
в двух поздних отпечатках доказательств. В конечном объекте
`commandReceiptFingerprint` обязан быть побайтно равен
`commandReceipt.resultFingerprint` точной квитанции `shutdown`; отдельные
`commandId`, `requestFingerprint` и `newControlEpoch` обязаны совпадать с той
же квитанцией. `controllerAfter.controllerIdentity`, `instanceId` и
`controllerStartId` обязаны совпадать с точным запросом `shutdown`, а PID,
маркер и группа — с его `socketIntent`. Любое несовпадение закрывает
восстановление. Отдельный файловый шаг `shutdown_socket_cleanup` планируется
с тем же `EXPECTED_SHUTDOWN_PROOF` как неизменяемым `before`, а при исполнении
получает конечный объект из сохранённого либо только что доказанного
`controller_shutdown.observedAfter`. Его неизменяемое `action` содержит
только заранее известные ограничения:
`commandId` источника, точную пару PID/маркер/группа, сокет, путь блокировки и
устройство/inode родителя сокета. Поздние отпечатки выхода процесса,
исключительной блокировки и всей конечной проекции в `action` не копируются.
Исполнитель повторно связывает доказательства из фактического наблюдения,
сверяет тот же inode, выполняет `unlinkat`, синхронизирует именно сохранённого
родителя и получает `absence-proof-v2` как `expectedAfter`;
база на этом шаге не меняется. `SIGKILL` не используется.

После потери ответа повтор того же `commandId` возвращает исходные эпоху,
полезную нагрузку и квитанцию без нового повышения эпохи. Внешний исполнитель
сначала доказывает отпечаток реконструированного исходного ответа, а затем
восстанавливает конечное намерение только из точной квитанции, её
`socketIntent` и свежих доказательств отсутствия
процесса с прежним маркером и получения исключительной блокировки. Наличие
точного осиротевшего сокета означает, что требуется
`shutdown_socket_cleanup`; иной сокет блокирует удаление. Одного исчезновения
сокета или процесса недостаточно.

Новый контроллер запускается прямым путём кандидата с новыми
`controllerStartId`, PID и маркером, ожидаемыми `operationId`, `activationId`,
`databaseId` и отдельным каналом готовности.
Он получает аренду до открытия SQLite, не создаёт схему из конструктора,
проверяет журнал, активацию и базу и публикует сокет только в
`MAINTENANCE`.

Действие запуска заранее хранит ровно три аргумента: канонический абсолютный
путь интерпретатора Python, канонический абсолютный путь
`ACTIVATION_ID/marketplace/plugins/codex-smart-subagents/controller/server.py`
и `--serve-candidate-v2`. `argvFingerprint` вычисляется только из этого
массива в области `codex-smart/controller-candidate-argv/v2`; дочерний
процесс повторно проверяет его до открытия базы или публикации канала.

До запуска `controller_candidate_spawn.expectedAfter` содержит
`EXPECTED_REGISTRATION` с `null` вместо PID, маркера, группы и канала;
завершённый шаг сохраняет `REGISTERED_READY` с фактическими значениями в
`observedAfter`. `controller_accept.before` остаётся тем же неизменяемым
`EXPECTED_REGISTRATION`, а исполнитель связывает его с сохранённым
`REGISTERED_READY`; после закрытия одноразового канала позднее возобновление
использует точное сохранённое `observedAfter`, а не повторный запуск или
повторное ожидание канала. Аналогично `controller_accept` и `controller_recover`
планируются как `EXPECTED_MAINTENANCE`, а `maintenance_resume` — как
`EXPECTED_ACCEPTING`; назначенный `instanceId`, PID и сокет появляются только
в фактических `MAINTENANCE` и `ACCEPTING`.

`controller_accept` одной транзакцией сравнивает активацию, базу, операцию,
запуск и отпечатки, назначает новый `instanceId`, повышает эпоху и пишет
квитанцию. Если этот процесс умер после принятия, новый процесс не повторяет
его `commandId`: восстановитель доказывает старую квитанцию и выполняет
отдельный `controller_recover`.
После `manifest_commit` метод `maintenance_resume` с той же операцией
переводит этот новый экземпляр в `ACCEPTING`; он не требует совпадения старых
отпечатков, а требует точного совпадения уже зафиксированной новой активации.
Действие `manifest_commit` до намерения хранит и `sourcePath` подготовленного
манифеста, и конечный `targetPath`; атомарная замена после сбоя поэтому не
восстанавливается из незафиксированного временного имени.

### Конечные сроки

| Действие | Предел |
|---|---:|
| Установочная блокировка | 30 секунд |
| Один запрос контроллеру | 5 секунд |
| Один полный `AccountEvidence` | 180 секунд |
| Победитель гонки запуска | 15 секунд |
| `HELLO` дочернего сторожа | 2 секунды |
| Сторож от `GUARDED` до решения | 8 секунд |
| Подтверждение `exec` | 1 секунда |
| Барьер `freeze` | 10 секунд |
| Осушение | 60 секунд |
| Штатное завершение | 15 секунд |
| Исчезновение сокета и освобождение блокировки | 5 секунд |
| Принятие нового контроллера | 15 секунд |
| Команда реестра Codex | 30 секунд |
| Весь `apply`, включая пробы | 600 секунд |
| Изменение состояния после проб интерфейса | остаток, но не более 300 секунд |
| Восстановление | 120 секунд |

Первые 300 секунд общего `apply` являются верхней границей полной проверки
интерфейса, а не гарантированно выделенным временем. Все пределы используют монотонное время и не продлеваются внутренним
повтором. Истечение возвращает точный код, оставляет журнал и закрытый шлюз.
Для остановки используется `CONTROLLER_SHUTDOWN_TIMEOUT`; бесконечное
ожидание, `SIGKILL` и скрытая отмена запрещены.

## Переход с выпуска 0.1.0

### Обязательные исходные данные и внешний барьер

Манифест 0.1.0 не содержит стабильную точку Codex, SHA-256 и `XDG_STATE_HOME`.
Поэтому переход требует явные `--codex-binary` и абсолютный
`--legacy-state-home`. Старый физический путь Codex является только
исторической строкой: его отсутствие после очистки Homebrew не считается
повреждением и не используется как текущий файл.

Автоматический переход разрешён только для одного доказанного старого корня.
На macOS установщик перечисляет процессы текущего пользователя и читает
`KERN_PROCARGS2`, извлекая только аргументы и значения `CODEX_HOME` и
`XDG_STATE_HOME`; остальные переменные не сохраняются и не журналируются.
Процесс старого контроллера распознаётся по аргументу запуска внутри точного
старого управляемого дерева. Недоступное окружение, другой корень или более
одного различного корня дают `LEGACY_STATE_ROOT_AMBIGUOUS` до открытия базы
на запись.

Старый шлюз не понимает журнал версии 2, поэтому первым внешним шагом одного
и того же основного журнала `kind=legacy-migration` становится постоянное
шлюзовое ограждение. Отдельной загрузочной транзакции и передачи владения
между журналами нет. В фазах `DISCOVERED` и `FENCING` этот журнал содержит
только доказательства владения путями и наблюдавшиеся процессы,
`fencedBefore=null` и `desired=null`; снимок старой базы ещё не авторитетен.
Тот же журнал последовательно ставит два независимых ограждения:

1. `legacy_gateway_fence` долговечно заменяет `codex-smart` постоянным
   шлюзом; старый `codex-highfd` после этого не достигает кода 0.1.0;
2. `legacy_marketplace_fence` ставит по старому зарегистрированному пути
   минимальный рынок-мост с тем же идентификатором и безопасными
   бездействующими хуками.

Второе ограждение состоит из отдельных шагов `legacy_bridge_prepare`,
`legacy_bridge_swap`, `legacy_marketplace_archive`. Журнал хранит точные
идентификаторы и отпечатки старого дерева, моста, временного и архивного
путей. На macOS `legacy_bridge_swap` использует
`renameatx_np(...,RENAME_SWAP)` только после пробы на том же томе, затем
синхронизирует каталог и проверяет обе стороны; архивирование имеет своё
`intent/completed` и синхронизацию обоих каталогов. Восстановитель различает
ровно три положения: до обмена, после обмена до архива, после архива. Он
соответственно повторяет обмен, переносит вторую сторону в архив или
дописывает завершение; иная комбинация даёт `RECOVERY_STATE_AMBIGUOUS`.

После обоих ограждений процессы сканируются заново. Затем сторож возврата
вооружается, старый контроллер замораживается и доказывается
`legacyMigrationQuiescent`. Перед `SIGTERM` тот же журнал долговечно
переходит в `phase=LEGACY_EXIT_PENDING` и `FORWARD_ONLY`, сохраняя
`fencedBefore=null` и `desired=null`. Это отдельное долговечное окно: старый
процесс уже можно только довести до выхода, но недоказанный снимок базы ещё
нельзя применять. После доказанного выхода и эксклюзивной аренды базы
атомарной заменой этого же файла фиксируются авторитетные
`fencedBefore`, стабилизированная резервная копия, точный `desired` и
`phase=FENCED`. До `FENCED` ранее наблюдавшийся снимок базы не может
использоваться для миграции. Прямой злонамеренный запуск архивного пути тем
же пользователем находится вне модели угроз.

Ошибка до `migration_forward_only` остаётся в том же журнале с
`recoveryPolicy=REVERSIBLE`, `fencedBefore=null` и `desired=null`; фазы
`ABORTING`, `FAILED` и терминальная квитанция отмены не создают второй журнал.
После `migration_forward_only` политика равна только `FORWARD_ONLY`, а
`LEGACY_EXIT_PENDING` остаётся с пустыми снимками до доказанного выхода.
`FENCED`, `APPLYING`, `COMMITTING`, последующий `FAILED` и терминальная
фиксация уже требуют полных `fencedBefore` и `desired`. Одинаковое имя фазы
`FAILED` различается долговечно записанной политикой: обратимый отказ до
границы ещё имеет пустые снимки, а отказ после `FENCED` — полные.

### Остановка старого контроллера

Новый код сам разбирает точный `health` протокола 1 и не импортирует модуль
0.1.0. Пользователь сокета проверяется `getpeereid`; PID на macOS получается
`getsockopt(SOL_LOCAL, LOCAL_PEERPID)`. Маркер процесса читается через
`proc_pidinfo(PROC_PIDTBSDINFO)` как десятичная строка
`darwin:<pbi_start_tvsec>:<pbi_start_tvusec>`. Перед каждым сигналом PID,
пользователь и маркер читаются повторно. Для Linux будущий адаптер использует
`SO_PEERCRED`; без платформенного адаптера переход запрещён.

Перед `SIGSTOP` запускается отдельный сторож вне группы процессов установщика
с частным унаследованным каналом и одноразовым знаком. Его закрытый автомат:

```text
CREATED → READY → ARMED → MONITORING → RESUME_SENT → RESUMED → EXITED
                                   ↘ TARGET_EXITED → EXITED
                                   ↘ MARKER_MISMATCH → SAFE_FAILURE
```

Установщик не посылает `SIGSTOP` до кадра `ARMED`, совпавшего PID, маркера и
знака. Контрольные кадры идут не реже раза в две секунды. Потеря канала или
пять секунд молчания вызывает условный `SIGCONT`; абсолютный срок сторожа —
30 секунд. Перед каждым сигналом заново проверяются пользователь и маркер.
Сторож не завершается, пока не доказан `SIGCONT` либо исчезновение процесса;
`DISARM` при существующем остановленном процессе запрещён. Внутренний поток
установщика недостаточен.

В замороженном состоянии мигратор пытается получить исключительный доступ к
указанной базе и проверяет точный критерий покоя. Любая работа даёт
`LEGACY_CONTROLLER_BUSY`, после чего отправляется `SIGCONT`. При покое
отправляются `SIGTERM` и `SIGCONT`; выход ждётся не более 15 секунд. Затем
проверяются отсутствие сокета, освобождение старой блокировки и исчезновение
исходного маркера. При любом сроке шлюз остаётся закрытым, `SIGCONT`
гарантируется сторожем, `SIGKILL` не применяется.

Шаги `watchdog_spawn`, `watchdog_arm`, `legacy_sigstop`, `legacy_sigterm` и
`legacy_sigcont` являются отдельными долговечными намерениями. Каждый
сигнальный шаг связывает точные PID, маркер старта, группу процессов и
`watchdogId`; восстановитель не заменяет эту четвёрку «последним найденным»
процессом. После срока `external_process_observe` записывает либо доказанный
`EXITED`, либо долговечный `EXTERNAL_PROCESS_STILL_RUNNING`. Во втором случае
операция остаётся нетерминальной и шлюз закрыт; последующий `recover` может
только выполнить `external_exit_recheck` по той же идентичности и повторить
`recovery_inspect`. Он не посылает новый сигнал, не запускает контроллер 2 и
не публикует квитанцию до доказанного выхода.

Состояние `external-command-v2` закрыто четырьмя вариантами; каждый содержит
отпечаток доказательства самого наблюдения:

| Состояние | `signalSent` | `exitProofFingerprint` | Следствие |
|---|---|---|---|
| `RUNNING` | только `null` | только `null` | срок ещё не истёк, продолжение перехода запрещено |
| `EXITED` | `null` или ранее отправленный `SIGTERM` | обязательный ненулевой отпечаток доказанного выхода | разрешена повторная проверка идентичности и продолжение |
| `MARKER_MISMATCH` | `null` или ранее отправленный `SIGTERM` | обязательный ненулевой отпечаток доказанного несовпадения исходного процесса | разрешено продолжение без сигнала новому процессу |
| `EXTERNAL_PROCESS_STILL_RUNNING` | только `SIGTERM` | только `null` | шлюз закрыт; разрешена только ветвь повторного доказательства выхода |

`EXITED` без доказательства, состояние «всё ещё работает» без фактически
записанного `SIGTERM`, а также любой ненулевой отпечаток выхода у `RUNNING`
или `EXTERNAL_PROCESS_STILL_RUNNING` являются недопустимыми. Миграция может
продолжиться только из `EXITED` либо `MARKER_MISMATCH` с ненулевым
доказательством; один статус без доказательства не является границей.

Только после остановки и внешнего шлюза новая версия получает собственную
аренду до любого открытия базы. Это устраняет старый порядок, где
`SmartStore` открывал и дополнял SQLite раньше блокировки контроллера.

## Откат, удаление и квитанции

### Матрица возврата

| Последняя долговечная граница | Разрешённое восстановление |
|---|---|
| Журнал создан, внешних действий нет | Квитанция отмены и удаление журнала |
| Поставлено только старое шлюзовое ограждение | Точное восстановление прежнего шлюза либо движение вперёд |
| Выполнен обмен рынка-моста | Обратный обмен и восстановление шлюза либо движение вперёд |
| Старый контроллер жив, `FORWARD_ONLY` ещё не записан | Возврат ограждений и продолжение старого контроллера |
| `FORWARD_ONLY` записан перед завершением старого контроллера | Только движение вперёд; полный итоговый откат выключает умный режим 0.1.0 |
| Контроллер 2 в `DRAINING` | Новый `commandId` для `maintenance_resume`, затем квитанция отмены |
| Контроллер 2 заморожен или остановлен до границы только вперёд | Запуск точного прежнего контроллера, `controller_recover`, `maintenance_resume` |
| Подготовлены база или активация-кандидат | Предыдущий пункт; кандидаты передаются отдельной уборке |
| Переключена ссылка, реестр ещё не менялся | Вернуть прежнюю ссылку и восстановить прежний контроллер |
| Записан `FORWARD_ONLY` перед первым изменением реестра | Только движение вперёд |
| Принят контроллер-кандидат или опубликован манифест | Только движение вперёд |
| Квитанция фиксации опубликована, журнал существует | Проверить квитанцию и удалить журнал |
| Журнал отсутствует, квитанция корректна | Операция завершена; возможна отдельная уборка |
| Наблюдается третье состояние | `RECOVERY_STATE_AMBIGUOUS`, шлюз закрыт |

После фиксации обновления между совместимыми поколениями схемы 2 отдельный
`rollback` может переключить только целую сохранённую активацию. После
перехода базы 1 → 2 старый умный выпуск автоматически не включается: исходная
база 1 сохраняется как архив, а полный откат выключает умный режим и
восстанавливает обычный `codex-highfd`. Будущая схема требует новой явной
матрицы.

Каждый успешный откат публикует новую commit-квитанцию, а не возвращает
старую. Текущая квитанция выбирается только по
`manifest.lastCommittedOperation`; операция предшественника извлекается из
проверенной исходной квитанции её `transitionLineage`. Точная квитанция
предшественника затем открывается по каноническому имени операции. Поиск по
`activationId` запрещён, поскольку цепочка `A → B → A → B` содержит несколько
неизменяемых квитанций одной активации. Отсутствующая, подменённая или вторая
квитанция той же операции делает восстановление неоднозначным и закрывает
шлюз.

В выпуске 0.2 удаление является отдельной журналируемой операцией
`uninstall --retain-data` после осушения. Оно восстанавливает
`originalBackup` прежнего `codex-highfd`, если квитанция доказывает, что
текущий файл принадлежит установке; отсутствие исходного файла
восстанавливается как отсутствие. Затем штатно удаляются только собственные
регистрационные записи, загрузчики, ссылка активации, каталог активации и
закрытая пара файлов установки: манифест и прежняя квитанция установщика.
Оба абсолютных пути и обе исходные проекции входят в действие и его отпечаток
владения шага `uninstall_manifest_remove`; скрытого пакетного удаления за этим
шагом нет. Если процесс прерван между двумя `unlink`, каждое из двух частичных
состояний пары имеет отдельную проекцию и принимается только при уже долговечно
записанном намерении этого же шага. Пока шаг имеет состояние `PLANNED`, такое
же частичное состояние считается внешним вмешательством и закрывает
восстановление.

База, архивы и карантин не удаляются. Квитанция фиксирует
`dataRetentionMode=retain-data`, стабильную `databaseBinding` и абсолютные
пути `backupsRoot` и `quarantineRoot`. Команда печатает эти пути и путь к
сохранённой точке восстановления. Отдельная разрушающая команда очистки в
выпуске 0.2 не поддерживается и не подразумевается повторным `uninstall`.

Постоянная точка восстановления размещается вне заменяемой активации и
остаётся доступной после удаления установки. Её проекция
`recoveryEntrypoint` входит в `retainedData`; операция удаления не содержит
шагов удаления базы, аварийной капсулы или административной точки входа.
Эта постоянная точка восстановления позволяет проверить сохранённые данные,
повторить восстановление или подготовить осознанную ручную очистку отдельным
будущим протоколом.

До удаления каждого принадлежащего установке объекта журнал пишет намерение
и доказательство владения. После удаления, но до исчезновения стабильного
журнала, через `O_EXCL` создаётся неизменяемая квитанция
`receipts/INSTALLATION_ID/OPERATION_ID.uninstall.json`. Она содержит
отпечатки удалённого манифеста, активации, реестра и загрузчиков,
восстановленного `originalBackup`, доказательство отсутствия и описание всех
сохранённых данных. После её синхронизации публикуется стабильный
`tombstone.json` с `installationId`, `operationId` и отпечатком квитанции;
последним шагом удаляется и синхронизируется журнал.

Поле `uninstallReceipt` надгробного указателя принимает только проекцию
`receipt-object-v2` с вложенным `receiptKind=installation-uninstall`.
Квитанция активации, отмены или уборки не может завершить удаление установки даже
при совпадении имени файла или внешнего отпечатка.

Повторное удаление установки возвращает `unchanged` только при совпадении
квитанции и одновременном отсутствии манифеста, ссылки, поколений,
собственных загрузчиков, рынка, подключаемого модуля и записей настройки.
Новый объект с тем же именем не удаляется. Отсутствие без журнала или
квитанции является `UNINSTALL_RESIDUE`.

Каждый новый цикл установки получает новый `installationId`, новую
квитанцию и собственный `originalBackup`; старый надгробный указатель при
наличии активного манифеста только диагностический. Поэтому последовательность
«установка → удаление → установка → удаление» не перезаписывает
неизменяемую квитанцию и не принимает доказательство прошлого цикла.

## Проверочный запуск, уборка и квоты

Каждый `smoke` создаёт частный каталог с меткой владения, содержащей
`smokeInvocationId=sm2_...`, PID, маркер старта, время и отпечаток корня.
`operationId` для читающей команды остаётся `null`. Немедленная уборка
гарантируется при штатном выходе и перехватываемых сигналах, но не обещается
для `SIGKILL`, сбоя машины или потери питания.

Следующий `doctor`, `smoke`, `apply` или `cleanup` распознаёт только каталоги с
валидной меткой. Если процесс отсутствует или его маркер отличается и каталог
старше 5 минут, он считается осиротевшим и удаляется после проверки
принадлежности. Повреждённая метка не даёт права удаления и создаёт проблему
`ORPHAN_OWNERSHIP_AMBIGUOUS`.

Уборка после успешной установки является самостоятельной операцией с
`cleanupId`, `cleanup.transaction.json`, закрытым списком объектов и своей
квитанцией. Перед каждым удалением она заново строит граф ссылок. Она не имеет
права удалять активную или предыдущую активацию, защищённый резервный снимок
Codex и базу 1, объект любого незавершённого основного журнала, текущую
квитанцию фиксации или актуальную квитанцию полного удаления. Её сбой даёт
`CLEANUP_INCOMPLETE`, но не закрывает готовую активацию. Главный `apply` не
сообщает `retired_generation`: это изменение возвращает только фактически
завершившаяся уборка.

`baseCommitReceipt` и в журнале, и в квитанции уборки является только
проекцией `receipt-object-v2` с вложенным
`receiptKind=activation-commit`. Квитанция подготовки не может стать
основанием пакета уборки вместо квитанции принятой активации. Квитанция самой
уборки, отмены или полного
удаления не может стать основанием нового пакета.

Один журнал уборки содержит не более 127 объектов: места 0–126 занимают
соответствующие им `cleanup_object_delete`, а место 127 зарезервировано за
атомарным `terminal_journal_freeze`. Поэтому шагов не более 128,
`firstIncompleteOrdinal` после замораживания равен 128, а `removedObjects`
квитанции содержит не более 127 элементов. Если подходящих объектов больше,
уборка завершает текущий пакет по последовательности
`cleanup_object_delete → terminal_journal_freeze → cleanup_receipt_publish →
cleanup_journal_close`, доказывает синхронизированное отсутствие журнала и
создаёт следующий пакет с новым `cleanupId`. Пакеты нельзя объединять задним
числом или дописывать после `TERMINAL_FROZEN`. К уборке применяется та же
входная матрица присутствия журнала и квитанции; завершение без неизменяемой
`cleanup-receipt-v2` недопустимо.

Автоматически хранятся активная и одна предыдущая активация, все объекты
незавершённого журнала, до 8 семантических свидетельств объёмом до 64 МиБ и до
32 квитанций объёмом до 16 МиБ. Осиротевшие проверочные деревья ограничены
8 экземплярами и 1 ГиБ; старше 24 часов они удаляются по тем же правилам.
Исходная резервная копия, архив базы 1, карантин и повреждённые доказательства
автоматически не удаляются; `cleanup --preview` перечисляет их, а отдельное
подтверждённое удаление требует точных отпечатков.

Если все объекты сверх мягкой квоты защищены, возвращается
`RETENTION_QUOTA_EXCEEDED_PROTECTED`; они не удаляются. Нехватка места для
нового кандидата проверяется до первого внешнего изменения. Если все
проверочные каталоги моложе пяти минут, уборка ничего не удаляет и сообщает
временное превышение, а не нарушает правило возраста.

## Инварианты аварийных окон

| Окно | Результат |
|---|---|
| До подготовительного журнала | Допустима только атомарная публикация повторно проверяемого адресуемого снимка Codex; активное состояние не изменено |
| После `preparation_intent`, до первого объектного намерения | Полный логический план подготовки долговечен; активное состояние не изменено; пустого подготовительного журнала нет |
| После намерения подготовительного объекта, до действия | Наблюдается доказанное отсутствие; действие повторимо по точному пути и смысловому хешу |
| После действия подготовки, до `COMPLETED` | Наблюдается только точный логический кандидат; дописывается полная физическая проекция |
| После `preparation_freeze`, до квитанции или закрытия подготовительного журнала | Журнал неизменяем; матрица присутствия однозначно публикует связанную квитанцию и доказывает синхронизированное отсутствие журнала |
| После квитанции подготовки, до основного журнала | Существуют только недоступные рабочему шлюзу объекты; их точные физические проекции повторно проверяются перед `gate_close` |
| После атомарного создания основного журнала, до первого изменяемого намерения | План долговечен, `gate_close` уже `COMPLETED`, шлюз закрыт; пустого журнального состояния нет |
| До журнала уборки | Ни один объект уборки не изменён |
| После атомарного создания журнала уборки, до первого объектного намерения | План уборки долговечен, курсор равен 0, удалений ещё нет |
| После `INTENT_DURABLE`, до действия | Наблюдается `before`, шаг повторим |
| После действия, до `COMPLETED` | Наблюдается полная фактическая проекция; для детерминированного шага она равна `expectedAfter`, для эффекта с назначаемыми полями она проходит связующий предикат ограничения и сохраняется как `observedAfter` |
| После `terminal_journal_freeze`, до публикации квитанции | Журнал присутствует и неизменяем; восстановитель проверяет `TERMINAL_FROZEN` и публикует только связанную квитанцию |
| После публикации квитанции, до обязательного итогового указателя | Для `UNINSTALL` журнал сохраняется, пока не опубликован и не проверен совпавший надгробный указатель; у остальных видов такого окна нет |
| После проверки квитанции и всех итоговых указателей, до удаления замороженного журнала | Восстановитель проверяет `frozenJournalFingerprint` и удаляет только этот журнал |
| После удаления журнала, до синхронизации родительского каталога | Существует только `absence-observation-v2` с `directorySyncCompleted=false`; операция ещё не завершена |
| После синхронизированного отсутствия журнала | Связанная квитанция и обязательный для `UNINSTALL` надгробный указатель остаются; операция завершена, повтор не изменяет состояние |
| После подготовки базы или активации | Кандидат недоступен рабочему шлюзу |
| Во время обслуживания | Новая умная работа запрещена, старая пара не смешивается |
| После ссылки, до реестра | Кандидат однозначен, но шлюз закрыт |
| После реестра, до манифеста | Новый код загружается только как закрытый шлюз |
| После принятия контроллера, до манифеста | Контроллер остаётся в `MAINTENANCE` |
| После манифеста, до `resume` | Восстановление идёт только вперёд |
| После `resume`, до терминального замораживания | Контроллер готов, но новые клиенты ещё закрыты журналом; журнал можно только довести до `TERMINAL_FROZEN` |
| После удаления целевого объекта отката, до терминального замораживания и квитанции | Журнал остаётся на месте и позволяет только завершить доказанный откат; замороженный журнал до публикации квитанции не удаляется |

Машинная проверка перечисляет 215 мест шагов во всех общих
последовательностях и условных ветвях: 167 мест `JOURNAL_MUTABLE` дают ровно
334 проверки двух общих аварийных окон, а 48 самонесущих атомарных или
послезамороженных мест проверяются своими фиксированными границами. Отдельно
проверяются все четыре пары физического присутствия журнала и квитанции.

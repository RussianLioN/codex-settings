---
name: using-smart-subagents
description: Use when an adaptive Codex turn is active and the task may benefit from independently verifiable delegated work.
---

# Использование умных субагентов

## Основное правило

При наличии добавочного контекста умного хода сначала один раз вызови
`smart_plan`. Контроллер, а не корневая модель, выбирает модель, уровень
рассуждения и профиль прав каждого узла.

При умном возобновлении обработчик может сообщить о присоединённом старом
маршруте. В таком случае не вызывай новый `smart_plan`, пока этот маршрут не
станет конечным: вызови `route_start`, если запуск ещё не создан, затем
продолжай `smart_wait`. После получения и проверки старого результата создай
ровно один новый `planInput` для текущего запроса и вызови `smart_plan`.

В управляемом ходе используй прямые имена команд:
`mcp__codex_smart_subagents__smart_plan`,
`mcp__codex_smart_subagents__route_start`,
`mcp__codex_smart_subagents__smart_wait` и
`mcp__codex_smart_subagents__smart_cancel`. Не ищи их в `ALL_TOOLS`: это
отдельное доверенное пространство команд корневой модели.

Не выдумывай идентификаторы маршрута, узла или запуска. Привязку хода и
шлюз активации сервер получает сам из проверенного контекста. Если добавочного
контекста нет, работай `direct`.

## Что передавать в план

- Делегируй только независимые и проверяемые подзадачи.
- Передавай миссию, роль, зависимости, ссылки на контекст, оценки и флаги
  риска.
- Не передавай пути, команды, переменные окружения, модель, уровень
  рассуждения или профиль прав.
- Публичный `routingInput` содержит только `taskFacts`, `contextBundle` и
  `roleTemplateId`. В `taskFacts.delegation` передавай только проверяемость и
  число независимых единиц; разрешение делегирования и остальные служебные
  поля добавляет контроллер.
- Не перепечатывай нормативный объект и не вычисляй контрольные суммы вручную.
  Возьми абсолютный путь этого `SKILL.md`, от каталога навыка поднимись на два
  уровня к корню подключаемого модуля и используй находящийся там
  `scripts/prepare_smart_plan.py`. Передай помощнику короткий смысловой объект
  через `--spec-json`; он сам копирует нормативный `baseInput`, проверяет поля,
  вычисляет SHA-256, `byteLength`, связанные `evidenceSha256` и
  `contextBundle.totalBytes` по точным байтам UTF-8 и печатает готовый
  `planInput`.
- Выбери смысловую роль по самой подзадаче, а не по роли корневого диалога:
  - `researcher-v1` — чтение, поиск и извлечение фактов; обязательные виды
    контекста: `task-request`, `source-excerpt`;
  - `diagnostician-v1` — поиск причины сбоя; обязательные виды:
    `task-request`, `source-excerpt`, `validation-result`;
  - `validator-v1` — независимая проверка результата; обязательные виды:
    `task-request`, `dependency-summary`, `validation-result`;
  - `risk_auditor-v1` — независимая проверка рисков; обязательные виды:
    `task-request`, `policy-excerpt`, `dependency-summary`;
  - `implementer-v1` — только изменение файлов; обязательные виды:
    `task-request`, `repository-instruction`, `dependency-summary`.

  Запиши выбранный идентификатор в `roleTemplateId` и приведи виды записей
  `contextBundle.entries` к обязательному набору этой роли. Лишняя запись
  допустима, недостающая — нет. Роль задаёт характер работы и профиль прав;
  модель и глубину рассуждений по-прежнему выбирает контроллер.
- До единственного вызова `smart_plan` обязательно получи успешный ответ
  `prepare_smart_plan.py`. Не подменяй помощника кодом с `TextEncoder`, Web
  Crypto или обрезанным чтением нормативного файла: эти средства не входят в
  договор среды выполнения. При ошибке помощника исправь смысловой объект, а
  не вызывай `smart_plan` с частичными данными.
- Оценки `q`, `p`, `v`, `o` определяй по нормативным описаниям в `tools/list`;
  `factorClaims` для `q`, `v`, `o` сохраняй из образца и меняй только при
  наличии соответствующего доказательства. Значение `p` выводит контроллер
  из формы работы и правил делегирования.
  Неизвестное значение не считай нулём: маршрутизатор выбирает
  консервативную верхнюю границу.
- Для простой, непроверяемой либо запрещённой к делегированию работы предложи
  консервативную оценку; решение `direct` вернёт контроллер.
- При `clarify` задай пользователю вопрос и не запускай маршрут.

## Выполнение

1. Сначала опиши узлы смысловым объектом и передай его проверенному помощнику.
   В каждом узле обязательны `clientNodeId`, `dependencyIds`, `taskText`,
   `roleTemplateId`, три доказательства `request`, `policy`, `scope`, четыре
   целых значения `workShape`, два значения `delegation` и `contextEntries`
   нужных для роли видов. `factorClaims` добавляй только для доказанных
   отклонений; остальные помощник помечает как неизвестные, а не как нулевые.
   Точный образец одного узла:

   ```javascript
   const spec = {
     nodes: [{
       clientNodeId: "stable-node-id",
       dependencyIds: [],
       taskText: "Точное описание подзадачи.",
       roleTemplateId: "researcher-v1",
       evidence: [
         {evidenceRefId: "request", kind: "user-request",
          statement: "Что именно просит пользователь."},
         {evidenceRefId: "policy", kind: "explicit-policy",
          statement: "Почему делегирование разрешено или не требуется."},
         {evidenceRefId: "scope", kind: "repository-file",
          statement: "Границы и форма этой подзадачи."},
       ],
       workShape: {scopeUnits: 1, workUnits: 1, boundaries: 1, workstreams: 1},
       delegation: {objectivelyVerifiable: true, independentWorkUnits: 1},
       contextEntries: [
         {contextRefId: "request", kind: "task-request",
          evidenceRefIds: ["request"], content: "Точный запрос."},
         {contextRefId: "source", kind: "source-excerpt",
          evidenceRefIds: ["scope"], content: "Нужный исходный контекст."},
       ],
     }],
   };
   const shellQuote = value => "'" + value.replaceAll("'", "'\"'\"'") + "'";
   const prepared = await tools.exec_command({
     cmd: "python3 " + shellQuote(builderPath) + " --spec-json " +
          shellQuote(JSON.stringify(spec)),
     workdir: projectRoot,
     yield_time_ms: 10000,
     max_output_tokens: 30000,
   });
   if (prepared.exit_code !== 0) throw new Error(prepared.output);
   const planInput = JSON.parse(prepared.output);
   const plan = await tools.mcp__codex_smart_subagents__smart_plan(planInput);
   ```

   Здесь `builderPath` — абсолютный путь к `scripts/prepare_smart_plan.py`, а
   `projectRoot` — текущий рабочий каталог. Не вставляй данные пользователя в
   команду без `shellQuote`. Ответ помощника уже содержит `nodes` на верхнем
   уровне: это готовый `planInput`. Никогда не присваивай его переменной
   `routingInput` и не оборачивай повторно в новый `nodes`.
   Для нескольких узлов задай каждому уникальный `clientNodeId`, а в
   `dependencyIds` перечисли только идентификаторы его предшественников.
2. При `direct` выполни задачу в корневом диалоге.
3. При `delegate` вызови `route_start` отдельно для указанного узла.
4. Первый `smart_wait` вызывай с `startRequestId` и `cursor: null`. В следующие
   вызовы передавай в `cursor` только непустой `nextCursor`, возвращённый
   предыдущим ответом. Повторяй, пока состояние не станет конечным.
5. Если маршрут устарел или больше не нужен, вызови `smart_cancel` с
   подходящим кодом причины.

Проверяй итоговые доказательства самостоятельно. Кандидат из карантина не
означает применение изменений в исходный репозиторий.

## Ограничения событий

`UserPromptSubmit` сохраняет ограниченный контекст текущего хода. Одноразовую
привязку выпускает сервер при `smart_plan`. `Stop` версии 2 не угадывает
состояние по журналу: авторитетны только долговечная база и явные ответы
`smart_wait`. События не применяют результат дочернего процесса автоматически.
Не разбирай журнал диалога как устойчивый интерфейс.

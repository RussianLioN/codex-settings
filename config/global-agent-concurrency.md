<!-- BEGIN CODEX AGENT CONCURRENCY -->
## Субагенты
policy_version=1
max_subagents_per_session=19
admission_backend={{ADMISSION_BACKEND}}

- До 19 субагентов на сессию; корень отдельно, другие вкладки не вычитаются.
- Состав минимально достаточный; полный Consilium — 19 ролей.
- Завершение не означает закрытие потока или освобождение места.
- macOS Air/Pro: обязательный fd-doctor; Linux/Windows: native. Отсутствующий или неизвестный backend запрещает запуск. Ошибку doctor нельзя обходить через native.
- Допуск проверяй на запрошенный размер. OK/ALLOW разрешает его; WARN — резерв до 6; BLOCK запрещает запуск.
- Для 7–19 используй доверенный навык, SHA и манифест по parallel-review-wave либо Consilium. Волна плоская, без вложенного делегирования; области записи не пересекаются.
<!-- END CODEX AGENT CONCURRENCY -->

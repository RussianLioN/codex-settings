from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType


REPO = Path(__file__).resolve().parents[2]
VALIDATOR = REPO / "scripts" / "validate_docs_navigation.py"
AUTONOMOUS_VALIDATOR = (
    REPO / "scripts" / "validate_autonomous_workflow.py"
)
ROOT_STATE_MUTATION_MARKER = "Реализовано для Codex 0.144.4"


def root_catalog_fixture() -> str:
    """Return a valid root catalog with a stable cell for mutation tests."""

    root = (REPO / "README.md").read_text(encoding="utf-8")
    lines = root.splitlines()
    try:
        header = lines.index("| Задача | Состояние | Куда перейти |")
        data_index = header + 2
        cells = lines[data_index].split("|")
    except (ValueError, IndexError) as exc:
        raise AssertionError("root quick-route table fixture is missing") from exc
    if len(cells) != 5 or cells[0] or cells[-1]:
        raise AssertionError("root quick-route data row is malformed")
    cells[2] = f" {ROOT_STATE_MUTATION_MARKER} "
    lines[data_index] = "|".join(cells)
    return "\n".join(lines) + ("\n" if root.endswith("\n") else "")


def load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "validate_docs_navigation_under_test",
        VALIDATOR,
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {VALIDATOR}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_autonomous_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "validate_autonomous_workflow_under_test",
        AUTONOMOUS_VALIDATOR,
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {AUTONOMOUS_VALIDATOR}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def issue_codes(issues: object) -> set[str | None]:
    return {
        getattr(issue, "code", None)
        for issue in issues  # type: ignore[union-attr]
    }


class DocsNavigationValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()

    def test_validator_script_exists(self) -> None:
        self.assertTrue(VALIDATOR.is_file(), VALIDATOR)

    def test_current_repository_navigation_is_valid(self) -> None:
        self.assertEqual(
            (),
            self.validator.validate_repository(REPO),
        )

    def test_live_validation_report_is_published_and_linked(self) -> None:
        report = (
            REPO
            / "docs/analysis/2026-07-20-adaptive-subagents-v2-validation.md"
        )
        self.assertTrue(report.is_file(), report)
        report_text = report.read_text(encoding="utf-8")
        self.assertIn("route2_", report_text)
        self.assertIn("gpt-5.6-luna", report_text)
        self.assertIn("reasoningEffort", report_text)
        self.assertIn("`SUCCEEDED`", report_text)

        links = {
            REPO / "README.md": (
                "docs/analysis/"
                "2026-07-20-adaptive-subagents-v2-validation.md"
            ),
            REPO / "plugins/codex-smart-subagents/README.md": (
                "../../docs/analysis/"
                "2026-07-20-adaptive-subagents-v2-validation.md"
            ),
            REPO / "docs/analysis/adaptive-subagents-v2-flow.md": (
                "2026-07-20-adaptive-subagents-v2-validation.md"
            ),
            REPO / "docs/runbooks/adaptive-subagents-v2-operations.md": (
                "../analysis/"
                "2026-07-20-adaptive-subagents-v2-validation.md"
            ),
        }
        for path, link in links.items():
            document = path.read_text(encoding="utf-8")
            with self.subTest(path=path.relative_to(REPO)):
                self.assertIn(f"]({link})", document)
                self.assertNotIn("отчёт ещё не опубликован", document.lower())
                self.assertNotIn(
                    "путь будущего актуального отчёта",
                    document.lower(),
                )

    def test_root_exposes_all_six_v2_flow_diagrams(self) -> None:
        root = (REPO / "README.md").read_text(encoding="utf-8")
        flow_path = REPO / "docs/analysis/adaptive-subagents-v2-flow.md"
        flow = self.validator.parse_markdown(
            flow_path.read_text(encoding="utf-8")
        )
        anchors = (
            "полный-поток-запроса",
            "поток-пишущего-результата",
            "возобновление-умного-маршрута",
            "обновление-откат-и-удаление-установки",
            "восстановление-временного-процесса-установщика",
            "восстановление-маршрута-после-прерывания",
        )

        for anchor in anchors:
            with self.subTest(anchor=anchor):
                self.assertIn(anchor, flow.anchors)
                self.assertIn(
                    "(docs/analysis/adaptive-subagents-v2-flow.md"
                    f"#{anchor})",
                    root,
                )

        mermaid = tuple(
            fence for fence in flow.fences if fence.language == "mermaid"
        )
        self.assertEqual(6, len(mermaid))
        self.assertEqual(
            [
                "flowchart TD",
                "sequenceDiagram",
                "flowchart TD",
                "flowchart TD",
                "flowchart TD",
                "flowchart TD",
            ],
            [
                self.validator._first_content_line(fence.content)
                for fence in mermaid
            ],
        )
        self.assertIn(
            "(plugins/codex-smart-subagents/README.md"
            "#корневая-модель-и-роль-agentsmd)",
            root,
        )

    def test_sol_medium_and_ultra_guidance_is_complete_and_honest(self) -> None:
        root_path = REPO / "README.md"
        plugin_path = REPO / "plugins/codex-smart-subagents/README.md"
        runbook_path = (
            REPO / "docs/runbooks/adaptive-subagents-v2-operations.md"
        )
        flow_path = REPO / "docs/analysis/adaptive-subagents-v2-flow.md"
        plan_path = (
            REPO
            / "docs/superpowers/plans/"
            "2026-07-28-sol-medium-native-ultra.md"
        )
        documents = {
            "root": root_path.read_text(encoding="utf-8"),
            "plugin": plugin_path.read_text(encoding="utf-8"),
            "runbook": runbook_path.read_text(encoding="utf-8"),
            "flow": flow_path.read_text(encoding="utf-8"),
        }

        self.assertTrue(plan_path.is_file(), plan_path)
        self.assertIn(
            "](docs/superpowers/plans/2026-07-28-sol-medium-native-ultra.md)",
            documents["root"],
        )

        required_everywhere = (
            "`gpt-5.6-sol`",
            "`gpt-5.6-terra`",
            "`medium`",
            "`codex-native`",
            "кодом 69",
        )
        for document_name, document in documents.items():
            for term in required_everywhere:
                with self.subTest(document=document_name, term=term):
                    self.assertIn(term, document)

        for document_name in ("plugin", "runbook", "flow"):
            document = documents[document_name]
            with self.subTest(document=document_name, behavior="ultra"):
                self.assertIn(
                    "codex -c 'model_reasoning_effort=\"ultra\"'",
                    document,
                )
                self.assertIn("`/model`", document)
                self.assertRegex(
                    document,
                    r"[Яя]вно\s+зада\w*[^.]{0,120}сохраня",
                )
                self.assertRegex(
                    document,
                    r"до\s+разрешателя и\s+контроллера",
                )
                self.assertRegex(
                    document,
                    r"`pro` — план подписки, а не уровень\s+рассуждений",
                )
                self.assertRegex(
                    document,
                    r"дочерних\s+`allowedPairs` нет\s+`gpt-5\.6-sol \+ medium`\s+и `ultra`",
                )
                self.assertRegex(
                    document,
                    r"[Уу]же работающую\s+управляемую сессию нельзя превратить в нативную",
                )

        fallback = (
            "codex-smart: COORDINATOR_PAIR_FALLBACK; "
            "gpt-5.6-sol+medium недоступен, используется "
            "gpt-5.6-terra+medium"
        )
        for document_name, document in documents.items():
            with self.subTest(document=document_name, behavior="fallback"):
                self.assertIn(fallback, document)
                self.assertNotIn("codex-native+", document)
                self.assertNotIn("codex-ultra", document)

        flow = self.validator.parse_markdown(documents["flow"])
        mermaid = tuple(
            fence for fence in flow.fences if fence.language == "mermaid"
        )
        self.assertEqual(6, len(mermaid))
        first_diagram = mermaid[0].content
        for branch in (
            "model_reasoning_effort=ultra",
            "Нативный Codex без контроллера",
            "gpt-5.6-sol + medium",
            "gpt-5.6-terra + medium",
            "Завершить запуск кодом 69",
            "Делегирование дочерних узлов",
        ):
            with self.subTest(branch=branch):
                self.assertIn(branch, first_diagram)
        self.assertLess(
            first_diagram.index("model_reasoning_effort=ultra"),
            first_diagram.index("codex-smart классифицирует управляемый запуск"),
        )

    def test_current_guides_use_exact_hook_event_names(self) -> None:
        for path in (
            REPO / "plugins/codex-smart-subagents/README.md",
            REPO / "docs/runbooks/adaptive-subagents-v2-operations.md",
            REPO / "docs/migrations/adaptive-subagents-v2.md",
        ):
            document = path.read_text(encoding="utf-8")
            with self.subTest(path=path.relative_to(REPO)):
                self.assertIn(
                    "`SessionStart`, `UserPromptSubmit`, `Stop` и `SessionEnd`",
                    document,
                )
                self.assertNotIn("`userPromptSubmit` и `stop`", document)

    def test_smart_resume_is_reachable_from_root_and_has_flow_diagram(self) -> None:
        root = (REPO / "README.md").read_text(encoding="utf-8")
        plugin = (
            REPO / "plugins/codex-smart-subagents/README.md"
        ).read_text(encoding="utf-8")
        flow_source = (
            REPO / "docs/analysis/adaptive-subagents-v2-flow.md"
        ).read_text(encoding="utf-8")
        flow = self.validator.parse_markdown(flow_source)

        self.assertIn("Возобновить умный сеанс проекта", root)
        self.assertIn(
            "plugins/codex-smart-subagents/README.md#умное-возобновление-сеанса",
            root,
        )
        self.assertIn("## Умное возобновление сеанса", plugin)
        self.assertIn("codex resume --last", plugin)
        self.assertIn("## Возобновление умного маршрута", flow_source)
        resume_diagrams = [
            fence.content
            for fence in flow.fences
            if fence.language == "mermaid" and "SessionStart(resume)" in fence.content
        ]
        self.assertEqual(1, len(resume_diagrams))
        for value in (
            "RESUME_OWNER_ACTIVE",
            "smart_wait",
            "ровно один новый smart_plan",
        ):
            self.assertIn(value, resume_diagrams[0])

    def test_current_guides_explain_all_four_smart_turn_tools(self) -> None:
        for path in (
            REPO / "plugins/codex-smart-subagents/README.md",
            REPO / "docs/runbooks/adaptive-subagents-v2-operations.md",
            REPO / "docs/analysis/adaptive-subagents-v2-flow.md",
        ):
            document = path.read_text(encoding="utf-8")
            with self.subTest(path=path.relative_to(REPO)):
                self.assertIn("`smart_cancel`", document)
                self.assertIn("`USER_REQUESTED`", document)
                self.assertIn("`TURN_ENDED`", document)
                self.assertIn("`ROUTE_SUPERSEDED`", document)

    def test_installer_recovery_commands_are_not_conflated(self) -> None:
        root = (REPO / "README.md").read_text(encoding="utf-8")
        migration = (
            REPO / "docs/migrations/adaptive-subagents-v2.md"
        ).read_text(encoding="utf-8")
        runbook = (
            REPO / "docs/runbooks/adaptive-subagents-v2-operations.md"
        ).read_text(encoding="utf-8")
        plugin = (
            REPO / "plugins/codex-smart-subagents/README.md"
        ).read_text(encoding="utf-8")
        flow_path = REPO / "docs/analysis/adaptive-subagents-v2-flow.md"
        flow_source = flow_path.read_text(encoding="utf-8")
        flow = self.validator.parse_markdown(flow_source)
        route_anchor = "восстановление-маршрута-после-прерывания"

        self.assertIn(route_anchor, flow.anchors)
        self.assertNotIn("что-происходит-после-прерывания", flow.anchors)
        self.assertIn(f"adaptive-subagents-v2-flow.md#{route_anchor}", root)
        self.assertIn(
            "Продолжить прерванную установку, обновление, откат или удаление",
            root,
        )
        self.assertIn("--cleanup --apply", flow_source)
        for document_name, document in (
            ("runbook", runbook),
            ("plugin", plugin),
            ("flow", flow_source),
            ("migration", migration),
        ):
            with self.subTest(document=document_name):
                self.assertIn("--uninstall --retain-data --apply --json", document)
                self.assertIn("--recover --preview --json", document)
                self.assertIn("--recover --apply --json", document)
                self.assertIn(
                    "`extensions.lifecycleAdapter.journalKind=uninstall`",
                    document,
                )
                self.assertIn(
                    "`extensions.lifecycleAdapter.internalOperationId`",
                    document,
                )
                self.assertRegex(document, r"тот же\s+`operationId`")
                self.assertIn("--cleanup --apply --json", document)

        for obsolete_claim in (
            "Общий установочный `--recover` относится только к установке, "
            "обновлению и откату",
            "Общий установочный `--recover` журнал удаления не продолжает",
            "общий `--recover` их отдельные журналы не продолжает",
            "общий `--recover` не перенаправляет один вид журнала в другой",
            "общий `--recover` не продолжает отдельные журналы удаления и уборки",
        ):
            with self.subTest(obsolete_claim=obsolete_claim):
                self.assertNotIn(
                    obsolete_claim,
                    "\n".join((runbook, plugin, flow_source, migration)),
                )

    def test_operator_guides_keep_inspect_projection_honest(self) -> None:
        for path in (
            REPO / "docs/runbooks/adaptive-subagents-v2-operations.md",
            REPO / "docs/analysis/adaptive-subagents-v2-flow.md",
            REPO / "docs/migrations/adaptive-subagents-v2.md",
        ):
            document = path.read_text(encoding="utf-8")
            with self.subTest(path=path.relative_to(REPO)):
                self.assertIn("`inspect` не возвращает зависимости", document)
                self.assertIn("`terminalResult` возвращает `smart_wait`", document)

    def test_runbook_covers_maintenance_and_candidate_failure_boundaries(
        self,
    ) -> None:
        runbook = (
            REPO / "docs/runbooks/adaptive-subagents-v2-operations.md"
        ).read_text(encoding="utf-8")
        self.assertIn("старые commit-квитанции не удаляются", runbook)
        for code in (
            "ROLLBACK_VERIFY_CANDIDATE_FAILED",
            "ROLLBACK_VERIFY_CANDIDATE_ACCEPTANCE_INVALID",
            "ROLLBACK_CANDIDATE_SUCCESSOR_INVALID",
            "CANDIDATE_SPAWN_COMPLETED_UNOBSERVABLE",
            "CANDIDATE_SPAWN_RECOVERY_EXPIRED",
            "SHUTDOWN_COMPLETION_TIMEOUT",
            "SHUTDOWN_PROCESS_*",
            "SHUTDOWN_LOCK_*",
            "SHUTDOWN_SOCKET_*",
            "SHUTDOWN_ORPHAN_PROOF_*",
        ):
            with self.subTest(code=code):
                self.assertIn(f"`{code}`", runbook)
        for state in ("`CANDIDATE_READY`", "`SUCCEEDED`", "`VERIFIED`"):
            with self.subTest(state=state):
                self.assertIn(state, runbook)
        self.assertIn(
            "`CANDIDATE_READY` сохраняется в полном договоре состояний",
            runbook,
        )
        self.assertIn(
            "успешная попытка пишущего узла завершается как `SUCCEEDED`",
            runbook,
        )
        self.assertIn(
            "публикация кандидата отдельно получает `VERIFIED`",
            runbook,
        )

    def test_v2_migration_guide_uses_only_current_operator_entrypoints(self) -> None:
        guide = (REPO / "docs/migrations/adaptive-subagents-v2.md").read_text(
            encoding="utf-8"
        )
        for obsolete in (
            "CODEX_SMART_ENABLED",
            "AWAITING_HOOK_TRUST",
            "codex-smart-subagents-admin rollback",
            "scripts/rollback_adaptive_subagents.py",
            "`explain`",
            "`report`",
            "`metrics`",
        ):
            with self.subTest(obsolete=obsolete):
                self.assertNotIn(obsolete, guide)
        for current in (
            "~/.local/bin/codex-smart",
            "~/.local/bin/codex-smart-subagents-admin status",
            "~/.local/bin/codex-smart-subagents-admin stop",
            "~/.local/bin/codex-smart-subagents-admin recover --dry-run",
        ):
            with self.subTest(current=current):
                self.assertIn(current, guide)

    def test_lifecycle_commands_are_discoverable_from_current_guides(self) -> None:
        root = (REPO / "README.md").read_text(encoding="utf-8")
        migration = (
            REPO / "docs/migrations/adaptive-subagents-v2.md"
        ).read_text(encoding="utf-8")
        runbook = (
            REPO / "docs/runbooks/adaptive-subagents-v2-operations.md"
        ).read_text(encoding="utf-8")
        plugin = (
            REPO / "plugins/codex-smart-subagents/README.md"
        ).read_text(encoding="utf-8")

        self.assertIn("обновление, откат, восстановление или удаление", root)
        commands = (
            "--rollback --preview --json",
            "--rollback --apply --json",
            "--uninstall --retain-data --preview --json",
            "--uninstall --retain-data --apply --json",
            "--recover --preview --json",
            "--recover --apply --json",
            "--cleanup --preview --json",
            "--cleanup --apply --json",
            "--inspect --json",
        )
        for document_name, document in (
            ("migration", migration),
            ("runbook", runbook),
            ("plugin", plugin),
        ):
            self.assertNotIn("readiness=FULL_READY", document)
            self.assertNotIn("status=FULL_READY", document)
            for command in commands:
                with self.subTest(document=document_name, command=command):
                    self.assertIn(command, document)

        for obsolete in (
            "не предоставляет команду автоматического отката",
            "подготовить отдельную управляемую процедуру обновления",
            "Административный интерфейс версии 2 намеренно ограничен командами",
        ):
            with self.subTest(obsolete=obsolete):
                self.assertNotIn(obsolete, runbook)

    def test_autonomous_validator_includes_docs_navigation_check(
        self,
    ) -> None:
        module = load_autonomous_validator()
        calls: list[str] = []
        for name, value in tuple(vars(module).items()):
            if name.startswith("check_") and callable(value):
                setattr(module, name, lambda: None)

        def record_docs_check() -> None:
            calls.append("docs")

        module.check_docs_navigation = record_docs_check
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(0, module.main())
        self.assertEqual(["docs"], calls)

    def test_autonomous_validator_reports_docs_setup_failure(
        self,
    ) -> None:
        state_path = (
            self.repo
            / "plugins/codex-smart-subagents/src/"
            "codex_smart_subagents/state.py"
        )
        state_path.write_text("not valid python )\n", encoding="utf-8")

        module = load_autonomous_validator()
        module.REPO = self.repo
        module.DOCS_NAVIGATION_VALIDATOR = VALIDATOR

        with self.assertRaisesRegex(
            AssertionError,
            "documentation navigation validation failed",
        ):
            module.check_docs_navigation()

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.directory.name) / "repo"
        self.repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(self.repo)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._write_valid_repository()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_accepts_fully_connected_documentation(self) -> None:
        self.assertEqual((), self.validator.validate_repository(self.repo))

    def test_accepts_tracked_cyrillic_paths_spaces_and_duplicate_anchors(
        self,
    ) -> None:
        target = Path("docs/Раздел с пробелом.md")
        self.write(
            target,
            "# Повтор\n\n## Повтор\n\n[Назад](guides/autonomous-workflow.md)\n",
        )
        self.append(
            Path("docs/guides/autonomous-workflow.md"),
            "\n[Раздел](../%D0%A0%D0%B0%D0%B7%D0%B4%D0%B5%D0%BB%20"
            "%D1%81%20%D0%BF%D1%80%D0%BE%D0%B1%D0%B5%D0%BB%D0%BE%D0%BC.md"
            "#повтор-1)\n",
        )
        self.track(target)

        self.assertEqual((), self.validator.validate_repository(self.repo))

    def test_accepts_parentheses_in_inline_link_destination(self) -> None:
        target = Path("docs/guide_(v2).md")
        self.write(target, "# Руководство\n")
        self.track(target)
        self.append(
            Path("README.md"),
            "\n[Руководство](docs/guide_(v2).md)\n",
        )

        self.assertEqual((), self.validator.validate_repository(self.repo))

    def test_first_reference_definition_wins(self) -> None:
        self.append(
            Path("README.md"),
            (
                "\n[Повторное определение]\n"
                "\n"
                "[Повторное определение]: docs/guides/full-access.md\n"
                "[Повторное определение]: docs/missing.md\n"
            ),
        )

        self.assertEqual((), self.validator.validate_repository(self.repo))

    def test_rejects_broken_html_and_shortcut_reference_links(
        self,
    ) -> None:
        self.append(
            Path("README.md"),
            (
                '\n<a href="docs/missing-html.md">HTML</a>\n'
                "[Сокращённая ссылка]\n"
                "\n"
                "[Сокращённая ссылка]: docs/missing-shortcut.md\n"
            ),
        )

        issues = self.validator.validate_repository(self.repo)
        missing = [
            issue
            for issue in issues
            if getattr(issue, "code", None)
            == "LOCAL_LINK_TARGET_MISSING"
        ]
        self.assertEqual(2, len(missing), issues)

    def test_rejects_missing_untracked_and_outside_targets(self) -> None:
        self.append(
            Path("README.md"),
            "\n[Нет](docs/missing.md)\n"
            "[Не отслеживается](docs/untracked.md)\n"
            "[Снаружи](../outside.md)\n",
        )
        self.write(Path("docs/untracked.md"), "# Не отслеживается\n")
        outside = self.repo.parent / "outside.md"
        outside.write_text("# Снаружи\n", encoding="utf-8")

        codes = issue_codes(self.validator.validate_repository(self.repo))

        self.assertIn("LOCAL_LINK_TARGET_MISSING", codes)
        self.assertIn("LOCAL_LINK_TARGET_UNTRACKED", codes)
        self.assertIn("LOCAL_LINK_OUTSIDE_REPO", codes)

    def test_rejects_encoded_parent_and_symlink_escape(self) -> None:
        outside = self.repo.parent / "outside.md"
        outside.write_text("# Снаружи\n", encoding="utf-8")
        escape = self.repo / "docs" / "escape.md"
        escape.symlink_to(outside)
        self.append(
            Path("README.md"),
            "\n[Кодированный выход](%2E%2E/outside.md)\n"
            "[Ссылка наружу](docs/escape.md)\n",
        )
        self.track(Path("docs/escape.md"))

        issues = self.validator.validate_repository(self.repo)

        outside_issues = [
            issue
            for issue in issues
            if getattr(issue, "code", None) == "LOCAL_LINK_OUTSIDE_REPO"
        ]
        self.assertEqual(2, len(outside_issues), issues)

    def test_rejects_document_symlink_without_reading_outside_repo(
        self,
    ) -> None:
        outside = self.repo.parent / "outside-readme.md"
        outside.write_text(
            self.read(Path("README.md")),
            encoding="utf-8",
        )
        readme = self.repo / "README.md"
        readme.unlink()
        readme.symlink_to(outside)

        self.assertIn(
            "DOCUMENT_NOT_REGULAR",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_rejects_missing_anchor_and_ignores_network_links(self) -> None:
        self.append(
            Path("README.md"),
            "\n[Нет якоря](docs/guides/full-access.md#нет-такого-раздела)\n"
            "[Сеть](https://example.com/missing.md#section)\n"
            "[Почта](mailto:operator@example.com)\n",
        )

        issues = self.validator.validate_repository(self.repo)

        self.assertEqual(
            {"LOCAL_LINK_ANCHOR_MISSING"},
            issue_codes(issues),
            issues,
        )

    def test_explicit_html_anchor_is_case_sensitive(self) -> None:
        self.append(
            Path("docs/guides/full-access.md"),
            '\n<a id="CaseSensitive"></a>\n',
        )
        self.append(
            Path("README.md"),
            (
                "\n[Неверный регистр]"
                "(docs/guides/full-access.md#casesensitive)\n"
            ),
        )

        self.assertIn(
            "LOCAL_LINK_ANCHOR_MISSING",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_multiline_block_html_tags_create_explicit_anchors(
        self,
    ) -> None:
        document = self.validator.parse_markdown(
            '<div id="foo"\n'
            ' class="bar">\n'
            "</div>\n"
            "\n"
            "<table\n"
            ' id="tab">\n'
            "</table>\n"
            "\n"
            "<section\n"
            ' name="named">\n'
            "</section>\n"
            "\n"
            '<table\fid="ff-table">\n'
            "</table>\n"
            "\n"
            "<iframe\n"
            ' id="frame" src="asset.md">\n'
            "</iframe>\n"
        )

        self.assertEqual(
            frozenset({"foo", "tab", "named", "ff-table"}),
            document.anchors,
        )
        self.assertEqual((), document.links)

        form_feed = self.validator.parse_markdown(
            '<a\fhref="target.md" id="anchor">x</a>\n'
        )
        self.assertEqual(frozenset({"anchor"}), form_feed.anchors)
        self.assertEqual(
            ["target.md"],
            [link.target for link in form_feed.links],
        )

        form_feed_block = self.validator.parse_markdown(
            "text\n"
            '<div\fid="block-anchor">\n'
            "[Скрытая](inside.md)\n"
        )
        self.assertEqual(
            frozenset({"block-anchor"}),
            form_feed_block.anchors,
        )
        self.assertEqual((), form_feed_block.links)

        for label, text in {
            "type_one": (
                '<script\ftype="x">\n'
                "[Скрытая](script.md)\n"
                "</script>\n"
            ),
            "declaration": (
                "text <!X\f[Скрытая](declaration.md)>\n"
            ),
            "type_seven": (
                "<custom>\f\n"
                "[Скрытая](custom.md)\n"
            ),
        }.items():
            with self.subTest(form_feed_html=label):
                self.assertEqual(
                    (),
                    self.validator.parse_markdown(text).links,
                )

        for label, text in {
            "type_one": (
                '<script\vtype="x">\n'
                "[Скрытая](script-vt.md)\n"
                "</script>\n"
            ),
            "type_six": (
                '<div\vid="not-an-anchor">\n'
                "[Скрытая](div-vt.md)\n"
            ),
            "declaration": (
                "text <!X\v[Скрытая](declaration-vt.md)>\n"
            ),
        }.items():
            with self.subTest(vertical_tab_html=label):
                document = self.validator.parse_markdown(text)
                self.assertEqual((), document.links)
                self.assertNotIn("not-an-anchor", document.anchors)

        non_html_space = self.validator.parse_markdown(
            '<a\u00a0href="missing.md" id="missing">x</a>\n'
        )
        self.assertEqual(frozenset(), non_html_space.anchors)
        self.assertEqual((), non_html_space.links)

    def test_rejects_unreachable_tracked_document(self) -> None:
        orphan = Path("docs/orphan.md")
        self.write(orphan, "# Потерянный документ\n")
        self.track(orphan)

        self.assertIn(
            "DOCUMENT_UNREACHABLE",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_comments_inline_code_and_images_do_not_create_navigation(
        self,
    ) -> None:
        readme = self.read(Path("README.md")).replace(
            "- [Полный доступ](docs/guides/full-access.md)\n",
            "",
        )
        self.write(
            Path("README.md"),
            (
                readme
                + "\n<!--\n[Полный доступ]"
                "(docs/guides/full-access.md)\n-->\n"
                + "`[Полный доступ](docs/guides/full-access.md)`\n"
            ),
        )
        image_only = Path("docs/image-only.md")
        self.write(image_only, "# Только изображение\n")
        self.track(image_only)
        self.append(
            Path("README.md"),
            "\n![Скрытый переход](docs/image-only.md)\n",
        )

        codes = issue_codes(self.validator.validate_repository(self.repo))
        self.assertIn("ROOT_ENTRYPOINT_MISSING", codes)
        self.assertIn("DOCUMENT_UNREACHABLE", codes)

    def test_block_code_and_raw_html_do_not_create_markdown_navigation(
        self,
    ) -> None:
        readme = self.read(Path("README.md")).replace(
            "- [Полный доступ](docs/guides/full-access.md)\n",
            "",
        )
        self.write(
            Path("README.md"),
            (
                readme
                + "\n<!-- Завершить предшествующий список. -->\n\n"
                + "    [Отступный код]"
                "(docs/guides/full-access.md)\n"
                + "\n`\n[Многострочный код]"
                "(docs/guides/full-access.md)\n`\n"
                + "\n<pre>\n[Сырой HTML]"
                "(docs/guides/full-access.md)\n</pre>\n"
                + "\n<div>\n[Блочный сырой HTML]"
                "(docs/guides/full-access.md)\n</div>\n\n"
                + "\n>     [Код в цитате]"
                "(docs/guides/full-access.md)\n"
                + "\n-     [Код в списке]"
                "(docs/guides/full-access.md)\n"
                + "\n> ~~~\n> [Ограждение в цитате]"
                "(docs/guides/full-access.md)\n> ~~~\n"
                + "\n<pre><script></script>"
                "[Вложенный сырой HTML]"
                "(docs/guides/full-access.md)</pre>\n"
            ),
        )

        codes = issue_codes(self.validator.validate_repository(self.repo))

        self.assertIn("ROOT_ENTRYPOINT_MISSING", codes)
        self.assertIn("DOCUMENT_UNREACHABLE", codes)

    def test_indented_list_continuation_remains_navigation(self) -> None:
        document = self.validator.parse_markdown(
            "- Элемент\n"
            "\n"
            "    [Продолжение](visible.md)\n"
        )

        self.assertEqual(
            ["visible.md"],
            [link.target for link in document.links],
        )

    def test_inline_commonmark_precedence_and_destinations(self) -> None:
        no_navigation = {
            "escaped_html": '\\<a href="missing.md">x</a>\n',
            "processing": "text <?pi [x](hidden.md) ?>\n",
            "declaration": "text <!ELEMENT [x](hidden.md)>\n",
            "cdata": "text <![CDATA[[x](hidden.md)]]>\n",
            "autolink": (
                "[foo<http://example.com/?search=](uri)>\n"
            ),
            "sibling_list_items": (
                "- <a\n"
                '- href="missing.md">x</a>\n'
            ),
            "line_break_in_angle_destination": (
                "[x](<foo\nbar>)\n"
            ),
        }
        for label, source in no_navigation.items():
            with self.subTest(label=label):
                self.assertEqual(
                    (),
                    self.validator.parse_markdown(source).links,
                )

        self.assertEqual(
            frozenset(),
            self.validator.parse_markdown(
                '\\<span id="fake">x</span>\n'
            ).anchors,
        )

        visible_after_invalid_comment = self.validator.parse_markdown(
            "foo <!--> [x](visible.md) -->\n"
        )
        visible_after_paragraph = self.validator.parse_markdown(
            "text <!--\n\n[x](visible.md)\n-->\n"
        )
        self.assertEqual(
            ["visible.md"],
            [
                link.target
                for link in visible_after_invalid_comment.links
            ],
        )
        self.assertEqual(
            ["visible.md"],
            [link.target for link in visible_after_paragraph.links],
        )
        tagfiltered_html = self.validator.parse_markdown(
            '<script>[x](hidden.md)<a href="visible.md">x</a>'
            "</script>\n"
        )
        self.assertEqual(
            ["visible.md"],
            [link.target for link in tagfiltered_html.links],
        )

        destinations = {
            "[x]()": "",
            "[x](<>)": "",
            '[x](foo"bar)': 'foo"bar',
            "[x](<!-->)": "!--",
            "[x](<`foo`>)": "`foo`",
            "[x](foo`bar`)": "foo`bar`",
            "[x](foo<!--bar-->)": "foo<!--bar-->",
            (
                "[foo](not a link)\n\n"
                "[foo]: /url1\n"
            ): "/url1",
        }
        for source, expected in destinations.items():
            with self.subTest(source=source):
                self.assertEqual(
                    [expected],
                    [
                        link.target
                        for link in self.validator.parse_markdown(
                            source
                        ).links
                    ],
                )

        image = self.validator.parse_markdown(
            "![[x](inner.md)](image.png)\n"
        )
        nested_image = self.validator.parse_markdown(
            "![[[foo](uri1)](uri2)](uri3)\n"
        )
        self.assertEqual(
            [("image.png", False)],
            [
                (link.target, link.navigable)
                for link in image.links
            ],
        )
        self.assertEqual(
            [("uri3", False)],
            [
                (link.target, link.navigable)
                for link in nested_image.links
            ],
        )

    def test_multiline_inline_boundaries_follow_gfm(self) -> None:
        sources = (
            "[x\n2. y](dest.md)\n",
            "> - [x\n>   y](dest.md)\n",
            "> [x\ny](dest.md)\n",
            "- [x\ny](dest.md)\n",
            "[x\r\n2. y](dest.md)\r\n",
        )

        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(
                    ["dest.md"],
                    [
                        link.target
                        for link in self.validator.parse_markdown(
                            source
                        ).links
                    ],
                )

        html_sources = (
            "- <a\n"
            '  href="ok.md">x</a>\n',
            "> - <a\n"
            '>   href="ok.md">x</a>\n',
        )
        for source in html_sources:
            with self.subTest(source=source):
                self.assertEqual(
                    ["ok.md"],
                    [
                        link.target
                        for link in self.validator.parse_markdown(
                            source
                        ).links
                    ],
                )

        blocked = (
            "[x\n1. y](dest.md)\n",
            "1. [x\n2. y](dest.md)\n",
            "> - [x\n> - y](dest.md)\n",
            "> - <a\n> - href=\"bad.md\">x</a>\n",
        )
        for source in blocked:
            with self.subTest(source=source):
                self.assertEqual(
                    (),
                    self.validator.parse_markdown(source).links,
                )

    def test_multiline_reference_definitions_match_commonmark(
        self,
    ) -> None:
        accepted = (
            (
                "   [foo]:\n"
                "      /url\n"
                "           'the title'\n"
                "[foo]\n"
            ),
            (
                "[foo]: /url '\n"
                "title\n"
                "line1\n"
                "line2\n"
                "'\n"
                "\n"
                "[foo]\n"
            ),
            "[foo]:\n/url\n\n[foo]\n",
            "[foo]: <>\n\n[foo]\n",
        )
        for source in accepted:
            with self.subTest(source=source):
                self.assertEqual(
                    ["/url" if "<>" not in source else ""],
                    [
                        link.target
                        for link in self.validator.parse_markdown(
                            source
                        ).links
                    ],
                )

        rejected = (
            (
                "[foo]: /url 'title\n"
                "\n"
                "with blank line'\n"
                "\n"
                "[foo]\n"
            ),
            "[foo]:\n\n[foo]\n",
            "[foo]: <bar>(baz)\n\n[foo]\n",
            "[foo]: foo\\ bar\n\n[foo]\n",
            "[foo]: foo\\\tbar\n\n[foo]\n",
        )
        for source in rejected:
            with self.subTest(source=source):
                self.assertEqual(
                    (),
                    self.validator.parse_markdown(source).links,
                )

        block_boundaries = (
            "---",
            "***",
            "```",
            "<table>",
        )
        for boundary in block_boundaries:
            with self.subTest(boundary=boundary):
                source = (
                    "[foo]:\n"
                    + boundary
                    + "\n\n[foo]\n"
                )
                self.assertEqual(
                    (),
                    self.validator.parse_markdown(source).links,
                )

        self.assertEqual(
            (),
            self.validator.parse_markdown(
                "[foo]: /url '\n"
                "# heading\n"
                "'\n\n"
                "[foo]\n"
            ).links,
        )
        self.assertEqual(
            ["/url"],
            [
                link.target
                for link in self.validator.parse_markdown(
                    "[foo]:\n"
                    "    /url\n\n"
                    "[foo]\n"
                ).links
            ],
        )
        self.assertEqual(
            ["/url"],
            [
                link.target
                for link in self.validator.parse_markdown(
                    "[foo]: /url\n"
                    "'unclosed\n\n"
                    "[foo]\n"
                ).links
            ],
        )

    def test_html_navigation_requires_a_real_anchor_tag(self) -> None:
        orphan = Path("docs/html-orphan.md")
        self.write(orphan, "# Потерянный документ\n")
        self.track(orphan)
        self.append(
            Path("README.md"),
            (
                '\nпример href="docs/html-orphan.md"\n'
                '<img href="docs/html-orphan.md">\n'
                '`<a href="docs/html-orphan.md">Код</a>`\n'
                '<a h*#bad="x" href="docs/html-orphan.md">Ошибка</a>\n'
                '<a href="docs/html-orphan.md"id="bad">Без пробела</a>\n'
                '<a\u00a0href="docs/html-orphan.md">Неразрывный</a>\n'
                '<pre><a href="docs/guides/full-access.md">'
                "Видимая ссылка</a></pre>\n"
            ),
        )

        codes = issue_codes(self.validator.validate_repository(self.repo))

        self.assertIn("DOCUMENT_UNREACHABLE", codes)
        self.assertNotIn("LOCAL_LINK_TARGET_MISSING", codes)

    def test_multiline_markdown_and_html_links_create_navigation(
        self,
    ) -> None:
        markdown_target = Path("docs/multiline-markdown.md")
        html_target = Path("docs/multiline-html.md")
        self.write(markdown_target, "# Многострочная Markdown-ссылка\n")
        self.write(html_target, "# Многострочная HTML-ссылка\n")
        self.track(markdown_target)
        self.track(html_target)
        self.append(
            Path("plugins/codex-smart-subagents/README.md"),
            (
                "\n[Перейти\n"
                "к документу](../../docs/multiline-markdown.md)\n"
                '<a\n href="../../docs/multiline-html.md">'
                "Перейти</a>\n"
            ),
        )

        self.assertEqual((), self.validator.validate_repository(self.repo))

    def test_multiline_html_link_inside_quote_is_navigation(
        self,
    ) -> None:
        document = self.validator.parse_markdown(
            "> <a\n"
            '> href="target.md">x</a>\n'
        )

        self.assertEqual(
            ["target.md"],
            [link.target for link in document.links],
        )

    def test_multiline_links_respect_blocks_and_line_endings(
        self,
    ) -> None:
        valid = self.validator.parse_markdown(
            "[Первая\n"
            " ссылка](one.md)\n"
            "[Вторая](\n"
            " two.md\n"
            ")\n"
            "- [Третья\n"
            "  ссылка](three.md)\n"
        )
        invalid = self.validator.parse_markdown(
            "[Через\n"
            "\n"
            " абзац](missing.md)\n"
            "- [Через элемент\n"
            "- списка](missing-list.md)\n"
            "[Через блок\n"
            "> цитаты](missing-quote.md)\n"
            "[Через разделитель\n"
            "***\n"
            "текста](missing-rule.md)\n"
            "| Колонка |\n"
            "|---|\n"
            "| [Через ячейки |\n"
            "| таблицы](missing-table.md) |\n"
            '<a\n\n href="missing-html.md">Нет</a>\n'
        )
        line_endings = self.validator.parse_markdown(
            "[Первая](one.md)\r\n"
            "[Вторая](two.md)\r"
            "[Третья](three.md)\n"
        )

        self.assertEqual(
            ["one.md", "two.md", "three.md"],
            [link.target for link in valid.links],
        )
        self.assertEqual((), invalid.links)
        self.assertEqual(
            [1, 2, 3],
            [link.line for link in line_endings.links],
        )

    def test_multiline_links_respect_actual_gfm_block_boundaries(
        self,
    ) -> None:
        pipe_text = self.validator.parse_markdown(
            "[x\n"
            "| y](missing.md)\n"
        )
        fenced = self.validator.parse_markdown(
            "[x\n"
            "```\n"
            "code\n"
            "```\n"
            "y](missing-backtick.md)\n"
            "[x\n"
            "~~~\n"
            "code\n"
            "~~~\n"
            "y](missing-tilde.md)\n"
        )
        table = self.validator.parse_markdown(
            "[x | h\n"
            "---|---\n"
            "a|b\n"
            "y](missing-table.md)\n"
        )
        code_span = self.validator.parse_markdown(
            "`code\n"
            "| [hidden](missing-code.md)\n"
            "more`\n"
        )

        self.assertEqual(
            ["missing.md"],
            [link.target for link in pipe_text.links],
        )
        self.assertEqual((), fenced.links)
        self.assertEqual((), table.links)
        self.assertEqual((), code_span.links)

    def test_heading_inline_code_preserves_anchor_content(self) -> None:
        self.append(
            Path("docs/guides/full-access.md"),
            (
                "\n## Запуск `smart_plan`\n"
                "## Команда `codex --model`\n"
                "## Код `<tag>` и `[x](y)`\n"
                "## foo_bar baz\n"
            ),
        )
        self.append(
            Path("plugins/codex-smart-subagents/README.md"),
            (
                "\n[Вызов]"
                "(../../docs/guides/full-access.md#запуск-smart_plan)\n"
                "[Команда]"
                "(../../docs/guides/full-access.md"
                "#команда-codex---model)\n"
                "[Литеральный код]"
                "(../../docs/guides/full-access.md#код-tag-и-xy)\n"
                "[Подчёркивание]"
                "(../../docs/guides/full-access.md#foo_bar-baz)\n"
            ),
        )

        self.assertEqual((), self.validator.validate_repository(self.repo))

    def test_nested_link_label_and_escaped_destination_are_supported(
        self,
    ) -> None:
        target = Path("docs/guide_(v3).md")
        self.write(target, "# Вложенный раздел\n")
        self.track(target)
        self.append(
            Path("README.md"),
            (
                "\n[Текст [вложенный]]"
                "(docs/guide_\\(v3\\).md#вложенный-раздел)\n"
                "[Сломанная [подпись]](docs/missing-nested.md)\n"
            ),
        )

        issues = self.validator.validate_repository(self.repo)
        missing = [
            issue
            for issue in issues
            if getattr(issue, "code", None)
            == "LOCAL_LINK_TARGET_MISSING"
        ]

        self.assertEqual(1, len(missing), issues)
        self.assertIn("missing-nested.md", missing[0].message)

    def test_invalid_inline_link_tail_does_not_create_navigation(
        self,
    ) -> None:
        orphan = Path("docs/invalid-inline-orphan.md")
        self.write(orphan, "# Потерянный документ\n")
        self.track(orphan)
        self.append(
            Path("README.md"),
            (
                "\n[Неверная ссылка]"
                "(docs/invalid-inline-orphan.md это-не-заголовок)\n"
            ),
        )

        codes = issue_codes(self.validator.validate_repository(self.repo))

        self.assertIn("DOCUMENT_UNREACHABLE", codes)
        self.assertNotIn("LOCAL_LINK_TARGET_MISSING", codes)

    def test_link_title_requires_whitespace_separator(self) -> None:
        document = self.validator.parse_markdown(
            '[Встроенная](<missing-inline.md>"заголовок")\n'
            "[Ссылочная]\n"
            '[Ссылочная]: <missing-reference.md>"заголовок"\n'
            '[Неразрывный](<missing-nbsp.md>\u00a0"заголовок")\n'
            '[Два переноса](<missing-lines.md>\n\n"заголовок")\n'
        )

        self.assertEqual((), document.links)

    def test_reference_label_length_is_bounded(self) -> None:
        accepted = "x" * 999
        rejected = "y" * 1_000
        document = self.validator.parse_markdown(
            f"[{accepted}]: accepted.md\n"
            f"[{accepted}]\n"
            f"[{accepted}][]\n"
            f"[{rejected}]: rejected.md\n"
            f"[{rejected}]\n"
            f"[{rejected}][]\n"
        )

        self.assertEqual(
            ["accepted.md", "accepted.md"],
            [link.target for link in document.links],
        )

    def test_multiline_reference_definition_is_supported(self) -> None:
        document = self.validator.parse_markdown(
            "[Переход]:\n"
            "  target.md\n"
            "\n"
            "[Переход]\n"
        )

        self.assertEqual(
            ["target.md"],
            [link.target for link in document.links],
        )
        self.assertEqual([4], [link.line for link in document.links])

    def test_reference_definitions_respect_blocks_and_full_grammar(
        self,
    ) -> None:
        interrupted_paragraph = self.validator.parse_markdown(
            "[x]\n"
            "[x]: target.md\n"
        )
        container_definition = self.validator.parse_markdown(
            "[foo]\n"
            "\n"
            "> [foo]: target.md\n"
        )
        multiline_label = self.validator.parse_markdown(
            "[\n"
            "foo\n"
            "]: target.md\n"
            "\n"
            "[foo]\n"
        )
        definition_title = self.validator.parse_markdown(
            "[x]:\n"
            "  target.md\n"
            '  "[hidden](missing.md)"\n'
            "\n"
            "[x]\n"
        )
        html_definition_title = self.validator.parse_markdown(
            "[html]:\n"
            "  target-html.md\n"
            "  '<a href=\"missing-html.md\">title</a>'\n"
            "\n"
            "[html]\n"
        )
        lazy_container_paragraphs = self.validator.parse_markdown(
            "> paragraph\n"
            "[quote]: missing-quote.md\n"
            "\n"
            "- paragraph\n"
            "[list]: missing-list.md\n"
            "\n"
            "[quote] [list]\n"
        )
        listed_definition = self.validator.parse_markdown(
            "- paragraph\n"
            "- [item]:\n"
            "  target-list.md\n"
            "\n"
            "[item]\n"
        )
        definitions_after_block_end = self.validator.parse_markdown(
            "Заголовок\n"
            "===\n"
            "[heading]: target-heading.md\n"
            "\n"
            "***\n"
            "[rule]: target-rule.md\n"
            "\n"
            "[heading] [rule]\n"
        )

        self.assertEqual((), interrupted_paragraph.links)
        self.assertEqual(
            ["target.md"],
            [link.target for link in container_definition.links],
        )
        self.assertEqual(
            ["target.md"],
            [link.target for link in multiline_label.links],
        )
        self.assertEqual(
            ["target.md"],
            [link.target for link in definition_title.links],
        )
        self.assertEqual(
            ["target-html.md"],
            [link.target for link in html_definition_title.links],
        )
        self.assertEqual((), lazy_container_paragraphs.links)
        self.assertEqual(
            ["target-list.md"],
            [link.target for link in listed_definition.links],
        )
        self.assertEqual(
            ["target-heading.md", "target-rule.md"],
            [link.target for link in definitions_after_block_end.links],
        )

    def test_link_destination_escape_rules(self) -> None:
        document = self.validator.parse_markdown(
            "[Пробел](foo\\ bar)\n"
            "[Перенос](foo\\\nbar)\n"
            "[Угол](<foo\\>bar>)\n"
        )

        self.assertEqual(
            ["foo>bar"],
            [link.target for link in document.links],
        )

    def test_angle_destinations_are_parsed_before_inline_html(
        self,
    ) -> None:
        valid_inline = self.validator.parse_markdown(
            "[a](<b)c>)\n"
        )
        invalid_inline = self.validator.parse_markdown(
            "[a](<b>c)\n"
        )
        valid_reference = self.validator.parse_markdown(
            "[foo]: <bar>\n"
            "\n"
            "[foo]\n"
        )
        invalid_reference = self.validator.parse_markdown(
            "[foo]: <bar>(baz)\n"
            "\n"
            "[foo]\n"
        )
        html_attribute = self.validator.parse_markdown(
            '<a title="[x](bad.md)" href="good.md">текст</a>\n'
        )
        html_comment = self.validator.parse_markdown(
            "<!-- [x](bad-comment.md) -->\n"
        )

        self.assertEqual(
            ["b)c"],
            [link.target for link in valid_inline.links],
        )
        self.assertEqual((), invalid_inline.links)
        self.assertEqual(
            ["bar"],
            [link.target for link in valid_reference.links],
        )
        self.assertEqual((), invalid_reference.links)
        self.assertEqual(
            ["good.md"],
            [link.target for link in html_attribute.links],
        )
        self.assertEqual((), html_comment.links)

    def test_valid_inline_link_titles_are_supported(self) -> None:
        target = Path("docs/titled guide.md")
        self.write(target, "# Руководство\n")
        self.track(target)
        self.append(
            Path("README.md"),
            (
                "\n[Двойные]"
                '(<docs/titled guide.md> "заголовок")\n'
                "[Одинарные]"
                "(<docs/titled guide.md> 'заголовок')\n"
                "[Круглые]"
                "(<docs/titled guide.md> (заголовок))\n"
            ),
        )

        self.assertEqual((), self.validator.validate_repository(self.repo))

    def test_container_fence_does_not_hide_following_outer_link(
        self,
    ) -> None:
        self.append(
            Path("README.md"),
            (
                "\n> ~~~\n"
                "> содержимое\n"
                "[Внешняя ссылка](docs/guides/full-access.md)\n"
            ),
        )

        self.assertNotIn(
            "MARKDOWN_FENCE_UNCLOSED",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_list_item_fence_masks_hidden_navigation(self) -> None:
        orphan = Path("docs/list-fence-orphan.md")
        self.write(orphan, "# Потерянный документ\n")
        self.track(orphan)
        self.append(
            Path("plugins/codex-smart-subagents/README.md"),
            (
                "\n- ```markdown\n"
                "  [Скрытая]"
                "(../../docs/list-fence-orphan.md)\n"
                "  ```\n"
            ),
        )

        codes = issue_codes(self.validator.validate_repository(self.repo))

        self.assertIn("DOCUMENT_UNREACHABLE", codes)
        self.assertNotIn("MARKDOWN_FENCE_UNCLOSED", codes)

    def test_nested_container_fences_and_sibling_items(self) -> None:
        hidden_cases = (
            (
                "- > ```markdown\n"
                "  > [Скрытая](missing-list-quote.md)\n"
                "  > ```\n"
            ),
            (
                "> - ```markdown\n"
                ">   [Скрытая](missing-quote-list.md)\n"
                ">   ```\n"
            ),
            (
                "- ```markdown\n"
                "\t[Скрытая](missing-tab.md)\n"
                "\t```\n"
            ),
            (
                "- ```markdown\n"
                "  до пустой строки\n"
                "\n"
                "  [Скрытая](missing-after-blank.md)\n"
                "  ```\n"
            ),
            (
                "- ```markdown\n"
                "  - [Скрытая](missing-list-marker.md)\n"
                "  ```\n"
            ),
        )
        for source in hidden_cases:
            with self.subTest(source=source.splitlines()[0]):
                document = self.validator.parse_markdown(source)
                self.assertEqual((), document.links)
                self.assertIsNone(document.unclosed_fence_line)

        sibling = self.validator.parse_markdown(
            "- ```markdown\n"
            "  содержимое\n"
            "- [Внешняя](visible.md)\n"
        )
        self.assertEqual(
            ["visible.md"],
            [link.target for link in sibling.links],
        )
        self.assertIsNone(sibling.unclosed_fence_line)

    def test_raw_html_block_respects_container_boundary(self) -> None:
        document = self.validator.parse_markdown(
            "> <div>\n"
            "> [Скрытая](hidden.md)\n"
            "[Видимая](visible.md)\n"
        )

        self.assertEqual(
            ["visible.md"],
            [link.target for link in document.links],
        )

    def test_raw_html_block_types_and_container_endings(self) -> None:
        hidden_blocks = self.validator.parse_markdown(
            "<custom>\n"
            "[Скрытая](custom.md)\n"
            "</custom>\n"
            "\n"
            "<?process\n"
            "[Скрытая](processing.md)\n"
            "?>\n"
            "\n"
            "<![CDATA[\n"
            "[Скрытая](cdata.md)\n"
            "]]>\n"
            "\n"
            "<pre\n"
            "[Скрытая](pre.md)\n"
            "</pre>\n"
        )
        container_end = self.validator.parse_markdown(
            "> <!--\n"
            "> [Скрытая](hidden.md)\n"
            "[Видимая](visible.md)\n"
        )
        inline_interruption = self.validator.parse_markdown(
            "[x\n"
            "<!-- -->\n"
            "y](missing.md)\n"
        )
        any_type_one_closer = self.validator.parse_markdown(
            "<pre>\n"
            "[Скрытая](hidden-pre.md)\n"
            "</style>\n"
            "[Видимая](visible-after-pre.md)\n"
        )
        type_seven_inside_paragraph = self.validator.parse_markdown(
            "[x\n"
            "<custom>\n"
            "y](visible-through-custom.md)\n"
        )
        self_closing_raw_tag = self.validator.parse_markdown(
            "<script/>\n"
            "[Видимая](visible-after-script.md)\n"
        )
        opaque_blocks = self.validator.parse_markdown(
            "<?process\n"
            '<a href="hidden-processing.md">hidden</a>\n'
            "?>\n"
            "\n"
            "<![CDATA[\n"
            '<a href="hidden-cdata.md">hidden</a>\n'
            "]]>\n"
            "\n"
            "<!DOCTYPE\n"
            '<a href="hidden-declaration.md">hidden</a>\n'
            ">\n"
        )
        type_seven_after_block_end = self.validator.parse_markdown(
            "Заголовок\n"
            "===\n"
            "<custom>\n"
            "[Скрытая](hidden-after-heading.md)\n"
            "\n"
            "[ref]: target.md\n"
            "<custom>\n"
            "[Скрытая](hidden-after-definition.md)\n"
        )
        type_seven_after_multiline_definition = (
            self.validator.parse_markdown(
                "[ref]:\n"
                "  target.md\n"
                "<custom>\n"
                "[Скрытая](hidden-after-multiline-definition.md)\n"
            )
        )
        nested_raw_stack = self.validator.parse_markdown(
            "> <div>\n"
            "> <script>\n"
            '> <a href="hidden-script.md">hidden</a>\n'
            "[Видимая](visible-after-container.md)\n"
        )
        invalid_comment_block = self.validator.parse_markdown(
            "<!--\n"
            '<a href="hidden-comment.md">hidden</a>\n'
            "--->\n"
        )
        invalid_declaration_block = self.validator.parse_markdown(
            "<!X1\n"
            '<a href="hidden-declaration-name.md">hidden</a>\n'
            ">\n"
        )
        closed_comment_block = self.validator.parse_markdown(
            "<!-->\n"
            '<a href="visible-after-comment.md">visible</a>\n'
        )

        self.assertEqual((), hidden_blocks.links)
        self.assertEqual(
            ["visible.md"],
            [link.target for link in container_end.links],
        )
        self.assertEqual((), inline_interruption.links)
        self.assertEqual(
            ["visible-after-pre.md"],
            [link.target for link in any_type_one_closer.links],
        )
        self.assertEqual(
            ["visible-through-custom.md"],
            [link.target for link in type_seven_inside_paragraph.links],
        )
        self.assertEqual(
            ["visible-after-script.md"],
            [link.target for link in self_closing_raw_tag.links],
        )
        self.assertEqual((), opaque_blocks.links)
        self.assertEqual((), type_seven_after_block_end.links)
        self.assertEqual(
            (),
            type_seven_after_multiline_definition.links,
        )
        self.assertEqual(
            [
                "hidden-script.md",
                "visible-after-container.md",
            ],
            [link.target for link in nested_raw_stack.links],
        )
        self.assertEqual((), invalid_comment_block.links)
        self.assertEqual((), invalid_declaration_block.links)
        self.assertEqual(
            ["visible-after-comment.md"],
            [link.target for link in closed_comment_block.links],
        )

    def test_html_attribute_cannot_cross_blank_paragraph(self) -> None:
        document = self.validator.parse_markdown(
            '<a href="missing.md\n'
            "\n"
            '">x</a>\n'
        )

        self.assertEqual((), document.links)

    def test_code_span_stops_at_blank_paragraph(self) -> None:
        document = self.validator.parse_markdown(
            "`код\n"
            "\n"
            "[Видимая](visible.md)\n"
            "`\n"
        )

        self.assertEqual(
            ["visible.md"],
            [link.target for link in document.links],
        )

    def test_unclosed_link_labels_are_parsed_with_bounded_growth(
        self,
    ) -> None:
        clock = time.process_time
        started = clock()
        self.validator.parse_markdown("[" * 600_000)
        unmatched_elapsed = clock() - started

        started = clock()
        malformed_html = (
            "<a "
            * ((2 * 1024 * 1024 // 3) + 1)
        )[: 2 * 1024 * 1024]
        self.validator.parse_markdown(malformed_html)
        malformed_html_elapsed = clock() - started

        adversarial_elapsed: dict[str, float] = {}
        for label, pattern, size in (
            ("comment", "x<!--", 256_000),
            ("processing", "x<?", 256_000),
            ("cdata", "x<![CDATA[", 256_000),
            ("declaration", "x<!A ", 256_000),
            ("destination", "[x](", 128_000),
        ):
            source = "#\n" + (
                pattern * ((size // len(pattern)) + 1)
            )[:size]
            started = clock()
            self.validator.parse_markdown(source)
            adversarial_elapsed[label] = (
                clock() - started
            )

        closing_comment_size = 1024 * 1024
        closing_comment = (
            "#\nx "
            + "<!--"
            * (
                (closing_comment_size // len("<!--"))
                + 1
            )
        )[: closing_comment_size - 5] + "--->"
        started = clock()
        self.validator.parse_markdown(closing_comment)
        adversarial_elapsed["late_comment_closer"] = (
            clock() - started
        )

        started = clock()
        self.validator.parse_markdown(
            "["
            * 2_000
            + "[x](target.md)"
            * 2_000
            + "]"
            * 2_000
        )
        nested_links_elapsed = clock() - started

        started = clock()
        self.validator.parse_markdown(
            "[x]: target.md\n"
            + "["
            * 64_000
            + "x"
            + "]"
            * 64_000
            + "\n"
        )
        shortcut_nesting_elapsed = clock() - started

        started = clock()
        self.validator.parse_markdown("строка\n" * 256_000)
        many_lines_elapsed = clock() - started

        started = clock()
        self.validator.parse_markdown("*\n" * 1_000_000)
        marker_lines_elapsed = clock() - started

        started = clock()
        self.validator.parse_markdown(
            "[x]: /url '\n"
            + "a\n" * 3_900
            + "\n[x]\n"
        )
        multiline_title_elapsed = clock() - started

        self.assertLess(unmatched_elapsed, 5.0)
        self.assertLess(malformed_html_elapsed, 5.0)
        self.assertLess(nested_links_elapsed, 5.0)
        self.assertLess(shortcut_nesting_elapsed, 5.0)
        self.assertLess(many_lines_elapsed, 5.0)
        self.assertLess(marker_lines_elapsed, 5.0)
        self.assertLess(multiline_title_elapsed, 5.0)
        for label, elapsed in adversarial_elapsed.items():
            with self.subTest(pathological=label):
                self.assertLess(elapsed, 5.0)

    def test_indented_atx_and_setext_headings_create_anchors(self) -> None:
        target = Path("docs/headings.md")
        self.write(
            target,
            "   ## Раздел ATX\n\nРаздел Setext\n---\n",
        )
        self.track(target)
        self.append(
            Path("README.md"),
            (
                "\n[ATX](docs/headings.md#раздел-atx)\n"
                "[Setext](docs/headings.md#раздел-setext)\n"
            ),
        )

        self.assertEqual((), self.validator.validate_repository(self.repo))

    def test_setext_headings_respect_container_boundaries(self) -> None:
        quoted = self.validator.parse_markdown(
            "> Заголовок\n"
            "> ---\n"
        )
        listed = self.validator.parse_markdown(
            "- Заголовок\n"
            "  ---\n"
        )
        separated = self.validator.parse_markdown(
            "Абзац\n"
            "> цитата\n"
            "---\n"
        )
        after_rule = self.validator.parse_markdown(
            "---\n"
            "Title\n"
            "===\n"
        )
        after_empty_list = self.validator.parse_markdown(
            "-\n"
            "Title\n"
            "---\n"
        )

        self.assertIn("заголовок", quoted.anchors)
        self.assertIn("заголовок", listed.anchors)
        self.assertEqual(frozenset(), separated.anchors)
        self.assertEqual(frozenset({"title"}), after_rule.anchors)
        self.assertEqual(frozenset({"title"}), after_empty_list.anchors)

    def test_setext_heading_text_may_start_with_pipe(self) -> None:
        document = self.validator.parse_markdown(
            "| foo\n"
            "---\n"
        )

        self.assertEqual(frozenset({"-foo"}), document.anchors)

    def test_heading_blocks_follow_commonmark_container_and_code_rules(
        self,
    ) -> None:
        cases = {
            "lazy_blockquote_continuation": (
                "> foo\n"
                "bar\n"
                "===\n",
                frozenset(),
            ),
            "multiline_emphasis": (
                "Foo *bar\n"
                "baz*\n"
                "====\n",
                frozenset({"foo-barbaz"}),
            ),
            "multiline_indented_emphasis": (
                "  Foo *bar\n"
                "baz*\t\n"
                "====\n",
                frozenset({"foo-barbaz"}),
            ),
            "multiline_plain": (
                "Foo\n"
                "Bar\n"
                "---\n",
                frozenset({"foobar"}),
            ),
            "indented_code_around_headings": (
                "# Heading\n"
                "    foo\n"
                "Heading\n"
                "------\n"
                "    foo\n"
                "----\n",
                frozenset({"heading", "heading-1"}),
            ),
            "empty_list_items": (
                "-\n"
                "  foo\n"
                "-\n",
                frozenset(),
            ),
        }

        for label, (text, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(
                    expected,
                    self.validator.parse_markdown(text).anchors,
                )

    def test_github_slug_uses_rendered_heading_text(self) -> None:
        document = self.validator.parse_markdown(
            "# [Foo][bar]\n"
            "# <https://example.com>\n"
            "# \\<tag>\n"
            "# &lt;tag&gt;\n"
            "# [Foo](a(b)c)\n"
            "# [link](foo_(bar).md)\n"
            "# [a [b]](t.md)\n"
            "# `Cafe\u0301`\n"
            "# <em>Rendered</em>\n"
            "# ![Alt *text*](image.png)\n"
            "\n"
            "[bar]: /url\n"
        )

        self.assertEqual(
            frozenset(
                {
                    "foo",
                    "httpsexamplecom",
                    "tag",
                    "tag-1",
                    "foo-1",
                    "link",
                    "a-b",
                    "cafe\u0301",
                    "rendered",
                    "alt-text",
                }
            ),
            document.anchors,
        )

    def test_duplicate_heading_suffixes_have_bounded_growth(self) -> None:
        started = time.process_time()
        document = self.validator.parse_markdown("## x\n" * 8_000)
        elapsed = time.process_time() - started

        self.assertEqual(8_000, len(document.anchors))
        self.assertIn("x-7999", document.anchors)
        self.assertLess(elapsed, 5.0)

    def test_github_slug_decodes_escapes_entities_and_preserves_spaces(
        self,
    ) -> None:
        document = self.validator.parse_markdown(
            "## foo\\_bar\n"
            "## A &amp; B\n"
            "## a  b\n"
            "## foo\n"
            "## foo-1\n"
            "## foo\n"
            "## bar\n"
            "## bar\n"
            "## bar-1\n"
            "## Straße\n"
            "## ς\n"
            "## Cafe\u0301\n"
            "## &#x20;\n"
            "## &#x20;a\n"
            "## a&#x20;\n"
            "## &#x20;a&#x20;\n"
            "## a&nbsp;b\n"
        )

        self.assertEqual(
            frozenset(
                {
                    "foo_bar",
                    "a--b",
                    "a--b-1",
                    "foo",
                    "foo-1",
                    "foo-2",
                    "bar",
                    "bar-1",
                    "bar-1-1",
                    "straße",
                    "ς",
                    "cafe\u0301",
                    "-",
                    "-a",
                    "a-",
                    "-a-",
                    "ab",
                }
            ),
            document.anchors,
        )

    def test_ordered_list_followed_by_rule_is_not_setext_heading(
        self,
    ) -> None:
        target = Path("docs/list-rule.md")
        self.write(target, "1. элемент\n---\n")
        self.track(target)
        self.append(
            Path("README.md"),
            "\n[Ложный якорь](docs/list-rule.md#1-элемент)\n",
        )

        self.assertIn(
            "LOCAL_LINK_ANCHOR_MISSING",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_ignores_tracked_installation_copy_tree(self) -> None:
        copied = Path(".smart-subagents/copy/docs/broken.md")
        self.write(copied, "# Копия\n\n[Нет](missing.md)\n")
        self.track(copied)

        self.assertEqual((), self.validator.validate_repository(self.repo))

    def test_requires_direct_root_entrypoints_and_forbids_fences(self) -> None:
        readme = self.read(Path("README.md"))
        readme = readme.replace(
            "- [Полный доступ](docs/guides/full-access.md)\n",
            "",
        )
        self.write(
            Path("README.md"),
            readme + "\n```text\nкоманда\n```\n",
        )

        codes = issue_codes(self.validator.validate_repository(self.repo))

        self.assertIn("ROOT_ENTRYPOINT_MISSING", codes)
        self.assertIn("ROOT_FENCE_FORBIDDEN", codes)

    def test_root_readme_rejects_non_catalog_sections_and_steps(
        self,
    ) -> None:
        self.append(
            Path("README.md"),
            (
                "\n## Инструкция запуска\n\n"
                "1. Выполнить установку.\n"
                "2. Изменить пользовательскую конфигурацию.\n"
            ),
        )

        self.assertIn(
            "ROOT_CATALOG_STRUCTURE_INVALID",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_root_readme_rejects_bracketed_non_link_text(self) -> None:
        self.append(
            Path("README.md"),
            "\nВыполнить служебную команду dangerous --all [не ссылка]\n",
        )

        self.assertIn(
            "ROOT_CATALOG_STRUCTURE_INVALID",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_structured_root_rejects_non_navigation_table_row(
        self,
    ) -> None:
        root = root_catalog_fixture()
        mutated = root.replace(
            "|---|---|---|\n",
            (
                "|---|---|---|\n"
                "| 1. Выполнить dangerous --all "
                "| без проверки | продолжить |\n"
            ),
            1,
        )

        self.assertTrue(
            self.validator.root_catalog_structure_errors(mutated)
        )

    def test_structured_root_enforces_exact_table_schema(self) -> None:
        root = root_catalog_fixture()
        lines = root.splitlines()
        first_header = lines.index(
            "| Задача | Состояние | Куда перейти |"
        )
        first_data = first_header + 2
        extra_column_lines = list(lines)
        extra_column_lines[first_data] = (
            extra_column_lines[first_data][:-1] + "| Лишнее |"
        )
        mutations = {
            "header": root.replace(
                "| Задача | Состояние | Куда перейти |",
                "| Задача | Куда перейти | Состояние |",
                1,
            ),
            "separator": root.replace(
                "|---|---|---|",
                "|:---|---|---|",
                1,
            ),
            "extra_column": "\n".join(extra_column_lines) + "\n",
            "missing_link": root.replace(
                (
                    "[Как проходит умный ход]"
                    "(plugins/codex-smart-subagents/"
                    "README.md#как-проходит-умный-ход)"
                ),
                "Как проходит умный ход",
                1,
            ),
            "second_link": root.replace(
                "Реализовано для Codex 0.144.4",
                (
                    "[Лишняя ссылка]"
                    "(docs/guides/full-access.md)"
                ),
                1,
            ),
            "angle_autolink": root.replace(
                "Реализовано для Codex 0.144.4",
                "<https://example.com>",
                1,
            ),
            "angle_autolink_in_required_label": root.replace(
                (
                    "[Как проходит умный ход]"
                    "(plugins/codex-smart-subagents/"
                    "README.md#как-проходит-умный-ход)"
                ),
                (
                    "[до <https://example.com> после]"
                    "(plugins/codex-smart-subagents/"
                    "README.md#как-проходит-умный-ход)"
                ),
                1,
            ),
            "angle_email_autolink": root.replace(
                "Реализовано для Codex 0.144.4",
                "<user@example.com>",
                1,
            ),
            "angle_dotless_email_autolink": root.replace(
                "Реализовано для Codex 0.144.4",
                "<u@example>",
                1,
            ),
            "angle_short_tld_email_autolink": root.replace(
                "Реализовано для Codex 0.144.4",
                "<u@example.x>",
                1,
            ),
            "angle_numeric_tld_email_autolink": root.replace(
                "Реализовано для Codex 0.144.4",
                "<u@example.123>",
                1,
            ),
            "angle_leading_dot_email_autolink": root.replace(
                "Реализовано для Codex 0.144.4",
                "<.u@example>",
                1,
            ),
            "angle_trailing_dot_email_autolink": root.replace(
                "Реализовано для Codex 0.144.4",
                "<u.@example>",
                1,
            ),
            "angle_double_dot_local_email_autolink": root.replace(
                "Реализовано для Codex 0.144.4",
                "<u..v@example>",
                1,
            ),
            "extended_protocol_autolink": root.replace(
                "Реализовано для Codex 0.144.4",
                "https://example.com",
                1,
            ),
            "extended_www_autolink": root.replace(
                "Реализовано для Codex 0.144.4",
                "www.example.com",
                1,
            ),
            "extended_email_autolink": root.replace(
                "Реализовано для Codex 0.144.4",
                "user@example.com",
                1,
            ),
            "nested_link": root.replace(
                (
                    "[Как проходит умный ход]"
                    "(plugins/codex-smart-subagents/"
                    "README.md#как-проходит-умный-ход)"
                ),
                (
                    "[[Внутренняя]"
                    "(docs/guides/full-access.md)]"
                    "(plugins/codex-smart-subagents/"
                    "README.md#как-проходит-умный-ход)"
                ),
                1,
            ),
            "image": root.replace(
                (
                    "[Как проходит умный ход]"
                    "(plugins/codex-smart-subagents/"
                    "README.md#как-проходит-умный-ход)"
                ),
                (
                    "![Изображение]"
                    "(plugins/codex-smart-subagents/README.md)"
                ),
                1,
            ),
            "html_link": root.replace(
                (
                    "[Как проходит умный ход]"
                    "(plugins/codex-smart-subagents/"
                    "README.md#как-проходит-умный-ход)"
                ),
                (
                    '<a href="plugins/codex-smart-subagents/'
                    'README.md#как-проходит-умный-ход">Переход</a>'
                ),
                1,
            ),
            "compatibility_table": (
                root
                + "\n| Запрещено | Здесь |\n"
                "|---|---|\n"
                "| без | ссылки |\n"
            ),
            "quoted_compatibility_table": (
                root.rstrip()
                + "\n> | Запрещено | Здесь |\n"
                "> |---|---|\n"
                "> | без | ссылки |\n"
            ),
            "deeply_quoted_compatibility_table": (
                root.rstrip()
                + "\n"
                + "> " * 17
                + "| Запрещено | Здесь |\n"
                + "> " * 17
                + "|---|---|\n"
                + "> " * 17
                + "| без | ссылки |\n"
            ),
            "html_compatibility_table": (
                root.rstrip()
                + "\n<table><tr><td>Запрещено</td></tr></table>\n"
            ),
            "type_six_html_compatibility_table": (
                root.rstrip()
                + "\n<table @foo><tr><td>Запрещено</td></tr>\n"
            ),
            "nested_list_html_compatibility_table": (
                root.rstrip()
                + "\n- outer\n"
                "  - inner\n"
                "    <table><tr><td>Запрещено</td></tr>\n"
            ),
            "quoted_list_html_compatibility_table": (
                root.rstrip()
                + "\n> - outer\n"
                ">   - inner\n"
                ">     <table><tr><td>Запрещено</td></tr>\n"
            ),
        }

        for label, source in mutations.items():
            with self.subTest(label=label):
                self.assertTrue(
                    self.validator.root_catalog_structure_errors(source)
                )

    def test_structured_root_uses_rendered_link_and_table_semantics(
        self,
    ) -> None:
        root = root_catalog_fixture()
        link = (
            "[Как проходит умный ход]"
            "(plugins/codex-smart-subagents/"
            "README.md#как-проходит-умный-ход)"
        )
        accepted = {
            "comment_url": root.replace(
                "Реализовано для Codex 0.144.4",
                "<!-- https://example.com -->состояние",
                1,
            ),
            "html_attribute_url": root.replace(
                "Реализовано для Codex 0.144.4",
                (
                    '<span data-url="https://example.com">'
                    "состояние</span>"
                ),
                1,
            ),
            "invalid_angle_email": root.replace(
                "Реализовано для Codex 0.144.4",
                "<u@example..com>",
                1,
            ),
            "bare_numeric_email_tld": root.replace(
                "Реализовано для Codex 0.144.4",
                "u@example.123",
                1,
            ),
            "url_without_gfm_left_boundary": root.replace(
                "Реализовано для Codex 0.144.4",
                "foo/www.example.com",
                1,
            ),
            "commented_html_table": (
                root.rstrip()
                + "\n<!--\n"
                "<table><tr><td>скрыто</td></tr></table>\n"
                "-->\n"
            ),
            "escaped_html_table": (
                root.rstrip()
                + "\n\\<table><tr><td>текст</td></tr></table>\n"
            ),
            "hidden_root_structure": (
                root.rstrip()
                + "\n<!--\n"
                "# Скрытый\n"
                "## Скрытый\n"
                "1. Скрытый\n"
                "-->\n"
            ),
            "code_bracket_in_link_label": root.replace(
                link,
                (
                    "[Код `]` внутри]"
                    "(plugins/codex-smart-subagents/"
                    "README.md#как-проходит-умный-ход)"
                ),
                1,
            ),
            "html_bracket_in_link_label": root.replace(
                link,
                (
                    '[HTML <span data-x="]">внутри</span>]'
                    "(plugins/codex-smart-subagents/"
                    "README.md#как-проходит-умный-ход)"
                ),
                1,
            ),
        }

        for label, source in accepted.items():
            with self.subTest(label=label):
                self.assertEqual(
                    (),
                    self.validator.root_catalog_structure_errors(source),
                )

        extended_email_inside_angles = root.replace(
            "Реализовано для Codex 0.144.4",
            "<u@example_foo.com>",
            1,
        )
        extended_domain_with_inner_underscore = root.replace(
            "Реализовано для Codex 0.144.4",
            "www.foo_bar.example.com",
            1,
        )
        short_www_autolink = root.replace(
            "Реализовано для Codex 0.144.4",
            "www.example",
            1,
        )
        self.assertTrue(
            self.validator.root_catalog_structure_errors(
                extended_email_inside_angles
            )
        )
        self.assertTrue(
            self.validator.root_catalog_structure_errors(
                extended_domain_with_inner_underscore
            )
        )
        self.assertTrue(
            self.validator.root_catalog_structure_errors(
                short_www_autolink
            )
        )

    def test_root_catalog_uses_rendered_block_and_autolink_semantics(
        self,
    ) -> None:
        contracts = sys.modules["docs_navigation_contracts"]
        root = root_catalog_fixture()
        preamble, sections = root.split("## Быстрые маршруты\n", 1)
        compatibility_prefix = root.split(
            "## Совместимость\n\n",
            1,
        )[0]

        for character in ("\u00a0", "\u2003", "\f", "\v"):
            with self.subTest(area="visible_text_line", character=repr(character)):
                lines = ["one", character, "two"]
                self.assertTrue(
                    contracts._is_single_visible_paragraph(lines)
                )
                source = (
                    compatibility_prefix
                    + "## Совместимость\n\n"
                    + "\n".join(lines)
                    + "\n"
                )
                self.assertNotIn(
                    (
                        "раздел «Совместимость» должен быть "
                        "одним абзацем"
                    ),
                    self.validator.root_catalog_structure_errors(
                        source
                    ),
                )

        for candidate in ("www._", "www..", "www.!", "www.?"):
            with self.subTest(area="short_www_autolink", candidate=candidate):
                self.assertTrue(
                    contracts._contains_gfm_autolink(candidate)
                )
                source = root.replace(
                    "Реализовано для Codex 0.144.4",
                    candidate,
                    1,
                )
                self.assertTrue(
                    self.validator.root_catalog_structure_errors(
                        source
                    )
                )

        extra_url = root.replace(
            "Реализовано для Codex 0.144.4",
            "_https://example.com",
            1,
        )
        nested_autolink = root.replace(
            "[Как проходит умный ход]",
            "[до <https://example.com> после]",
            1,
        )
        simple_nested_autolink = (
            "# Каталог\n\n"
            "[до <https://example.com> после](target.md)\n"
        )
        angle_extended_email = root.replace(
            "[Как проходит умный ход]",
            "[<u@example_foo.com>]",
            1,
        )
        literal_extended_candidates = root.replace(
            "Реализовано для Codex 0.144.4",
            "http://- и WWW.example.com",
            1,
        )
        trailing_url_punctuation = root.replace(
            "Реализовано для Codex 0.144.4",
            "https://example.com_",
            1,
        )
        trailing_email = root.replace(
            "Реализовано для Codex 0.144.4",
            "a@b.c.",
            1,
        )
        punctuated_email = root.replace(
            "Реализовано для Codex 0.144.4",
            "u!x@example.com",
            1,
        )

        self.assertTrue(
            self.validator.root_catalog_structure_errors(extra_url)
        )
        self.assertTrue(
            self.validator.root_catalog_structure_errors(nested_autolink)
        )
        self.assertTrue(
            self.validator.root_catalog_structure_errors(
                simple_nested_autolink
            )
        )
        self.assertEqual(
            (),
            self.validator.root_catalog_structure_errors(
                angle_extended_email
            ),
        )
        self.assertEqual(
            (),
            self.validator.root_catalog_structure_errors(
                literal_extended_candidates
            ),
        )
        self.assertTrue(
            self.validator.root_catalog_structure_errors(
                trailing_url_punctuation
            )
        )
        self.assertFalse(
            contracts._contains_gfm_autolink(
                "[https://example.com"
            )
        )
        self.assertFalse(
            contracts._contains_gfm_autolink(
                "http://[::1]"
            )
        )
        self.assertFalse(
            contracts._contains_gfm_autolink(
                "u@example.123"
            )
        )
        self.assertTrue(
            contracts._contains_gfm_autolink(
                "u@a.1a"
            )
        )
        self.assertFalse(
            contracts._contains_gfm_autolink(
                "u@a.a1"
            )
        )
        self.assertTrue(
            self.validator.root_catalog_structure_errors(
                trailing_email
            )
        )
        self.assertTrue(
            self.validator.root_catalog_structure_errors(
                punctuated_email
            )
        )

        for body in ("- пункт", "> цитата", "<div>пункт</div>"):
            with self.subTest(area="preamble", body=body):
                source = (
                    preamble.split("\n\n", 1)[0]
                    + "\n\n"
                    + body
                    + "\n\n## Быстрые маршруты\n"
                    + sections
                )
                self.assertIn(
                    "до первого раздела должен быть один вводный абзац",
                    self.validator.root_catalog_structure_errors(
                        source
                    ),
                )
            with self.subTest(area="compatibility", body=body):
                source = (
                    compatibility_prefix
                    + "## Совместимость\n\n"
                    + body
                    + "\n"
                )
                self.assertIn(
                    (
                        "раздел «Совместимость» должен быть "
                        "одним абзацем"
                    ),
                    self.validator.root_catalog_structure_errors(
                        source
                    ),
                )

        self.assertFalse(
            contracts._is_single_visible_paragraph(
                ["[x]: target"]
            )
        )
        self.assertFalse(
            contracts._is_single_visible_paragraph(
                ["[x]:", "  target"]
            )
        )
        for body in ("--", "=", "=="):
            with self.subTest(area="single_paragraph", body=body):
                self.assertTrue(
                    contracts._is_single_visible_paragraph(
                        [body]
                    )
                )
        for lines in (
            ["one", "    continuation"],
            ["one", "2. two"],
            ["one", "1. "],
            ["one", "+ "],
        ):
            with self.subTest(area="lazy_paragraph", lines=lines):
                self.assertTrue(
                    contracts._is_single_visible_paragraph(lines)
                )
        for body in ("-", "+", "*"):
            with self.subTest(area="empty_list", body=body):
                self.assertFalse(
                    contracts._is_single_visible_paragraph([body])
                )

    def test_root_catalog_detects_only_rendered_tables(self) -> None:
        root = root_catalog_fixture()
        prefix = root.split("## Совместимость\n\n", 1)[0]
        table_error = (
            "раздел «Совместимость» не должен содержать таблицу"
        )
        html_error = (
            "раздел «Совместимость» не должен содержать HTML-таблицу"
        )

        visible_gfm = {
            "short_delimiter": (
                "| a | b |\n"
                "| - | -- |\n"
                "| x | y |\n"
            ),
            "inside_list": (
                "- | a | b |\n"
                "  | - | - |\n"
                "  | x | y |\n"
            ),
            "inside_quoted_list": (
                "> - | a | b |\n"
                ">   | - | - |\n"
                ">   | x | y |\n"
            ),
            "pipe_in_code_span": "`a|b`\n-|-\n",
            "pipe_in_html_attribute": (
                '<span data-x="a|b">x</span>\n'
                "-|-\n"
            ),
            "pipe_in_angle_autolink": (
                "<https://e/x|y>\n"
                "-|-\n"
            ),
            "pipe_in_inline_comment": (
                "x <!-- a|b -->\n"
                "-|-\n"
            ),
        }
        for label, body in visible_gfm.items():
            with self.subTest(label=label):
                source = prefix + "## Совместимость\n\n" + body
                self.assertIn(
                    table_error,
                    self.validator.root_catalog_structure_errors(
                        source
                    ),
                )

        non_tables = {
            "pipe_in_code_span": "`a|b`|c\n|-|-|\n",
            "atx_heading": "# a|b\n|-|-|\n",
            "pipe_in_html_attribute": (
                '<span data-x="a|b">x</span>|b\n'
                "|-|-|\n"
            ),
            "extra_pipe_after_inline_comment": (
                "x <!-- a|b --> c|d\n"
                "-|-\n"
            ),
            "four_space_separator": "a|b\n    -|-\n",
            "tab_separator": "a|b\n\t-|-\n",
            "nonbreaking_spaces": (
                "|a|b|\n"
                "|\N{NO-BREAK SPACE}-\N{NO-BREAK SPACE}|"
                "\N{NO-BREAK SPACE}-\N{NO-BREAK SPACE}|\n"
            ),
        }
        for label, body in non_tables.items():
            with self.subTest(label=label):
                source = prefix + "## Совместимость\n\n" + body
                self.assertNotIn(
                    table_error,
                    self.validator.root_catalog_structure_errors(
                        source
                    ),
                )

        visible_html = {
            "inline_tagfiltered": (
                "x <script><table><tr><td>x</td></tr>"
                "</table></script> y\n"
            ),
            "invalid_inline_comment": (
                "x <!--x<table></table>---> y\n"
            ),
            "invalid_inline_declaration_without_space": (
                "x <!X<table></table>> y\n"
            ),
            "invalid_inline_declaration_name": (
                "x <!X1 <table></table>> y\n"
            ),
            "fence_inside_raw": (
                "<div>\n"
                "```\n"
                "foo <table><tr><td>x</td></tr></table>\n"
                "```\n"
            ),
        }
        for label, body in visible_html.items():
            with self.subTest(label=label):
                source = prefix + "## Совместимость\n\n" + body
                self.assertIn(
                    html_error,
                    self.validator.root_catalog_structure_errors(
                        source
                    ),
                )

        hidden_html = {
            "inline_processing": (
                "x <?foo <table><tr><td>x</td></tr></table> ?> y\n"
            ),
            "inline_declaration": (
                "x <!ELEMENT <table><tr><td>x</td></tr></table>> y\n"
            ),
            "inline_cdata": (
                "x <![CDATA[<table><tr><td>x</td></tr></table>]]> y\n"
            ),
            "nested_comment": (
                "- a\n"
                "  - b\n"
                "    <!--\n"
                "    <table><tr><td>x</td></tr></table>\n"
                "    -->\n"
            ),
            "invalid_attribute": (
                '<div @foo="<table><tr><td>x</td></tr></table>">'
                "ok</div>\n"
            ),
            "link_destination": "[x](<table>)\n",
            "link_title": '[x](url "<table>")\n',
            "invalid_raw_tag_name": "<div>\n<table@foo>\n",
            "incomplete": "<table\n",
        }
        for label, body in hidden_html.items():
            with self.subTest(label=label):
                source = prefix + "## Совместимость\n\n" + body
                self.assertNotIn(
                    html_error,
                    self.validator.root_catalog_structure_errors(
                        source
                    ),
                )

        nested_tables = (
            "<table><tr><td>x</td></tr></table>",
            "<!--x--> <table></table>",
            "<?x?> <table></table>",
            "<!X x> <table></table>",
            "<!--x<table></table>--->",
            "<!X1 <table></table>>",
        )
        for body in nested_tables:
            with self.subTest(cell_html=body):
                nested_table = root.replace(
                    "Реализовано для Codex 0.144.4",
                    body,
                    1,
                )
                self.assertTrue(
                    any(
                        "HTML-таблица внутри ячейки запрещена"
                        in error
                        for error in (
                            self.validator.root_catalog_structure_errors(
                                nested_table
                            )
                        )
                    )
                )

        invalid_nested_table = root.replace(
            "Реализовано для Codex 0.144.4",
            "<table !foo>",
            1,
        )
        self.assertFalse(
            any(
                "HTML-таблица внутри ячейки запрещена" in error
                for error in self.validator.root_catalog_structure_errors(
                    invalid_nested_table
                )
            )
        )

    def test_visible_html_table_detector_respects_gfm_raw_blocks(
        self,
    ) -> None:
        root = root_catalog_fixture()
        prefix = root.split("## Совместимость\n\n", 1)[0]

        def with_compatibility(body: str) -> str:
            return prefix + "## Совместимость\n\n" + body

        visible = {
            "tagfiltered_script": (
                "<script>\n"
                "<table><tr><td>x</td></tr></table>\n"
                "</script>\n"
            ),
            "fence_inside_raw_html": (
                "<div>\n"
                "```\n"
                "<table><tr><td>x</td></tr></table>\n"
                "```\n"
            ),
            "escape_inside_raw_html": (
                "<div>\n"
                "\\<table><tr><td>x</td></tr></table>\n"
            ),
        }
        hidden = {
            "fenced_code": (
                "```\n"
                "<table><tr><td>x</td></tr></table>\n"
                "```\n"
            ),
            "indented_code": (
                "    <table><tr><td>x</td></tr></table>\n"
            ),
            "comment": (
                "<!--\n"
                "<table><tr><td>x</td></tr></table>\n"
                "-->\n"
            ),
            "processing": (
                "<?process\n"
                "<table><tr><td>x</td></tr></table>\n"
                "?>\n"
            ),
            "declaration": (
                "<!DOCTYPE\n"
                "<table><tr><td>x</td></tr></table>\n"
                ">\n"
            ),
            "cdata": (
                "<![CDATA[\n"
                "<table><tr><td>x</td></tr></table>\n"
                "]]>\n"
            ),
            "html_attribute": (
                '<span data-x="<table>">текст</span>\n'
            ),
            "escaped_text": (
                "\\<table><tr><td>x</td></tr></table>\n"
            ),
            "closing_only": "</table>\n",
        }

        for label, source in visible.items():
            with self.subTest(label=label):
                self.assertIn(
                    (
                        "раздел «Совместимость» не должен содержать "
                        "HTML-таблицу"
                    ),
                    self.validator.root_catalog_structure_errors(
                        with_compatibility(source)
                    ),
                )
        for label, source in hidden.items():
            with self.subTest(label=label):
                self.assertNotIn(
                    (
                        "раздел «Совместимость» не должен содержать "
                        "HTML-таблицу"
                    ),
                    self.validator.root_catalog_structure_errors(
                        with_compatibility(source)
                    ),
                )

    def test_requires_exact_mermaid_kinds_and_closed_fences(self) -> None:
        adaptive = self.read(
            Path("plugins/codex-smart-subagents/README.md")
        )
        adaptive = adaptive.replace(
            "```mermaid\nflowchart LR\n    A --> B\n```\n",
            "```mermaid\nflowchart TD\n    A --> B\n```\n",
        )
        adaptive += "\n```text\nнезакрытый блок\n"
        self.write(
            Path("plugins/codex-smart-subagents/README.md"),
            adaptive,
        )

        codes = issue_codes(self.validator.validate_repository(self.repo))

        self.assertIn("MERMAID_KIND_INVALID", codes)
        self.assertIn("MARKDOWN_FENCE_UNCLOSED", codes)

    def test_mermaid_fences_allow_at_most_three_leading_spaces(
        self,
    ) -> None:
        runbook_path = Path(
            "docs/runbooks/adaptive-subagents-v2-operations.md"
        )
        runbook = self.read(runbook_path).replace(
            "```mermaid\n",
            "    ```mermaid\n",
            1,
        )
        self.write(runbook_path, runbook)

        self.assertIn(
            "MERMAID_COUNT_INVALID",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

        runbook = self.read(runbook_path).replace(
            "    ```mermaid\n",
            "```mermaid\n",
            1,
        ).replace(
            "\n```\n",
            "\n    ```\n",
            1,
        )
        self.write(runbook_path, runbook)

        self.assertIn(
            "MARKDOWN_FENCE_UNCLOSED",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_state_diagram_must_match_runtime_states_and_transitions(
        self,
    ) -> None:
        runbook = self.read(
            Path("docs/runbooks/adaptive-subagents-v2-operations.md")
        )
        runbook = runbook.replace(
            "    PLANNED --> SUCCEEDED\n",
            "    PLANNED --> FAILED\n",
        )
        self.write(
            Path("docs/runbooks/adaptive-subagents-v2-operations.md"),
            runbook,
        )

        codes = issue_codes(self.validator.validate_repository(self.repo))

        self.assertIn("STATE_DIAGRAM_STATES_MISMATCH", codes)
        self.assertIn("STATE_DIAGRAM_TRANSITIONS_MISMATCH", codes)

    def test_state_diagram_rejects_duplicate_transitions(self) -> None:
        runbook = self.read(
            Path("docs/runbooks/adaptive-subagents-v2-operations.md")
        )
        runbook = runbook.replace(
            "    PLANNED --> SUCCEEDED\n",
            (
                "    PLANNED --> SUCCEEDED\n"
                "    PLANNED --> SUCCEEDED\n"
            ),
        )
        self.write(
            Path("docs/runbooks/adaptive-subagents-v2-operations.md"),
            runbook,
        )

        self.assertIn(
            "STATE_DIAGRAM_DUPLICATE_TRANSITION",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_state_diagram_must_match_runtime_terminal_states(
        self,
    ) -> None:
        state_path = Path(
            "plugins/codex-smart-subagents/src/"
            "codex_smart_subagents/state.py"
        )
        source = self.read(state_path).replace(
            "TERMINAL_STATES = frozenset({RouteState.SUCCEEDED})",
            (
                "TERMINAL_STATES = frozenset("
                "{RouteState.PLANNED, RouteState.SUCCEEDED})"
            ),
        ).replace(
            (
                "    RouteState.PLANNED: "
                "frozenset({RouteState.SUCCEEDED}),\n"
            ),
            "",
        )
        self.write(state_path, source)

        self.assertIn(
            "STATE_DIAGRAM_TERMINALS_MISMATCH",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_state_diagram_rejects_noncanonical_transition_lines(
        self,
    ) -> None:
        runbook_path = Path(
            "docs/runbooks/adaptive-subagents-v2-operations.md"
        )
        runbook = self.read(runbook_path).replace(
            "    PLANNED --> SUCCEEDED\n",
            "    PLANNED --> SUCCEEDED: подпись\n",
        )
        self.write(runbook_path, runbook)

        self.assertIn(
            "STATE_DIAGRAM_TRANSITION_FORMAT_INVALID",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_state_diagram_rejects_extra_state_declaration(
        self,
    ) -> None:
        runbook_path = Path(
            "docs/runbooks/adaptive-subagents-v2-operations.md"
        )
        runbook = self.read(runbook_path).replace(
            "stateDiagram-v2\n",
            'stateDiagram-v2\n    state "Лишнее" as EXTRA\n',
        )
        self.write(runbook_path, runbook)

        self.assertIn(
            "STATE_DIAGRAM_CONTENT_INVALID",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_state_contract_is_parsed_without_executing_module(
        self,
    ) -> None:
        state_path = Path(
            "plugins/codex-smart-subagents/src/"
            "codex_smart_subagents/state.py"
        )
        self.append(state_path, "\nraise SystemExit(77)\n")

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(
                2,
                self.validator.main(["--repo", str(self.repo)]),
            )

    def test_state_contract_rejects_mutation_and_shadowing(self) -> None:
        state_path = Path(
            "plugins/codex-smart-subagents/src/"
            "codex_smart_subagents/state.py"
        )
        original = self.read(state_path)
        mutations = (
            "\nALLOWED_TRANSITIONS.clear()\n",
            "\nALLOWED_TRANSITIONS.update({})\n",
            (
                "\nALLOWED_TRANSITIONS[RouteState.PLANNED]"
                " = frozenset()\n"
            ),
            "\ndel ALLOWED_TRANSITIONS[RouteState.PLANNED]\n",
            "\nTERMINAL_STATES |= frozenset({RouteState.PLANNED})\n",
            "\ntransition_alias = ALLOWED_TRANSITIONS\n",
            "\ndef frozenset(items=()):\n    return tuple()\n",
            "\nclass StrEnum:\n    pass\n",
            (
                "\ndef mutate_indirect_call():\n"
                "    (ALLOWED_TRANSITIONS or {}).clear()\n"
            ),
            (
                "\ndef mutate_nested_target():\n"
                "    [ALLOWED_TRANSITIONS][0]"
                "[RouteState.PLANNED] = set()\n"
            ),
            (
                "\ndef leak_nested_value():\n"
                "    return [ALLOWED_TRANSITIONS]\n"
            ),
            (
                "\ndef mutate_reflectively():\n"
                "    mutate_reflectively.__globals__"
                '["ALLOWED_TRANSITIONS"].clear()\n'
            ),
            (
                "\ndef mutate_through_module():\n"
                "    import sys\n"
                "    sys.modules[__name__]."
                "ALLOWED_TRANSITIONS.clear()\n"
            ),
            (
                "\ndef expose_type_alias():\n"
                "    type Alias = ALLOWED_TRANSITIONS\n"
                "    return Alias.__value__\n"
            ),
            (
                "\ndef shadow_match(value):\n"
                "    match value:\n"
                "        case frozenset:\n"
                "            return frozenset\n"
            ),
        )

        for mutation in mutations:
            with self.subTest(mutation=mutation.strip().splitlines()[0]):
                self.write(state_path, original + mutation)
                with redirect_stdout(
                    io.StringIO()
                ), redirect_stderr(io.StringIO()):
                    self.assertEqual(
                        2,
                        self.validator.main(
                            ["--repo", str(self.repo)]
                        ),
                    )

    def test_state_contract_rejects_runtime_divergent_forms(self) -> None:
        state_path = Path(
            "plugins/codex-smart-subagents/src/"
            "codex_smart_subagents/state.py"
        )
        original = self.read(state_path)
        late_import = original.replace(
            "from enum import StrEnum\n\n\n",
            "",
        ).replace(
            "\n\nTERMINAL_STATES",
            "\n\nfrom enum import StrEnum\n\nTERMINAL_STATES",
        )
        shadowed_expansion = original.replace(
            (
                "**{state: frozenset() "
                "for state in TERMINAL_STATES}"
            ),
            (
                "**{frozenset: frozenset() "
                "for frozenset in TERMINAL_STATES}"
            ),
        )
        executable_annotation = original.replace(
            "from enum import StrEnum\n\n\n",
            (
                "from enum import StrEnum\n\n\n"
                "def marker():\n"
                "    return dict\n\n\n"
            ),
        ).replace(
            "ALLOWED_TRANSITIONS = {",
            "ALLOWED_TRANSITIONS: marker() = {",
        )
        missing_future = original.replace(
            "from __future__ import annotations\n\n",
            "",
        )
        redefined_dataclass = original.replace(
            "@dataclass\nclass StateTransitionError",
            (
                "def dataclass(cls):\n"
                "    dataclass.__globals__"
                '["ALLOWED_TRANSITIONS"].clear()\n'
                "    return cls\n\n\n"
                "@dataclass\nclass StateTransitionError"
            ),
        )
        late_dataclass = original.replace(
            "from dataclasses import dataclass\n",
            "",
        ).replace(
            "\n\ndef assert_transition",
            (
                "\n\nfrom dataclasses import dataclass\n\n\n"
                "def assert_transition"
            ),
        )
        generic_route = original.replace(
            "class RouteState(StrEnum):",
            "class RouteState[T](StrEnum):",
        )
        bounded_generic_route = original.replace(
            "class RouteState(StrEnum):",
            "class RouteState[T: int](StrEnum):",
        )
        defaulted_generic_route = original.replace(
            "class RouteState(StrEnum):",
            "class RouteState[T = int](StrEnum):",
        )

        for label, source in (
            ("late_import", late_import),
            ("shadowed_expansion", shadowed_expansion),
            ("executable_annotation", executable_annotation),
            ("missing_future", missing_future),
            ("redefined_dataclass", redefined_dataclass),
            ("late_dataclass", late_dataclass),
            ("generic_route", generic_route),
            ("bounded_generic_route", bounded_generic_route),
            ("defaulted_generic_route", defaulted_generic_route),
        ):
            with self.subTest(label=label):
                self.write(state_path, source)
                with redirect_stdout(
                    io.StringIO()
                ), redirect_stderr(io.StringIO()):
                    self.assertEqual(
                        2,
                        self.validator.main(
                            ["--repo", str(self.repo)]
                        ),
                    )

    def test_state_contract_requires_complete_transition_keys(
        self,
    ) -> None:
        state_path = Path(
            "plugins/codex-smart-subagents/src/"
            "codex_smart_subagents/state.py"
        )
        source = self.read(state_path).replace(
            (
                "    RouteState.PLANNED: "
                "frozenset({RouteState.SUCCEEDED}),\n"
            ),
            "",
        )
        self.write(state_path, source)

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(
                2,
                self.validator.main(["--repo", str(self.repo)]),
            )

    def test_state_contract_rejects_enum_special_members(self) -> None:
        state_path = Path(
            "plugins/codex-smart-subagents/src/"
            "codex_smart_subagents/state.py"
        )
        source = self.read(state_path).replace(
            "class RouteState(StrEnum):\n",
            'class RouteState(StrEnum):\n    _ignore_ = "HELPER"\n',
        )
        self.write(state_path, source)

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(
                2,
                self.validator.main(["--repo", str(self.repo)]),
            )

    def test_state_contract_rejects_worktree_symlink(self) -> None:
        relative = Path(
            "plugins/codex-smart-subagents/src/"
            "codex_smart_subagents/state.py"
        )
        outside = self.repo.parent / "outside-state.py"
        outside.write_text(self.read(relative), encoding="utf-8")
        state_path = self.repo / relative
        state_path.unlink()
        state_path.symlink_to(outside)

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(
                2,
                self.validator.main(["--repo", str(self.repo)]),
            )

    def test_cli_returns_zero_one_and_two(self) -> None:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(
                0,
                self.validator.main(["--repo", str(self.repo)]),
            )

            self.append(Path("README.md"), "\n[Нет](docs/missing.md)\n")
            self.assertEqual(
                1,
                self.validator.main(["--repo", str(self.repo)]),
            )

            not_git = Path(self.directory.name) / "not-git"
            not_git.mkdir()
            self.assertEqual(
                2,
                self.validator.main(["--repo", str(not_git)]),
            )

    def test_malformed_link_targets_return_validation_status(
        self,
    ) -> None:
        self.append(
            Path("README.md"),
            "\n[Нулевой байт](docs/%00.md)\n"
            "[Повреждённая сеть](https://[)\n",
        )

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(
                1,
                self.validator.main(["--repo", str(self.repo)]),
            )
        self.assertIn(
            "LOCAL_LINK_INVALID",
            issue_codes(self.validator.validate_repository(self.repo)),
        )

    def test_cli_returns_two_for_invalid_state_contract(self) -> None:
        state_path = (
            self.repo
            / "plugins/codex-smart-subagents/src/"
            "codex_smart_subagents/state.py"
        )
        state_path.write_text("not valid python )\n", encoding="utf-8")

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(
                2,
                self.validator.main(["--repo", str(self.repo)]),
            )

    def _write_valid_repository(self) -> None:
        files = {
            Path("README.md"): """\
# Каталог

- [Адаптивные субагенты](plugins/codex-smart-subagents/README.md#как-проходит-умный-ход)
- [Эксплуатация](docs/runbooks/adaptive-subagents-v2-operations.md)
- [Автономный процесс](docs/guides/autonomous-workflow.md)
- [Полный доступ](docs/guides/full-access.md)
- [Архитектура](docs/decisions/001-adaptive-subagents-external-controller.md)
- [Угрозы](docs/threat-models/adaptive-subagents.md)
""",
            Path("plugins/codex-smart-subagents/README.md"): """\
# Адаптивные субагенты

## Как проходит умный ход

```mermaid
sequenceDiagram
    A->>B: Запрос
```

```mermaid
flowchart LR
    A --> B
```

- [Переход](../../docs/migrations/adaptive-subagents-v2.md)
- [План](../../docs/plans/codex-adaptive-subagents-v2-implementation-plan.md)
""",
            Path("docs/runbooks/adaptive-subagents-v2-operations.md"): """\
# Эксплуатация

```mermaid
stateDiagram-v2
    PLANNED --> SUCCEEDED
```
""",
            Path("docs/guides/autonomous-workflow.md"): """\
# Автономный процесс

[Инженерный план](../plans/codex-autonomous-subagents-profiles-workers-plan.md)
""",
            Path("docs/guides/full-access.md"): """\
# Полный доступ

[Инженерный план](../plans/codex-full-access-defaults.md)
""",
            Path("docs/decisions/001-adaptive-subagents-external-controller.md"): """\
# Архитектурное решение
""",
            Path("docs/threat-models/adaptive-subagents.md"): """\
# Модель угроз
""",
            Path("docs/migrations/adaptive-subagents-v2.md"): """\
# Переход
""",
            Path("docs/plans/codex-adaptive-subagents-v2-implementation-plan.md"): """\
# План адаптивных субагентов
""",
            Path("docs/plans/codex-autonomous-subagents-profiles-workers-plan.md"): """\
# План автономного процесса
""",
            Path("docs/plans/codex-full-access-defaults.md"): """\
# План полного доступа
""",
            Path(
                "plugins/codex-smart-subagents/src/"
                "codex_smart_subagents/state.py"
            ): """\
\"\"\"Route state machine for tests.\"\"\"

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RouteState(StrEnum):
    PLANNED = "PLANNED"
    SUCCEEDED = "SUCCEEDED"


TERMINAL_STATES = frozenset({RouteState.SUCCEEDED})

ALLOWED_TRANSITIONS: dict[RouteState, frozenset[RouteState]] = {
    RouteState.PLANNED: frozenset({RouteState.SUCCEEDED}),
    **{state: frozenset() for state in TERMINAL_STATES},
}


@dataclass
class StateTransitionError(ValueError):
    before: RouteState
    after: RouteState

    def __str__(self) -> str:
        return f"invalid route transition: {self.before} -> {self.after}"


def assert_transition(before: RouteState, after: RouteState) -> None:
    if after not in ALLOWED_TRANSITIONS[before]:
        raise StateTransitionError(before, after)


def is_terminal(state: RouteState) -> bool:
    return state in TERMINAL_STATES
""",
        }
        for path, content in files.items():
            self.write(path, content)
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "--all"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def write(self, relative: Path, content: str) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def append(self, relative: Path, content: str) -> None:
        path = self.repo / relative
        path.write_text(
            path.read_text(encoding="utf-8") + content,
            encoding="utf-8",
        )

    def read(self, relative: Path) -> str:
        return (self.repo / relative).read_text(encoding="utf-8")

    def track(self, relative: Path) -> None:
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "--", str(relative)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


if __name__ == "__main__":
    unittest.main()

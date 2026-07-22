from __future__ import annotations

import importlib.util
import copy
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents import installer_command_v2 as subject  # noqa: E402
from codex_smart_subagents.canonical_json import domain_fingerprint  # noqa: E402


SCHEMA_PATH = ROOT / "docs/contracts/schemas/lifecycle-command-result-v2.schema.json"


class InstallerCommandV2AvailabilityTests(unittest.TestCase):
    def test_installer_command_module_is_available(self) -> None:
        self.assertIsNotNone(
            importlib.util.find_spec("codex_smart_subagents.installer_command_v2")
        )


class LifecycleCommandResultBuilderV2Tests(unittest.TestCase):
    def test_builder_sorts_collections_fingerprints_projection_and_validates_schema(
        self,
    ) -> None:
        builder = getattr(subject, "build_lifecycle_command_result_v2", None)
        result = (
            builder(
                command="apply",
                status="installed",
                readiness="READY",
                operation_id="op2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                attempt_id="opa2_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                changes=[
                    {
                        "kind": "gate_opened",
                        "beforeFingerprint": None,
                        "afterFingerprint": "3" * 64,
                    },
                    {
                        "kind": "migrated_manifest",
                        "beforeFingerprint": None,
                        "afterFingerprint": "1" * 64,
                    },
                    {
                        "kind": "staged_generation",
                        "beforeFingerprint": None,
                        "afterFingerprint": "2" * 64,
                    },
                ],
                problems=[
                    {
                        "code": "THIRD_INFO",
                        "severity": "info",
                        "component": "installer",
                        "message": "Журнал сохранён.",
                        "remediation": "Сохраните журнал.",
                    },
                    {
                        "code": "SECOND_WARNING",
                        "severity": "warning",
                        "component": "controller",
                        "message": "Контроллер остановлен.",
                        "remediation": "Проверьте состояние.",
                    },
                    {
                        "code": "FIRST_ERROR",
                        "severity": "error",
                        "component": "activation",
                        "message": "Ошибка активации.",
                        "remediation": "Выполните восстановление.",
                    },
                ],
            )
            if builder is not None
            else None
        )

        self.assertIsInstance(result, dict)
        assert isinstance(result, dict)
        self.assertEqual(2, result["schemaVersion"])
        self.assertEqual(
            ["migrated_manifest", "staged_generation", "gate_opened"],
            [change["kind"] for change in result["changes"]],
        )
        self.assertEqual(
            ["FIRST_ERROR", "SECOND_WARNING", "THIRD_INFO"],
            [problem["code"] for problem in result["problems"]],
        )
        projection = {
            "schemaVersion": 2,
            "command": "apply",
            "status": "installed",
            "readiness": "READY",
            "smokeInvocationId": None,
            "changes": result["changes"],
            "problems": [
                {
                    "code": problem["code"],
                    "severity": problem["severity"],
                    "component": problem["component"],
                }
                for problem in result["problems"]
            ],
        }
        self.assertEqual(
            domain_fingerprint("codex-smart/command-result/v2", projection),
            result["resultFingerprint"],
        )
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual([], list(Draft202012Validator(schema).iter_errors(result)))

    def test_builder_rejects_duplicate_change_kind(self) -> None:
        change = {
            "kind": "gate_closed",
            "beforeFingerprint": "1" * 64,
            "afterFingerprint": "2" * 64,
        }

        with self.assertRaises(subject.LifecycleCommandResultV2Error) as caught:
            subject.build_lifecycle_command_result_v2(
                command="apply",
                status="failed",
                readiness="BROKEN",
                operation_id="op2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                attempt_id="opa2_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                changes=[change, dict(change)],
                problems=[
                    {
                        "code": "ACTIVATION_FAILED",
                        "severity": "error",
                        "component": "activation",
                        "message": "Не удалось активировать поколение.",
                        "remediation": "Выполните восстановление.",
                    }
                ],
            )

        self.assertEqual("CHANGE_KIND_DUPLICATE", caught.exception.code)

    def test_builder_rejects_change_without_effect(self) -> None:
        with self.assertRaises(subject.LifecycleCommandResultV2Error) as caught:
            subject.build_lifecycle_command_result_v2(
                command="rollback",
                status="rolled_back",
                readiness="READY",
                operation_id="op2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                attempt_id="opa2_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                changes=[
                    {
                        "kind": "published_activation",
                        "beforeFingerprint": "4" * 64,
                        "afterFingerprint": "4" * 64,
                    }
                ],
            )

        self.assertEqual("CHANGE_NO_EFFECT", caught.exception.code)

    def test_builder_enforces_command_specific_change_semantics(self) -> None:
        with self.assertRaises(subject.LifecycleCommandResultV2Error) as caught:
            subject.build_lifecycle_command_result_v2(
                command="rollback",
                status="rolled_back",
                readiness="READY",
                operation_id="op2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                attempt_id="opa2_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                changes=[
                    {
                        "kind": "retired_generation",
                        "beforeFingerprint": "4" * 64,
                        "afterFingerprint": None,
                    }
                ],
            )

        self.assertEqual("RETIRED_GENERATION_OUTSIDE_CLEANUP", caught.exception.code)

    def test_builder_wraps_malformed_input_as_structural_error(self) -> None:
        caught: BaseException | None = None
        try:
            subject.build_lifecycle_command_result_v2(
                command="apply",
                status="failed",
                readiness="BROKEN",
                changes=[
                    {
                        "kind": "gate_closed",
                        "beforeFingerprint": "1" * 64,
                    }
                ],
            )
        except BaseException as error:  # noqa: BLE001 - проверяется граница API
            caught = error

        self.assertIsInstance(caught, subject.LifecycleCommandResultV2Error)

        caught = None
        try:
            subject.build_lifecycle_command_result_v2(
                command="apply",
                status="failed",
                readiness="BROKEN",
                changes=[object()],  # type: ignore[list-item]
            )
        except BaseException as error:  # noqa: BLE001 - проверяется граница API
            caught = error
        self.assertIsInstance(caught, subject.LifecycleCommandResultV2Error)

    def test_failed_result_remains_strict_json(self) -> None:
        result = subject.build_lifecycle_command_result_v2(
            command="recover",
            status="failed",
            readiness="BROKEN",
            problems=[
                {
                    "code": "RECOVERY_FAILED",
                    "severity": "error",
                    "component": "recovery",
                    "message": "Восстановление не завершилось.",
                    "remediation": "Сохраните журнал и повторите операцию.",
                }
            ],
        )

        decoded = json.loads(json.dumps(result, ensure_ascii=False, sort_keys=True))
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(result, decoded)
        self.assertEqual([], list(Draft202012Validator(schema).iter_errors(decoded)))

    def test_builder_rejects_non_json_extensions(self) -> None:
        for invalid in (object(), float("nan")):
            with self.subTest(invalid_type=type(invalid).__name__):
                with self.assertRaises(subject.LifecycleCommandResultV2Error) as caught:
                    subject.build_lifecycle_command_result_v2(
                        command="inspect",
                        status="inspected",
                        readiness="READY",
                        extensions={"invalid": invalid},
                    )
                self.assertEqual("RESULT_JSON_INVALID", caught.exception.code)


class InstallerArgvV2Tests(unittest.TestCase):
    def test_no_mode_is_backward_compatible_apply_preview(self) -> None:
        parser = getattr(subject, "parse_installer_argv_v2", None)
        parsed = parser([]) if parser is not None else None

        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual("apply", parsed.command)
        self.assertFalse(parsed.execute)
        self.assertFalse(parsed.json)
        self.assertEqual(str(ROOT), parsed.source_root)
        self.assertEqual("codex", parsed.codex_binary)
        self.assertIsNone(parsed.codex_home)
        self.assertIsNone(parsed.bin_dir)
        self.assertIsNone(parsed.state_home)
        self.assertFalse(parsed.retain_data)

    def test_preserves_legacy_paths_binary_and_json_for_apply(self) -> None:
        parsed = subject.parse_installer_argv_v2(
            [
                "--source-root",
                "/source",
                "--codex-home",
                "/codex",
                "--bin-dir",
                "/bin",
                "--state-home",
                "/state",
                "--codex-binary",
                "/tools/codex",
                "--json",
                "--apply",
            ]
        )

        self.assertEqual("apply", parsed.command)
        self.assertTrue(parsed.execute)
        self.assertTrue(parsed.json)
        self.assertEqual("/source", parsed.source_root)
        self.assertEqual("/codex", parsed.codex_home)
        self.assertEqual("/bin", parsed.bin_dir)
        self.assertEqual("/state", parsed.state_home)
        self.assertEqual("/tools/codex", parsed.codex_binary)

    def test_read_only_modes_execute_and_reject_execution_modifiers(self) -> None:
        for mode in ("doctor", "smoke", "inspect"):
            with self.subTest(mode=mode):
                parsed = subject.parse_installer_argv_v2([f"--{mode}"])
                self.assertEqual(mode, parsed.command)
                self.assertTrue(parsed.execute)
                for modifier in ("--preview", "--apply"):
                    with self.assertRaises(subject.InvalidInstallerInvocationV2):
                        subject.parse_installer_argv_v2([f"--{mode}", modifier])

    def test_new_mutating_modes_require_exactly_one_execution_modifier(self) -> None:
        for mode in ("rollback", "uninstall", "recover", "cleanup"):
            required = ["--retain-data"] if mode == "uninstall" else []
            with self.subTest(mode=mode, case="missing"):
                with self.assertRaises(subject.InvalidInstallerInvocationV2):
                    subject.parse_installer_argv_v2([f"--{mode}", *required])
            with self.subTest(mode=mode, case="both"):
                with self.assertRaises(subject.InvalidInstallerInvocationV2):
                    subject.parse_installer_argv_v2(
                        [f"--{mode}", *required, "--preview", "--apply"]
                    )
            with self.subTest(mode=mode, case="preview"):
                preview = subject.parse_installer_argv_v2(
                    [f"--{mode}", *required, "--preview"]
                )
                self.assertEqual(mode, preview.command)
                self.assertFalse(preview.execute)
            with self.subTest(mode=mode, case="apply"):
                apply = subject.parse_installer_argv_v2(
                    [f"--{mode}", *required, "--apply"]
                )
                self.assertEqual(mode, apply.command)
                self.assertTrue(apply.execute)

    def test_retain_data_is_required_only_for_uninstall(self) -> None:
        with self.assertRaises(subject.InvalidInstallerInvocationV2):
            subject.parse_installer_argv_v2(["--uninstall", "--preview"])
        for mode in (
            None,
            "doctor",
            "smoke",
            "inspect",
            "rollback",
            "recover",
            "cleanup",
        ):
            arguments = ["--retain-data"]
            if mode is not None:
                arguments.insert(0, f"--{mode}")
            if mode in {"rollback", "recover", "cleanup"}:
                arguments.append("--preview")
            with self.subTest(mode=mode):
                with self.assertRaises(subject.InvalidInstallerInvocationV2):
                    subject.parse_installer_argv_v2(arguments)

    def test_apply_preview_and_apply_are_mutually_exclusive(self) -> None:
        preview = subject.parse_installer_argv_v2(["--preview"])
        self.assertEqual("apply", preview.command)
        self.assertFalse(preview.execute)
        with self.assertRaises(subject.InvalidInstallerInvocationV2):
            subject.parse_installer_argv_v2(["--preview", "--apply"])

    def test_operation_modes_are_mutually_exclusive(self) -> None:
        with self.assertRaises(subject.InvalidInstallerInvocationV2):
            subject.parse_installer_argv_v2(["--doctor", "--smoke"])


class InstallerExitCodeV2Tests(unittest.TestCase):
    def test_valid_results_map_to_zero_or_two_without_code_one(self) -> None:
        classify = getattr(subject, "exit_code_v2", lambda _outcome: 1)
        ready = subject.build_lifecycle_command_result_v2(
            command="inspect",
            status="inspected",
            readiness="READY",
        )
        degraded = subject.build_lifecycle_command_result_v2(
            command="doctor",
            status="DEGRADED",
            readiness="DEGRADED",
            problems=[
                {
                    "code": "CONTROLLER_NOT_READY",
                    "severity": "warning",
                    "component": "controller",
                    "message": "Контроллер ещё не готов.",
                    "remediation": "Повторите проверку.",
                }
            ],
        )
        failed_but_structured = subject.build_lifecycle_command_result_v2(
            command="apply",
            status="failed",
            readiness="READY",
            problems=[
                {
                    "code": "ACTIVATION_FAILED",
                    "severity": "error",
                    "component": "activation",
                    "message": "Активация не завершилась.",
                    "remediation": "Запустите восстановление.",
                }
            ],
        )

        self.assertEqual(0, classify(ready))
        self.assertEqual(2, classify(degraded))
        self.assertEqual(2, classify(failed_but_structured))
        self.assertNotIn(1, {classify(ready), classify(degraded)})

    def test_successful_uninstall_is_zero_even_when_readiness_is_disabled(self) -> None:
        result = subject.build_lifecycle_command_result_v2(
            command="uninstall",
            status="uninstalled",
            readiness="DISABLED",
            operation_id="op2_" + "a" * 32,
            attempt_id="opa2_" + "b" * 32,
            changes=[
                {
                    "kind": "removed_installation",
                    "beforeFingerprint": "c" * 64,
                    "afterFingerprint": None,
                }
            ],
        )

        self.assertEqual(0, subject.exit_code_v2(result))

    def test_successful_recovery_of_uninstall_is_zero_when_disabled(self) -> None:
        result = subject.build_lifecycle_command_result_v2(
            command="recover",
            status="recovered",
            readiness="DISABLED",
            operation_id="op2_" + "a" * 32,
            attempt_id="opa2_" + "b" * 32,
        )

        self.assertEqual(0, subject.exit_code_v2(result))

    def test_invocation_internal_and_proven_busy_errors_have_distinct_codes(
        self,
    ) -> None:
        classify = getattr(subject, "exit_code_v2", lambda _outcome: 1)
        busy_type = getattr(subject, "ProvenTemporaryBusyV2", RuntimeError)
        busy = (
            busy_type(
                code="CONTROLLER_BUSY",
                message="Контроллер занят другой операцией.",
                proof={"operationId": "op2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            )
            if busy_type is not RuntimeError
            else RuntimeError("missing ProvenTemporaryBusyV2")
        )

        self.assertEqual(
            64,
            classify(subject.InvalidInstallerInvocationV2("неверный вызов")),
        )
        self.assertEqual(75, classify(busy))
        self.assertEqual(70, classify(RuntimeError("внутренняя ошибка")))
        self.assertEqual(70, classify({"schemaVersion": 2}))

    def test_structural_unicode_error_maps_to_seventy(self) -> None:
        result = subject.build_lifecycle_command_result_v2(
            command="doctor",
            status="DEGRADED",
            readiness="DEGRADED",
            problems=[
                {
                    "code": "CONTROLLER_NOT_READY",
                    "severity": "warning",
                    "component": "controller",
                    "message": "Контроллер ещё не готов.",
                    "remediation": "Повторите проверку.",
                }
            ],
        )
        malformed = copy.deepcopy(result)
        malformed["problems"][0]["message"] = "\ud800"
        caught: BaseException | None = None
        try:
            code = subject.exit_code_v2(malformed)
        except BaseException as error:  # noqa: BLE001 - проверяется граница API
            caught = error
            code = None

        self.assertIsNone(caught)
        self.assertEqual(70, code)


if __name__ == "__main__":
    unittest.main()

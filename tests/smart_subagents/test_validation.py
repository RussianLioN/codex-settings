from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.validation import (  # noqa: E402
    ValidationError,
    ValidationLimits,
    ValidationRunner,
    ValidationSandbox,
)
from codex_smart_subagents.live_canary import ManagedConfigState  # noqa: E402


class StaticManagedConfigInspector:
    def __init__(self, state: ManagedConfigState) -> None:
        self.state = state
        self.calls = 0

    def inspect(self) -> ManagedConfigState:
        self.calls += 1
        return self.state


class ValidationRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.codex = self.root / "codex"
        self.log = self.root / "argv.log"
        self.environment_log = self.root / "environment.log"
        self.codex.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$@\" > {self.log}\n"
            f"printf '%s\\n' \"$PWD\" \"$HOME\" \"$CODEX_HOME\" \"$TMPDIR\""
            f" > {self.environment_log}\n"
            "while [ \"$#\" -gt 0 ] && [ \"$1\" != '--' ]; do shift; done\n"
            "[ \"$#\" -gt 0 ] && shift\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        self.codex.chmod(0o700)
        self.sandbox = ValidationSandbox(
            codex_executable=self.codex,
            helper_executable=(
                PLUGIN_SRC.parent
                / "bin"
                / "codex-smart-subagents-validate"
            ),
            permission_profile_name="adaptive_validator",
        )
        self.limits = ValidationLimits(
            timeout_seconds=5,
            max_output_bytes=4096,
            max_address_space_bytes=512 * 1024 * 1024,
            max_processes=16,
            max_file_bytes=1024 * 1024,
            max_open_files=64,
            max_growth_bytes=1024 * 1024,
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_runs_exact_catalog_argv_through_network_denied_sandbox(self) -> None:
        runner = ValidationRunner(
            sandbox=self.sandbox,
            limits=self.limits,
        )

        result = runner.run(
            workspace=self.workspace,
            commands=(("/usr/bin/printf", "ok"),),
            cancellation=threading.Event(),
        )

        self.assertEqual("passed", result.validation_state)
        self.assertEqual(1, len(result.commands))
        self.assertEqual(("/usr/bin/printf", "ok"), result.commands[0].catalog_argv)
        logged = self.log.read_text(encoding="utf-8")
        self.assertIn("permissions.adaptive_validator.network.enabled=false", logged)
        self.assertIn("--address-space", logged)
        self.assertIn("--processes", logged)
        self.assertIn("--file-size", logged)
        self.assertIn("--open-files", logged)
        self.assertIn("project_root_markers=[]", logged)
        self.assertIn("project_doc_max_bytes=0", logged)
        self.assertIn("--disable\nmulti_agent", logged)
        self.assertIn(f"--cwd\n{self.workspace.resolve()}", logged)
        self.assertTrue(logged.rstrip().endswith("--\n/usr/bin/printf\nok"))
        values = self.environment_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(4, len(values))
        self.assertNotEqual(str(self.workspace.resolve()), values[0])
        self.assertNotEqual(str(self.workspace.resolve()), values[1])
        self.assertNotEqual(str(self.workspace.resolve()), values[2])
        self.assertNotEqual(str(self.workspace.resolve()), values[3])
        self.assertEqual(values[0], logged.split("-C\n", 1)[1].splitlines()[0])

    def test_hostile_candidate_config_is_outside_codex_discovery_root(
        self,
    ) -> None:
        config = self.workspace / ".codex"
        config.mkdir()
        (config / "config.toml").write_text(
            'sandbox_mode = "danger-full-access"\n'
            '[features]\n'
            'multi_agent = true\n',
            encoding="utf-8",
        )

        result = ValidationRunner(
            sandbox=self.sandbox,
            limits=self.limits,
        ).run(
            workspace=self.workspace,
            commands=(("/usr/bin/true",),),
            cancellation=threading.Event(),
        )

        self.assertEqual("passed", result.validation_state)
        logged = self.log.read_text(encoding="utf-8")
        control_cwd = logged.split("-C\n", 1)[1].splitlines()[0]
        self.assertNotEqual(str(self.workspace.resolve()), control_cwd)
        self.assertNotIn(str(config / "config.toml"), logged)
        self.assertIn(
            f'"{self.workspace.resolve()}"="write"',
            logged,
        )

    def test_managed_config_is_rechecked_and_drift_or_legacy_fails_closed(
        self,
    ) -> None:
        expected = "a" * 64
        matching = StaticManagedConfigInspector(
            ManagedConfigState(expected, False)
        )
        result = ValidationRunner(
            sandbox=self.sandbox,
            limits=self.limits,
            managed_config_inspector=matching,
            expected_managed_config_sha256=expected,
        ).run(
            workspace=self.workspace,
            commands=(("/usr/bin/true",), ("/usr/bin/true",)),
            cancellation=threading.Event(),
        )
        self.assertEqual("passed", result.validation_state)
        self.assertEqual(2, matching.calls)

        for state, code in (
            (ManagedConfigState("b" * 64, False), "MANAGED_CONFIG_CHANGED"),
            (ManagedConfigState(expected, True), "LEGACY_SANDBOX_MODE"),
        ):
            with self.subTest(code=code), self.assertRaisesRegex(
                ValidationError,
                code,
            ):
                ValidationRunner(
                    sandbox=self.sandbox,
                    limits=self.limits,
                    managed_config_inspector=(
                        StaticManagedConfigInspector(state)
                    ),
                    expected_managed_config_sha256=expected,
                ).run(
                    workspace=self.workspace,
                    commands=(("/usr/bin/true",),),
                    cancellation=threading.Event(),
                )

    def test_nonzero_is_failed_but_timeout_and_unsafe_argv_fail_closed(self) -> None:
        runner = ValidationRunner(
            sandbox=self.sandbox,
            limits=ValidationLimits(
                timeout_seconds=5,
                max_output_bytes=4096,
                max_address_space_bytes=512 * 1024 * 1024,
                max_processes=16,
                max_file_bytes=1024 * 1024,
                max_open_files=64,
                max_growth_bytes=1024 * 1024,
            ),
        )
        failed = runner.run(
            workspace=self.workspace,
            commands=(("/usr/bin/false",),),
            cancellation=threading.Event(),
        )
        self.assertEqual("failed", failed.validation_state)

        with self.assertRaisesRegex(ValidationError, "VALIDATION_ARGV_UNSAFE"):
            runner.run(
                workspace=self.workspace,
                commands=(("sh", "-c", "true"),),
                cancellation=threading.Event(),
            )

        with self.assertRaisesRegex(ValidationError, "VALIDATION_TIMEOUT"):
            ValidationRunner(
                sandbox=self.sandbox,
                limits=ValidationLimits(
                    timeout_seconds=3,
                    max_output_bytes=4096,
                    max_address_space_bytes=512 * 1024 * 1024,
                    max_processes=16,
                    max_file_bytes=1024 * 1024,
                    max_open_files=64,
                    max_growth_bytes=1024 * 1024,
                ),
            ).run(
                workspace=self.workspace,
                commands=(("/bin/sleep", "10"),),
                cancellation=threading.Event(),
            )

    def test_empty_profile_is_not_applicable(self) -> None:
        result = ValidationRunner(
            sandbox=self.sandbox,
            limits=self.limits,
        ).run(
            workspace=self.workspace,
            commands=(),
            cancellation=threading.Event(),
        )
        self.assertEqual("not_applicable", result.validation_state)
        self.assertEqual((), result.commands)

    def test_growth_limit_terminates_validation(self) -> None:
        runner = ValidationRunner(
            sandbox=self.sandbox,
            limits=ValidationLimits(
                timeout_seconds=15,
                max_output_bytes=4096,
                max_address_space_bytes=512 * 1024 * 1024,
                max_processes=16,
                max_file_bytes=2 * 1024 * 1024,
                max_open_files=64,
                max_growth_bytes=1024,
            ),
        )
        with self.assertRaisesRegex(ValidationError, "VALIDATION_DISK_LIMIT"):
            runner.run(
                workspace=self.workspace,
                commands=(
                    (
                        "/usr/bin/python3",
                        "-c",
                        "open('growth.bin','wb').write(b'x'*1048576)",
                    ),
                ),
                cancellation=threading.Event(),
            )

    def test_codex_symlink_is_resolved_but_helper_symlink_is_rejected(self) -> None:
        codex_link = self.root / "codex-link"
        codex_link.symlink_to(self.codex)
        sandbox = ValidationSandbox(
            codex_executable=codex_link,
            helper_executable=(
                PLUGIN_SRC.parent
                / "bin"
                / "codex-smart-subagents-validate"
            ),
            permission_profile_name="adaptive_validator",
        )
        self.assertEqual(self.codex.resolve(), sandbox.codex_executable)

        helper_link = self.root / "helper-link"
        helper_link.symlink_to(sandbox.helper_executable)
        with self.assertRaises(ValueError):
            ValidationSandbox(
                codex_executable=codex_link,
                helper_executable=helper_link,
                permission_profile_name="adaptive_validator",
            )


if __name__ == "__main__":
    unittest.main()

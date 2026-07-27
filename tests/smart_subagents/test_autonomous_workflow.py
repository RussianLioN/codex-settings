from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "validate_autonomous_workflow.py"
TARGET_ALIASES = (
    b"alias codex='CODEX_SMART_ENABLED=1 CODEX_SMART_REQUIRED=1 "
    b"$HOME/.local/bin/codex-highfd'\n"
    b"alias codex-native='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 "
    b"$HOME/.local/bin/codex-highfd'\n"
    b"alias codexs='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 "
    b"$HOME/.local/bin/codex-highfd --profile standard'\n"
    b"alias codexro='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 "
    b"$HOME/.local/bin/codex-highfd --profile safe-readonly'\n"
    b"alias codexwide='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 "
    b"$HOME/.local/bin/codex-highfd --profile wide-readers'\n"
    b"alias codexfa='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 "
    b"$HOME/.local/bin/codex-highfd --profile full-access'\n"
    b"alias codexfd='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 "
    b"$HOME/.local/bin/codex-highfd --fd-doctor'\n"
)


def load_validator() -> ModuleType:
    name = "autonomous_workflow_entrypoint_contract_under_test"
    spec = importlib.util.spec_from_file_location(name, VALIDATOR)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load validator: {VALIDATOR}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AutonomousWorkflowEntrypointContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp",
            prefix="autonomous-workflow-entrypoint-",
        )
        self.root = Path(self.temporary.name)
        self.aliases = self.root / "codex-autonomous-aliases.zsh"
        self.installed_highfd = self.root / "installed-codex-highfd"
        self.tracked_highfd = self.root / "tracked-codex-highfd"
        self.journal = self.root / "codex-entrypoint-v1.journal.json"
        self.aliases.write_bytes(TARGET_ALIASES)
        self.tracked_highfd.write_bytes(b"tracked highfd\n")
        self.installed_highfd.write_bytes(self.tracked_highfd.read_bytes())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _failures(self) -> list[str]:
        return self.validator.entrypoint_contract_failures(
            aliases_path=self.aliases,
            installed_highfd_path=self.installed_highfd,
            tracked_highfd_path=self.tracked_highfd,
            journal_path=self.journal,
        )

    def test_exact_managed_entrypoint_contract_is_healthy(self) -> None:
        self.assertEqual(TARGET_ALIASES, self.validator.ENTRYPOINT_ALIASES_BYTES)
        self.assertEqual([], self._failures())

    def test_alias_contract_rejects_one_byte_drift_and_legacy_substrings(
        self,
    ) -> None:
        self.aliases.write_bytes(
            b"# tolerated-looking prefix\n" + TARGET_ALIASES
        )

        failures = self._failures()

        self.assertTrue(
            any("exact managed bytes" in failure for failure in failures),
            failures,
        )

    def test_highfd_contract_accepts_only_current_tracked_bytes(self) -> None:
        self.installed_highfd.write_bytes(b"supported legacy highfd\n")

        failures = self._failures()

        self.assertTrue(
            any("tracked codex-highfd hash" in failure for failure in failures),
            failures,
        )

    def test_healthy_contract_rejects_a_pending_reconciler_journal(self) -> None:
        self.journal.write_text("{}\n", encoding="utf-8")

        failures = self._failures()

        self.assertTrue(
            any("reconciler journal" in failure for failure in failures),
            failures,
        )

    def test_contract_reports_missing_files_without_using_real_home(self) -> None:
        self.aliases.unlink()
        self.installed_highfd.unlink()

        failures = self._failures()

        self.assertTrue(
            any(str(self.aliases) in failure for failure in failures),
            failures,
        )
        self.assertTrue(
            any(str(self.installed_highfd) in failure for failure in failures),
            failures,
        )


if __name__ == "__main__":
    unittest.main()

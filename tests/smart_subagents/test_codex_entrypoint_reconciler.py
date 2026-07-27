from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
HIGHFD = ROOT / "scripts" / "codex-highfd"
RECONCILER = ROOT / "scripts" / "reconcile_codex_entrypoint.py"
LEGACY_HIGHFD = (
    ROOT / "tests" / "smart_subagents" / "fixtures" / "codex-highfd-legacy"
).read_bytes()
LEGACY_ALIASES = (
    b"# Codex autonomous workflow profile aliases.\n"
    b"alias codex='$HOME/.local/bin/codex-highfd'\n"
    b"alias codexs='$HOME/.local/bin/codex-highfd --profile standard'\n"
    b"alias codexro='$HOME/.local/bin/codex-highfd --profile safe-readonly'\n"
    b"alias codexwide='$HOME/.local/bin/codex-highfd --profile wide-readers'\n"
    b"alias codexfa='$HOME/.local/bin/codex-highfd --profile full-access'\n"
    b"alias codexfd='$HOME/.local/bin/codex-highfd --fd-doctor'\n"
)
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
RECEIPT_DOCUMENT_TYPE = "codex-entrypoint-receipt-v1"
JOURNAL_DOCUMENT_TYPE = "codex-entrypoint-journal-v1"
RECEIPT_FINGERPRINT_DOMAIN = b"codex-entrypoint-receipt-v1\x00"
JOURNAL_FINGERPRINT_DOMAIN = b"codex-entrypoint-journal-v1\x00"


def load_reconciler() -> ModuleType:
    name = "codex_entrypoint_reconciler_under_test"
    spec = importlib.util.spec_from_file_location(name, RECONCILER)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load reconciler: {RECONCILER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class CodexHighfdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp",
            prefix="codex-entrypoint-highfd-",
        )
        self.root = Path(self.temporary.name)
        self.native = self._write_probe("native")
        self.smart = self._write_probe("smart")
        self.doctor = self._write_probe("doctor")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_probe(self, name: str) -> Path:
        path = self.root / name
        path.write_text(
            (
                "#!/usr/bin/env python3\n"
                "import json\n"
                "import os\n"
                "import sys\n"
                "print(json.dumps({\n"
                f"    'launcher': {name!r},\n"
                "    'argv': sys.argv[1:],\n"
                "    'smart_enabled': os.environ.get('CODEX_SMART_ENABLED'),\n"
                "    'smart_required': os.environ.get('CODEX_SMART_REQUIRED'),\n"
                "    'real_bin': os.environ.get('CODEX_REAL_BIN'),\n"
                "}, sort_keys=True))\n"
            ),
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    def _run(
        self,
        *,
        enabled: str | None,
        required: str | None,
        arguments: tuple[str, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "CODEX_NOFILE_LIMIT": "1",
                "CODEX_REAL_BIN": str(self.native),
                "CODEX_SMART_LAUNCHER": str(self.smart),
                "CODEX_FD_DOCTOR": str(self.doctor),
            }
        )
        if enabled is None:
            env.pop("CODEX_SMART_ENABLED", None)
        else:
            env["CODEX_SMART_ENABLED"] = enabled
        if required is None:
            env.pop("CODEX_SMART_REQUIRED", None)
        else:
            env["CODEX_SMART_REQUIRED"] = required
        return subprocess.run(
            ("/bin/zsh", str(HIGHFD), *arguments),
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_smart_pair_routes_to_smart_and_preserves_arguments(self) -> None:
        completed = self._run(
            enabled="1",
            required="1",
            arguments=("--profile", "standard", "argument with spaces"),
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual("smart", result["launcher"])
        self.assertEqual(
            ["--profile", "standard", "argument with spaces"],
            result["argv"],
        )
        self.assertEqual("1", result["smart_enabled"])
        self.assertEqual("1", result["smart_required"])
        self.assertEqual(str(self.native), result["real_bin"])

    def test_native_pair_routes_to_native_and_clears_smart_markers(self) -> None:
        completed = self._run(
            enabled="0",
            required="0",
            arguments=("exec", "--json", "argument with spaces"),
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual("native", result["launcher"])
        self.assertEqual(
            ["exec", "--json", "argument with spaces"],
            result["argv"],
        )
        self.assertIsNone(result["smart_enabled"])
        self.assertIsNone(result["smart_required"])

    def test_required_without_enabled_is_rejected(self) -> None:
        completed = self._run(enabled="0", required="1")

        self.assertEqual(2, completed.returncode)
        self.assertIn(
            "CODEX_SMART_REQUIRED=1 requires CODEX_SMART_ENABLED=1",
            completed.stderr,
        )
        self.assertEqual("", completed.stdout)

    def test_values_outside_binary_domain_are_rejected(self) -> None:
        cases = (
            ("invalid", "0", "CODEX_SMART_ENABLED"),
            ("0", "invalid", "CODEX_SMART_REQUIRED"),
            ("2", "1", "CODEX_SMART_ENABLED"),
            ("1", "-1", "CODEX_SMART_REQUIRED"),
        )
        for enabled, required, marker in cases:
            with self.subTest(enabled=enabled, required=required):
                completed = self._run(enabled=enabled, required=required)
                self.assertEqual(2, completed.returncode)
                self.assertIn(marker, completed.stderr)
                self.assertEqual("", completed.stdout)

    def test_default_markers_route_to_native(self) -> None:
        completed = self._run(enabled=None, required=None)

        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual("native", result["launcher"])
        self.assertIsNone(result["smart_enabled"])
        self.assertIsNone(result["smart_required"])

    def test_fd_doctor_never_reaches_smart_launcher(self) -> None:
        completed = self._run(
            enabled="1",
            required="1",
            arguments=("--fd-doctor", "--json"),
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual("doctor", result["launcher"])
        self.assertEqual(["--json"], result["argv"])

    def test_self_test_never_reaches_smart_launcher(self) -> None:
        completed = self._run(
            enabled="1",
            required="1",
            arguments=("--self-test",),
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("smart_enabled=1", completed.stdout)
        self.assertIn("smart_required=1", completed.stdout)
        self.assertNotIn('"launcher": "smart"', completed.stdout)


class CodexEntrypointReconcilerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp",
            prefix="codex-entrypoint-reconciler-",
        )
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.highfd = self.home / ".local" / "bin" / "codex-highfd"
        self.external_codex = self.home / ".local" / "bin" / "codex"
        self.aliases = self.home / ".codex" / "codex-autonomous-aliases.zsh"
        self.manifests = self.home / ".codex" / "install-manifests"
        self.receipt = self.manifests / "codex-entrypoint-v1.json"
        self.journal = self.manifests / "codex-entrypoint-v1.journal.json"
        self.lock = self.manifests / "codex-entrypoint-v1.lock"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(
        self,
        command: str,
        *,
        failpoint: str | None = None,
        path_value: str = "/test/path:/usr/bin",
        source_root: Path = ROOT,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        env = os.environ.copy()
        env["PATH"] = path_value
        if failpoint is None:
            env.pop("CODEX_ENTRYPOINT_TEST_FAILPOINT", None)
        else:
            env["CODEX_ENTRYPOINT_TEST_FAILPOINT"] = failpoint
        completed = subprocess.run(
            (
                sys.executable,
                str(RECONCILER),
                f"--{command}",
                "--json",
                "--home",
                str(self.home.resolve()),
                "--source-root",
                str(source_root.resolve()),
            ),
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self.fail(
                f"reconciler emitted invalid JSON: {exc}; "
                f"stdout={completed.stdout!r}; stderr={completed.stderr!r}"
            )
        self.assertEqual(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
            completed.stdout,
        )
        return completed, result

    def _seed(
        self,
        path: Path,
        data: bytes,
        mode: int,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def _snapshot(self) -> tuple[tuple[str, str, object], ...]:
        if not self.home.exists():
            return ()
        result: list[tuple[str, str, object]] = []
        for path in sorted(self.home.rglob("*"), key=lambda item: item.as_posix()):
            relative = path.relative_to(self.home).as_posix()
            info = path.lstat()
            mode = stat.S_IMODE(info.st_mode)
            if path.is_symlink():
                result.append((relative, "symlink", (os.readlink(path), mode)))
            elif path.is_dir():
                result.append((relative, "directory", mode))
            elif path.is_file():
                result.append((relative, "file", (path.read_bytes(), mode)))
            else:
                result.append((relative, "other", mode))
        return tuple(result)

    def _assert_projection(
        self,
        projection: object,
        *,
        data: bytes | None,
        mode: int | None,
    ) -> None:
        self.assertIsInstance(projection, dict)
        value = projection
        if data is None:
            self.assertEqual({"type": "absent"}, value)
            return
        self.assertEqual("file", value["type"])
        self.assertEqual(base64.b64encode(data).decode("ascii"), value["dataBase64"])
        self.assertEqual(mode, value["mode"])
        self.assertEqual(len(data), value["size"])
        self.assertEqual(hashlib.sha256(data).hexdigest(), value["sha256"])

    def _projection(self, data: bytes, mode: int) -> dict[str, object]:
        return {
            "dataBase64": base64.b64encode(data).decode("ascii"),
            "mode": mode,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "type": "file",
        }

    def _json_strings(self, value: object) -> set[str]:
        if isinstance(value, str):
            return {value}
        if isinstance(value, dict):
            strings: set[str] = set()
            for key, child in value.items():
                strings.add(str(key))
                strings.update(self._json_strings(child))
            return strings
        if isinstance(value, list):
            strings = set()
            for child in value:
                strings.update(self._json_strings(child))
            return strings
        return set()

    def _seal_document(
        self,
        document: dict[str, object],
        *,
        domain: bytes,
    ) -> dict[str, object]:
        sealed = dict(document)
        sealed.pop("fingerprint", None)
        payload = json.dumps(
            sealed,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        sealed["fingerprint"] = hashlib.sha256(domain + payload).hexdigest()
        return sealed

    def _write_json_document(
        self,
        path: Path,
        document: dict[str, object],
    ) -> None:
        path.write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)

    def _write_receipt(
        self,
        *,
        state: str,
        before: dict[str, dict[str, object]],
        desired: dict[str, dict[str, object]],
    ) -> None:
        receipt = self._seal_document(
            {
                "before": before,
                "desired": desired,
                "documentType": RECEIPT_DOCUMENT_TYPE,
                "schemaVersion": 1,
                "state": state,
                "targets": {
                    "aliases": str(self.aliases.resolve()),
                    "highfd": str(self.highfd.resolve()),
                },
            },
            domain=RECEIPT_FINGERPRINT_DOMAIN,
        )
        self.receipt.parent.mkdir(parents=True, exist_ok=True)
        self._write_json_document(self.receipt, receipt)

    def _write_source_root(self, name: str, highfd: bytes) -> Path:
        source_root = self.root / name
        source_highfd = source_root / "scripts" / "codex-highfd"
        legacy_fixture = (
            source_root
            / "tests"
            / "smart_subagents"
            / "fixtures"
            / "codex-highfd-legacy"
        )
        self._seed(source_highfd, highfd, 0o755)
        self._seed(legacy_fixture, LEGACY_HIGHFD, 0o644)
        return source_root

    def _apply_from_legacy(self) -> tuple[dict[str, object], bytes, bytes]:
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)
        self._seed(self.external_codex, b"external-codex\n", 0o755)
        external_before = self.external_codex.read_bytes()
        path_sentinel = "/PATH_SENTINEL_MUST_NOT_PERSIST:/usr/bin"

        completed, result = self._run(
            "apply",
            path_value=path_sentinel,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("applied", result["status"])
        self.assertEqual("ENTRYPOINT_APPLIED", result["code"])
        self.assertEqual(external_before, self.external_codex.read_bytes())
        receipt_bytes = self.receipt.read_bytes()
        receipt_strings = self._json_strings(json.loads(receipt_bytes))
        output_strings = self._json_strings(result)
        for unmanaged in (path_sentinel, str(self.external_codex)):
            self.assertNotIn(unmanaged, receipt_strings)
            self.assertNotIn(unmanaged, output_strings)
        return result, external_before, receipt_bytes

    def _seed_desired_without_receipt(self) -> None:
        self._seed(self.highfd, HIGHFD.read_bytes(), 0o755)
        self._seed(self.aliases, TARGET_ALIASES, 0o600)

    def test_managed_version_registry_is_literal_and_exact(self) -> None:
        reconciler = load_reconciler()
        expected = frozenset(
            {
                (
                    "a04efa493f60cc4a31cfe443aecfc8d02"
                    "e804422aeb976cfc3cc7aa4602a8e57",
                    2169,
                    0o755,
                    "f3cc0056eec087ea40fe34ce5dccd044"
                    "c1bad32964fc9649651f1eb59813a330",
                    741,
                    0o600,
                ),
                (
                    "a04efa493f60cc4a31cfe443aecfc8d02"
                    "e804422aeb976cfc3cc7aa4602a8e57",
                    2169,
                    0o755,
                    "7e12c02b07fb90a072cc04742ef63d060"
                    "70b8beb1a4270e5d61c079ac655185e",
                    420,
                    0o600,
                ),
            }
        )
        self.assertEqual(expected, reconciler.REGISTERED_MANAGED_VERSIONS)
        tree = ast.parse(RECONCILER.read_text(encoding="utf-8"))
        assignment = next(
            node
            for node in tree.body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "REGISTERED_MANAGED_VERSIONS"
        )
        calls = [
            node.func.id
            for node in ast.walk(assignment.value)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        ]
        self.assertEqual(["frozenset"], calls)

    def test_preview_is_read_only_even_when_home_does_not_exist(self) -> None:
        before = self._snapshot()

        completed, result = self._run("preview")

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("planned", result["status"])
        self.assertEqual("ENTRYPOINT_CHANGES_REQUIRED", result["code"])
        self.assertEqual("preview", result["command"])
        self.assertTrue(result["changed"])
        self.assertEqual(before, self._snapshot())
        self.assertFalse(self.home.exists())

    def test_preview_matches_apply_conflict_for_desired_without_receipt(
        self,
    ) -> None:
        self._seed_desired_without_receipt()
        before = self._snapshot()

        completed, result = self._run("preview")

        self.assertEqual(2, completed.returncode)
        self.assertEqual("conflict", result["status"])
        self.assertEqual("ENTRYPOINT_RECEIPT_MISSING", result["code"])
        self.assertEqual("preview", result["command"])
        self.assertEqual(before, self._snapshot())

    def test_preview_reports_a_pending_journal_consistently(self) -> None:
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)
        completed, _result = self._run(
            "apply",
            failpoint="after_highfd_replace",
        )
        self.assertEqual(70, completed.returncode)
        before = self._snapshot()

        completed, result = self._run("preview")

        self.assertEqual(1, completed.returncode)
        self.assertEqual("RECOVERY_REQUIRED", result["status"])
        self.assertEqual("ENTRYPOINT_RECOVERY_REQUIRED", result["code"])
        self.assertEqual("preview", result["command"])
        self.assertEqual(before, self._snapshot())

    def test_apply_migrates_exact_legacy_files_and_records_full_projections(
        self,
    ) -> None:
        self._apply_from_legacy()

        self.assertEqual(HIGHFD.read_bytes(), self.highfd.read_bytes())
        self.assertEqual(0o755, stat.S_IMODE(self.highfd.stat().st_mode))
        self.assertEqual(TARGET_ALIASES, self.aliases.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(self.aliases.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(self.receipt.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(self.lock.stat().st_mode))
        self.assertFalse(self.journal.exists())

        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual(1, receipt["schemaVersion"])
        self.assertEqual("active", receipt["state"])
        self.assertEqual({"aliases", "highfd"}, set(receipt["before"]))
        self.assertEqual({"aliases", "highfd"}, set(receipt["desired"]))
        self._assert_projection(
            receipt["before"]["highfd"],
            data=LEGACY_HIGHFD,
            mode=0o755,
        )
        self._assert_projection(
            receipt["before"]["aliases"],
            data=LEGACY_ALIASES,
            mode=0o644,
        )
        self._assert_projection(
            receipt["desired"]["highfd"],
            data=HIGHFD.read_bytes(),
            mode=0o755,
        )
        self._assert_projection(
            receipt["desired"]["aliases"],
            data=TARGET_ALIASES,
            mode=0o600,
        )
        self.assertEqual({"aliases", "highfd"}, set(receipt["targets"]))
        self.assertNotIn(str(self.external_codex), receipt["targets"].values())

    def test_apply_twice_is_byte_idempotent(self) -> None:
        self._apply_from_legacy()
        before = self._snapshot()

        completed, result = self._run("apply")

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("unchanged", result["status"])
        self.assertEqual("ENTRYPOINT_UNCHANGED", result["code"])
        self.assertFalse(result["changed"])
        self.assertEqual(before, self._snapshot())

    def test_apply_rejects_desired_files_without_rollback_receipt(self) -> None:
        self._seed_desired_without_receipt()
        before = self._snapshot()

        completed, result = self._run("apply")

        self.assertEqual(2, completed.returncode)
        self.assertEqual("conflict", result["status"])
        self.assertEqual("ENTRYPOINT_RECEIPT_MISSING", result["code"])
        self.assertEqual(before, self._snapshot())

    def _assert_receipt_mutation_conflicts(self, mutation: str) -> None:
        self._apply_from_legacy()
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        receipt["documentType"] = RECEIPT_DOCUMENT_TYPE
        receipt = self._seal_document(
            receipt,
            domain=RECEIPT_FINGERPRINT_DOMAIN,
        )
        if mutation == "fingerprint":
            receipt["fingerprint"] = "0" * 64
        else:
            receipt["unexpected"] = "foreign"
            receipt = self._seal_document(
                receipt,
                domain=RECEIPT_FINGERPRINT_DOMAIN,
            )
        self._write_json_document(self.receipt, receipt)
        before = self._snapshot()

        completed, result = self._run("apply")

        self.assertEqual(2, completed.returncode)
        self.assertEqual("conflict", result["status"])
        self.assertEqual("ENTRYPOINT_STATE_INVALID", result["code"])
        self.assertEqual(before, self._snapshot())

    def test_receipt_fingerprint_is_mandatory(self) -> None:
        self._assert_receipt_mutation_conflicts("fingerprint")

    def test_receipt_has_closed_exact_fields(self) -> None:
        self._assert_receipt_mutation_conflicts("extra-field")

    def test_receipt_cannot_supply_foreign_initial_bytes(self) -> None:
        self._apply_from_legacy()
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        receipt["documentType"] = RECEIPT_DOCUMENT_TYPE
        receipt["before"]["highfd"] = self._projection(
            b"foreign rollback payload\n",
            0o755,
        )
        receipt = self._seal_document(
            receipt,
            domain=RECEIPT_FINGERPRINT_DOMAIN,
        )
        self._write_json_document(self.receipt, receipt)
        self.lock.unlink()
        before = self._snapshot()

        completed, result = self._run("rollback")

        self.assertEqual(2, completed.returncode)
        self.assertEqual("conflict", result["status"])
        self.assertEqual("ENTRYPOINT_STATE_INVALID", result["code"])
        self.assertEqual(before, self._snapshot())

    def test_receipt_rejects_foreign_matching_managed_pair(self) -> None:
        foreign_highfd = b"#!/bin/zsh\nexec foreign-codex \"$@\"\n"
        before_state = {
            "highfd": self._projection(LEGACY_HIGHFD, 0o755),
            "aliases": self._projection(LEGACY_ALIASES, 0o644),
        }
        foreign_desired = {
            "highfd": self._projection(foreign_highfd, 0o755),
            "aliases": self._projection(TARGET_ALIASES, 0o600),
        }
        self._seed(self.highfd, foreign_highfd, 0o755)
        self._seed(self.aliases, TARGET_ALIASES, 0o600)
        self._write_receipt(
            state="active",
            before=before_state,
            desired=foreign_desired,
        )
        before = self._snapshot()

        completed, result = self._run("apply")

        self.assertEqual(2, completed.returncode)
        self.assertEqual("conflict", result["status"])
        self.assertEqual("ENTRYPOINT_STATE_INVALID", result["code"])
        self.assertEqual(before, self._snapshot())

    def test_journal_cannot_supply_foreign_target_bytes(self) -> None:
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)
        completed, _result = self._run(
            "apply",
            failpoint="after_highfd_replace",
        )
        self.assertEqual(70, completed.returncode)
        journal = json.loads(self.journal.read_text(encoding="utf-8"))
        journal["documentType"] = JOURNAL_DOCUMENT_TYPE
        journal["targets"] = {
            "aliases": str(self.aliases.resolve()),
            "highfd": str(self.highfd.resolve()),
        }
        journal["desired"]["highfd"] = self._projection(
            b"foreign journal payload\n",
            0o755,
        )
        journal = self._seal_document(
            journal,
            domain=JOURNAL_FINGERPRINT_DOMAIN,
        )
        self._write_json_document(self.journal, journal)
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self.lock.unlink()
        before = self._snapshot()

        completed, result = self._run("apply")

        self.assertEqual(2, completed.returncode)
        self.assertEqual("conflict", result["status"])
        self.assertEqual("ENTRYPOINT_STATE_INVALID", result["code"])
        self.assertEqual(before, self._snapshot())

    def test_journal_parses_receipt_desired_before_recovery(self) -> None:
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)
        completed, _result = self._run(
            "apply",
            failpoint="after_highfd_replace",
        )
        self.assertEqual(70, completed.returncode)
        journal = json.loads(self.journal.read_text(encoding="utf-8"))
        journal["documentType"] = JOURNAL_DOCUMENT_TYPE
        journal["targets"] = {
            "aliases": str(self.aliases.resolve()),
            "highfd": str(self.highfd.resolve()),
        }
        journal["receiptDesired"] = self._projection(
            b'{"foreign":"receipt"}\n',
            0o600,
        )
        journal = self._seal_document(
            journal,
            domain=JOURNAL_FINGERPRINT_DOMAIN,
        )
        self._write_json_document(self.journal, journal)
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self.lock.unlink()
        before = self._snapshot()

        completed, result = self._run("apply")

        self.assertEqual(2, completed.returncode)
        self.assertEqual("conflict", result["status"])
        self.assertEqual("ENTRYPOINT_STATE_INVALID", result["code"])
        self.assertEqual(before, self._snapshot())

    def _assert_journal_mutation_conflicts(self, mutation: str) -> None:
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)
        completed, _result = self._run(
            "apply",
            failpoint="after_highfd_replace",
        )
        self.assertEqual(70, completed.returncode)
        journal = json.loads(self.journal.read_text(encoding="utf-8"))
        journal["documentType"] = JOURNAL_DOCUMENT_TYPE
        journal["targets"] = {
            "aliases": str(self.aliases.resolve()),
            "highfd": str(self.highfd.resolve()),
        }
        if mutation == "extra-field":
            journal["unexpected"] = "foreign"
        else:
            journal["targets"]["highfd"] = str(
                self.root / "foreign-highfd"
            )
        journal = self._seal_document(
            journal,
            domain=JOURNAL_FINGERPRINT_DOMAIN,
        )
        self._write_json_document(self.journal, journal)
        self.lock.unlink()
        before = self._snapshot()

        completed, result = self._run("apply")

        self.assertEqual(2, completed.returncode)
        self.assertEqual("conflict", result["status"])
        self.assertEqual("ENTRYPOINT_STATE_INVALID", result["code"])
        self.assertEqual(before, self._snapshot())

    def test_journal_has_closed_exact_fields(self) -> None:
        self._assert_journal_mutation_conflicts("extra-field")

    def test_journal_binds_current_target_paths(self) -> None:
        self._assert_journal_mutation_conflicts("wrong-paths")

    def test_rollback_journal_parses_receipt_before_projection(self) -> None:
        self._apply_from_legacy()
        active = json.loads(self.receipt.read_text(encoding="utf-8"))
        active["documentType"] = RECEIPT_DOCUMENT_TYPE
        active = self._seal_document(
            active,
            domain=RECEIPT_FINGERPRINT_DOMAIN,
        )
        rolled_back = dict(active)
        rolled_back["state"] = "rolled_back"
        rolled_back = self._seal_document(
            rolled_back,
            domain=RECEIPT_FINGERPRINT_DOMAIN,
        )
        foreign_receipt = b'{"foreign":"receipt-before"}\n'
        journal = {
            "before": active["desired"],
            "desired": active["before"],
            "documentType": JOURNAL_DOCUMENT_TYPE,
            "operation": "rollback",
            "phase": "prepared",
            "receiptBefore": self._projection(foreign_receipt, 0o600),
            "receiptDesired": self._projection(
                (
                    json.dumps(
                        rolled_back,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8"),
                0o600,
            ),
            "schemaVersion": 1,
            "targets": {
                "aliases": str(self.aliases.resolve()),
                "highfd": str(self.highfd.resolve()),
            },
        }
        journal = self._seal_document(
            journal,
            domain=JOURNAL_FINGERPRINT_DOMAIN,
        )
        self._write_json_document(self.journal, journal)
        self.receipt.write_bytes(foreign_receipt)
        self.receipt.chmod(0o600)
        self.lock.unlink()
        before = self._snapshot()

        completed, result = self._run("rollback")

        self.assertEqual(2, completed.returncode)
        self.assertEqual("conflict", result["status"])
        self.assertEqual("ENTRYPOINT_STATE_INVALID", result["code"])
        self.assertEqual(before, self._snapshot())

    def test_foreign_contents_conflict_without_touching_either_target(
        self,
    ) -> None:
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, b"foreign aliases\n", 0o600)
        highfd_before = self.highfd.read_bytes()
        aliases_before = self.aliases.read_bytes()
        filesystem_before = self._snapshot()

        completed, result = self._run("apply")

        self.assertEqual(2, completed.returncode)
        self.assertEqual("conflict", result["status"])
        self.assertEqual("ENTRYPOINT_ALIASES_CONTENT_CONFLICT", result["code"])
        self.assertEqual(highfd_before, self.highfd.read_bytes())
        self.assertEqual(aliases_before, self.aliases.read_bytes())
        self.assertEqual(filesystem_before, self._snapshot())
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.journal.exists())

    def test_unknown_metadata_is_a_stable_conflict(self) -> None:
        cases = ("mode", "link-count", "type", "size")
        for case in cases:
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory(
                    dir="/tmp",
                    prefix=f"codex-entrypoint-{case}-",
                ) as raw:
                    home = Path(raw) / "home"
                    highfd = home / ".local" / "bin" / "codex-highfd"
                    highfd.parent.mkdir(parents=True)
                    expected_code: str
                    if case == "mode":
                        highfd.write_bytes(LEGACY_HIGHFD)
                        highfd.chmod(0o700)
                        expected_code = "ENTRYPOINT_HIGHFD_MODE_CONFLICT"
                    elif case == "link-count":
                        highfd.write_bytes(LEGACY_HIGHFD)
                        highfd.chmod(0o755)
                        os.link(highfd, highfd.with_name("second-link"))
                        expected_code = "ENTRYPOINT_HIGHFD_LINK_COUNT_CONFLICT"
                    elif case == "type":
                        highfd.symlink_to(ROOT / "scripts" / "codex-highfd")
                        expected_code = "ENTRYPOINT_HIGHFD_TYPE_CONFLICT"
                    else:
                        highfd.write_bytes(b"x" * (256 * 1024 + 1))
                        highfd.chmod(0o755)
                        expected_code = "ENTRYPOINT_HIGHFD_SIZE_CONFLICT"

                    completed = subprocess.run(
                        (
                            sys.executable,
                            str(RECONCILER),
                            "--apply",
                            "--json",
                            "--home",
                            str(home.resolve()),
                            "--source-root",
                            str(ROOT.resolve()),
                        ),
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    result = json.loads(completed.stdout)
                    self.assertEqual(2, completed.returncode)
                    self.assertEqual("conflict", result["status"])
                    self.assertEqual(expected_code, result["code"])

    def test_rollback_restores_exact_legacy_bytes_and_modes(self) -> None:
        _, external_before, _ = self._apply_from_legacy()

        completed, result = self._run("rollback")

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("rolled_back", result["status"])
        self.assertEqual("ENTRYPOINT_ROLLED_BACK", result["code"])
        self.assertEqual(LEGACY_HIGHFD, self.highfd.read_bytes())
        self.assertEqual(0o755, stat.S_IMODE(self.highfd.stat().st_mode))
        self.assertEqual(LEGACY_ALIASES, self.aliases.read_bytes())
        self.assertEqual(0o644, stat.S_IMODE(self.aliases.stat().st_mode))
        self.assertEqual(external_before, self.external_codex.read_bytes())
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual("rolled_back", receipt["state"])
        self.assertFalse(self.journal.exists())

    def test_active_receipt_updates_to_new_tracked_source_and_keeps_initial_before(
        self,
    ) -> None:
        source_v1_bytes = HIGHFD.read_bytes()
        source_v2_bytes = HIGHFD.read_bytes() + b"\n# tracked source v2\n"
        source_v1 = ROOT
        source_v2 = self._write_source_root("source-v2", source_v2_bytes)
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)

        completed, first = self._run("apply", source_root=source_v1)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("applied", first["status"])
        completed, updated = self._run("apply", source_root=source_v2)

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("applied", updated["status"])
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self._assert_projection(
            receipt["before"]["highfd"],
            data=LEGACY_HIGHFD,
            mode=0o755,
        )
        self._assert_projection(
            receipt["desired"]["highfd"],
            data=source_v2_bytes,
            mode=0o755,
        )
        self.assertEqual(source_v2_bytes, self.highfd.read_bytes())

        completed, rolled_back = self._run(
            "rollback",
            source_root=source_v2,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("rolled_back", rolled_back["status"])
        self.assertEqual(LEGACY_HIGHFD, self.highfd.read_bytes())
        self.assertEqual(LEGACY_ALIASES, self.aliases.read_bytes())

    def test_rolled_back_receipt_reapplies_new_tracked_source(self) -> None:
        source_v1_bytes = HIGHFD.read_bytes()
        source_v2_bytes = HIGHFD.read_bytes() + b"\n# rolled source v2\n"
        source_v1 = ROOT
        source_v2 = self._write_source_root(
            "rolled-source-v2",
            source_v2_bytes,
        )
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)
        completed, first = self._run("apply", source_root=source_v1)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("applied", first["status"])
        completed, rolled_back = self._run(
            "rollback",
            source_root=source_v1,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("rolled_back", rolled_back["status"])

        completed, reapplied = self._run("apply", source_root=source_v2)

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("applied", reapplied["status"])
        self.assertEqual(source_v2_bytes, self.highfd.read_bytes())
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self._assert_projection(
            receipt["before"]["highfd"],
            data=LEGACY_HIGHFD,
            mode=0o755,
        )
        self._assert_projection(
            receipt["desired"]["highfd"],
            data=source_v2_bytes,
            mode=0o755,
        )

    def test_active_historical_aliases_update_as_one_registered_pair(
        self,
    ) -> None:
        source_v2_bytes = HIGHFD.read_bytes() + b"\n# aliases source v2\n"
        source_v2 = self._write_source_root(
            "aliases-active-v2",
            source_v2_bytes,
        )
        initial = {
            "highfd": self._projection(LEGACY_HIGHFD, 0o755),
            "aliases": self._projection(LEGACY_ALIASES, 0o644),
        }
        historical = {
            "highfd": self._projection(HIGHFD.read_bytes(), 0o755),
            "aliases": self._projection(LEGACY_ALIASES, 0o600),
        }
        self._seed(self.highfd, HIGHFD.read_bytes(), 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o600)
        self._write_receipt(
            state="active",
            before=initial,
            desired=historical,
        )

        completed, result = self._run("apply", source_root=source_v2)

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("applied", result["status"])
        self.assertEqual(source_v2_bytes, self.highfd.read_bytes())
        self.assertEqual(TARGET_ALIASES, self.aliases.read_bytes())
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual(initial, receipt["before"])

    def test_rolled_back_historical_aliases_reapply_as_registered_pair(
        self,
    ) -> None:
        source_v2_bytes = HIGHFD.read_bytes() + b"\n# aliases rolled v2\n"
        source_v2 = self._write_source_root(
            "aliases-rolled-v2",
            source_v2_bytes,
        )
        initial = {
            "highfd": self._projection(LEGACY_HIGHFD, 0o755),
            "aliases": self._projection(LEGACY_ALIASES, 0o644),
        }
        historical = {
            "highfd": self._projection(HIGHFD.read_bytes(), 0o755),
            "aliases": self._projection(LEGACY_ALIASES, 0o600),
        }
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)
        self._write_receipt(
            state="rolled_back",
            before=initial,
            desired=historical,
        )

        completed, result = self._run("apply", source_root=source_v2)

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("applied", result["status"])
        self.assertEqual(source_v2_bytes, self.highfd.read_bytes())
        self.assertEqual(TARGET_ALIASES, self.aliases.read_bytes())
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual(initial, receipt["before"])

    def test_rollback_restores_absence_and_is_idempotent(self) -> None:
        completed, applied = self._run("apply")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("applied", applied["status"])

        completed, rolled_back = self._run("rollback")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("rolled_back", rolled_back["status"])
        self.assertFalse(self.highfd.exists())
        self.assertFalse(self.aliases.exists())
        receipt_before = self.receipt.read_bytes()

        completed, unchanged = self._run("rollback")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("unchanged", unchanged["status"])
        self.assertEqual("ENTRYPOINT_UNCHANGED", unchanged["code"])
        self.assertEqual(receipt_before, self.receipt.read_bytes())

    def test_rollback_without_receipt_conflicts_when_any_target_exists(
        self,
    ) -> None:
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        before = self._snapshot()

        completed, result = self._run("rollback")

        self.assertEqual(2, completed.returncode)
        self.assertEqual("conflict", result["status"])
        self.assertEqual("ENTRYPOINT_RECEIPT_MISSING", result["code"])
        self.assertEqual(before, self._snapshot())

    def test_apply_recovers_journal_after_named_first_replace_failpoint(
        self,
    ) -> None:
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)

        completed, failed = self._run(
            "apply",
            failpoint="after_highfd_replace",
        )

        self.assertEqual(70, completed.returncode)
        self.assertEqual("failed", failed["status"])
        self.assertEqual("ENTRYPOINT_TEST_FAILPOINT", failed["code"])
        self.assertEqual(HIGHFD.read_bytes(), self.highfd.read_bytes())
        self.assertEqual(LEGACY_ALIASES, self.aliases.read_bytes())
        self.assertTrue(self.journal.is_file())
        self.assertEqual(0o600, stat.S_IMODE(self.journal.stat().st_mode))
        self.assertFalse(self.receipt.exists())
        journal = json.loads(self.journal.read_text(encoding="utf-8"))
        self.assertEqual("apply", journal["operation"])
        self.assertEqual("prepared", journal["phase"])
        self._assert_projection(
            journal["before"]["highfd"],
            data=LEGACY_HIGHFD,
            mode=0o755,
        )
        self._assert_projection(
            journal["desired"]["aliases"],
            data=TARGET_ALIASES,
            mode=0o600,
        )

        completed, recovered = self._run("apply")

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("applied", recovered["status"])
        self.assertEqual("ENTRYPOINT_RECOVERED", recovered["code"])
        self.assertEqual(HIGHFD.read_bytes(), self.highfd.read_bytes())
        self.assertEqual(TARGET_ALIASES, self.aliases.read_bytes())
        self.assertTrue(self.receipt.is_file())
        self.assertFalse(self.journal.exists())

    def test_apply_recovers_registered_v1_then_updates_to_tracked_v2(
        self,
    ) -> None:
        source_v2_bytes = HIGHFD.read_bytes() + b"\n# recovery source v2\n"
        source_v2 = self._write_source_root(
            "recovery-source-v2",
            source_v2_bytes,
        )
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)
        completed, failed = self._run(
            "apply",
            failpoint="after_highfd_replace",
            source_root=ROOT,
        )
        self.assertEqual(70, completed.returncode)
        self.assertTrue(self.journal.is_file())

        completed, result = self._run("apply", source_root=source_v2)

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("applied", result["status"])
        self.assertEqual("ENTRYPOINT_APPLIED", result["code"])
        self.assertEqual(source_v2_bytes, self.highfd.read_bytes())
        self.assertEqual(TARGET_ALIASES, self.aliases.read_bytes())
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self._assert_projection(
            receipt["before"]["highfd"],
            data=LEGACY_HIGHFD,
            mode=0o755,
        )
        self._assert_projection(
            receipt["desired"]["highfd"],
            data=source_v2_bytes,
            mode=0o755,
        )
        self.assertFalse(self.journal.exists())

    def test_apply_rejects_a_coherent_unregistered_pending_pair(self) -> None:
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)
        completed, failed = self._run(
            "apply",
            failpoint="after_highfd_replace",
        )
        self.assertEqual(70, completed.returncode)
        journal = json.loads(self.journal.read_text(encoding="utf-8"))
        receipt_desired = json.loads(
            base64.b64decode(
                journal["receiptDesired"]["dataBase64"],
                validate=True,
            )
        )
        foreign_highfd = b"#!/bin/zsh\nexec coherent-foreign \"$@\"\n"
        foreign_projection = self._projection(foreign_highfd, 0o755)
        receipt_desired["desired"]["highfd"] = foreign_projection
        receipt_desired = self._seal_document(
            receipt_desired,
            domain=RECEIPT_FINGERPRINT_DOMAIN,
        )
        receipt_bytes = (
            json.dumps(
                receipt_desired,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        journal["desired"]["highfd"] = foreign_projection
        journal["receiptDesired"] = self._projection(receipt_bytes, 0o600)
        journal = self._seal_document(
            journal,
            domain=JOURNAL_FINGERPRINT_DOMAIN,
        )
        self._write_json_document(self.journal, journal)
        self.lock.unlink()
        before = self._snapshot()

        completed, result = self._run("apply")

        self.assertEqual(2, completed.returncode)
        self.assertEqual("conflict", result["status"])
        self.assertEqual("ENTRYPOINT_STATE_INVALID", result["code"])
        self.assertEqual(before, self._snapshot())

    def test_rollback_recovers_after_first_target_effect(self) -> None:
        self._apply_from_legacy()

        completed, failed = self._run(
            "rollback",
            failpoint="after_rollback_highfd_replace",
        )

        self.assertEqual(70, completed.returncode)
        self.assertEqual("failed", failed["status"])
        self.assertEqual(LEGACY_HIGHFD, self.highfd.read_bytes())
        self.assertEqual(TARGET_ALIASES, self.aliases.read_bytes())
        self.assertTrue(self.journal.is_file())
        active_receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual("active", active_receipt["state"])

        completed, recovered = self._run("rollback")

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("rolled_back", recovered["status"])
        self.assertEqual("ENTRYPOINT_RECOVERED", recovered["code"])
        self.assertEqual(LEGACY_HIGHFD, self.highfd.read_bytes())
        self.assertEqual(LEGACY_ALIASES, self.aliases.read_bytes())
        self.assertFalse(self.journal.exists())

    def test_rollback_recovers_registered_v1_under_tracked_v2(self) -> None:
        source_v2 = self._write_source_root(
            "rollback-recovery-v2",
            HIGHFD.read_bytes() + b"\n# rollback recovery v2\n",
        )
        self._apply_from_legacy()
        completed, failed = self._run(
            "rollback",
            failpoint="after_rollback_highfd_replace",
            source_root=ROOT,
        )
        self.assertEqual(70, completed.returncode)
        self.assertTrue(self.journal.is_file())

        completed, result = self._run("rollback", source_root=source_v2)

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("rolled_back", result["status"])
        self.assertEqual("ENTRYPOINT_RECOVERED", result["code"])
        self.assertEqual(LEGACY_HIGHFD, self.highfd.read_bytes())
        self.assertEqual(LEGACY_ALIASES, self.aliases.read_bytes())
        self.assertFalse(self.journal.exists())

    def test_apply_recovers_after_receipt_before_journal_removal(
        self,
    ) -> None:
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)

        completed, failed = self._run(
            "apply",
            failpoint="after_apply_receipt_replace",
        )

        self.assertEqual(70, completed.returncode)
        self.assertEqual("failed", failed["status"])
        self.assertEqual(HIGHFD.read_bytes(), self.highfd.read_bytes())
        self.assertEqual(TARGET_ALIASES, self.aliases.read_bytes())
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual("active", receipt["state"])
        self.assertTrue(self.journal.is_file())

        completed, recovered = self._run("apply")

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("applied", recovered["status"])
        self.assertEqual("ENTRYPOINT_RECOVERED", recovered["code"])
        self.assertFalse(self.journal.exists())

    def test_oserror_after_durable_effect_reports_unknown_change_state(
        self,
    ) -> None:
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)

        completed, result = self._run(
            "apply",
            failpoint="oserror_after_highfd_replace",
        )

        self.assertEqual(74, completed.returncode)
        self.assertEqual("failed", result["status"])
        self.assertEqual("ENTRYPOINT_IO_ERROR", result["code"])
        self.assertIsNone(result["changed"])
        self.assertTrue(self.journal.is_file())

    def test_path_and_external_codex_never_enter_pending_journal(self) -> None:
        path_sentinel = "/PATH_SENTINEL_MUST_NOT_PERSIST:/usr/bin"
        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)
        self._seed(self.external_codex, b"external-codex\n", 0o755)

        completed, result = self._run(
            "apply",
            failpoint="after_highfd_replace",
            path_value=path_sentinel,
        )

        self.assertEqual(70, completed.returncode)
        journal_bytes = self.journal.read_bytes()
        journal = json.loads(journal_bytes)
        journal_strings = self._json_strings(journal)
        output_strings = self._json_strings(result)
        for unmanaged in (path_sentinel, str(self.external_codex)):
            self.assertNotIn(unmanaged, journal_strings)
            self.assertNotIn(unmanaged, output_strings)
        self.assertEqual(
            {"aliases", "highfd"},
            set(journal.get("targets", {})),
        )
        self.assertNotIn("path", json.dumps(result).lower())

    def test_doctor_reports_ready_drift_and_recovery_without_writes(
        self,
    ) -> None:
        before = self._snapshot()
        completed, drift = self._run("doctor")
        self.assertEqual(1, completed.returncode)
        self.assertEqual("DRIFT", drift["status"])
        self.assertEqual(before, self._snapshot())
        self.assertFalse(self.home.exists())

        self._apply_from_legacy()
        before = self._snapshot()
        completed, ready = self._run("doctor")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("READY", ready["status"])
        self.assertEqual(before, self._snapshot())

        self._seed(self.highfd, LEGACY_HIGHFD, 0o755)
        self._seed(self.aliases, LEGACY_ALIASES, 0o644)
        self.receipt.unlink()
        completed, _ = self._run(
            "apply",
            failpoint="after_highfd_replace",
        )
        self.assertEqual(70, completed.returncode)
        before = self._snapshot()

        completed, recovery = self._run("doctor")

        self.assertEqual(1, completed.returncode)
        self.assertEqual("RECOVERY_REQUIRED", recovery["status"])
        self.assertEqual(before, self._snapshot())

    def test_doctor_requires_an_active_receipt_for_desired_files(self) -> None:
        self._seed_desired_without_receipt()
        before = self._snapshot()

        completed, result = self._run("doctor")

        self.assertEqual(1, completed.returncode)
        self.assertEqual("DRIFT", result["status"])
        self.assertEqual("ENTRYPOINT_RECEIPT_MISSING", result["code"])
        self.assertEqual(before, self._snapshot())

    def test_doctor_rejects_rolled_back_receipt_with_desired_files(
        self,
    ) -> None:
        self._apply_from_legacy()
        completed, result = self._run("rollback")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("rolled_back", result["status"])
        self._seed_desired_without_receipt()
        before = self._snapshot()

        completed, result = self._run("doctor")

        self.assertEqual(1, completed.returncode)
        self.assertEqual("DRIFT", result["status"])
        self.assertEqual("ENTRYPOINT_RECEIPT_STATE_CONFLICT", result["code"])
        self.assertEqual(before, self._snapshot())

    def test_doctor_rejects_stale_active_receipt_with_desired_files(
        self,
    ) -> None:
        self._apply_from_legacy()
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        receipt["desired"]["aliases"] = self._projection(
            LEGACY_ALIASES,
            0o600,
        )
        receipt = self._seal_document(
            receipt,
            domain=RECEIPT_FINGERPRINT_DOMAIN,
        )
        self._write_json_document(self.receipt, receipt)
        before = self._snapshot()

        completed, result = self._run("doctor")

        self.assertEqual(1, completed.returncode)
        self.assertEqual("DRIFT", result["status"])
        self.assertEqual("ENTRYPOINT_RECEIPT_STATE_CONFLICT", result["code"])
        self.assertEqual(before, self._snapshot())

    def test_failpoint_requires_explicit_non_real_test_home(self) -> None:
        reconciler = load_reconciler()
        with mock.patch.dict(
            os.environ,
            {"CODEX_ENTRYPOINT_TEST_FAILPOINT": "after_highfd_replace"},
        ):
            self.assertFalse(
                reconciler._test_failpoints_permitted(
                    ["--apply", "--json"],
                    self.home,
                )
            )
            self.assertFalse(
                reconciler._test_failpoints_permitted(
                    [
                        "--apply",
                        "--json",
                        "--home",
                        str(Path.home()),
                    ],
                    Path.home(),
                )
            )
            self.assertTrue(
                reconciler._test_failpoints_permitted(
                    [
                        "--apply",
                        "--json",
                        "--home",
                        str(self.home),
                    ],
                    self.home,
                )
            )


if __name__ == "__main__":
    unittest.main()

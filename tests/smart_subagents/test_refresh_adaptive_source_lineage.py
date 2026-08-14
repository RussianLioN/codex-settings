from __future__ import annotations

import contextlib
import io
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "refresh_adaptive_source_lineage.py"


def load_script():
    spec = importlib.util.spec_from_file_location(
        "refresh_adaptive_source_lineage_under_test",
        SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RefreshAdaptiveSourceLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source_root = Path(self.tmp.name) / "source"
        self.lineage_path = (
            self.source_root
            / "plugins"
            / "codex-smart-subagents"
            / "config"
            / "source-lineage-v2.json"
        )
        self.lineage_path.parent.mkdir(parents=True)

    def write_lineage(self, *, generation: int, digest: str) -> None:
        self.lineage_path.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "kind": "codex-smart-source-lineage/v2",
                    "generation": generation,
                    "implementationDigest": digest,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def test_check_reports_current_lineage_without_writing(self) -> None:
        refresh = load_script()
        self.write_lineage(generation=7, digest="a" * 64)

        result = refresh.refresh_source_lineage(
            source_root=self.source_root,
            write=False,
            digest_func=lambda _layout: "a" * 64,
        )

        self.assertEqual("ok", result["status"])
        self.assertEqual(7, result["generation"])
        self.assertEqual("a" * 64, result["implementationDigest"])
        self.assertEqual(str(self.lineage_path.resolve()), result["path"])

    def test_check_rejects_stale_digest_without_writing(self) -> None:
        refresh = load_script()
        self.write_lineage(generation=7, digest="a" * 64)
        before = self.lineage_path.read_text(encoding="utf-8")

        with self.assertRaises(refresh.LineageRefreshError) as captured:
            refresh.refresh_source_lineage(
                source_root=self.source_root,
                write=False,
                digest_func=lambda _layout: "b" * 64,
            )

        self.assertEqual("SOURCE_LINEAGE_MISMATCH", captured.exception.code)
        self.assertEqual(before, self.lineage_path.read_text(encoding="utf-8"))

    def test_write_advances_generation_once_and_second_write_is_unchanged(self) -> None:
        refresh = load_script()
        self.write_lineage(generation=7, digest="a" * 64)

        updated = refresh.refresh_source_lineage(
            source_root=self.source_root,
            write=True,
            digest_func=lambda _layout: "b" * 64,
        )
        unchanged = refresh.refresh_source_lineage(
            source_root=self.source_root,
            write=True,
            digest_func=lambda _layout: "b" * 64,
        )

        self.assertEqual("updated", updated["status"])
        self.assertEqual(8, updated["generation"])
        self.assertEqual("b" * 64, updated["implementationDigest"])
        self.assertEqual("unchanged", unchanged["status"])
        self.assertEqual(8, unchanged["generation"])
        document = json.loads(self.lineage_path.read_text(encoding="utf-8"))
        self.assertEqual(8, document["generation"])
        self.assertEqual("b" * 64, document["implementationDigest"])
        self.assertTrue(self.lineage_path.read_bytes().endswith(b"\n"))

    def test_invalid_shape_fails_closed_without_write(self) -> None:
        refresh = load_script()
        self.lineage_path.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "kind": "codex-smart-source-lineage/v2",
                    "generation": 0,
                    "implementationDigest": "a" * 64,
                }
            ),
            encoding="utf-8",
        )
        before = self.lineage_path.read_text(encoding="utf-8")

        with self.assertRaises(refresh.LineageRefreshError) as captured:
            refresh.refresh_source_lineage(
                source_root=self.source_root,
                write=True,
                digest_func=lambda _layout: "b" * 64,
            )

        self.assertEqual("SOURCE_LINEAGE_INVALID", captured.exception.code)
        self.assertEqual(before, self.lineage_path.read_text(encoding="utf-8"))

    def test_relative_source_root_is_rejected(self) -> None:
        refresh = load_script()

        with self.assertRaises(refresh.LineageRefreshError) as captured:
            refresh.refresh_source_lineage(
                source_root=Path("relative"),
                write=True,
                digest_func=lambda _layout: "b" * 64,
            )

        self.assertEqual("SOURCE_ROOT_INVALID", captured.exception.code)

    def test_main_reports_digest_failures_as_one_safe_json(self) -> None:
        refresh = load_script()
        self.write_lineage(generation=8, digest="a" * 64)
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            code = refresh.main(
                [
                    "--source-root",
                    str(self.source_root.resolve()),
                    "--check",
                ]
            )

        lines = stdout.getvalue().splitlines()
        self.assertEqual(1, code)
        self.assertEqual(1, len(lines))
        response = json.loads(lines[0])
        self.assertEqual("error", response["status"])
        self.assertEqual("SOURCE_DIGEST_FAILED", response["code"])
        self.assertIn("message", response)
        self.assertNotIn(str(self.source_root.resolve()), lines[0])
        self.assertNotIn("Traceback", lines[0])


if __name__ == "__main__":
    unittest.main()

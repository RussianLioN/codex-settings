from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.catalog import Catalog, CatalogError  # noqa: E402
from codex_smart_subagents.contracts import (  # noqa: E402
    export_tool_schemas,
    get_tool_definitions,
)


class CatalogTests(unittest.TestCase):
    def test_repository_catalog_is_strict_and_stable(self) -> None:
        catalog = Catalog.load(REPO / ".codex" / "adaptive-subagents.toml")
        self.assertEqual(2, catalog.schema_version)
        self.assertEqual("0.144.4", catalog.minimum_codex_version)
        self.assertTrue(catalog.supports_codex_version("0.144.6"))
        self.assertRegex(catalog.generation, r"^cg1_[a-f0-9]{16}$")
        self.assertEqual(
            {"gpt-5.6-luna", "gpt-5.6-terra", "gpt-5.6-sol"},
            set(catalog.models),
        )
        self.assertEqual(
            "first-verified-available",
            catalog.coordinator_selection,
        )
        self.assertEqual(
            (
                {
                    "model": "gpt-5.6-sol",
                    "reasoning_effort": "medium",
                },
                {
                    "model": "gpt-5.6-terra",
                    "reasoning_effort": "medium",
                },
            ),
            catalog.coordinator_candidates,
        )
        self.assertEqual(
            {
                "model": "gpt-5.6-sol",
                "reasoning_effort": "medium",
            },
            catalog.coordinator,
        )
        self.assertEqual(
            ["medium", "high", "xhigh", "max"],
            catalog.models["gpt-5.6-sol"]["reasoning_efforts"],
        )
        self.assertEqual(20, catalog.limits["global_processes"])
        self.assertEqual(6, catalog.limits["root_processes"])
        self.assertEqual(2, catalog.limits["sol_processes"])
        self.assertEqual(100, catalog.limits["queue_nodes"])
        self.assertEqual(
            (REPO / ".codex" / "adaptive-subagents.toml").read_bytes(),
            (
                PLUGIN_ROOT / "config" / "adaptive-subagents.toml"
            ).read_bytes(),
        )

    def test_opaque_ids_are_hash_derived_and_do_not_leak_paths(self) -> None:
        catalog = Catalog.load(REPO / ".codex" / "adaptive-subagents.toml")
        scope_id = catalog.opaque_id("scope", "default")
        validation_id = catalog.opaque_id("validation", "none")
        self.assertRegex(scope_id, r"^scope_[a-f0-9]{16}$")
        self.assertRegex(validation_id, r"^validation_[a-f0-9]{16}$")
        self.assertNotIn("/", scope_id)
        self.assertNotIn(str(REPO), scope_id)

    def test_unknown_keys_and_invalid_values_fail_closed(self) -> None:
        source = (REPO / ".codex" / "adaptive-subagents.toml").read_text()
        with tempfile.TemporaryDirectory() as directory:
            unknown = Path(directory) / "unknown.toml"
            unknown.write_text(source + "\nunknown_key = true\n")
            with self.assertRaises(CatalogError):
                Catalog.load(unknown)

            invalid = Path(directory) / "invalid.toml"
            invalid.write_text(source.replace("global_processes = 20", "global_processes = 0"))
            with self.assertRaises(CatalogError):
                Catalog.load(invalid)

            invalid_coordinator = Path(directory) / "invalid-coordinator.toml"
            invalid_coordinator.write_text(
                source.replace(
                    'model = "gpt-5.6-terra"',
                    'model = "unknown-model"',
                    1,
                )
            )
            with self.assertRaises(CatalogError):
                Catalog.load(invalid_coordinator)

    def test_legacy_v1_catalog_remains_readable(self) -> None:
        source = (REPO / ".codex" / "adaptive-subagents.toml").read_text()
        source = source.replace("schema_version = 2", "schema_version = 1", 1)
        source = source.replace(
            (
                '[coordinator]\n'
                'selection = "first-verified-available"\n'
                "candidates = [\n"
                '  { model = "gpt-5.6-sol", reasoning_effort = "medium" },\n'
                '  { model = "gpt-5.6-terra", reasoning_effort = "medium" },\n'
                "]"
            ),
            (
                '[coordinator]\n'
                'model = "gpt-5.6-terra"\n'
                'reasoning_effort = "medium"'
            ),
            1,
        )
        source = source.replace(
            'reasoning_efforts = ["medium", "high", "xhigh", "max"]',
            'reasoning_efforts = ["high", "xhigh", "max"]',
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "v1.toml"
            path.write_text(source, encoding="utf-8")
            catalog = Catalog.load(path)

        self.assertEqual(1, catalog.schema_version)
        self.assertRegex(catalog.generation, r"^cg1_[a-f0-9]{16}$")
        self.assertEqual(
            (
                {
                    "model": "gpt-5.6-terra",
                    "reasoning_effort": "medium",
                },
            ),
            catalog.coordinator_candidates,
        )

    def test_v2_coordinator_candidates_are_bounded_unique_and_supported(self) -> None:
        source = (REPO / ".codex" / "adaptive-subagents.toml").read_text()
        candidate_lines = (
            '  { model = "gpt-5.6-sol", reasoning_effort = "medium" },\n'
            '  { model = "gpt-5.6-terra", reasoning_effort = "medium" },\n'
        )
        self.assertIn(candidate_lines, source)
        invalid_candidates = {
            "empty": "",
            "duplicate": (
                '  { model = "gpt-5.6-sol", reasoning_effort = "medium" },\n'
                '  { model = "gpt-5.6-sol", reasoning_effort = "medium" },\n'
            ),
            "too-many": candidate_lines
            + (
                '  { model = "gpt-5.6-luna", reasoning_effort = "low" },\n'
                '  { model = "gpt-5.6-luna", reasoning_effort = "medium" },\n'
                '  { model = "gpt-5.6-terra", reasoning_effort = "high" },\n'
                '  { model = "gpt-5.6-terra", reasoning_effort = "xhigh" },\n'
                '  { model = "gpt-5.6-sol", reasoning_effort = "high" },\n'
                '  { model = "gpt-5.6-sol", reasoning_effort = "xhigh" },\n'
                '  { model = "gpt-5.6-sol", reasoning_effort = "max" },\n'
            ),
            "unsupported": (
                '  { model = "gpt-5.6-sol", reasoning_effort = "low" },\n'
            ),
            "unhashable-model": (
                '  { model = ["gpt-5.6-sol"], reasoning_effort = "medium" },\n'
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, replacement in invalid_candidates.items():
                with self.subTest(name=name):
                    path = Path(directory) / f"{name}.toml"
                    path.write_text(
                        source.replace(candidate_lines, replacement, 1),
                        encoding="utf-8",
                    )
                    with self.assertRaises(CatalogError):
                        Catalog.load(path)

    def test_v2_coordinator_accepts_one_and_eight_candidates(self) -> None:
        source = (REPO / ".codex" / "adaptive-subagents.toml").read_text()
        repository_candidates = (
            '  { model = "gpt-5.6-sol", reasoning_effort = "medium" },\n'
            '  { model = "gpt-5.6-terra", reasoning_effort = "medium" },\n'
        )
        boundaries = {
            1: '  { model = "gpt-5.6-sol", reasoning_effort = "medium" },\n',
            8: (
                repository_candidates
                + '  { model = "gpt-5.6-luna", reasoning_effort = "low" },\n'
                + '  { model = "gpt-5.6-luna", reasoning_effort = "medium" },\n'
                + '  { model = "gpt-5.6-terra", reasoning_effort = "high" },\n'
                + '  { model = "gpt-5.6-terra", reasoning_effort = "xhigh" },\n'
                + '  { model = "gpt-5.6-sol", reasoning_effort = "high" },\n'
                + '  { model = "gpt-5.6-sol", reasoning_effort = "xhigh" },\n'
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            for count, replacement in boundaries.items():
                with self.subTest(count=count):
                    path = Path(directory) / f"{count}.toml"
                    path.write_text(
                        source.replace(repository_candidates, replacement, 1),
                        encoding="utf-8",
                    )
                    self.assertEqual(
                        count,
                        len(Catalog.load(path).coordinator_candidates),
                    )

    def test_v2_coordinator_candidate_order_is_significant(self) -> None:
        source = (REPO / ".codex" / "adaptive-subagents.toml").read_text()
        first = (
            '  { model = "gpt-5.6-sol", reasoning_effort = "medium" },\n'
            '  { model = "gpt-5.6-terra", reasoning_effort = "medium" },\n'
        )
        second = (
            '  { model = "gpt-5.6-terra", reasoning_effort = "medium" },\n'
            '  { model = "gpt-5.6-sol", reasoning_effort = "medium" },\n'
        )
        self.assertIn(first, source)
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original.toml"
            reordered = Path(directory) / "reordered.toml"
            original.write_text(source, encoding="utf-8")
            reordered.write_text(source.replace(first, second, 1), encoding="utf-8")
            original_catalog = Catalog.load(original)
            reordered_catalog = Catalog.load(reordered)

        self.assertNotEqual(
            original_catalog.coordinator_candidates,
            reordered_catalog.coordinator_candidates,
        )
        self.assertNotEqual(
            original_catalog.canonical_sha256,
            reordered_catalog.canonical_sha256,
        )

    def test_v2_rejects_unknown_coordinator_selection(self) -> None:
        source = (REPO / ".codex" / "adaptive-subagents.toml").read_text()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selection.toml"
            path.write_text(
                source.replace(
                    'selection = "first-verified-available"',
                    'selection = "last-known"',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaises(CatalogError):
                Catalog.load(path)

    def test_coordinator_contract_cascade_is_reproducible(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(REPO / "scripts" / "update_coordinator_contract_cascade.py"),
                "--check",
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr or result.stdout)

    def test_generation_changes_when_normalized_catalog_changes(self) -> None:
        source = (REPO / ".codex" / "adaptive-subagents.toml").read_text()
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.toml"
            second = Path(directory) / "second.toml"
            first.write_text(source)
            second.write_text(source.replace("queue_nodes = 100", "queue_nodes = 99"))
            self.assertNotEqual(
                Catalog.load(first).generation,
                Catalog.load(second).generation,
            )


class SchemaExportTests(unittest.TestCase):
    def test_exported_schemas_match_public_tool_definitions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            export_tool_schemas(destination)
            for tool in get_tool_definitions():
                input_path = destination / f"{tool['name']}-input.schema.json"
                output_path = destination / f"{tool['name']}-output.schema.json"
                self.assertEqual(
                    tool["inputSchema"],
                    json.loads(input_path.read_text()),
                )
                self.assertEqual(
                    tool["outputSchema"],
                    json.loads(output_path.read_text()),
                )


if __name__ == "__main__":
    unittest.main()

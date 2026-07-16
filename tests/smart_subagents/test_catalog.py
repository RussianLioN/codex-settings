from __future__ import annotations

import json
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
        self.assertEqual(("0.144.4",), catalog.supported_codex_versions)
        self.assertRegex(catalog.generation, r"^cg1_[a-f0-9]{16}$")
        self.assertEqual(
            {"gpt-5.6-luna", "gpt-5.6-terra", "gpt-5.6-sol"},
            set(catalog.models),
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

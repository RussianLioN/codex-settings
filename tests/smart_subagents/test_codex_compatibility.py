from __future__ import annotations

import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.catalog import Catalog  # noqa: E402
from codex_smart_subagents.compatibility import (  # noqa: E402
    MINIMUM_STABLE_CODEX_VERSION,
    VERIFIED_STABLE_CODEX_VERSIONS,
    codex_version_supported,
    parse_stable_codex_version,
)


class CodexCompatibilityTests(unittest.TestCase):
    def test_only_source_verified_stable_versions_are_supported(
        self,
    ) -> None:
        self.assertEqual((0, 145, 0), parse_stable_codex_version("0.145.0"))
        self.assertEqual("0.144.4", MINIMUM_STABLE_CODEX_VERSION)
        self.assertEqual(
            frozenset({"0.144.4", "0.144.5", "0.144.6", "0.145.0"}),
            VERIFIED_STABLE_CODEX_VERSIONS,
        )
        for version in VERIFIED_STABLE_CODEX_VERSIONS:
            with self.subTest(version=version):
                self.assertTrue(codex_version_supported(version))
        for version in ("0.144.7", "0.145.1", "0.146.0", "1.0.0"):
            with self.subTest(version=version):
                self.assertFalse(codex_version_supported(version))

    def test_old_prerelease_or_noncanonical_versions_are_rejected(self) -> None:
        for version in (
            "0.144.3",
            "0.145.0-alpha.1",
            "v0.144.6",
            "00.144.6",
            "0.144",
            "latest",
            "",
        ):
            with self.subTest(version=version):
                self.assertFalse(codex_version_supported(version))

    def test_catalog_uses_a_minimum_version_within_the_verified_set(
        self,
    ) -> None:
        source = REPO / ".codex" / "adaptive-subagents.toml"
        installed = (
            REPO
            / "plugins"
            / "codex-smart-subagents"
            / "config"
            / "adaptive-subagents.toml"
        )
        self.assertEqual(source.read_bytes(), installed.read_bytes())
        catalog = Catalog.load(source)
        self.assertEqual("0.144.4", catalog.minimum_codex_version)
        self.assertTrue(catalog.supports_codex_version("0.144.6"))
        self.assertTrue(catalog.supports_codex_version("0.145.0"))
        self.assertFalse(catalog.supports_codex_version("0.144.7"))
        self.assertFalse(catalog.supports_codex_version("0.145.1"))
        self.assertFalse(catalog.supports_codex_version("0.200.0"))
        self.assertFalse(catalog.supports_codex_version("0.144.3"))
        self.assertFalse(catalog.supports_codex_version("0.145.0-alpha.1"))

    def test_legacy_unverified_version_allowlists_are_absent_from_runtime(
        self,
    ) -> None:
        source_root = PLUGIN_SRC / "codex_smart_subagents"
        for path in source_root.glob("*.py"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertNotIn("SUPPORTED_CODEX_VERSION", text)
                self.assertNotIn("supported_codex_versions", text)


if __name__ == "__main__":
    unittest.main()

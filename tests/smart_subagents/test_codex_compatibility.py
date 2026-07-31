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
    codex_version_supported,
    parse_stable_codex_version,
)


class CodexCompatibilityTests(unittest.TestCase):
    def test_accepts_canonical_future_stable_versions_at_or_above_minimum(
        self,
    ) -> None:
        self.assertEqual((0, 145, 0), parse_stable_codex_version("0.145.0"))
        self.assertEqual("0.144.4", MINIMUM_STABLE_CODEX_VERSION)
        for version in ("0.146.0", "0.999.0", "1.0.0", "12.34.56"):
            with self.subTest(version=version):
                self.assertTrue(codex_version_supported(version))

    def test_rejects_prerelease_noncanonical_and_old_versions(self) -> None:
        for version in (
            "0.144.3",
            "0.146.0-alpha.2",
            "v0.146.0",
            "00.146.0",
            "0.144",
            "latest",
            "",
        ):
            with self.subTest(version=version):
                self.assertFalse(codex_version_supported(version))

    def test_never_lowers_the_global_stable_version_floor(self) -> None:
        self.assertFalse(
            codex_version_supported("0.1.0", minimum="0.1.0")
        )
        self.assertTrue(
            codex_version_supported("0.144.4", minimum="0.1.0")
        )

    def test_catalog_uses_a_minimum_stable_version(
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
        self.assertTrue(catalog.supports_codex_version("0.146.0"))
        self.assertTrue(catalog.supports_codex_version("1.0.0"))
        self.assertTrue(catalog.supports_codex_version("0.200.0"))
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

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.catalog import Catalog  # noqa: E402
from codex_smart_subagents.model_catalog import (  # noqa: E402
    AppServerModelCatalogInspector,
    ModelCatalogError,
    account_catalog_policy,
    parse_model_catalog,
    probe_model_catalog,
    require_catalog_support,
)


def model(slug: str, *efforts: str) -> dict[str, object]:
    return {
        "slug": slug,
        "supported_reasoning_levels": [
            {"effort": effort} for effort in efforts
        ],
    }


def account_model(slug: str, *efforts: str) -> dict[str, object]:
    return {
        "model": slug,
        "supportedReasoningEfforts": [
            {"reasoningEffort": effort} for effort in efforts
        ],
    }


class FakeAppServerClient:
    def __init__(self, responses: list[dict[str, object]]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(
        self,
        method: str,
        params: dict[str, object],
    ) -> dict[str, object]:
        self.calls.append((method, dict(params)))
        return self.responses.pop(0)


class ModelCatalogParsingTests(unittest.TestCase):
    def test_parses_only_public_model_capabilities(self) -> None:
        payload = json.dumps(
            [
                model("gpt-5.6-luna", "low", "medium", "high", "xhigh", "max"),
                model(
                    "gpt-5.6-terra",
                    "low",
                    "medium",
                    "high",
                    "xhigh",
                    "max",
                    "ultra",
                ),
                model(
                    "gpt-5.6-sol",
                    "low",
                    "medium",
                    "high",
                    "xhigh",
                    "max",
                    "ultra",
                ),
            ]
        ).encode()
        observed = parse_model_catalog(payload)
        self.assertEqual(
            frozenset({"low", "medium", "high", "xhigh", "max"}),
            observed["gpt-5.6-luna"],
        )

    def test_rejects_duplicate_models_malformed_efforts_and_oversized_data(
        self,
    ) -> None:
        cases = (
            json.dumps([model("gpt-5.6-luna", "low"), model("gpt-5.6-luna", "low")]).encode(),
            json.dumps([{"slug": "gpt-5.6-luna", "supported_reasoning_levels": [{}]}]).encode(),
            b"x" * (16 * 1024 * 1024 + 1),
        )
        for payload in cases:
            with self.subTest(size=len(payload)), self.assertRaises(
                ModelCatalogError
            ):
                parse_model_catalog(payload)


class ModelCatalogProbeTests(unittest.TestCase):
    def test_probe_uses_bundled_catalog_without_shell_or_user_flags(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            executable = root / "codex"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            codex_home = root / "codex-home"
            codex_home.mkdir(mode=0o700)
            completed = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    [model("gpt-5.6-luna", "low", "medium")]
                ).encode(),
                stderr=b"",
            )
            with mock.patch(
                "codex_smart_subagents.model_catalog.subprocess.run",
                return_value=completed,
            ) as run:
                observed = probe_model_catalog(executable, codex_home)
            self.assertIn("gpt-5.6-luna", observed)
            kwargs = run.call_args.kwargs
            self.assertEqual(
                [str(executable.resolve()), "debug", "models", "--bundled"],
                run.call_args.args[0],
            )
            self.assertFalse(kwargs["shell"])
            self.assertEqual(str(codex_home.resolve()), kwargs["env"]["CODEX_HOME"])
            self.assertNotIn("SSH_AUTH_SOCK", kwargs["env"])

    def test_probe_fails_closed_on_process_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            executable = root / "codex"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            codex_home = root / "codex-home"
            codex_home.mkdir(mode=0o700)
            completed = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout=b"",
                stderr=b"failure",
            )
            with mock.patch(
                "codex_smart_subagents.model_catalog.subprocess.run",
                return_value=completed,
            ), self.assertRaises(ModelCatalogError):
                probe_model_catalog(executable, codex_home)

    def test_probe_rejects_a_group_writable_codex_home(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            executable = root / "codex"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            codex_home = root / "codex-home"
            codex_home.mkdir(mode=0o770)
            codex_home.chmod(0o770)
            with self.assertRaises(ModelCatalogError):
                probe_model_catalog(executable, codex_home)


class CatalogCompatibilityTests(unittest.TestCase):
    def test_active_policy_is_supported_by_installed_catalog(self) -> None:
        catalog = Catalog.load(REPO / ".codex" / "adaptive-subagents.toml")
        observed = {
            name: frozenset(
                {"low", "medium", "high", "xhigh", "max", "ultra"}
            )
            for name in catalog.models
        }
        require_catalog_support(catalog, observed)

    def test_missing_model_or_effort_is_rejected(self) -> None:
        catalog = Catalog.load(REPO / ".codex" / "adaptive-subagents.toml")
        complete = {
            name: frozenset(
                {"low", "medium", "high", "xhigh", "max", "ultra"}
            )
            for name in catalog.models
        }
        for observed in (
            {key: value for key, value in complete.items() if not key.endswith("sol")},
            {
                **complete,
                "gpt-5.6-sol": frozenset({"low", "medium", "high", "xhigh"}),
            },
        ):
            with self.subTest(models=sorted(observed)), self.assertRaises(
                ModelCatalogError
            ):
                require_catalog_support(catalog, observed)

    def test_account_policy_intersects_visibility_and_policy_efforts(
        self,
    ) -> None:
        catalog = Catalog.load(REPO / ".codex" / "adaptive-subagents.toml")
        policy = account_catalog_policy(
            catalog,
            {
                "gpt-5.6-luna": frozenset({"low", "medium", "high"}),
                "gpt-5.6-sol": frozenset({"high"}),
                "untrusted-model": frozenset({"max"}),
            },
        )
        self.assertEqual(
            {
                "gpt-5.6-luna": frozenset({"low", "medium"}),
                "gpt-5.6-sol": frozenset({"high"}),
            },
            policy,
        )


class AccountModelInspectorTests(unittest.TestCase):
    def test_reads_bounded_paged_account_model_list(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            executable = root / "codex"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            codex_home = root / "codex-home"
            codex_home.mkdir(mode=0o700)
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)
            client = FakeAppServerClient(
                [
                    {
                        "data": [
                            account_model(
                                "gpt-5.6-luna",
                                "low",
                                "medium",
                            )
                        ],
                        "nextCursor": "page-2",
                    },
                    {
                        "data": [
                            account_model(
                                "gpt-5.6-terra",
                                "medium",
                                "high",
                            )
                        ],
                        "nextCursor": None,
                    },
                ]
            )
            inspector = AppServerModelCatalogInspector(
                codex_executable=executable,
                codex_home=codex_home,
                runtime_parent=runtime,
                client_factory=lambda **_kwargs: client,
            )

            observed = inspector.inspect()

        self.assertEqual(
            frozenset({"low", "medium"}),
            observed["gpt-5.6-luna"],
        )
        self.assertEqual(
            [
                (
                    "model/list",
                    {"includeHidden": True, "limit": 100},
                ),
                (
                    "model/list",
                    {
                        "includeHidden": True,
                        "limit": 100,
                        "cursor": "page-2",
                    },
                ),
            ],
            client.calls,
        )

    def test_rejects_duplicate_or_malformed_account_records(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            executable = root / "codex"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            codex_home = root / "codex-home"
            codex_home.mkdir(mode=0o700)
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)
            client = FakeAppServerClient(
                [
                    {
                        "data": [
                            account_model("gpt-5.6-luna", "low"),
                            account_model("gpt-5.6-luna", "medium"),
                        ],
                        "nextCursor": None,
                    }
                ]
            )
            inspector = AppServerModelCatalogInspector(
                codex_executable=executable,
                codex_home=codex_home,
                runtime_parent=runtime,
                client_factory=lambda **_kwargs: client,
            )
            with self.assertRaisesRegex(
                ModelCatalogError,
                "MODEL_LIST_INVALID",
            ):
                inspector.inspect()


if __name__ == "__main__":
    unittest.main()

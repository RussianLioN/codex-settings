from __future__ import annotations

import json
import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import domain_fingerprint  # noqa: E402
from codex_smart_subagents.codex_binary_snapshot import (  # noqa: E402
    SnapshotCommand,
    SnapshotCommandResult,
)
from codex_smart_subagents.interface_probe_v1 import (  # noqa: E402
    InterfaceProbeV1Error,
    probe_codex_interface_v1,
    probe_bundled_catalog_v1,
    project_bundled_catalog_v1,
)
from codex_smart_subagents.policy_bundle_v2 import load_policy_bundle_v2  # noqa: E402


class _Executor:
    def __init__(self, result: SnapshotCommandResult) -> None:
        self.result = result
        self.commands: list[SnapshotCommand] = []

    def run(self, command: SnapshotCommand) -> SnapshotCommandResult:
        self.commands.append(command)
        return self.result


class _SequenceExecutor:
    def __init__(self, results: list[SnapshotCommandResult]) -> None:
        self.results = list(results)
        self.commands: list[SnapshotCommand] = []

    def run(self, command: SnapshotCommand) -> SnapshotCommandResult:
        self.commands.append(command)
        return self.results.pop(0)


class BundledCatalogProjectionTests(unittest.TestCase):
    def test_projection_ignores_descriptions_and_sorts_by_utf8(self) -> None:
        raw = {
            "future": {"ignored": True},
            "models": [
                {
                    "slug": "terra",
                    "description": "ignored",
                    "supported_reasoning_levels": [
                        {"effort": "medium", "description": "ignored"},
                        {"effort": "high"},
                    ],
                },
                {
                    "slug": "luna",
                    "supported_reasoning_levels": [{"effort": "low"}],
                },
            ],
        }

        projection = project_bundled_catalog_v1(raw)

        self.assertEqual(
            {
                "models": [
                    {"model": "luna", "reasoningEfforts": ["low"]},
                    {
                        "model": "terra",
                        "reasoningEfforts": ["high", "medium"],
                    },
                ]
            },
            projection,
        )

    def test_projection_rejects_duplicate_or_unbounded_identity(self) -> None:
        cases = (
            {
                "models": [
                    {"slug": "same", "supported_reasoning_levels": [{"effort": "low"}]},
                    {"slug": "same", "supported_reasoning_levels": [{"effort": "high"}]},
                ]
            },
            {
                "models": [
                    {
                        "slug": "model",
                        "supported_reasoning_levels": [
                            {"effort": "low"},
                            {"effort": "low"},
                        ],
                    }
                ]
            },
            {
                "models": [
                    {
                        "slug": "m" * 129,
                        "supported_reasoning_levels": [{"effort": "low"}],
                    }
                ]
            },
        )
        for value in cases:
            with self.subTest(value=value), self.assertRaises(InterfaceProbeV1Error):
                project_bundled_catalog_v1(value)


class BundledCatalogProcessTests(unittest.TestCase):
    def test_probe_uses_only_the_verified_snapshot_and_closed_environment(self) -> None:
        raw = {
            "models": [
                {
                    "slug": "gpt-test",
                    "supported_reasoning_levels": [{"effort": "medium"}],
                }
            ]
        }
        executor = _Executor(
            SnapshotCommandResult(
                exit_code=0,
                stdout=json.dumps(raw).encode("utf-8"),
                stderr=b"",
            )
        )
        executable = Path("/private/snapshot/codex")

        result = probe_bundled_catalog_v1(executable, executor=executor)

        self.assertEqual(
            {"models": [{"model": "gpt-test", "reasoningEfforts": ["medium"]}]},
            result.projection,
        )
        self.assertEqual(
            domain_fingerprint("codex-smart/bundled-catalog/v1", result.projection),
            result.fingerprint,
        )
        self.assertEqual(1, len(executor.commands))
        command = executor.commands[0]
        self.assertEqual(
            (str(executable), "debug", "models", "--bundled"),
            command.argv,
        )
        self.assertEqual(executable.parent, command.cwd)
        self.assertEqual(
            {
                "LANG": "C",
                "LC_ALL": "C",
                "NO_COLOR": "1",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            },
            dict(command.environment),
        )

    def test_probe_rejects_process_error_malformed_json_and_excess_output(self) -> None:
        cases = (
            SnapshotCommandResult(exit_code=1, stdout=b"{}", stderr=b"failed"),
            SnapshotCommandResult(exit_code=0, stdout=b"not-json", stderr=b""),
            SnapshotCommandResult(
                exit_code=0,
                stdout=b"{" + b" " * (1024 * 1024),
                stderr=b"",
            ),
        )
        for result in cases:
            with self.subTest(result=result), self.assertRaises(InterfaceProbeV1Error):
                probe_bundled_catalog_v1(
                    Path("/private/snapshot/codex"),
                    executor=_Executor(result),
                )


class InterfaceEvidenceProcessTests(unittest.TestCase):
    @staticmethod
    def _bundle():
        vectors = ROOT / "docs" / "contracts" / "vectors"
        return load_policy_bundle_v2(
            catalog_path=ROOT / ".codex" / "adaptive-subagents.toml",
            routing_vector_path=vectors / "routing-policy-v2.json",
            delegation_vector_path=vectors / "delegation-policy-v2.json",
            role_vector_path=vectors / "role-template-v1.json",
            child_profile_vector_path=vectors / "child-profile-v1.json",
        )

    def _subject(self) -> dict[str, object]:
        return json.loads(
            (ROOT / "docs/contracts/vectors/interface-evidence-v1.json").read_text(
                encoding="utf-8"
            )
        )["base"]["subject"]

    def test_probe_builds_semantics_from_current_contract_files_and_policy(self) -> None:
        bundled = {
            "models": [
                {
                    "slug": "gpt-new",
                    "supported_reasoning_levels": [{"effort": "medium"}],
                }
            ]
        }
        executor = _SequenceExecutor(
            [
                SnapshotCommandResult(0, json.dumps(bundled).encode("utf-8"), b""),
                SnapshotCommandResult(0, b"--strict-config --listen", b""),
                SnapshotCommandResult(
                    0,
                    (
                        b"--strict-config --model --skip-git-repo-check --ephemeral "
                        b"--ignore-user-config --ignore-rules --output-schema --json"
                    ),
                    b"",
                ),
            ]
        )
        bundle = self._bundle()

        observed = probe_codex_interface_v1(
            subject=self._subject(),
            contract_root=ROOT / "docs" / "contracts",
            policy_bundle=bundle,
            executor=executor,
        )

        semantic = observed.interface_evidence["semantic"]
        self.assertEqual(bundle.router.policy_fingerprint, semantic["routingPolicyFingerprint"])
        self.assertEqual(
            dict(bundle.child_profile_fingerprints),
            semantic["childProfiles"],
        )
        self.assertEqual(
            observed.bundled_catalog.fingerprint,
            semantic["bundledCatalogFingerprint"],
        )
        self.assertEqual(3, len(executor.commands))
        schemas = ROOT / "docs" / "contracts" / "schemas"
        for name, record in semantic["machineSchemas"].items():
            self.assertEqual(
                hashlib.sha256((schemas / f"{name}.schema.json").read_bytes()).hexdigest(),
                record["schemaSha256"],
            )

    def test_probe_fails_when_required_help_surface_is_missing(self) -> None:
        bundled = {
            "models": [
                {
                    "slug": "gpt-new",
                    "supported_reasoning_levels": [{"effort": "medium"}],
                }
            ]
        }
        executor = _SequenceExecutor(
            [
                SnapshotCommandResult(0, json.dumps(bundled).encode("utf-8"), b""),
                SnapshotCommandResult(0, b"--strict-config", b""),
            ]
        )
        with self.assertRaisesRegex(InterfaceProbeV1Error, "INTERFACE_OPTION_MISSING"):
            probe_codex_interface_v1(
                subject=self._subject(),
                contract_root=ROOT / "docs" / "contracts",
                policy_bundle=self._bundle(),
                executor=executor,
            )


if __name__ == "__main__":
    unittest.main()

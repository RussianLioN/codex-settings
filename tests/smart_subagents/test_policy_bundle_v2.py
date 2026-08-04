from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.policy_bundle_v2 import (  # noqa: E402
    PolicyBundleError,
    load_policy_bundle_v2,
)


class PolicyBundleV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = ROOT / ".codex" / "adaptive-subagents.toml"
        self.routing = ROOT / "docs/contracts/vectors/routing-policy-v2.json"
        self.delegation = ROOT / "docs/contracts/vectors/delegation-policy-v2.json"
        self.roles = ROOT / "docs/contracts/vectors/role-template-v1.json"
        self.child_profiles = ROOT / "docs/contracts/vectors/child-profile-v1.json"

    def _load(self, **overrides: Path):
        paths = {
            "catalog_path": self.catalog,
            "routing_vector_path": self.routing,
            "delegation_vector_path": self.delegation,
            "role_vector_path": self.roles,
            "child_profile_vector_path": self.child_profiles,
        }
        paths.update(overrides)
        return load_policy_bundle_v2(**paths)

    def _mutated_json(
        self, source: Path, mutate
    ) -> tuple[tempfile.TemporaryDirectory, Path]:
        temporary = tempfile.TemporaryDirectory()
        target = Path(temporary.name) / source.name
        value = json.loads(source.read_text(encoding="utf-8"))
        mutate(value)
        target.write_text(
            json.dumps(value, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        return temporary, target

    def _mutated_catalog(
        self,
        old: str,
        new: str,
    ) -> tuple[tempfile.TemporaryDirectory, Path]:
        temporary = tempfile.TemporaryDirectory()
        target = Path(temporary.name) / self.catalog.name
        source = self.catalog.read_text(encoding="utf-8")
        self.assertIn(old, source)
        target.write_text(source.replace(old, new, 1), encoding="utf-8")
        return temporary, target

    def test_loads_closed_bundle_and_builds_router(self) -> None:
        bundle = self._load()

        self.assertEqual(2, bundle.schema_version)
        self.assertEqual("q+p+v+o-v2", bundle.algorithm_version)
        self.assertEqual(
            bundle.routing_policy_snapshot["policy"]["coordinator"],
            {
                "selection": bundle.coordinator_selection,
                "candidates": list(bundle.coordinator_candidates),
            },
        )
        self.assertEqual(
            {
                "model": "gpt-5.6-sol",
                "reasoningEffort": "medium",
            },
            bundle.coordinator_candidates[0],
        )
        self.assertEqual(
            {
                "model": "gpt-5.6-terra",
                "reasoningEffort": "medium",
            },
            bundle.coordinator_candidates[1],
        )
        self.assertEqual(
            bundle.routing_policy_snapshot["policy"]["allowedPairs"],
            list(bundle.policy_pairs),
        )
        self.assertEqual(5, len(bundle.role_templates))
        self.assertEqual(3, len(bundle.child_profiles))
        self.assertTrue(bundle.known_child_features)
        self.assertEqual("codex-smart/child-profile/v1", bundle.child_profile_domain)
        self.assertEqual("codex-smart/argv/v2", bundle.child_argv_domain)
        self.assertEqual(
            "codex-smart/environment/v1",
            bundle.child_environment_domain,
        )
        self.assertEqual(
            "codex-smart/launch-secret/v1",
            bundle.child_secret_domain,
        )
        self.assertEqual(
            {
                "virtualRoot": "/private/schemas",
                "repositoryRoot": "docs/contracts/schemas",
            },
            bundle.result_schema_resolution,
        )
        self.assertEqual("0.144.4", bundle.minimum_codex_version)
        self.assertEqual(("darwin-arm64",), bundle.supported_platforms)
        self.assertEqual(900, bundle.catalog_limits["child_timeout_seconds"])
        self.assertEqual(
            8 * 1024 * 1024,
            bundle.catalog_limits["child_max_output_bytes"],
        )
        self.assertEqual(20000, bundle.catalog_limits["snapshot_max_files"])
        self.assertEqual(
            8 * 1024 * 1024,
            bundle.catalog_limits["snapshot_max_file_bytes"],
        )
        self.assertEqual(
            256 * 1024 * 1024,
            bundle.catalog_limits["snapshot_max_total_bytes"],
        )
        self.assertEqual(
            (("/usr/bin/env", "python3", "-m", "unittest", "discover", "-v"),),
            bundle.validation_commands["writer-validation-v2"],
        )
        self.assertEqual((), bundle.validation_commands["reader-validation-v2"])
        self.assertEqual(
            {"classifier", "reader", "writer"},
            {profile["role"] for profile in bundle.child_profiles},
        )
        self.assertRegex(bundle.bundle_fingerprint, r"^[0-9a-f]{64}$")
        self.assertEqual(
            bundle.routing_policy_snapshot["fingerprint"],
            bundle.router.policy_fingerprint,
        )

    def test_current_loader_preserves_a_verified_schema1_policy(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        catalog_path = root / "adaptive-subagents.toml"
        catalog = self.catalog.read_text(encoding="utf-8")
        catalog = catalog.replace("schema_version = 2", "schema_version = 1", 1)
        catalog = catalog.replace(
            '[coordinator]\nselection = "first-verified-available"\n'
            "candidates = [\n"
            '  { model = "gpt-5.6-sol", reasoning_effort = "medium" },\n'
            '  { model = "gpt-5.6-terra", reasoning_effort = "medium" },\n'
            "]",
            '[coordinator]\nmodel = "gpt-5.6-terra"\n'
            'reasoning_effort = "medium"',
            1,
        )
        catalog = catalog.replace(
            'reasoning_efforts = ["medium", "high", "xhigh", "max"]',
            'reasoning_efforts = ["high", "xhigh", "max"]',
            1,
        )
        catalog_path.write_text(catalog, encoding="utf-8")

        def schema1_coordinator(value: dict[str, object]) -> None:
            policy = value["policy"]
            assert isinstance(policy, dict)
            policy["coordinator"] = {
                "model": "gpt-5.6-terra",
                "reasoningEffort": "medium",
            }
            canonical = json.dumps(
                policy,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            value["canonicalUtf8"] = canonical
            import hashlib

            domain = value["domain"]
            assert isinstance(domain, str)
            value["fingerprint"] = hashlib.sha256(
                domain.encode("utf-8") + b"\0" + canonical.encode("utf-8")
            ).hexdigest()

        routing_temporary, routing_path = self._mutated_json(
            self.routing,
            schema1_coordinator,
        )
        self.addCleanup(routing_temporary.cleanup)

        bundle = self._load(
            catalog_path=catalog_path,
            routing_vector_path=routing_path,
        )

        self.assertEqual(2, bundle.schema_version)
        self.assertEqual(
            ({"model": "gpt-5.6-terra", "reasoningEffort": "medium"},),
            bundle.coordinator_candidates,
        )
        self.assertEqual(
            bundle.routing_policy_snapshot["fingerprint"],
            bundle.router.policy_fingerprint,
        )

    def test_coordinator_only_sol_medium_never_expands_child_pairs(self) -> None:
        bundle = self._load()
        coordinator_only = {
            "model": "gpt-5.6-sol",
            "reasoningEffort": "medium",
        }

        self.assertIn(coordinator_only, bundle.coordinator_candidates)
        self.assertNotIn(
            coordinator_only,
            bundle.routing_policy_snapshot["policy"]["allowedPairs"],
        )
        self.assertNotIn(coordinator_only, bundle.policy_pairs)
        self.assertEqual(
            {
                ("gpt-5.6-luna", "low"),
                ("gpt-5.6-luna", "medium"),
                ("gpt-5.6-terra", "medium"),
                ("gpt-5.6-terra", "high"),
                ("gpt-5.6-sol", "high"),
                ("gpt-5.6-sol", "xhigh"),
                ("gpt-5.6-sol", "max"),
            },
            {
                (pair["model"], pair["reasoningEffort"])
                for pair in bundle.policy_pairs
            },
        )

    def test_runtime_module_contains_no_model_name_literal(self) -> None:
        source = (
            PLUGIN_SRC / "codex_smart_subagents" / "policy_bundle_v2.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("gpt-", source)

    def test_rejects_coordinator_drift_between_catalog_and_policy(self) -> None:
        temporary, target = self._mutated_json(
            self.routing,
            lambda value: value["policy"]["coordinator"]["candidates"][0].update(
                {"reasoningEffort": "high"}
            ),
        )
        self.addCleanup(temporary.cleanup)

        with self.assertRaisesRegex(
            PolicyBundleError,
            "ROUTING_POLICY_SNAPSHOT_INVALID|COORDINATOR_POLICY_DRIFT",
        ):
            self._load(routing_vector_path=target)

    def test_rejects_policy_pair_absent_from_catalog(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            policy = value["policy"]
            assert isinstance(policy, dict)
            pairs = policy["allowedPairs"]
            assert isinstance(pairs, list)
            pairs.append({"model": "unknown-model", "reasoningEffort": "low"})
            canonical = json.dumps(
                policy,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            value["canonicalUtf8"] = canonical
            import hashlib

            domain = value["domain"]
            assert isinstance(domain, str)
            value["fingerprint"] = hashlib.sha256(
                domain.encode("utf-8") + b"\0" + canonical.encode("utf-8")
            ).hexdigest()

        temporary, target = self._mutated_json(self.routing, mutate)
        self.addCleanup(temporary.cleanup)

        with self.assertRaisesRegex(PolicyBundleError, "POLICY_PAIR_NOT_IN_CATALOG"):
            self._load(routing_vector_path=target)

    def test_rejects_duplicate_catalog_rank(self) -> None:
        text = self.catalog.read_text(encoding="utf-8")
        text = text.replace(
            '[models."gpt-5.6-terra"]\nrank = 1',
            '[models."gpt-5.6-terra"]\nrank = 0',
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        target = Path(temporary.name) / "adaptive-subagents.toml"
        target.write_text(text, encoding="utf-8")

        with self.assertRaisesRegex(PolicyBundleError, "CATALOG_MODEL_RANK_DUPLICATE"):
            self._load(catalog_path=target)

    def test_rejects_non_positive_catalog_limit(self) -> None:
        temporary, target = self._mutated_catalog(
            "child_timeout_seconds = 900",
            "child_timeout_seconds = 0",
        )
        self.addCleanup(temporary.cleanup)

        with self.assertRaisesRegex(PolicyBundleError, "CATALOG_INVALID"):
            self._load(catalog_path=target)

    def test_rejects_missing_catalog_limit(self) -> None:
        temporary, target = self._mutated_catalog(
            "child_max_output_bytes = 8388608\n",
            "",
        )
        self.addCleanup(temporary.cleanup)

        with self.assertRaisesRegex(PolicyBundleError, "CATALOG_INVALID"):
            self._load(catalog_path=target)

    def test_rejects_inconsistent_catalog_leases(self) -> None:
        temporary, target = self._mutated_catalog(
            "heartbeat_seconds = 10",
            "heartbeat_seconds = 45",
        )
        self.addCleanup(temporary.cleanup)

        with self.assertRaisesRegex(PolicyBundleError, "CATALOG_INVALID"):
            self._load(catalog_path=target)


if __name__ == "__main__":
    unittest.main()

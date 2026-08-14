from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_v1,
    domain_fingerprint,
)
from codex_smart_subagents.managed_requirements_v1 import (  # noqa: E402
    ManagedRequirementsError,
    normalize_managed_requirements,
    verify_managed_requirements_compatibility,
)


class ManagedRequirementsV1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = json.loads(
            (
                ROOT
                / "docs"
                / "contracts"
                / "vectors"
                / "config-requirements-v1.json"
            ).read_text(encoding="utf-8")
        )

    def test_matches_all_applicable_primary_vectors(self) -> None:
        checked = 0
        for case in self.vectors["cases"]:
            source = case["source"]
            envelope = source.get("value")
            if source["kind"] != "parsed" or "requirements" not in envelope:
                continue
            expected = case["expected"]["normalization"]
            with self.subTest(case=case["name"]):
                if expected["status"] == "rejected":
                    with self.assertRaises(ManagedRequirementsError) as raised:
                        normalize_managed_requirements(envelope["requirements"])
                    self.assertEqual(expected["errorCode"], raised.exception.code)
                    self.assertEqual(expected["phase"], raised.exception.phase)
                else:
                    normalized = normalize_managed_requirements(
                        envelope["requirements"]
                    )
                    self.assertEqual(expected["normalized"], normalized)
                    self.assertEqual(
                        expected["canonicalUtf8"], canonical_json_v1(normalized)
                    )
                    self.assertEqual(
                        expected["fingerprint"],
                        domain_fingerprint(
                            "codex-smart/requirements/v1", normalized
                        ),
                    )
                checked += 1
        self.assertEqual(20, checked)

    def test_rejects_cycles_depth_node_count_and_unsafe_integer(self) -> None:
        cyclic: dict[str, Any] = {}
        cyclic["network"] = cyclic
        too_deep: Any = None
        for _ in range(17):
            too_deep = {"network": too_deep}
        invalid = (
            cyclic,
            too_deep,
            {"allowedDomains": [str(index) for index in range(4_096)]},
            {"network": {"httpPort": 9_007_199_254_740_992}},
        )
        for value in invalid:
            with self.subTest(value=repr(value)[:80]):
                with self.assertRaises(ManagedRequirementsError):
                    normalize_managed_requirements(value)

    def test_does_not_mutate_the_source_tree(self) -> None:
        source = {
            "allowedApprovalPolicies": [
                {
                    "granular": {
                        "mcp_elicitations": False,
                        "rules": False,
                        "sandbox_approval": False,
                    }
                }
            ]
        }
        before = copy.deepcopy(source)
        normalized = normalize_managed_requirements(source)
        self.assertEqual(before, source)
        self.assertIn(
            "request_permissions",
            normalized["allowedApprovalPolicies"][0]["granular"],
        )

    def test_compatibility_matches_all_normalized_primary_vectors(self) -> None:
        profiles_document = json.loads(
            (
                ROOT
                / "docs"
                / "contracts"
                / "vectors"
                / "child-profile-v1.json"
            ).read_text(encoding="utf-8")
        )
        profiles = {
            case["name"]: case["profile"] for case in profiles_document["cases"]
        }
        known_features = {
            feature
            for profile in profiles.values()
            for feature in profile["disabledFeatures"]
        }
        checked = 0
        for case in self.vectors["cases"]:
            source = case["source"]
            envelope = source.get("value")
            expected = case["expected"]
            if (
                source["kind"] != "parsed"
                or "requirements" not in envelope
                or expected["normalization"]["status"] != "complete"
            ):
                continue
            context = self.vectors["contexts"][case["contextRef"]]
            normalized = normalize_managed_requirements(envelope["requirements"])
            profile = profiles[context["profileCase"]]
            with self.subTest(case=case["name"]):
                if expected["compatibility"]["status"] == "compatible":
                    verify_managed_requirements_compatibility(
                        normalized,
                        profile=profile,
                        selected_pair=context["selectedPair"],
                        known_features=known_features,
                    )
                else:
                    with self.assertRaises(ManagedRequirementsError) as raised:
                        verify_managed_requirements_compatibility(
                            normalized,
                            profile=profile,
                            selected_pair=context["selectedPair"],
                            known_features=known_features,
                        )
                    self.assertEqual(
                        expected["compatibility"]["errorCode"],
                        raised.exception.code,
                    )
                checked += 1
        self.assertEqual(17, checked)


if __name__ == "__main__":
    unittest.main()

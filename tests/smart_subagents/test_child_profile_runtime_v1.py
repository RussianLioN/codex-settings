from __future__ import annotations

import json
import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.child_profile_runtime_v1 import (  # noqa: E402
    ChildProfileDomainsV1,
    ChildProfileRuntimeError,
    materialize_child_profile_v1,
    secret_fingerprint_v1,
)


class ChildProfileRuntimeV1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = json.loads(
            (ROOT / "docs/contracts/vectors/child-profile-v1.json").read_text(
                encoding="utf-8"
            )
        )
        cls.profiles = {case["name"]: case["profile"] for case in cls.vectors["cases"]}
        cls.domains = ChildProfileDomainsV1(
            argv=cls.vectors["argvDomain"],
            environment=cls.vectors["environmentDomain"],
            secret=cls.vectors["secretDomain"],
        )

    def test_all_three_roles_match_contract_vectors_byte_for_byte(self) -> None:
        raw_header = self.vectors["syntheticSecretFixture"]["syntheticSecretUtf8"]
        for role, fixture in self.vectors["concreteLaunch"]["positiveRoles"].items():
            with self.subTest(role=role):
                binding = materialize_child_profile_v1(
                    profile=self.profiles[role],
                    trusted_context=fixture["trustedContext"],
                    snapshot_path="/private/codex",
                    raw_otel_headers=raw_header,
                    domains=self.domains,
                )

                self.assertEqual(fixture["binding"], binding.contract_value())

    def test_secret_is_only_in_exec_environment_and_has_separate_fingerprint(
        self,
    ) -> None:
        fixture = self.vectors["concreteLaunch"]["positiveRoles"]["reader"]
        first_context = copy.deepcopy(fixture["trustedContext"])
        second_context = copy.deepcopy(fixture["trustedContext"])
        first_context["secretSlotFingerprints"]["otelHeaders"] = secret_fingerprint_v1(
            self.domains.secret,
            "X-Test=first-secret-value",
        )
        second_context["secretSlotFingerprints"]["otelHeaders"] = secret_fingerprint_v1(
            self.domains.secret,
            "X-Test=second-secret-value",
        )
        first = materialize_child_profile_v1(
            profile=self.profiles["reader"],
            trusted_context=first_context,
            snapshot_path="/private/codex",
            raw_otel_headers="X-Test=first-secret-value",
            domains=self.domains,
        )
        second = materialize_child_profile_v1(
            profile=self.profiles["reader"],
            trusted_context=second_context,
            snapshot_path="/private/codex",
            raw_otel_headers="X-Test=second-secret-value",
            domains=self.domains,
        )

        self.assertEqual(first.argv, second.argv)
        self.assertEqual(first.argv_fingerprint, second.argv_fingerprint)
        self.assertNotEqual(first.secret_sha256, second.secret_sha256)
        self.assertNotEqual(
            first.environment_fingerprint,
            second.environment_fingerprint,
        )
        self.assertNotIn("OTEL_EXPORTER_OTLP_HEADERS", first.non_secret_environment)
        self.assertEqual(
            "X-Test=first-secret-value",
            first.exec_environment["OTEL_EXPORTER_OTLP_HEADERS"],
        )
        argv_text = "\0".join(first.argv)
        self.assertNotIn("first-secret-value", argv_text)
        self.assertNotIn("second-secret-value", argv_text)
        self.assertNotIn("first-secret-value", repr(first))

    def test_profile_without_complete_permission_table_is_not_launchable(self) -> None:
        fixture = self.vectors["concreteLaunch"]["positiveRoles"]["reader"]
        profile = copy.deepcopy(self.profiles["reader"])
        permission_slots = {
            "permissionDescriptionConfig",
            "permissionFilesystemConfig",
            "permissionNetworkConfig",
        }
        profile["argvTemplate"] = [
            item
            for item in profile["argvTemplate"]
            if item.get("slot") not in permission_slots
        ]

        with self.assertRaisesRegex(
            ChildProfileRuntimeError,
            "PROFILE_PERMISSION_TABLE_MISSING",
        ):
            materialize_child_profile_v1(
                profile=profile,
                trusted_context=fixture["trustedContext"],
                snapshot_path="/private/codex",
                raw_otel_headers=self.vectors["syntheticSecretFixture"][
                    "syntheticSecretUtf8"
                ],
                domains=self.domains,
            )


if __name__ == "__main__":
    unittest.main()

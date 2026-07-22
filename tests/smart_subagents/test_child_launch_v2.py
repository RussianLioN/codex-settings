from __future__ import annotations

import hashlib
import copy
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.child_launch_v2 import (  # noqa: E402
    ChildLaunchV2Error,
    cleanup_prepared_child_launch_v2,
    prepare_child_launch_v2,
)
from codex_smart_subagents.child_profile_runtime_v1 import (  # noqa: E402
    ChildProfileDomainsV1,
)
from codex_smart_subagents.child_runner import (  # noqa: E402
    ChildRuntimeLayout,
    ChildTelemetryConfig,
)
from codex_smart_subagents.policy_bundle_v2 import load_policy_bundle_v2  # noqa: E402


class _AttemptResource:
    def __init__(self) -> None:
        self.telemetry_config = ChildTelemetryConfig(
            endpoint="http://127.0.0.1:4318/private",
            header_name="X-Codex-Attestation-Token",
            token="test-token-abcdefghijklmnopqrstuvwxyz",
        )
        self.closed = False

    def attest(self, *_arguments: object):
        raise AssertionError("materialization test must not attest")

    def close(self) -> None:
        self.closed = True


def _bundle():
    vectors = ROOT / "docs" / "contracts" / "vectors"
    return load_policy_bundle_v2(
        catalog_path=ROOT / ".codex" / "adaptive-subagents.toml",
        routing_vector_path=vectors / "routing-policy-v2.json",
        delegation_vector_path=vectors / "delegation-policy-v2.json",
        role_vector_path=vectors / "role-template-v1.json",
        child_profile_vector_path=vectors / "child-profile-v1.json",
    )


class ChildLaunchV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.executable = self.root / "codex"
        self.executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.executable.chmod(0o500)
        self.schema = self.root / "output.schema.json"
        self.schema.write_text('{"type":"object"}\n', encoding="utf-8")
        self.schema.chmod(0o400)
        self.snapshot_root = self.root / "snapshot-root"
        self.snapshot_root.mkdir(mode=0o500)
        self.workspace_root = self.root / "workspace-root"
        self.workspace_root.mkdir(mode=0o700)
        self.auth_file = self.root / "source-auth.json"
        self.auth_file.write_text('{"fixture":true}\n', encoding="utf-8")
        self.auth_file.chmod(0o600)
        self.bundle = _bundle()
        self.runtime_counter = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _runtime(self) -> ChildRuntimeLayout:
        self.runtime_counter += 1
        return ChildRuntimeLayout.create(self.root / f"runtime-{self.runtime_counter}")

    def _prepare(
        self,
        pair=None,
        *,
        role="reader",
        snapshot_sha256=None,
        attempt_resource=None,
    ):
        chosen = dict(self.bundle.policy_pairs[0]) if pair is None else pair
        profile = next(
            profile for profile in self.bundle.child_profiles if profile["role"] == role
        )
        prepared = prepare_child_launch_v2(
            executable=self.executable,
            snapshot_sha256=(
                hashlib.sha256(self.executable.read_bytes()).hexdigest()
                if snapshot_sha256 is None
                else snapshot_sha256
            ),
            snapshot_identity_fingerprint="a" * 64,
            pair=chosen,
            allowed_pairs=self.bundle.policy_pairs,
            runtime=self._runtime(),
            snapshot_root=self.snapshot_root,
            output_schema=self.schema,
            profile=profile,
            profile_domain=self.bundle.child_profile_domain,
            expected_profile_fingerprint=self.bundle.child_profile_fingerprints[role],
            domains=ChildProfileDomainsV1(
                argv=self.bundle.child_argv_domain,
                environment=self.bundle.child_environment_domain,
                secret=self.bundle.child_secret_domain,
            ),
            compatibility_fingerprint="b" * 64,
            account_context_fingerprint="c" * 64,
            expected_cli_version="0.107.0-test",
            attempt_resource=attempt_resource or _AttemptResource(),
            auth_file=self.auth_file,
            prompt="Проверь договор.",
            workspace_root=self.workspace_root if role == "writer" else None,
            completion=(
                type(
                    "Completion",
                    (),
                    {"complete": lambda self, result: result},
                )()
                if role == "writer"
                else None
            ),
        )
        self.addCleanup(cleanup_prepared_child_launch_v2, prepared)
        return prepared

    def test_prepares_exact_profile_environment_and_separate_fingerprints(self) -> None:
        prepared = self._prepare()
        pair = dict(self.bundle.policy_pairs[0])

        model_index = prepared.argv.index("--model")
        self.assertEqual(pair["model"], prepared.argv[model_index + 1])
        self.assertIn(
            f'model_reasoning_effort="{pair["reasoningEffort"]}"',
            prepared.argv,
        )
        self.assertIn('otel.environment="adaptive-child"', prepared.argv)
        self.assertIn("otel.log_user_prompt=false", prepared.argv)
        self.assertIn('otel.metrics_exporter="none"', prepared.argv)
        self.assertIn('otel.trace_exporter="none"', prepared.argv)
        self.assertIn(
            'otel.exporter={ otlp-http = { endpoint="http://127.0.0.1:4318/private/v1/logs", protocol="json", headers={} } }',
            prepared.argv,
        )
        self.assertEqual("codex-smart-reader", prepared.permission_profile_id)
        self.assertEqual(
            {
                "CODEX_ADAPTIVE_CHILD",
                "CODEX_ADAPTIVE_SNAPSHOT_ROOT",
                "CODEX_HOME",
                "CODEX_SQLITE_HOME",
                "HOME",
                "LANG",
                "LC_ALL",
                "NO_COLOR",
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "PATH",
                "TMPDIR",
            },
            set(prepared.non_secret_environment),
        )
        self.assertEqual(
            set(prepared.non_secret_environment) | {"OTEL_EXPORTER_OTLP_HEADERS"},
            set(prepared.environment),
        )
        self.assertNotIn(
            prepared.environment["OTEL_EXPORTER_OTLP_HEADERS"],
            "\0".join(prepared.argv),
        )
        self.assertRegex(prepared.argv_fingerprint, r"^[0-9a-f]{64}$")
        self.assertRegex(prepared.environment_fingerprint, r"^[0-9a-f]{64}$")
        self.assertRegex(prepared.secret_sha256, r"^[0-9a-f]{64}$")

    def test_writer_materializes_required_workspace_slot(self) -> None:
        prepared = self._prepare(role="writer")

        self.assertEqual(
            os.fspath(self.workspace_root),
            prepared.non_secret_environment["CODEX_ADAPTIVE_WORKSPACE_ROOT"],
        )
        self.assertIn(
            '"CODEX_ADAPTIVE_WORKSPACE_ROOT":',
            "\0".join(prepared.argv),
        )

    def test_stages_private_auth_and_cleanup_is_idempotent(self) -> None:
        prepared = self._prepare()
        staged = prepared.staged_auth_path
        self.assertIsNotNone(staged)
        assert staged is not None
        self.assertEqual(0o600, stat.S_IMODE(staged.stat().st_mode))
        self.assertEqual(self.auth_file.read_bytes(), staged.read_bytes())

        cleanup_prepared_child_launch_v2(prepared)
        cleanup_prepared_child_launch_v2(prepared)
        self.assertFalse(staged.exists())
        self.assertTrue(prepared.attempt_resource.closed)

    def test_rejects_pair_not_in_policy_without_fallback(self) -> None:
        attempt_resource = _AttemptResource()
        with self.assertRaisesRegex(ChildLaunchV2Error, "PAIR_NOT_ALLOWED"):
            self._prepare(
                {"model": "outside-policy", "reasoningEffort": "low"},
                attempt_resource=attempt_resource,
            )
        self.assertTrue(attempt_resource.closed)

    def test_rejects_profile_changed_after_policy_loading(self) -> None:
        profile = next(
            copy.deepcopy(profile)
            for profile in self.bundle.child_profiles
            if profile["role"] == "reader"
        )
        profile["disabledFeatures"].append("unexpected-feature")
        with self.assertRaisesRegex(ChildLaunchV2Error, "PROFILE_FINGERPRINT_MISMATCH"):
            prepare_child_launch_v2(
                executable=self.executable,
                snapshot_sha256=hashlib.sha256(
                    self.executable.read_bytes()
                ).hexdigest(),
                snapshot_identity_fingerprint="a" * 64,
                pair=dict(self.bundle.policy_pairs[0]),
                allowed_pairs=self.bundle.policy_pairs,
                runtime=self._runtime(),
                snapshot_root=self.snapshot_root,
                output_schema=self.schema,
                profile=profile,
                profile_domain=self.bundle.child_profile_domain,
                expected_profile_fingerprint=self.bundle.child_profile_fingerprints[
                    "reader"
                ],
                domains=ChildProfileDomainsV1(
                    argv=self.bundle.child_argv_domain,
                    environment=self.bundle.child_environment_domain,
                    secret=self.bundle.child_secret_domain,
                ),
                compatibility_fingerprint="b" * 64,
                account_context_fingerprint="c" * 64,
                expected_cli_version="0.107.0-test",
                attempt_resource=_AttemptResource(),
                auth_file=self.auth_file,
                prompt="Проверь договор.",
            )

    def test_rejects_changed_snapshot_before_staging_auth(self) -> None:
        with self.assertRaisesRegex(ChildLaunchV2Error, "SNAPSHOT_SHA256_MISMATCH"):
            self._prepare(snapshot_sha256="0" * 64)

        self.assertEqual([], list(self.root.glob("runtime-*/codex-home/auth.json")))

    def test_runtime_module_contains_no_model_name_literal(self) -> None:
        source = (
            PLUGIN_SRC / "codex_smart_subagents" / "child_launch_v2.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("gpt-", source)


if __name__ == "__main__":
    unittest.main()

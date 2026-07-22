from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = ROOT / "plugins" / "codex-smart-subagents"
PLUGIN_SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    GatewayRuntimeBindingV2,
)
from codex_smart_subagents.controller_entrypoint_v2 import (  # noqa: E402
    ControllerEntrypointConfigV2,
)
from codex_smart_subagents.policy_bundle_v2 import (  # noqa: E402
    load_policy_bundle_v2,
)
from codex_smart_subagents.live_canary import ManagedConfigState  # noqa: E402
from codex_smart_subagents.production_composition_v2 import (  # noqa: E402
    ProductionCompositionV2Error,
    build_default_production_dispatcher_dependencies_v2,
)
from codex_smart_subagents.snapshot import SnapshotBuilder  # noqa: E402
from codex_smart_subagents.state_store_v2 import SmartStoreV2  # noqa: E402
from codex_smart_subagents.writer_publication_v2 import (  # noqa: E402
    WriterPublicationCoordinatorV2,
)


class _Inspector:
    def inspect(self, *_args: object, **_kwargs: object) -> object:
        return ManagedConfigState(
            sha256="9" * 64,
            legacy_sandbox_mode=False,
        )


class ProductionCompositionV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="pcv2-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        auth = self.codex_home / "auth.json"
        auth.write_text('{"token":"fixture"}\n', encoding="utf-8")
        auth.chmod(0o600)
        self.state_home = self.codex_home / "state" / "codex-smart-subagents-v2"
        self.state_home.mkdir(parents=True, mode=0o700)
        self.database = self.state_home / "state.sqlite3"
        self.database.touch(mode=0o600)
        self.codex = self.root / "codex"
        self.codex.write_bytes(b"codex-snapshot-v2")
        self.codex.chmod(0o500)
        self.wrapper = self.root / "codex-smart"
        self.wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
        self.wrapper.chmod(0o500)
        digest = hashlib.sha256(self.codex.read_bytes()).hexdigest()
        activation_fingerprint = "a" * 64
        activation_id = "act2_" + activation_fingerprint
        compatibility = "b" * 64
        self.binding = GatewayRuntimeBindingV2(
            activation_id=activation_id,
            activation_fingerprint=activation_fingerprint,
            compatibility_fingerprint=compatibility,
            control_epoch=3,
            state_home=self.state_home,
            marketplace_path=ROOT,
            database_path=self.database,
            database_identity_row={
                "activation_id": activation_id,
                "activation_fingerprint": activation_fingerprint,
            },
            controller_row={
                "controller_identity": "controller-v2",
                "controller_pid": os.getpid(),
                "controller_process_start_marker": "start-v2",
                "activation_id": activation_id,
                "activation_fingerprint": activation_fingerprint,
                "compatibility_fingerprint": compatibility,
                "control_epoch": 3,
            },
            interface_evidence={
                "subject": {
                    "snapshotPath": str(self.codex),
                    "snapshotSha256": digest,
                    "version": "codex-cli 0.144.6",
                }
            },
            activation_identity={
                "codexSnapshot": {
                    "absolutePath": str(self.codex),
                    "sha256": digest,
                }
            },
        )
        self.config = ControllerEntrypointConfigV2(
            source_root=ROOT,
            plugin_root=PLUGIN_ROOT,
            codex_home=self.codex_home,
            state_home=self.state_home,
            codex_binary=self.codex,
            wrapper=self.wrapper,
            environment={"CODEX_HOME": str(self.codex_home)},
        )
        self.bundle = load_policy_bundle_v2(
            catalog_path=ROOT / ".codex" / "adaptive-subagents.toml",
            routing_vector_path=ROOT / "docs/contracts/vectors/routing-policy-v2.json",
            delegation_vector_path=(
                ROOT / "docs/contracts/vectors/delegation-policy-v2.json"
            ),
            role_vector_path=ROOT / "docs/contracts/vectors/role-template-v1.json",
            child_profile_vector_path=(
                ROOT / "docs/contracts/vectors/child-profile-v1.json"
            ),
        )
        self.decision = SimpleNamespace(state="READY", runtime_binding=self.binding)

    def test_ready_binding_builds_every_required_production_dependency(self) -> None:
        dependencies = build_default_production_dispatcher_dependencies_v2(
            config=self.config,
            policy_bundle=self.bundle,
            launch_decision=self.decision,
            managed_config_inspector_factory=lambda **_kwargs: _Inspector(),
        )

        self.assertEqual(
            dict(self.bundle.result_schema_resolution),
            dict(
                dependencies.result_schema_resolution_provider(
                    self.binding,
                    self.bundle,
                )
            ),
        )
        self.assertIsInstance(
            dependencies.bounded_snapshot_builder_factory(self._snapshot_limits()),
            SnapshotBuilder,
        )
        self.assertIsNotNone(
            dependencies.writer_publication_coordinator_factory,
        )
        self.assertIsNotNone(dependencies.writer_validation_commands_provider)
        assert dependencies.writer_validation_commands_provider is not None
        self.assertEqual(
            self.bundle.validation_commands["writer-validation-v2"],
            dependencies.writer_validation_commands_provider(
                SimpleNamespace(
                    node=SimpleNamespace(
                        validation_profile_id="writer-validation-v2",
                    )
                ),
                self.bundle,
            ),
        )
        assert dependencies.writer_publication_coordinator_factory is not None
        coordinator = dependencies.writer_publication_coordinator_factory(
            store=SmartStoreV2.__new__(SmartStoreV2),
            binding=self.binding,
            policy_bundle=self.bundle,
            environment={"CODEX_HOME": str(self.codex_home)},
            snapshot_builder=dependencies.bounded_snapshot_builder_factory(
                self._snapshot_limits()
            ),
        )
        self.assertIsInstance(coordinator, WriterPublicationCoordinatorV2)
        self.assertEqual(
            "9" * 64,
            coordinator.validation_runner.expected_managed_config_sha256,
        )
        second = build_default_production_dispatcher_dependencies_v2(
            config=self.config,
            policy_bundle=self.bundle,
            launch_decision=self.decision,
            managed_config_inspector_factory=lambda **_kwargs: _Inspector(),
        )
        self.assertIs(dependencies.launch_barrier, second.launch_barrier)

    def test_ordinary_decision_is_rejected_before_dependencies_are_created(
        self,
    ) -> None:
        with self.assertRaisesRegex(ProductionCompositionV2Error, "not READY"):
            build_default_production_dispatcher_dependencies_v2(
                config=self.config,
                policy_bundle=self.bundle,
                launch_decision=SimpleNamespace(
                    state="ORDINARY",
                    runtime_binding=None,
                ),
                managed_config_inspector_factory=lambda **_kwargs: _Inspector(),
            )

        self.assertFalse((self.state_home / "permission-canary-v2").exists())

    def test_equivalent_reloaded_policy_bundle_keeps_schema_resolution_bound(
        self,
    ) -> None:
        dependencies = build_default_production_dispatcher_dependencies_v2(
            config=self.config,
            policy_bundle=self.bundle,
            launch_decision=self.decision,
            managed_config_inspector_factory=lambda **_kwargs: _Inspector(),
        )
        vectors = ROOT / "docs" / "contracts" / "vectors"
        reloaded = load_policy_bundle_v2(
            catalog_path=ROOT / ".codex" / "adaptive-subagents.toml",
            routing_vector_path=vectors / "routing-policy-v2.json",
            delegation_vector_path=vectors / "delegation-policy-v2.json",
            role_vector_path=vectors / "role-template-v1.json",
            child_profile_vector_path=vectors / "child-profile-v1.json",
        )

        self.assertIsNot(self.bundle.router, reloaded.router)
        self.assertEqual(self.bundle.bundle_fingerprint, reloaded.bundle_fingerprint)
        self.assertEqual(
            dict(reloaded.result_schema_resolution),
            dependencies.result_schema_resolution_provider(self.binding, reloaded),
        )

    def _snapshot_limits(self):
        from codex_smart_subagents.snapshot import SnapshotLimits

        return SnapshotLimits(
            max_files=10,
            max_file_bytes=1024,
            max_total_bytes=4096,
        )


if __name__ == "__main__":
    unittest.main()

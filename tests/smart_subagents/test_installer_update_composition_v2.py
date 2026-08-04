from __future__ import annotations

import hashlib
import sys
import json
import os
import socket
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.installer_update_composition_v2 import (  # noqa: E402
    InstallerUpdateCompositionV2,
    InstallerUpdateCompositionV2Error,
    InstallerUpdateRecoveryEvidenceV2,
    LauncherBindingV2,
    RegistryRuntimeBindingsV2,
    RegistryUpdatePlanV2,
    UpdateSourceBindingV2,
    build_launcher_step_definition_v2,
    build_launcher_step_port_v2,
    build_launcher_update_plan_v2,
    build_controller_shutdown_constraint_v2,
    build_candidate_spawn_action_v2,
    build_registry_step_definitions_v2,
    build_registry_step_ports_v2,
    build_registry_update_plan_v2,
    build_shutdown_socket_cleanup_step_definition_v2,
    build_shutdown_socket_cleanup_step_port_v2,
    build_update_matched_active_definition_v2,
    build_update_matched_active_composition_v2,
    load_update_matched_active_recovery_evidence_v2,
    recover_update_matched_active_composition_v2,
    verify_update_source_binding_v2,
    _wrap_completed_port_with_candidate_successor_v2,
)
from codex_smart_subagents.lifecycle_operation_v2 import ProjectionV2  # noqa: E402
from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    _LIFECYCLE_SCHEMA_SHA256,
)
from codex_smart_subagents.canonical_json import domain_fingerprint  # noqa: E402
from codex_smart_subagents.activation_preparation_v2 import (  # noqa: E402
    ActivationPreparationExecutorV2,
)
from codex_smart_subagents.installer_upgrade_v2 import (  # noqa: E402
    build_upgrade_preparation_v2,
)
from codex_smart_subagents.installer_update_controller_ports_v2 import (  # noqa: E402
    observe_controller_database_state_v2,
)
from tests.smart_subagents.test_installer_entrypoint_v2 import (  # noqa: E402
    _load_installer,
)
from codex_smart_subagents.candidate_ready_channel_v2 import (  # noqa: E402
    CandidateReadyReconnectV2,
    CandidateReadyChannelV2Error,
)
from codex_smart_subagents.installer_update_operation_v2 import (  # noqa: E402
    UpdateStepPortV2,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    OperationExecutorV2,
    OperationJournalStoreV2,
    StepDefinitionV2,
    build_operation_journal_validator_v2,
)
from codex_smart_subagents.lifecycle_plan_v2 import (  # noqa: E402
    LifecyclePlanRegistryV2,
)


class InstallerUpdateCompositionSourceBindingV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.codex_sha256 = "a" * 64
        self.source_digest = "b" * 64
        self.receipt = SimpleNamespace(
            activation_intent=SimpleNamespace(
                source_locator={"sourceObservedSha256": self.codex_sha256}
            )
        )
        self.preparation = SimpleNamespace(
            prepared_manifest_plan=SimpleNamespace(
                manifest_document={
                    "extensions": {"installerSourceDigest": self.source_digest}
                }
            )
        )

    def test_changed_source_digest_is_rejected_before_composition(self) -> None:
        binding = UpdateSourceBindingV2(
            expected_source_digest=self.source_digest,
            expected_codex_sha256=self.codex_sha256,
            observe_source_digest=lambda: "c" * 64,
        )

        with self.assertRaises(InstallerUpdateCompositionV2Error) as caught:
            verify_update_source_binding_v2(
                binding=binding,
                preparation=self.preparation,
                preparation_receipt=self.receipt,
            )

        self.assertEqual("UPDATE_SOURCE_CHANGED", caught.exception.code)

    def test_changed_codex_snapshot_is_rejected_before_composition(self) -> None:
        binding = UpdateSourceBindingV2(
            expected_source_digest=self.source_digest,
            expected_codex_sha256="d" * 64,
            observe_source_digest=lambda: self.source_digest,
        )

        with self.assertRaises(InstallerUpdateCompositionV2Error) as caught:
            verify_update_source_binding_v2(
                binding=binding,
                preparation=self.preparation,
                preparation_receipt=self.receipt,
            )

        self.assertEqual("UPDATE_CODEX_SNAPSHOT_CHANGED", caught.exception.code)

    def test_exact_source_binding_is_returned(self) -> None:
        binding = UpdateSourceBindingV2(
            expected_source_digest=self.source_digest,
            expected_codex_sha256=self.codex_sha256,
            observe_source_digest=lambda: self.source_digest,
        )

        self.assertEqual(
            binding,
            verify_update_source_binding_v2(
                binding=binding,
                preparation=self.preparation,
                preparation_receipt=self.receipt,
            ),
        )

    def test_binding_not_equal_to_prepared_manifest_source_is_rejected(self) -> None:
        binding = UpdateSourceBindingV2(
            expected_source_digest="c" * 64,
            expected_codex_sha256=self.codex_sha256,
            observe_source_digest=lambda: "c" * 64,
        )

        with self.assertRaises(InstallerUpdateCompositionV2Error) as caught:
            verify_update_source_binding_v2(
                binding=binding,
                preparation=self.preparation,
                preparation_receipt=self.receipt,
            )

        self.assertEqual("UPDATE_PREPARED_SOURCE_MISMATCH", caught.exception.code)


class CompletedPortCandidateSuccessorV2Tests(unittest.TestCase):
    @staticmethod
    def _projection(schema_id: str, token: str) -> ProjectionV2:
        return ProjectionV2(
            schema_id=schema_id,
            schema_sha256=token * 64,
            value={"token": token},
            value_fingerprint=token * 64,
        )

    @staticmethod
    def _definition(
        kind: str,
        before: ProjectionV2,
        after: ProjectionV2,
    ) -> StepDefinitionV2:
        return StepDefinitionV2(
            kind=kind,
            command_id=None,
            action={"actionKind": "test"},
            before=before,
            expected_after=after,
        )

    def test_registered_candidate_is_a_proved_successor_of_completed_step(
        self,
    ) -> None:
        historical_before = self._projection("history-v2", "1")
        historical_after = self._projection("history-v2", "2")
        candidate_before = self._projection("candidate-v2", "3")
        candidate_after = self._projection("candidate-v2", "4")
        accepted_after = self._projection("controller-v2", "5")
        historical = self._definition(
            "controller_shutdown", historical_before, historical_after
        )
        candidate = self._definition(
            "controller_candidate_spawn", candidate_before, candidate_after
        )
        accept = self._definition(
            "controller_accept", candidate_after, accepted_after
        )
        base_observations: list[str] = []
        base = UpdateStepPortV2(
            observe=lambda _definition: (
                base_observations.append("base") or historical_after
            ),
            apply=lambda _definition: None,
        )
        candidate_port = UpdateStepPortV2(
            observe=lambda _definition: candidate_after,
            apply=lambda _definition: None,
        )
        accept_port = UpdateStepPortV2(
            observe=lambda _definition: accepted_after,
            apply=lambda _definition: None,
        )
        wrapped = _wrap_completed_port_with_candidate_successor_v2(
            port=base,
            candidate_port=candidate_port,
            candidate_definition=candidate,
            accept_port=accept_port,
            accept_definition=accept,
        )

        observed = wrapped.observe(historical)

        self.assertEqual(candidate_after, observed)
        self.assertEqual([], base_observations)
        self.assertTrue(
            wrapped.completed_current_matches(
                historical_after,
                observed,
                historical,
            )
        )

    def test_accept_receipt_bridges_closed_candidate_ready_channel(self) -> None:
        historical_before = self._projection("history-v2", "1")
        historical_after = self._projection("history-v2", "2")
        candidate_before = self._projection("candidate-v2", "3")
        candidate_after = self._projection("candidate-v2", "4")
        accepted_after = self._projection("controller-v2", "5")
        historical = self._definition(
            "shutdown_socket_cleanup", historical_before, historical_after
        )
        candidate = self._definition(
            "controller_candidate_spawn", candidate_before, candidate_after
        )
        accept = self._definition(
            "controller_accept", candidate_after, accepted_after
        )

        def closed_ready(_definition):
            raise CandidateReadyChannelV2Error(
                "CANDIDATE_SPAWN_COMPLETED_UNOBSERVABLE",
                "канал закрыт после принятия",
            )

        wrapped = _wrap_completed_port_with_candidate_successor_v2(
            port=UpdateStepPortV2(
                observe=lambda _definition: historical_after,
                apply=lambda _definition: None,
            ),
            candidate_port=UpdateStepPortV2(
                observe=closed_ready,
                apply=lambda _definition: None,
            ),
            candidate_definition=candidate,
            accept_port=UpdateStepPortV2(
                observe=lambda _definition: accepted_after,
                apply=lambda _definition: None,
            ),
            accept_definition=accept,
        )

        observed = wrapped.observe(historical)

        self.assertEqual(accepted_after, observed)
        self.assertTrue(
            wrapped.completed_current_matches(
                historical_after,
                observed,
                historical,
            )
        )

    def test_no_candidate_effect_falls_back_to_original_observation(self) -> None:
        historical_before = self._projection("history-v2", "1")
        historical_after = self._projection("history-v2", "2")
        candidate_before = self._projection("candidate-v2", "3")
        candidate_after = self._projection("candidate-v2", "4")
        accepted_after = self._projection("controller-v2", "5")
        historical = self._definition(
            "controller_shutdown", historical_before, historical_after
        )
        candidate = self._definition(
            "controller_candidate_spawn", candidate_before, candidate_after
        )
        accept = self._definition(
            "controller_accept", candidate_after, accepted_after
        )
        wrapped = _wrap_completed_port_with_candidate_successor_v2(
            port=UpdateStepPortV2(
                observe=lambda _definition: historical_after,
                apply=lambda _definition: None,
            ),
            candidate_port=UpdateStepPortV2(
                observe=lambda _definition: candidate_before,
                apply=lambda _definition: None,
            ),
            candidate_definition=candidate,
            accept_port=UpdateStepPortV2(
                observe=lambda _definition: self.fail(
                    "accept port must not be observed"
                ),
                apply=lambda _definition: None,
            ),
            accept_definition=accept,
        )

        observed = wrapped.observe(historical)

        self.assertEqual(historical_after, observed)
        self.assertTrue(
            wrapped.completed_current_matches(
                historical_after,
                observed,
                historical,
            )
        )

    def test_unrelated_candidate_error_is_not_hidden(self) -> None:
        historical_before = self._projection("history-v2", "1")
        historical_after = self._projection("history-v2", "2")
        candidate_before = self._projection("candidate-v2", "3")
        candidate_after = self._projection("candidate-v2", "4")
        accepted_after = self._projection("controller-v2", "5")
        historical = self._definition(
            "controller_shutdown", historical_before, historical_after
        )
        candidate = self._definition(
            "controller_candidate_spawn", candidate_before, candidate_after
        )
        accept = self._definition(
            "controller_accept", candidate_after, accepted_after
        )

        def broken_candidate(_definition):
            raise CandidateReadyChannelV2Error(
                "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
                "историческая квитанция повреждена",
            )

        wrapped = _wrap_completed_port_with_candidate_successor_v2(
            port=UpdateStepPortV2(
                observe=lambda _definition: historical_after,
                apply=lambda _definition: None,
            ),
            candidate_port=UpdateStepPortV2(
                observe=broken_candidate,
                apply=lambda _definition: None,
            ),
            candidate_definition=candidate,
            accept_port=UpdateStepPortV2(
                observe=lambda _definition: accepted_after,
                apply=lambda _definition: None,
            ),
            accept_definition=accept,
        )

        with self.assertRaises(CandidateReadyChannelV2Error) as raised:
            wrapped.observe(historical)
        self.assertEqual(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            raised.exception.code,
        )

    def test_untyped_lookalike_candidate_error_is_not_hidden(self) -> None:
        historical_before = self._projection("history-v2", "1")
        historical_after = self._projection("history-v2", "2")
        candidate_before = self._projection("candidate-v2", "3")
        candidate_after = self._projection("candidate-v2", "4")
        accepted_after = self._projection("controller-v2", "5")
        historical = self._definition(
            "controller_shutdown", historical_before, historical_after
        )
        candidate = self._definition(
            "controller_candidate_spawn", candidate_before, candidate_after
        )
        accept = self._definition(
            "controller_accept", candidate_after, accepted_after
        )

        class LookalikeError(RuntimeError):
            code = "CANDIDATE_SPAWN_COMPLETED_UNOBSERVABLE"

        def broken_candidate(_definition):
            raise LookalikeError("не типизированная ошибка")

        wrapped = _wrap_completed_port_with_candidate_successor_v2(
            port=UpdateStepPortV2(
                observe=lambda _definition: historical_after,
                apply=lambda _definition: None,
            ),
            candidate_port=UpdateStepPortV2(
                observe=broken_candidate,
                apply=lambda _definition: None,
            ),
            candidate_definition=candidate,
            accept_port=UpdateStepPortV2(
                observe=lambda _definition: self.fail(
                    "accept port must not be observed"
                ),
                apply=lambda _definition: None,
            ),
            accept_definition=accept,
        )

        with self.assertRaises(LookalikeError):
            wrapped.observe(historical)

    def test_closed_ready_requires_completed_accept_effect(self) -> None:
        historical_before = self._projection("history-v2", "1")
        historical_after = self._projection("history-v2", "2")
        candidate_before = self._projection("candidate-v2", "3")
        candidate_after = self._projection("candidate-v2", "4")
        accepted_after = self._projection("controller-v2", "5")
        historical = self._definition(
            "shutdown_socket_cleanup", historical_before, historical_after
        )
        candidate = self._definition(
            "controller_candidate_spawn", candidate_before, candidate_after
        )
        accept = self._definition(
            "controller_accept", candidate_after, accepted_after
        )

        def closed_ready(_definition):
            raise CandidateReadyChannelV2Error(
                "CANDIDATE_SPAWN_COMPLETED_UNOBSERVABLE",
                "канал закрыт после принятия",
            )

        wrapped = _wrap_completed_port_with_candidate_successor_v2(
            port=UpdateStepPortV2(
                observe=lambda _definition: historical_after,
                apply=lambda _definition: None,
            ),
            candidate_port=UpdateStepPortV2(
                observe=closed_ready,
                apply=lambda _definition: None,
            ),
            candidate_definition=candidate,
            accept_port=UpdateStepPortV2(
                observe=lambda _definition: candidate_after,
                apply=lambda _definition: None,
            ),
            accept_definition=accept,
        )

        with self.assertRaises(InstallerUpdateCompositionV2Error) as raised:
            wrapped.observe(historical)
        self.assertEqual("CANDIDATE_SUCCESSOR_INVALID", raised.exception.code)

    def test_completed_match_rejects_changed_successor(self) -> None:
        historical_before = self._projection("history-v2", "1")
        historical_after = self._projection("history-v2", "2")
        candidate_before = self._projection("candidate-v2", "3")
        candidate_after = self._projection("candidate-v2", "4")
        changed_candidate = self._projection("candidate-v2", "6")
        accepted_after = self._projection("controller-v2", "5")
        historical = self._definition(
            "controller_shutdown", historical_before, historical_after
        )
        candidate = self._definition(
            "controller_candidate_spawn", candidate_before, candidate_after
        )
        accept = self._definition(
            "controller_accept", candidate_after, accepted_after
        )
        observations = iter((candidate_after, changed_candidate))
        wrapped = _wrap_completed_port_with_candidate_successor_v2(
            port=UpdateStepPortV2(
                observe=lambda _definition: historical_after,
                apply=lambda _definition: None,
            ),
            candidate_port=UpdateStepPortV2(
                observe=lambda _definition: next(observations),
                apply=lambda _definition: None,
                matches_after=lambda _observed, _definition: True,
            ),
            candidate_definition=candidate,
            accept_port=UpdateStepPortV2(
                observe=lambda _definition: accepted_after,
                apply=lambda _definition: None,
            ),
            accept_definition=accept,
        )

        current = wrapped.observe(historical)

        self.assertEqual(candidate_after, current)
        self.assertFalse(
            wrapped.completed_current_matches(
                historical_after,
                current,
                historical,
            )
        )


class _RegistryCodexV2:
    def __init__(self, *, root: Path) -> None:
        self.root = root
        self.old_marketplace = root / "old-marketplace"
        self.new_marketplace = root / "new-marketplace"
        self.old_marketplace.mkdir(mode=0o700)
        self.new_marketplace.mkdir(mode=0o700)
        self.plugin_relative = Path("plugins/codex-smart-subagents")
        (self.old_marketplace / self.plugin_relative).mkdir(parents=True, mode=0o700)
        (self.new_marketplace / self.plugin_relative).mkdir(parents=True, mode=0o700)
        self.marketplace: Path | None = self.old_marketplace
        self.plugin_enabled = True
        self.calls: list[tuple[tuple[str, ...], Path, dict[str, str], int]] = []

    def write_config(self, codex_home: Path) -> None:
        marketplace = (
            ""
            if self.marketplace is None
            else "[marketplaces.codex-settings-adaptive]\n"
        )
        plugin = (
            ""
            if not self.plugin_enabled
            else (
                '[plugins."codex-smart-subagents@codex-settings-adaptive"]\n'
                "enabled = true\n"
            )
        )
        path = codex_home / "config.toml"
        path.write_text("unrelated = 7\n" + marketplace + plugin, encoding="utf-8")
        path.chmod(0o600)

    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout_ms: int,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, cwd, dict(env), timeout_ms))
        command = argv[1:]
        if command == ("plugin", "marketplace", "list", "--json"):
            marketplaces = []
            if self.marketplace is not None:
                path = str(self.marketplace)
                marketplaces.append(
                    {
                        "name": "codex-settings-adaptive",
                        "root": path,
                        "marketplaceSource": {
                            "sourceType": "local",
                            "source": path,
                        },
                    }
                )
            stdout = json.dumps({"marketplaces": marketplaces})
        elif command == ("plugin", "list", "--json"):
            installed = []
            if self.plugin_enabled and self.marketplace is not None:
                marketplace = str(self.marketplace)
                installed.append(
                    {
                        "pluginId": "codex-smart-subagents@codex-settings-adaptive",
                        "name": "codex-smart-subagents",
                        "marketplaceName": "codex-settings-adaptive",
                        "version": "0.2.0",
                        "installed": True,
                        "enabled": True,
                        "source": {
                            "source": "local",
                            "path": str(self.marketplace / self.plugin_relative),
                        },
                        "marketplaceSource": {
                            "sourceType": "local",
                            "source": marketplace,
                        },
                        "installPolicy": "AVAILABLE",
                        "authPolicy": "ON_INSTALL",
                    }
                )
            stdout = json.dumps({"installed": installed, "available": []})
        elif command == (
            "plugin",
            "remove",
            "codex-smart-subagents@codex-settings-adaptive",
        ):
            self.plugin_enabled = False
            self.write_config(Path(env["CODEX_HOME"]))
            stdout = json.dumps({"removed": True})
        elif command == (
            "plugin",
            "marketplace",
            "remove",
            "codex-settings-adaptive",
        ):
            self.marketplace = None
            self.write_config(Path(env["CODEX_HOME"]))
            stdout = json.dumps({"removed": True})
        elif command[:3] == ("plugin", "marketplace", "add"):
            self.marketplace = Path(command[3]).resolve(strict=True)
            self.write_config(Path(env["CODEX_HOME"]))
            stdout = json.dumps({"name": "codex-settings-adaptive"})
        elif command == (
            "plugin",
            "add",
            "codex-smart-subagents@codex-settings-adaptive",
        ):
            self.plugin_enabled = True
            self.write_config(Path(env["CODEX_HOME"]))
            stdout = json.dumps({"installed": True})
        else:  # pragma: no cover - сообщение облегчает разбор регрессии
            return subprocess.CompletedProcess(argv, 64, "", "unexpected command")
        return subprocess.CompletedProcess(argv, 0, stdout, "")


def _fixture_source_digest_v2(fixture) -> str:
    installer = _load_installer()
    return installer._source_digest(
        installer.InstallLayout(
            source_root=ROOT,
            codex_home=fixture.codex_home,
            bin_dir=fixture.operator_bin,
            codex_binary=fixture.codex_binary,
            state_home=fixture.binding.state_home,
        )
    )


def _build_fresh_composition_inputs_v2(fixture) -> SimpleNamespace:
    """Create one complete fresh-update boundary for mutation tests."""

    proof = fixture.capture()
    operation_id = "op2_" + "9" * 32
    source_digest = _fixture_source_digest_v2(fixture)
    preparation = build_upgrade_preparation_v2(
        proof=proof,
        operation_id=operation_id,
        source_root=ROOT,
        codex_binary=fixture.codex_binary,
        policy_bundle=fixture.policy,
        snapshotter=fixture.snapshotter,
        interface_executor=fixture.interface_executor,
        source_digest=source_digest,
    )
    receipt = ActivationPreparationExecutorV2(
        definition=preparation.definition,
        callbacks=preparation.callbacks,
    ).execute()
    fake = object.__new__(_RegistryCodexV2)
    fake.root = fixture.root
    fake.old_marketplace = proof.activation_dir / "marketplace"
    fake.new_marketplace = receipt.activation_intent.activation_dir / "marketplace"
    fake.plugin_relative = Path("plugins/codex-smart-subagents")
    fake.marketplace = fake.old_marketplace
    fake.plugin_enabled = True
    fake.calls = []
    fake.write_config(fixture.codex_home)
    registry_plan = build_registry_update_plan_v2(
        installation_id=proof.installation_id,
        operation_id=operation_id,
        codex_binary=receipt.activation_intent.snapshot_path,
        codex_home=fixture.codex_home,
        working_directory=fixture.root,
        marketplace_path=proof.layout.marketplace_link,
        previous_registered_marketplace_path=fake.old_marketplace,
        registered_marketplace_path=fake.new_marketplace,
        plugin_relative_path=fake.plugin_relative,
        plugin_version="0.2.0",
        install_policy="AVAILABLE",
        auth_policy="ON_INSTALL",
        receipt_directory=proof.layout.receipts_root / proof.installation_id,
        command_runner=fake,
    )
    links = proof.installer_receipt_document["links"]
    launcher_plan = build_launcher_update_plan_v2(
        installation_id=proof.installation_id,
        operation_id=operation_id,
        bindings=tuple(
            LauncherBindingV2(
                name=Path(item["path"]).name,
                role=(
                    "gateway"
                    if Path(item["path"]).name == "codex-smart"
                    else "admin"
                ),
                path=Path(item["path"]),
                target=Path(item["target"]),
                expected_resolved_target=(
                    fake.new_marketplace
                    / fake.plugin_relative
                    / "bin"
                    / Path(item["path"]).name
                ),
            )
            for item in links
        ),
    )
    readiness_token = "candidate-secret-for-test-00000000"
    candidate_action = build_candidate_spawn_action_v2(
        preparation_receipt=receipt,
        readiness_token=readiness_token,
        interpreter=Path(sys.executable),
        server_entrypoint=(
            receipt.activation_intent.activation_dir
            / "marketplace/plugins/codex-smart-subagents/controller/server.py"
        ),
        private_ready_channel_path=(
            receipt.activation_intent.state_home / "candidate-test.ready.sock"
        ),
        readiness_window_ms=30_000,
    )
    automaton = json.loads(
        (ROOT / "docs/contracts/vectors/lifecycle-v2.json").read_text(
            encoding="utf-8"
        )
    )["fixtures"]["automaton"]
    registry = LifecyclePlanRegistryV2.from_document(automaton)
    return SimpleNamespace(
        proof=proof,
        operation_id=operation_id,
        preparation=preparation,
        receipt=receipt,
        fake=fake,
        registry_plan=registry_plan,
        launcher_plan=launcher_plan,
        candidate_action=candidate_action,
        readiness_token=readiness_token,
        wrapper_path=(
            receipt.activation_intent.activation_dir
            / "marketplace/plugins/codex-smart-subagents/bin/codex-smart"
        ),
        registry=registry,
        source_digest=source_digest,
        source_binding=UpdateSourceBindingV2(
            expected_source_digest=source_digest,
            expected_codex_sha256=receipt.activation_intent.source_locator[
                "sourceObservedSha256"
            ],
            observe_source_digest=lambda: source_digest,
        ),
    )


class InstallerUpdateCrossPlanBindingV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.smart_subagents.test_activation_transition_v2 import (
            ActivationTransitionV2Tests,
        )

        self.fixture = ActivationTransitionV2Tests(methodName="runTest")
        self.fixture.setUp()
        self.inputs = _build_fresh_composition_inputs_v2(self.fixture)

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def test_candidate_action_persists_readiness_window_not_build_time(self) -> None:
        document = self.inputs.candidate_action.to_document()

        self.assertEqual(30_000, document["readinessWindowMs"])
        self.assertNotIn("absoluteDeadlineMonotonicMs", document)

    def _build(self, **changes: object) -> InstallerUpdateCompositionV2:
        arguments = {
            "registry": self.inputs.registry,
            "proof": self.inputs.proof,
            "preparation": self.inputs.preparation,
            "preparation_receipt": self.inputs.receipt,
            "source_binding": self.inputs.source_binding,
            "registry_plan": self.inputs.registry_plan,
            "launcher_plan": self.inputs.launcher_plan,
            "candidate_action": self.inputs.candidate_action,
            "readiness_token": self.inputs.readiness_token,
            "wrapper_path": self.inputs.wrapper_path,
            "schema_directory": ROOT / "docs/contracts/schemas",
        }
        arguments.update(changes)
        return build_update_matched_active_composition_v2(**arguments)

    def _assert_rejected_without_durable_effect(
        self,
        code: str,
        **changes: object,
    ) -> None:
        authorization_path = (
            self.inputs.proof.layout.receipts_root
            / self.inputs.proof.installation_id
            / (
                f"{self.inputs.operation_id}."
                "candidate-spawn.authorization.json"
            )
        )

        with self.assertRaises(InstallerUpdateCompositionV2Error) as caught:
            self._build(**changes)

        self.assertEqual(code, caught.exception.code)
        self.assertFalse(authorization_path.exists())
        self.assertFalse(self.inputs.proof.layout.journal_path.exists())

    def test_registry_plan_mutations_are_rejected_before_authorization(self) -> None:
        foreign_home = self.fixture.root / "foreign-codex-home"
        foreign_home.mkdir(mode=0o700)
        foreign_binary = self.fixture.root / "foreign-codex"
        foreign_binary.write_text("#!/bin/sh\n# foreign\n", encoding="utf-8")
        foreign_binary.chmod(0o700)
        foreign_marketplace = self.fixture.root / "foreign-marketplace-link"
        foreign_marketplace.symlink_to(self.inputs.fake.old_marketplace)
        foreign_old = self.fixture.root / "foreign-old-marketplace"
        foreign_new = self.fixture.root / "foreign-new-marketplace"
        for directory in (foreign_old, foreign_new):
            (directory / self.inputs.fake.plugin_relative).mkdir(
                parents=True,
                mode=0o700,
            )
        foreign_receipts = self.fixture.root / "foreign-receipts"
        foreign_receipts.mkdir(mode=0o700)
        mutations = {
            "codex_home": {"codex_home": foreign_home},
            "codex_binary": {"codex_binary": foreign_binary},
            "marketplace_path": {"marketplace_path": foreign_marketplace},
            "previous_marketplace": {
                "previous_registered_marketplace_path": foreign_old
            },
            "candidate_marketplace": {
                "registered_marketplace_path": foreign_new
            },
            "receipt_directory": {"receipt_directory": foreign_receipts},
            "installation_id": {"installation_id": "ins2_" + "e" * 32},
            "operation_id": {"operation_id": "op2_" + "e" * 32},
        }
        for name, changes in mutations.items():
            with self.subTest(name=name):
                plan = replace(self.inputs.registry_plan, **changes)
                self._assert_rejected_without_durable_effect(
                    "UPDATE_REGISTRY_BINDING_INVALID",
                    registry_plan=plan,
                )

    def test_changed_codex_snapshot_is_rejected_before_authorization(self) -> None:
        snapshot = self.inputs.receipt.activation_intent.snapshot_path
        snapshot.chmod(0o700)
        snapshot.write_bytes(b"#!/bin/sh\n# changed snapshot\n")
        snapshot.chmod(0o500)

        self._assert_rejected_without_durable_effect(
            "UPDATE_REGISTRY_BINDING_INVALID"
        )

    def test_update_cannot_override_maintenance_reason(self) -> None:
        with self.assertRaises(TypeError) as caught:
            self._build(
                controller_port_options={
                    "maintenance_reason_code": "ROLLBACK",
                }
            )

        self.assertIn("maintenance_reason_code", str(caught.exception))

    def test_update_cannot_override_expected_orphan_operation(self) -> None:
        with self.assertRaises(TypeError) as caught:
            self._build(
                controller_port_options={
                    "expected_orphan_operation_id": "op2_" + "0" * 32,
                }
            )

        self.assertIn("expected_orphan_operation_id", str(caught.exception))

    def test_launcher_set_and_roles_are_bound_to_installer_receipt(self) -> None:
        first, second = self.inputs.launcher_plan.bindings
        mutations = {
            "missing_receipt_link": (second,),
            "wrong_role": (replace(first, role="admin"), second),
        }
        for name, bindings in mutations.items():
            with self.subTest(name=name):
                plan = build_launcher_update_plan_v2(
                    installation_id=self.inputs.proof.installation_id,
                    operation_id=self.inputs.operation_id,
                    bindings=bindings,
                )
                self._assert_rejected_without_durable_effect(
                    "UPDATE_LAUNCHER_BINDING_INVALID",
                    launcher_plan=plan,
                )

    def test_launcher_lexical_target_is_bound_to_installer_receipt(self) -> None:
        first, second = self.inputs.launcher_plan.bindings
        foreign_target = self.fixture.root / "foreign-launcher"
        foreign_target.write_text("#!/bin/sh\n", encoding="utf-8")
        foreign_target.chmod(0o500)
        first.path.unlink()
        first.path.symlink_to(foreign_target)
        plan = build_launcher_update_plan_v2(
            installation_id=self.inputs.proof.installation_id,
            operation_id=self.inputs.operation_id,
            bindings=(replace(first, target=foreign_target), second),
        )

        self._assert_rejected_without_durable_effect(
            "UPDATE_LAUNCHER_BINDING_INVALID",
            launcher_plan=plan,
        )

    def test_launcher_candidate_target_is_bound_to_prepared_activation(self) -> None:
        first, second = self.inputs.launcher_plan.bindings
        old_target = first.target.resolve(strict=True)
        plan = build_launcher_update_plan_v2(
            installation_id=self.inputs.proof.installation_id,
            operation_id=self.inputs.operation_id,
            bindings=(
                replace(first, expected_resolved_target=old_target),
                second,
            ),
        )

        self._assert_rejected_without_durable_effect(
            "UPDATE_LAUNCHER_BINDING_INVALID",
            launcher_plan=plan,
        )

    def test_candidate_identity_mutations_are_rejected_before_authorization(
        self,
    ) -> None:
        mutations = {
            "candidate_id": {"candidate_id": "cand2_" + "e" * 32},
            "controller_start_id": {
                "controller_start_id": "cs2_" + "e" * 32
            },
            "operation_id": {"operation_id": "op2_" + "e" * 32},
            "activation_id": {"activation_id": "act2_" + "e" * 64},
            "activation_fingerprint": {"activation_fingerprint": "e" * 64},
            "database_id": {"database_id": "db2_" + "e" * 32},
            "controller_identity": {"controller_identity": "e" * 64},
            "snapshot_fingerprint": {"snapshot_fingerprint": "e" * 64},
            "readiness_token_hash": {"readiness_token_hash": "e" * 64},
        }
        for name, changes in mutations.items():
            with self.subTest(name=name):
                action = replace(self.inputs.candidate_action, **changes)
                self._assert_rejected_without_durable_effect(
                    "UPDATE_CANDIDATE_BINDING_INVALID",
                    candidate_action=action,
                )

    def test_candidate_server_and_argv_are_bound_to_prepared_activation(self) -> None:
        action = build_candidate_spawn_action_v2(
            preparation_receipt=self.inputs.receipt,
            readiness_token=self.inputs.readiness_token,
            interpreter=Path(sys.executable),
            server_entrypoint=(
                ROOT / "plugins/codex-smart-subagents/controller/server.py"
            ),
            private_ready_channel_path=(
                self.inputs.receipt.activation_intent.state_home
                / "candidate-test.ready.sock"
            ),
            readiness_window_ms=30_000,
        )

        self._assert_rejected_without_durable_effect(
            "UPDATE_CANDIDATE_BINDING_INVALID",
            candidate_action=action,
        )

    def test_candidate_ready_path_parent_is_bound_to_state_home(self) -> None:
        foreign_parent = self.fixture.root / "foreign-ready-parent"
        foreign_parent.mkdir(mode=0o700)
        action = build_candidate_spawn_action_v2(
            preparation_receipt=self.inputs.receipt,
            readiness_token=self.inputs.readiness_token,
            interpreter=Path(sys.executable),
            server_entrypoint=(
                self.inputs.receipt.activation_intent.activation_dir
                / "marketplace/plugins/codex-smart-subagents/controller/server.py"
            ),
            private_ready_channel_path=foreign_parent / "candidate.ready.sock",
            readiness_window_ms=30_000,
        )

        self._assert_rejected_without_durable_effect(
            "UPDATE_CANDIDATE_BINDING_INVALID",
            candidate_action=action,
        )

    def test_candidate_raw_token_shape_is_checked_before_authorization(self) -> None:
        action = replace(
            self.inputs.candidate_action,
            readiness_token_hash=hashlib.sha256(b"").hexdigest(),
        )

        self._assert_rejected_without_durable_effect(
            "UPDATE_CANDIDATE_BINDING_INVALID",
            candidate_action=action,
            readiness_token="",
        )

    def test_source_tree_wrapper_is_rejected_before_authorization(self) -> None:
        self._assert_rejected_without_durable_effect(
            "UPDATE_WRAPPER_BINDING_INVALID",
            wrapper_path=(ROOT / "plugins/codex-smart-subagents/bin/codex-smart"),
        )

    def test_candidate_wrapper_mode_is_rechecked_before_authorization(self) -> None:
        self.inputs.wrapper_path.chmod(0o755)

        self._assert_rejected_without_durable_effect(
            "UPDATE_WRAPPER_BINDING_INVALID"
        )

    def test_candidate_wrapper_link_count_is_rechecked_before_authorization(
        self,
    ) -> None:
        os.link(self.inputs.wrapper_path, self.fixture.root / "wrapper-hardlink")

        self._assert_rejected_without_durable_effect(
            "UPDATE_WRAPPER_BINDING_INVALID"
        )


class InstallerUpdateRegistryCompositionV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="csur2-")
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.receipts = self.root / "receipts"
        self.receipts.mkdir(mode=0o700)
        self.codex_binary = self.root / "codex"
        self.codex_binary.write_text("#!/bin/sh\n", encoding="utf-8")
        self.codex_binary.chmod(0o700)
        self.stable_marketplace = self.root / "marketplace-current"
        self.fake = _RegistryCodexV2(root=self.root)
        self.stable_marketplace.symlink_to(self.fake.new_marketplace)
        self.fake.write_config(self.codex_home)
        self.plan = self._plan()
        self.definitions = build_registry_step_definitions_v2(self.plan)
        self.ports = build_registry_step_ports_v2(
            plan=self.plan,
            definitions=self.definitions,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _plan(self, **changes: object) -> RegistryUpdatePlanV2:
        arguments = {
            "installation_id": "ins2_" + "1" * 32,
            "operation_id": "op2_" + "2" * 32,
            "codex_binary": self.codex_binary,
            "codex_home": self.codex_home,
            "working_directory": self.root,
            "marketplace_path": self.stable_marketplace,
            "previous_registered_marketplace_path": self.fake.old_marketplace,
            "registered_marketplace_path": self.fake.new_marketplace,
            "plugin_relative_path": self.fake.plugin_relative,
            "plugin_version": "0.2.0",
            "install_policy": "AVAILABLE",
            "auth_policy": "ON_INSTALL",
            "receipt_directory": self.receipts,
            "command_runner": self.fake,
        }
        arguments.update(changes)
        return build_registry_update_plan_v2(**arguments)

    def test_executes_exact_closed_registry_sequence_and_proves_supersession(
        self,
    ) -> None:
        marketplace = self.definitions["marketplace_registry"]
        plugin = self.definitions["plugin_registry"]

        self.assertEqual(
            marketplace.before, self.ports["marketplace_registry"].observe(marketplace)
        )
        self.ports["marketplace_registry"].apply(marketplace)
        marketplace_after = self.ports["marketplace_registry"].observe(marketplace)
        self.assertTrue(
            self.ports["marketplace_registry"].matches_after(
                marketplace_after, marketplace
            )
        )
        observed_plugin_before = self.ports["plugin_registry"].observe(plugin)
        self.assertTrue(
            self.ports["plugin_registry"].matches_before(observed_plugin_before, plugin)
        )
        self.ports["plugin_registry"].apply(plugin)
        plugin_after = self.ports["plugin_registry"].observe(plugin)

        self.assertTrue(
            self.ports["plugin_registry"].matches_after(plugin_after, plugin)
        )
        self.assertTrue(
            self.ports["marketplace_registry"].completed_current_matches(
                marketplace_after,
                plugin_after,
                marketplace,
            )
        )
        mutations = [call[0][1:] for call in self.fake.calls if "list" not in call[0]]
        self.assertEqual(
            [
                ("plugin", "remove", "codex-smart-subagents@codex-settings-adaptive"),
                ("plugin", "marketplace", "remove", "codex-settings-adaptive"),
                ("plugin", "marketplace", "add", str(self.stable_marketplace)),
                ("plugin", "add", "codex-smart-subagents@codex-settings-adaptive"),
            ],
            mutations,
        )
        expected_environment = {
            "CODEX_HOME": str(self.codex_home),
            "PATH": os.defpath,
            "PYTHONNOUSERSITE": "1",
        }
        self.assertTrue(self.fake.calls)
        self.assertTrue(
            all(
                call[2] == expected_environment and call[3] == 30_000
                for call in self.fake.calls
            )
        )
        for path in self.receipts.iterdir():
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertEqual(
                path.read_bytes(),
                json.dumps(
                    json.loads(path.read_text(encoding="utf-8")),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
            )

    def test_owned_codex_home_mode_0755_is_supported(self) -> None:
        self.codex_home.chmod(0o755)

        plan = self._plan()

        self.assertEqual(self.codex_home, plan.codex_home)

    def test_group_or_other_writable_codex_home_is_rejected(self) -> None:
        for mode in (0o775, 0o757):
            with self.subTest(mode=f"0{mode:o}"):
                self.codex_home.chmod(mode)
                with self.assertRaises(InstallerUpdateCompositionV2Error) as caught:
                    self._plan()
                self.assertEqual("UPDATE_PATH_INVALID", caught.exception.code)

    def test_missing_main_receipt_is_reconciled_from_subcommand_receipts(self) -> None:
        definition = self.definitions["marketplace_registry"]
        port = self.ports["marketplace_registry"]
        port.apply(definition)
        expected = port.observe(definition)
        self.plan.marketplace_receipt_path.unlink()

        observed = port.observe(definition)

        self.assertEqual(expected, observed)
        self.assertTrue(self.plan.marketplace_receipt_path.is_file())

    def test_receipt_from_different_registered_source_is_never_reused(self) -> None:
        marketplace = self.definitions["marketplace_registry"]
        self.ports["marketplace_registry"].apply(marketplace)
        self.ports["marketplace_registry"].observe(marketplace)
        other = self.root / "other-marketplace"
        other.mkdir(mode=0o700)
        (other / self.fake.plugin_relative).mkdir(parents=True, mode=0o700)
        changed_plan = replace(self.plan, registered_marketplace_path=other)
        changed_definitions = build_registry_step_definitions_v2(changed_plan)
        changed_ports = build_registry_step_ports_v2(
            plan=changed_plan,
            definitions=changed_definitions,
        )

        with self.assertRaises(InstallerUpdateCompositionV2Error) as caught:
            changed_ports["marketplace_registry"].observe(
                changed_definitions["marketplace_registry"]
            )

        self.assertEqual("REGISTRY_RECEIPT_CONFLICT", caught.exception.code)


class InstallerUpdateLauncherCompositionV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="csul2-")
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir(mode=0o700)
        self.old_marketplace = self.root / "old-marketplace"
        self.new_marketplace = self.root / "new-marketplace"
        for marketplace, marker in (
            (self.old_marketplace, "old"),
            (self.new_marketplace, "new"),
        ):
            target_dir = marketplace / "plugins/codex-smart-subagents/bin"
            target_dir.mkdir(parents=True, mode=0o700)
            for name in ("codex-smart", "codex-smart-subagents-admin"):
                target = target_dir / name
                target.write_text(f"#!/bin/sh\n# {marker}-{name}\n", encoding="utf-8")
                target.chmod(0o700)
        self.marketplace = self.root / "marketplace-current"
        self.marketplace.symlink_to(self.old_marketplace)
        lexical_bin = self.marketplace / "plugins/codex-smart-subagents/bin"
        new_bin = self.new_marketplace / "plugins/codex-smart-subagents/bin"
        self.bindings = (
            LauncherBindingV2(
                name="codex-smart",
                role="gateway",
                path=self.bin_dir / "codex-smart",
                target=lexical_bin / "codex-smart",
                expected_resolved_target=new_bin / "codex-smart",
            ),
            LauncherBindingV2(
                name="codex-smart-subagents-admin",
                role="admin",
                path=self.bin_dir / "codex-smart-subagents-admin",
                target=lexical_bin / "codex-smart-subagents-admin",
                expected_resolved_target=new_bin / "codex-smart-subagents-admin",
            ),
        )
        for binding in self.bindings:
            binding.path.symlink_to(binding.target)
        self.plan = build_launcher_update_plan_v2(
            installation_id="ins2_" + "1" * 32,
            operation_id="op2_" + "2" * 32,
            bindings=self.bindings,
        )
        self.definition = build_launcher_step_definition_v2(self.plan)
        self.port = build_launcher_step_port_v2(
            plan=self.plan,
            definition=self.definition,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _activate_new_marketplace(self) -> None:
        replacement = self.root / ".marketplace-current.next"
        replacement.symlink_to(self.new_marketplace)
        os.replace(replacement, self.marketplace)

    def test_stable_launcher_links_follow_new_activation_and_replay_safely(
        self,
    ) -> None:
        self.assertEqual(self.plan.before, self.port.observe(self.definition))
        self._activate_new_marketplace()

        causal_after = self.port.observe(self.definition)

        self.assertEqual(self.plan.expected_after, causal_after)
        self.assertTrue(self.port.matches_before(causal_after, self.definition))
        self.assertTrue(self.port.matches_after(causal_after, self.definition))
        self.assertTrue(
            self.port.replay_safe_when_indistinguishable(
                causal_after,
                self.definition,
            )
        )
        self.port.apply(self.definition)
        self.assertEqual(self.plan.expected_after, self.port.observe(self.definition))
        for binding in self.bindings:
            self.assertTrue(binding.path.is_symlink())
            self.assertEqual(str(binding.target), os.readlink(binding.path))
            self.assertEqual(
                binding.expected_resolved_target,
                binding.path.resolve(strict=True),
            )

    def test_changed_launcher_is_not_silently_repaired(self) -> None:
        self.bindings[0].path.unlink()
        self.bindings[0].path.symlink_to(self.bindings[1].target)

        with self.assertRaises(InstallerUpdateCompositionV2Error) as caught:
            self.port.observe(self.definition)

        self.assertEqual("LAUNCHER_STATE_AMBIGUOUS", caught.exception.code)


class InstallerUpdateShutdownCleanupCompositionV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.smart_subagents.test_shutdown_socket_cleanup_v2 import (
            ShutdownSocketCleanupV2Tests,
        )

        self.fixture = ShutdownSocketCleanupV2Tests(methodName="runTest")
        self.fixture.setUp()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def _controller_before(self) -> ProjectionV2:
        from tests.smart_subagents.test_state_store_v2 import database_identity

        source = self.fixture.initial_controller
        database = database_identity()
        plan = self.fixture.plan
        value = {
            "controllerIdentity": source.controller_identity,
            "instanceId": source.instance_id,
            "controllerStartId": source.controller_start_id,
            "pid": plan.target_pid,
            "processStartMarker": plan.target_start_marker,
            "processGroupId": plan.target_process_group_id,
            "controlEpoch": self.fixture.shutdown.shutdown.previous_control_epoch,
            "state": "MAINTENANCE",
            "maintenanceMode": "freeze",
            "operationId": self.fixture.plan.operation_id,
            "activationId": source.activation_id,
            "activationFingerprint": source.activation_fingerprint,
            "databaseId": database.database_id,
            "socket": {
                "path": str(plan.socket_path),
                "device": plan.socket_device,
                "inode": plan.socket_inode,
                "ownerUid": plan.socket_owner_uid,
                "ownerGid": plan.socket_owner_gid,
                "mode": plan.socket_mode,
            },
            "lockHeld": True,
            "acceptingNewRoutes": False,
            "quiescent": True,
        }
        envelope = {
            "schemaId": "controller-state-v2",
            "schemaSha256": _LIFECYCLE_SCHEMA_SHA256,
            "value": value,
        }
        return ProjectionV2(
            schema_id="controller-state-v2",
            schema_sha256=_LIFECYCLE_SCHEMA_SHA256,
            value=value,
            value_fingerprint=domain_fingerprint(
                "codex-smart/controller-state/v2", envelope
            ),
        )

    def test_real_cleanup_port_proves_orphan_before_unlink(self) -> None:
        shutdown_constraint = build_controller_shutdown_constraint_v2(
            codex_home=self.fixture.codex_home,
            shell_session_id="installer-v2",
            operation_id=self.fixture.plan.operation_id,
            command_id=self.fixture.plan.shutdown_command_id,
            controller_before=self._controller_before(),
            lock_path=self.fixture.plan.lock_path,
        )
        self.assertEqual(
            self.fixture.shutdown.shutdown.request_fingerprint,
            shutdown_constraint.value["requestFingerprint"],
        )
        self.assertEqual(
            self.fixture.shutdown.shutdown.payload["commandReceipt"][
                "resultFingerprint"
            ],
            shutdown_constraint.value["commandReceiptFingerprint"],
        )
        definition = build_shutdown_socket_cleanup_step_definition_v2(
            plan=self.fixture.plan,
            shutdown_constraint=shutdown_constraint,
        )
        port = build_shutdown_socket_cleanup_step_port_v2(
            plan=self.fixture.plan,
            definition=definition,
            shutdown_proof_provider=lambda: self.fixture.shutdown,
        )
        self.fixture._stop_process()

        before = port.observe(definition)

        self.assertTrue(port.matches_before(before, definition))
        self.assertEqual(
            "SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN",
            before.value["status"],
        )
        port.apply(definition)
        after = port.observe(definition)
        self.assertEqual(definition.expected_after, after)
        self.assertTrue(port.matches_after(after, definition))
        self.assertTrue(port.matches_before(after, definition))
        self.assertTrue(
            port.replay_safe_when_indistinguishable(after, definition)
        )


class InstallerUpdateFullDefinitionV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.smart_subagents.test_activation_transition_v2 import (
            ActivationTransitionV2Tests,
        )

        self.fixture = ActivationTransitionV2Tests(methodName="runTest")
        self.fixture.setUp()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def test_initial_main_journal_contains_schema_valid_full_twenty_step_plan(
        self,
    ) -> None:
        proof = self.fixture.capture()
        operation_id = "op2_" + "9" * 32
        source_digest = _fixture_source_digest_v2(self.fixture)
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=source_digest,
        )
        receipt = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        fake = object.__new__(_RegistryCodexV2)
        fake.root = self.fixture.root
        fake.old_marketplace = proof.activation_dir / "marketplace"
        fake.new_marketplace = receipt.activation_intent.activation_dir / "marketplace"
        fake.plugin_relative = Path("plugins/codex-smart-subagents")
        fake.marketplace = fake.old_marketplace
        fake.plugin_enabled = True
        fake.calls = []
        fake.write_config(self.fixture.codex_home)
        registry_plan = build_registry_update_plan_v2(
            installation_id=proof.installation_id,
            operation_id=operation_id,
            codex_binary=receipt.activation_intent.snapshot_path,
            codex_home=self.fixture.codex_home,
            working_directory=self.fixture.root,
            marketplace_path=proof.layout.marketplace_link,
            previous_registered_marketplace_path=fake.old_marketplace,
            registered_marketplace_path=fake.new_marketplace,
            plugin_relative_path=fake.plugin_relative,
            plugin_version="0.2.0",
            install_policy="AVAILABLE",
            auth_policy="ON_INSTALL",
            receipt_directory=proof.layout.receipts_root / proof.installation_id,
            command_runner=fake,
        )
        links = proof.installer_receipt_document["links"]
        launcher_plan = build_launcher_update_plan_v2(
            installation_id=proof.installation_id,
            operation_id=operation_id,
            bindings=tuple(
                LauncherBindingV2(
                    name=Path(item["path"]).name,
                    role=(
                        "gateway"
                        if Path(item["path"]).name == "codex-smart"
                        else "admin"
                    ),
                    path=Path(item["path"]),
                    target=Path(item["target"]),
                    expected_resolved_target=(
                        fake.new_marketplace
                        / fake.plugin_relative
                        / "bin"
                        / Path(item["path"]).name
                    ),
                )
                for item in links
            ),
        )
        candidate_action = build_candidate_spawn_action_v2(
            preparation_receipt=receipt,
            readiness_token="candidate-secret-for-test-00000000",
            interpreter=Path(sys.executable),
            server_entrypoint=(
                receipt.activation_intent.activation_dir
                / "marketplace/plugins/codex-smart-subagents/controller/server.py"
            ),
            private_ready_channel_path=(
                receipt.activation_intent.state_home / "candidate-test.ready.sock"
            ),
            readiness_window_ms=30_000,
        )
        automaton = json.loads(
            (ROOT / "docs/contracts/vectors/lifecycle-v2.json").read_text(
                encoding="utf-8"
            )
        )["fixtures"]["automaton"]
        registry = LifecyclePlanRegistryV2.from_document(automaton)

        fresh_controller, fresh_controller_row = (
            observe_controller_database_state_v2(proof.database_path)
        )
        from codex_smart_subagents.shutdown_socket_cleanup_v2 import (
            build_shutdown_socket_cleanup_plan_v2,
        )

        with (
            mock.patch(
                "codex_smart_subagents.installer_update_controller_ports_v2."
                "observe_controller_database_state_v2",
                return_value=(fresh_controller, fresh_controller_row),
            ) as controller_observer,
            mock.patch(
                "codex_smart_subagents.shutdown_socket_cleanup_v2."
                "build_shutdown_socket_cleanup_plan_v2",
                wraps=build_shutdown_socket_cleanup_plan_v2,
            ) as cleanup_builder,
        ):
            plans = build_update_matched_active_definition_v2(
                registry=registry,
                proof=proof,
                preparation=preparation,
                preparation_receipt=receipt,
                registry_plan=registry_plan,
                launcher_plan=launcher_plan,
                candidate_action=candidate_action,
            )
        controller_observer.assert_called_once_with(proof.database_path)
        self.assertEqual(
            fresh_controller,
            plans.controller_definitions["maintenance_begin"].before,
        )
        self.assertIs(
            fresh_controller_row,
            cleanup_builder.call_args.kwargs["controller_state"],
        )
        self.assertFalse(
            plans.controller_definitions["maintenance_resume"]
            .expected_after.value["quiescent"]
        )

        prepared_activation = receipt.prepared.activation
        prepared_envelope = {
            "schemaId": prepared_activation.schema_id,
            "schemaSha256": prepared_activation.schema_sha256,
            "value": dict(prepared_activation.value),
        }
        self.assertEqual(
            domain_fingerprint(
                "codex-smart/activation/v2",
                prepared_envelope,
            ),
            prepared_activation.value_fingerprint,
        )
        assert plans.definition.terminal is not None
        commit_activation = plans.definition.terminal.receipt_payload.activation
        commit_envelope = {
            "schemaId": commit_activation.schema_id,
            "schemaSha256": commit_activation.schema_sha256,
            "value": dict(commit_activation.value),
        }
        self.assertEqual(prepared_envelope, commit_envelope)
        self.assertEqual(
            domain_fingerprint(
                "codex-smart/journal-state/v2",
                commit_envelope,
            ),
            commit_activation.value_fingerprint,
        )
        self.assertNotEqual(
            prepared_activation.value_fingerprint,
            commit_activation.value_fingerprint,
        )

        source_observations: list[str] = []

        def observe_source_digest():
            source_observations.append("observed")
            return source_digest

        source_binding = UpdateSourceBindingV2(
            expected_source_digest=source_digest,
            expected_codex_sha256=receipt.activation_intent.source_locator[
                "sourceObservedSha256"
            ],
            observe_source_digest=observe_source_digest,
        )
        composition = build_update_matched_active_composition_v2(
            registry=registry,
            proof=proof,
            preparation=preparation,
            preparation_receipt=receipt,
            source_binding=source_binding,
            registry_plan=registry_plan,
            launcher_plan=launcher_plan,
            candidate_action=candidate_action,
            readiness_token="candidate-secret-for-test-00000000",
            wrapper_path=(
                receipt.activation_intent.activation_dir
                / "marketplace/plugins/codex-smart-subagents/bin/codex-smart"
            ),
            schema_directory=ROOT / "docs/contracts/schemas",
            candidate_port_options={"monotonic_ms": lambda: 10_000},
        )

        self.assertIsInstance(composition, InstallerUpdateCompositionV2)
        self.assertEqual(plans.definition, composition.definition)
        authorization_path = composition.candidate_authorization_store.path
        authorization_info = authorization_path.stat()
        self.assertEqual(0o600, authorization_info.st_mode & 0o777)
        self.assertEqual(1, authorization_info.st_nlink)
        authorization_document = json.loads(
            authorization_path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            authorization_path.read_bytes(),
            json.dumps(
                authorization_document,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8"),
        )
        external_kinds = set(
            plans.definition.execution_plan.composed_step_kinds[1:17]
        ) - {"recovery_forward_only"}
        self.assertEqual(15, len(external_kinds))
        for kind in external_kinds:
            self.assertIsNotNone(composition.ports.require(kind))

        executor = OperationExecutorV2(
            store=OperationJournalStoreV2(
                journal_path=proof.layout.journal_path,
                lock_path=proof.layout.lock_path,
                validate_document=build_operation_journal_validator_v2(
                    ROOT / "docs/contracts/schemas"
                ),
            ),
            now=lambda: __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ),
        )
        executor.begin(plans.definition)
        journal = executor.store.read()
        recovery = load_update_matched_active_recovery_evidence_v2(
            store=executor.store,
            preparation=preparation,
            preparation_receipt_path=preparation.definition.receipt_path,
            source_binding=source_binding,
        )
        recovered_composition = recover_update_matched_active_composition_v2(
            registry=registry,
            store=executor.store,
            preparation=preparation,
            preparation_receipt_path=preparation.definition.receipt_path,
            source_binding=source_binding,
            registry_runtime=RegistryRuntimeBindingsV2(
                working_directory=self.fixture.root,
                plugin_relative_path=fake.plugin_relative,
                plugin_version="0.2.0",
                install_policy="AVAILABLE",
                auth_policy="ON_INSTALL",
                command_runner=fake,
            ),
            launcher_bindings=launcher_plan.bindings,
            wrapper_path=(
                receipt.activation_intent.activation_dir
                / "marketplace/plugins/codex-smart-subagents/bin/codex-smart"
            ),
            candidate_port_options={"monotonic_ms": lambda: 10_000},
        )

        self.assertEqual(20, len(plans.definition.execution_plan.composed_step_kinds))
        self.assertEqual(17, len(journal["steps"]))
        self.assertEqual(
            list(plans.definition.execution_plan.composed_step_kinds[:17]),
            [step["kind"] for step in journal["steps"]],
        )
        self.assertTrue(
            all(step["state"] == "PLANNED" for step in journal["steps"][1:])
        )
        self.assertIsInstance(recovery, InstallerUpdateRecoveryEvidenceV2)
        self.assertEqual(journal, recovery.journal)
        self.assertEqual(plans.definition, recovery.definition)
        self.assertEqual(receipt, recovery.preparation_receipt)
        self.assertTrue(recovery.transition_proof.complete)
        self.assertEqual(
            proof.proof_fingerprint, recovery.transition_proof.proof_fingerprint
        )
        self.assertEqual(plans.definition, recovered_composition.definition)
        self.assertIsNot(composition.operation, recovered_composition.operation)

        @contextmanager
        def installation_lock():
            yield

        recovery_context = recovered_composition.as_main_journal_recovery_v2(
            installation_lock=installation_lock,
        )
        self.assertIs(recovered_composition.executor, recovery_context.executor)
        self.assertIs(recovered_composition.callbacks, recovery_context.callbacks)
        self.assertIs(
            recovered_composition.terminal_callbacks,
            recovery_context.terminal_callbacks,
        )

        states: dict[str, ProjectionV2] = {}

        def projected(template, value, domain):
            envelope = {
                "schemaId": template.schema_id,
                "schemaSha256": template.schema_sha256,
                "value": value,
            }
            return ProjectionV2(
                schema_id=template.schema_id,
                schema_sha256=template.schema_sha256,
                value=value,
                value_fingerprint=domain_fingerprint(domain, envelope),
            )

        def factual_after(definition):
            value = dict(definition.expected_after.value)
            if definition.kind == "controller_shutdown":
                value.update(
                    {
                        "processExitProofFingerprint": "e" * 64,
                        "exclusiveLockProofFingerprint": "f" * 64,
                        "status": "SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN",
                    }
                )
                return projected(
                    definition.expected_after,
                    value,
                    "codex-smart/shutdown-intent/v2",
                )
            if definition.kind in {"marketplace_registry", "plugin_registry"}:
                registry_before = definitions_by_kind[
                    "marketplace_registry"
                ].before.value
                value.update(
                    {
                        "status": (
                            "MARKETPLACE_REGISTERED"
                            if definition.kind == "marketplace_registry"
                            else "PLUGIN_ENABLED"
                        ),
                        "configFile": registry_before["configFile"],
                        "marketplaceListFingerprint": "a" * 64,
                        "pluginListFingerprint": "b" * 64,
                    }
                )
                return projected(
                    definition.expected_after,
                    value,
                    "codex-smart/registry-state/v2",
                )
            if definition.kind in {"controller_accept", "maintenance_resume"}:
                old = definitions_by_kind["maintenance_begin"].before.value
                value.update(
                    {
                        "instanceId": "ci2_" + "a" * 32,
                        "pid": old["pid"],
                        "processStartMarker": old["processStartMarker"],
                        "processGroupId": old["processGroupId"],
                        "socket": old["socket"],
                        "state": (
                            "MAINTENANCE"
                            if definition.kind == "controller_accept"
                            else "ACCEPTING"
                        ),
                    }
                )
                return projected(
                    definition.expected_after,
                    value,
                    "codex-smart/controller-state/v2",
                )
            return definition.expected_after

        def controlled_port(definition):
            states[definition.kind] = definition.before
            after = factual_after(definition)

            def observe(_received):
                return states[definition.kind]

            def apply(_received):
                states[definition.kind] = after

            return UpdateStepPortV2(
                observe=observe,
                apply=apply,
                matches_before=lambda observed, _received: (
                    observed == definition.before
                ),
                matches_after=lambda observed, _received: observed == after,
                replay_safe_when_indistinguishable=lambda observed, _received: (
                    observed == definition.before == definition.expected_after
                ),
                completed_current_matches=lambda persisted, current, _received: (
                    persisted == current
                ),
            )

        definitions_by_kind = {
            step.kind: step for step in plans.definition.mutable_steps
        }
        overrides = {
            kind: controlled_port(definition)
            for kind, definition in definitions_by_kind.items()
            if kind not in {"recovery_forward_only", "controller_candidate_spawn"}
        }
        listeners: list[socket.socket] = []
        spawn_tokens: list[str] = []

        def fake_spawn(**arguments):
            action = arguments["action"]
            spawn_tokens.append(arguments["authorization"].consume_for(action))
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(action.private_ready_channel_path))
            os.chmod(action.private_ready_channel_path, 0o600)
            listener.listen(1)
            listeners.append(listener)

        candidate_definition = definitions_by_kind["controller_candidate_spawn"]

        def fake_reconnect(**_arguments):
            info = os.lstat(candidate_action.private_ready_channel_path)
            ready = {
                "path": str(candidate_action.private_ready_channel_path),
                "device": info.st_dev,
                "inode": info.st_ino,
                "ownerUid": info.st_uid,
                "ownerGid": info.st_gid,
                "mode": "0600",
            }
            registration = dict(candidate_definition.expected_after.value)
            registration.update(
                {
                    "privateReadyChannel": ready,
                    "pid": 4100,
                    "processStartMarker": "candidate-test-marker",
                    "processGroupId": 4100,
                    "registrationFingerprint": "c" * 64,
                    "databaseLeaseProofFingerprint": "d" * 64,
                    "databaseOpened": True,
                    "status": "REGISTERED_READY",
                }
            )
            return CandidateReadyReconnectV2(
                response={},
                response_bytes=b"{}",
                registration=registration,
                database_lease={},
                working_controller_socket={},
            )

        execution_composition = recover_update_matched_active_composition_v2(
            registry=registry,
            store=executor.store,
            preparation=preparation,
            preparation_receipt_path=preparation.definition.receipt_path,
            source_binding=source_binding,
            registry_runtime=RegistryRuntimeBindingsV2(
                working_directory=self.fixture.root,
                plugin_relative_path=fake.plugin_relative,
                plugin_version="0.2.0",
                install_policy="AVAILABLE",
                auth_policy="ON_INSTALL",
                command_runner=fake,
            ),
            launcher_bindings=launcher_plan.bindings,
            wrapper_path=(
                receipt.activation_intent.activation_dir
                / "marketplace/plugins/codex-smart-subagents/bin/codex-smart"
            ),
            candidate_port_options={
                "monotonic_ms": lambda: 10_000,
                "spawn_primitive": fake_spawn,
                "candidate_reconnect": fake_reconnect,
            },
            port_overrides=overrides,
        )
        try:
            run = execution_composition.operation.execute()
        finally:
            for listener in listeners:
                listener.close()
            try:
                candidate_action.private_ready_channel_path.unlink()
            except FileNotFoundError:
                pass

        self.assertEqual("COMPLETED", run.status)
        self.assertEqual(
            ["candidate-secret-for-test-00000000"],
            spawn_tokens,
        )
        self.assertFalse(execution_composition.executor.store.journal_path.exists())
        self.assertFalse(
            execution_composition.candidate_authorization_store.path.exists()
        )
        self.assertTrue(execution_composition.receipt_store.path.is_file())
        self.assertEqual(["observed"], source_observations)


if __name__ == "__main__":
    unittest.main()

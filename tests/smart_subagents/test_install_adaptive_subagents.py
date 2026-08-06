from __future__ import annotations

import copy
import dataclasses
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
INSTALLER_PATH = ROOT / "scripts" / "install_adaptive_subagents.py"


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class MarketplaceContractTests(unittest.TestCase):
    def test_repo_marketplace_exposes_the_bundled_plugin(self) -> None:
        agents_document = json.loads(
            (ROOT / ".agents" / "plugins" / "marketplace.json").read_text(
                encoding="utf-8"
            )
        )
        codex_document = json.loads(
            (ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8")
        )

        self.assertEqual("codex-settings-adaptive", agents_document["name"])
        self.assertEqual("codex-settings-adaptive", codex_document["name"])
        self.assertEqual(1, len(agents_document["plugins"]))
        self.assertEqual(1, len(codex_document["plugins"]))
        self.assertEqual(
            "codex-smart-subagents",
            agents_document["plugins"][0]["name"],
        )
        self.assertEqual(
            "codex-smart-subagents",
            codex_document["plugins"][0]["name"],
        )
        self.assertEqual(
            "./plugins/codex-smart-subagents",
            codex_document["plugins"][0]["source"],
        )
        self.assertEqual(
            json.loads(
                (
                    ROOT
                    / "plugins"
                    / "codex-smart-subagents"
                    / ".codex-plugin"
                    / "plugin.json"
                ).read_text(encoding="utf-8")
            )["version"],
            codex_document["plugins"][0]["version"],
        )

    def test_source_manifests_form_one_strict_primary_contract(self) -> None:
        installer = load_script(
            "install_adaptive_subagents_marketplace_contract_under_test",
            INSTALLER_PATH,
        )
        agents_document = json.loads(
            (ROOT / ".agents" / "plugins" / "marketplace.json").read_text(
                encoding="utf-8"
            )
        )
        codex_document = json.loads(
            (ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8")
        )
        plugin_document = json.loads(
            (
                ROOT
                / "plugins"
                / "codex-smart-subagents"
                / ".codex-plugin"
                / "plugin.json"
            ).read_text(encoding="utf-8")
        )

        contract = installer._validate_marketplace_source_documents(
            agents_document,
            codex_document,
            plugin_document,
        )

        self.assertEqual("0.2.0", contract.plugin_version)
        self.assertEqual("AVAILABLE", contract.install_policy)
        self.assertEqual("ON_INSTALL", contract.auth_policy)
        self.assertEqual(
            "./plugins/codex-smart-subagents",
            contract.plugin_source_path,
        )

    def test_malformed_source_manifests_never_leak_attribute_error(self) -> None:
        installer = load_script(
            "install_adaptive_subagents_malformed_marketplace_under_test",
            INSTALLER_PATH,
        )
        agents_document = json.loads(
            (ROOT / ".agents" / "plugins" / "marketplace.json").read_text(
                encoding="utf-8"
            )
        )
        codex_document = json.loads(
            (ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8")
        )
        plugin_document = json.loads(
            (
                ROOT
                / "plugins"
                / "codex-smart-subagents"
                / ".codex-plugin"
                / "plugin.json"
            ).read_text(encoding="utf-8")
        )
        mutations = (
            ([], codex_document, plugin_document),
            (
                {**agents_document, "plugins": [None]},
                codex_document,
                plugin_document,
            ),
            (
                {
                    **agents_document,
                    "plugins": [
                        {
                            **agents_document["plugins"][0],
                            "source": "./plugins/codex-smart-subagents",
                        }
                    ],
                },
                codex_document,
                plugin_document,
            ),
            (
                agents_document,
                {**codex_document, "plugins": [42]},
                plugin_document,
            ),
            (
                {
                    **agents_document,
                    "plugins": [
                        {
                            **agents_document["plugins"][0],
                            "policy": {
                                "installation": "AVAILABLE",
                                "authentication": "NEVER",
                            },
                        }
                    ],
                },
                codex_document,
                plugin_document,
            ),
            (
                agents_document,
                {
                    **codex_document,
                    "plugins": [{**codex_document["plugins"][0], "version": "9.9.9"}],
                },
                plugin_document,
            ),
            (agents_document, codex_document, "not-an-object"),
        )

        for agents, codex, plugin in mutations:
            with self.subTest(
                agents_type=type(agents).__name__,
                codex_type=type(codex).__name__,
                plugin_type=type(plugin).__name__,
            ):
                with self.assertRaises(installer.InstallError) as captured:
                    installer._validate_marketplace_source_documents(
                        agents,
                        codex,
                        plugin,
                    )
                self.assertEqual(
                    "MARKETPLACE_IDENTITY_MISMATCH",
                    captured.exception.code,
                )


class _InstallerBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = load_script(
            "install_adaptive_subagents_v2_under_test",
            INSTALLER_PATH,
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="csiv2-")
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir(mode=0o700)
        self.fake_codex = self.root / "codex"
        self.fake_codex.write_text(
            (
                ROOT / "tests" / "smart_subagents" / "test_install_fake_codex.py"
            ).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        self.fake_codex.chmod(0o700)
        self.layout = self.installer.InstallLayout(
            source_root=ROOT.resolve(),
            codex_home=self.codex_home,
            bin_dir=self.bin_dir,
            codex_binary=self.fake_codex,
            state_home=self.codex_home / "state" / "codex-smart-subagents-v2",
        )
        self.activation_id = "act2_" + "a" * 64
        self.installation_id = "ins2_" + "b" * 32
        self.operation_id = "op2_" + "c" * 32

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def ready_decision(self):
        from codex_smart_subagents.activation_gateway_v2 import (
            GatewayDecision,
            GatewayState,
        )

        gate = {"gateFingerprint": "d" * 64}
        return GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.fake_codex,
            coordinator={"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
            activation_id=self.activation_id,
            gate_fingerprint="d" * 64,
            activation_gate=gate,
            catalog_path=(
                self.layout.gateway_layout.marketplace_link
                / "plugins"
                / "codex-smart-subagents"
                / "config"
                / "adaptive-subagents.toml"
            ),
        )

    def ordinary_decision(self, reason: str = "MANIFEST_UNAVAILABLE"):
        from codex_smart_subagents.activation_gateway_v2 import (
            GatewayDecision,
            GatewayState,
        )

        return GatewayDecision(
            state=GatewayState.ORDINARY,
            reason_code=reason,
            executable=self.fake_codex,
        )

    def publish_fake_activation(
        self,
        *,
        installation_id: str | None = None,
        operation_id: str | None = None,
    ) -> None:
        from codex_smart_subagents.activation_materializer_v2 import (
            _materialize_marketplace,
        )

        if installation_id is None or operation_id is None:
            if self.layout.first_install_journal_path.exists():
                journal = self.installer._load_first_install_journal_v2(self.layout)
                installation_id = str(journal["installationId"])
                operation_id = str(journal["operationId"])
            else:
                installation_id = installation_id or self.installation_id
                operation_id = operation_id or self.operation_id

        gateway = self.layout.gateway_layout
        activation = gateway.managed_root / "activations" / self.activation_id
        marketplace = activation / "marketplace"
        plugin = marketplace / "plugins" / "codex-smart-subagents"
        activation.mkdir(parents=True, mode=0o700)
        _materialize_marketplace(
            source_root=self.layout.source_root,
            marketplace=marketplace,
            plugin_root=plugin,
            bundled_catalog={},
        )
        snapshot_sha256 = hashlib.sha256(self.fake_codex.read_bytes()).hexdigest()
        snapshot = (
            gateway.managed_root
            / "codex-snapshots"
            / snapshot_sha256
            / "codex"
        )
        snapshot.parent.mkdir(parents=True, mode=0o700)
        snapshot.write_bytes(self.fake_codex.read_bytes())
        snapshot.chmod(0o500)
        snapshot_locator = {
            "absolutePath": str(snapshot),
            "sha256": snapshot_sha256,
        }
        (activation / "activation.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "activationId": self.activation_id,
                    "activationFingerprint": "a" * 64,
                    "identity": {"codexSnapshot": snapshot_locator},
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        (activation / "activation.json").chmod(0o600)
        gateway.marketplace_link.symlink_to(
            f"activations/{self.activation_id}/marketplace"
        )
        gateway.manifest_root.mkdir(mode=0o700, exist_ok=True)
        gateway.manifest_path.write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "installationId": installation_id,
                    "activeActivation": {
                        "activationId": self.activation_id,
                        "symlinkTarget": (
                            f"activations/{self.activation_id}/marketplace"
                        ),
                    },
                    "previousActivation": None,
                    "lastCommittedOperation": operation_id,
                    "codexSnapshot": snapshot_locator,
                    "sourceLocator": {
                        "lexicalPath": str(self.fake_codex),
                        "resolvedPathAtCapture": str(self.fake_codex.resolve()),
                        "argv0Policy": "lexical",
                        "sourceObservedSha256": snapshot_sha256,
                    },
                    "stateHome": str(
                        self.codex_home / "state" / "codex-smart-subagents-v2"
                    ),
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        gateway.manifest_path.chmod(0o600)

    def successful_first_apply(self):
        events: list[str] = []
        process = SimpleNamespace(
            poll=lambda: None,
            terminate=lambda: events.append("terminate"),
            wait=lambda timeout=None: 0,
            kill=lambda: events.append("kill"),
        )

        def spawn(
            layout,
            source_environment=None,
            *,
            first_install_journal=None,
        ):
            del first_install_journal
            events.append("spawn")
            self.assertTrue(layout.launcher_path.is_symlink())
            self.assertTrue(layout.admin_path.is_symlink())
            return process

        def wait(layout, spawned):
            events.append("ready")
            self.assertIs(process, spawned)
            self.publish_fake_activation()
            return self.ready_decision()

        with (
            mock.patch.object(self.installer, "_spawn_initial_controller", spawn),
            mock.patch.object(self.installer, "_wait_for_full_ready", wait),
        ):
            result = self.installer.install(self.layout, apply=True)
        return result, events


class InstallerV2ContractTests(_InstallerBase):
    def test_source_digest_includes_the_installer_entrypoint(self) -> None:
        source_root = self.root / "digest-source"
        for relative in (
            Path(".agents"),
            Path(".claude-plugin"),
            Path(".codex"),
            Path("docs/contracts"),
            Path("plugins/codex-smart-subagents"),
        ):
            shutil.copytree(ROOT / relative, source_root / relative)
        installer = source_root / "scripts" / "install_adaptive_subagents.py"
        installer.parent.mkdir(mode=0o700)
        shutil.copy2(INSTALLER_PATH, installer)
        layout = self.installer.InstallLayout(
            source_root=source_root,
            codex_home=self.layout.codex_home,
            bin_dir=self.layout.bin_dir,
            codex_binary=self.layout.codex_binary,
            state_home=self.layout.state_home,
        )
        before = self.installer._source_digest(layout)

        installer.write_bytes(installer.read_bytes() + b"\n")

        self.assertNotEqual(before, self.installer._source_digest(layout))

    def test_first_install_intent_is_durable_before_the_first_link(self) -> None:
        journal_path = (
            self.layout.manifest_root
            / "codex-smart-subagents-v2.first-install.transaction.json"
        )
        observed: list[dict[str, object] | None] = []

        def reject_first_effect(_path: Path, _target: Path) -> None:
            if journal_path.exists():
                observed.append(
                    json.loads(journal_path.read_text(encoding="utf-8"))
                )
            else:
                observed.append(None)
            raise self.installer.InstallError(
                "TEST_FIRST_EFFECT_STOP",
                "проверка останавливает первый внешний эффект",
            )

        with (
            mock.patch.object(
                self.installer,
                "_preflight_first_install",
                return_value=None,
            ),
            mock.patch.object(
                self.installer,
                "_create_stable_link",
                side_effect=reject_first_effect,
            ),
        ):
            with self.assertRaises(self.installer.InstallError) as captured:
                self.installer._first_install(
                    self.layout,
                    source_digest="a" * 64,
                    codex_version="0.144.6",
                    extra_environment=None,
                )

        self.assertEqual("TEST_FIRST_EFFECT_STOP", captured.exception.code)
        self.assertEqual(1, len(observed))
        self.assertIsNotNone(observed[0])
        assert observed[0] is not None
        self.assertEqual("first-install", observed[0].get("operation"))
        self.assertEqual("INTENT_DURABLE", observed[0].get("phase"))

    def _completed_supervised_controller(self, *, group_alive: bool):
        signals: list[int] = []
        transitions: list[tuple[str, object]] = []
        process = SimpleNamespace(
            pid=8111,
            poll=mock.Mock(return_value=0),
        )
        identity = (
            self.installer.operation_process_group_supervisor_v2.
            ProcessIdentityV2(
                pid=process.pid,
                process_group_id=process.pid,
                session_id=process.pid,
                start_marker="completed-controller-marker",
            )
        )
        supervisor = (
            self.installer.operation_process_group_supervisor_v2.
            OperationProcessGroupSupervisorV2(
                popen_factory=lambda _argv, **_kwargs: process,
                killpg=lambda _pgid, signum: signals.append(signum),
                group_exists=lambda _pgid: group_alive,
                identity_reader=lambda _pid: identity,
                ownership_publisher=lambda _lease, _context: None,
                ownership_transition=(
                    lambda _lease, _context, outcome, obligation:
                    transitions.append((outcome, obligation))
                ),
            )
        )
        lease = supervisor.spawn_transient(
            label="initial-controller",
            argv=("/usr/bin/true",),
        )
        process._codex_process_supervisor_v2 = supervisor
        process._codex_process_lease_v2 = lease
        return process, supervisor, lease, signals, transitions

    def test_completed_initial_controller_releases_disappeared_group(self) -> None:
        (
            process,
            supervisor,
            lease,
            signals,
            transitions,
        ) = self._completed_supervised_controller(group_alive=False)

        self.installer._stop_spawned_process(process)

        self.assertEqual((), supervisor.owned_lease_ids())
        self.assertEqual([("verified-exit", None)], transitions)
        self.assertEqual([], signals)
        self.assertFalse(hasattr(process, "_codex_process_supervisor_v2"))
        self.assertFalse(hasattr(process, "_codex_process_lease_v2"))
        self.assertNotIn(lease.lease_id, supervisor.owned_lease_ids())

    def test_reaped_real_controller_clears_transient_and_durable_ownership(
        self,
    ) -> None:
        invocation = self.installer.InstallerInvocationV2(
            command="apply",
            execute=True,
            json=True,
            source_root=str(ROOT),
            codex_home=str(self.codex_home),
            bin_dir=str(self.bin_dir),
            state_home=str(self.layout.state_home),
            codex_binary=sys.executable,
            retain_data=False,
        )
        store_type = self.installer.DurableProcessOwnershipStoreV2
        real_publish = store_type.publish
        real_transition = store_type.transition
        callback_contexts: list[
            tuple[str, type[object], dict[str, object]]
        ] = []
        observed: dict[str, object] = {}

        def recording_publish(store, lease, context):
            callback_contexts.append(
                ("publish", type(context), copy.deepcopy(dict(context)))
            )
            return real_publish(store, lease, context)

        def recording_transition(
            store,
            lease,
            context,
            outcome,
            cleanup_obligation,
        ):
            callback_contexts.append(
                ("transition", type(context), copy.deepcopy(dict(context)))
            )
            return real_transition(
                store,
                lease,
                context,
                outcome,
                cleanup_obligation,
            )

        def execute_with_real_process(_invocation, **_kwargs):
            supervisor = (
                self.installer.operation_process_group_supervisor_v2.
                current_process_group_supervisor_v2()
            )
            self.assertIsNotNone(supervisor)
            lease = supervisor.spawn_transient(
                label="initial-controller",
                argv=(
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    "import time; time.sleep(0.2)",
                ),
            )
            process = lease.process
            process._codex_process_supervisor_v2 = supervisor
            process._codex_process_lease_v2 = lease
            self.assertEqual(0, process.wait(timeout=5))
            self.assertEqual((lease.lease_id,), supervisor.owned_lease_ids())

            self.installer._stop_spawned_process(process)

            observed["supervisor"] = supervisor
            observed["process"] = process
            return {"status": "ok"}

        with (
            mock.patch.object(store_type, "publish", recording_publish),
            mock.patch.object(store_type, "transition", recording_transition),
            mock.patch.object(
                self.installer,
                "_execute_installer_invocation_without_lock_budget_v2",
                side_effect=execute_with_real_process,
            ),
        ):
            result = self.installer.execute_installer_invocation_v2(invocation)

        self.assertEqual({"status": "ok"}, result)
        supervisor = observed["supervisor"]
        process = observed["process"]
        self.assertEqual((), supervisor.owned_lease_ids())
        store = store_type(self.codex_home)
        self.assertEqual((), store.load_all())
        self.assertFalse(hasattr(process, "_codex_process_supervisor_v2"))
        self.assertFalse(hasattr(process, "_codex_process_lease_v2"))
        expected_context = {
            "schemaVersion": 2,
            "contextKind": "installer-transient-v2",
            "processLabel": "initial-controller",
        }
        self.assertEqual(
            [
                ("publish", dict, expected_context),
                ("transition", dict, expected_context),
            ],
            callback_contexts,
        )

    def test_completed_controller_with_live_descendants_keeps_primary_error(
        self,
    ) -> None:
        (
            process,
            supervisor,
            lease,
            signals,
            transitions,
        ) = self._completed_supervised_controller(group_alive=True)
        monotonic_now = [0]
        deadline = (
            self.installer.operation_deadline_v2.OperationDeadlineV2.start(
                operation="apply",
                timeout_seconds=1,
                timeout_code="TEST_ROLLBACK_DEADLINE_EXCEEDED",
                monotonic_ns=lambda: monotonic_now[0],
            )
        )

        def fail_after_deadline(*_args, **_kwargs):
            monotonic_now[0] = 2_000_000_000
            raise self.installer.InstallError(
                "PRIMARY_STARTUP_FAILURE",
                "исходная ошибка запуска",
            )

        with (
            self.installer.operation_deadline_v2.scoped_current_deadline_v2(
                deadline
            ),
            mock.patch.object(
                self.installer,
                "_preflight_first_install",
                return_value=None,
            ),
            mock.patch.object(
                self.installer,
                "_spawn_initial_controller",
                return_value=process,
            ),
            mock.patch.object(
                self.installer,
                "_wait_for_full_ready",
                side_effect=fail_after_deadline,
            ),
        ):
            with self.assertRaises(self.installer.InstallError) as captured:
                self.installer._first_install(
                    self.layout,
                    source_digest="a" * 64,
                    codex_version="0.144.6",
                    extra_environment=None,
                )

        self.assertEqual("PRIMARY_STARTUP_FAILURE", captured.exception.code)
        self.assertIn("CONTROLLER_CLEANUP_REQUIRED", captured.exception.message)
        self.assertEqual((lease.lease_id,), supervisor.owned_lease_ids())
        self.assertEqual([], signals)
        self.assertEqual(1, len(transitions))
        self.assertEqual("cleanup-required", transitions[0][0])
        self.assertIsNotNone(transitions[0][1])
        self.assertTrue(hasattr(process, "_codex_process_supervisor_v2"))
        self.assertTrue(hasattr(process, "_codex_process_lease_v2"))

    def test_state_home_capacity_covers_the_longest_candidate_ready_socket(
        self,
    ) -> None:
        candidate_name = ".r-" + "0" * 12 + ".sock"
        state_home = Path("/s")
        while len(os.fsencode(state_home / candidate_name)) < 100:
            state_home = Path(str(state_home) + "s")

        self.assertLess(len(os.fsencode(state_home / "controller.sock")), 100)
        self.assertGreaterEqual(
            len(os.fsencode(state_home / candidate_name)),
            100,
        )
        with self.assertRaises(self.installer.InstallError) as captured:
            self.installer._require_socket_path_capacity(state_home)

        self.assertEqual(
            "STATE_HOME_SOCKET_PATH_TOO_LONG",
            captured.exception.code,
        )

    def test_standard_public_codex_home_mode_is_accepted_without_mutation(self) -> None:
        self.codex_home.chmod(0o755)

        self.installer._validate_source_layout(self.layout)

        self.assertEqual(0o755, stat.S_IMODE(self.codex_home.stat().st_mode))

    def test_writable_by_group_codex_home_is_rejected(self) -> None:
        self.codex_home.chmod(0o775)

        with self.assertRaises(self.installer.InstallError) as caught:
            self.installer._validate_source_layout(self.layout)

        self.assertEqual("UNSAFE_DIRECTORY", caught.exception.code)

    def test_divergent_catalog_copies_are_rejected_before_installation(self) -> None:
        source_root = self.root / "divergent-source"
        source_root.mkdir(mode=0o700)
        alternate = dataclasses.replace(self.layout, source_root=source_root)
        required = (
            self.layout.marketplace_source,
            self.layout.codex_marketplace_source,
            self.layout.installer_receipt_schema_source,
            self.layout.catalog_source,
            self.layout.controller_entrypoint,
            self.layout.plugin_source / ".codex-plugin" / "plugin.json",
            self.layout.plugin_source / "config" / "adaptive-subagents.toml",
            self.layout.plugin_source / "bin" / "codex-smart",
            self.layout.plugin_source / "bin" / "codex-smart-subagents-admin",
            *self.layout.policy_source_paths,
            *self.layout.runtime_schema_paths,
            *self.layout.runtime_vector_paths,
        )
        for source in required:
            destination = source_root / source.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            destination.chmod(stat.S_IMODE(source.stat().st_mode))
        divergent = (
            alternate.plugin_source / "config" / "adaptive-subagents.toml"
        )
        divergent.write_bytes(divergent.read_bytes() + b"\n# divergent\n")

        with self.assertRaises(self.installer.InstallError) as caught:
            self.installer._validate_source_layout(alternate)

        self.assertEqual("SOURCE_CATALOG_MISMATCH", caught.exception.code)
        self.assertFalse(alternate.gateway_layout.managed_root.exists())

        divergent.write_bytes(alternate.catalog_source.read_bytes())
        generated_contracts = alternate.plugin_source / "config" / "contracts"
        generated_contracts.mkdir()
        (generated_contracts / "extra.txt").write_bytes(b"not recoverable\n")
        with self.assertRaises(self.installer.InstallError) as caught:
            self.installer._validate_source_layout(alternate)
        self.assertEqual("SOURCE_GENERATED_PATH_CONFLICT", caught.exception.code)
        (generated_contracts / "extra.txt").unlink()
        generated_contracts.rmdir()

        generated_catalog = (
            alternate.plugin_source / "config" / "bundled-catalog-v1.json"
        )
        generated_catalog.write_bytes(b"{}\n")
        with self.assertRaises(self.installer.InstallError) as caught:
            self.installer._validate_source_layout(alternate)
        self.assertEqual("SOURCE_GENERATED_PATH_CONFLICT", caught.exception.code)
        generated_catalog.unlink()

        generated_runtime_schema = (
            alternate.plugin_source
            / "config"
            / "runtime-schemas"
            / "extra.schema.json"
        )
        generated_runtime_schema.parent.mkdir()
        generated_runtime_schema.write_bytes(b"{}\n")
        with self.assertRaises(self.installer.InstallError) as caught:
            self.installer._validate_source_layout(alternate)
        self.assertEqual("SOURCE_GENERATED_PATH_CONFLICT", caught.exception.code)
        self.assertFalse(alternate.gateway_layout.managed_root.exists())

    def test_materialized_capsule_rejects_runtime_schema_drift(self) -> None:
        from codex_smart_subagents.activation_materializer_v2 import (
            _MCP_RUNTIME_SCHEMA_FILES,
            _materialize_marketplace,
        )

        activation = self.root / "capsule-activation"
        source_root = activation / "marketplace"
        plugin_root = source_root / "plugins" / "codex-smart-subagents"
        activation.mkdir(mode=0o700)
        _materialize_marketplace(
            source_root=ROOT,
            marketplace=source_root,
            plugin_root=plugin_root,
            bundled_catalog={},
        )
        layout = dataclasses.replace(self.layout, source_root=source_root)
        self.installer._validate_source_layout(layout)
        cached = plugin_root / "config" / "runtime-schemas"
        schema = cached / _MCP_RUNTIME_SCHEMA_FILES[0]
        original = schema.read_bytes()
        extra = cached / "extra.schema.json"

        def mutate_schema() -> None:
            schema.chmod(0o600)
            schema.write_bytes(original + b"\n")

        def restore_schema() -> None:
            schema.write_bytes(original)
            schema.chmod(0o400)

        def add_extra() -> None:
            cached.chmod(0o700)
            extra.write_bytes(b"{}\n")

        def remove_extra() -> None:
            extra.unlink()
            cached.chmod(0o500)

        mutations = (
            (
                "changed",
                mutate_schema,
                restore_schema,
            ),
            (
                "extra",
                add_extra,
                remove_extra,
            ),
        )
        for name, mutate, restore in mutations:
            with self.subTest(mutation=name):
                mutate()
                try:
                    with self.assertRaises(self.installer.InstallError) as caught:
                        self.installer._validate_source_layout(layout)
                    self.assertEqual(
                        "SOURCE_GENERATED_PATH_CONFLICT",
                        caught.exception.code,
                    )
                finally:
                    restore()

    def test_update_launcher_plan_is_derived_from_receipt_and_candidate(self) -> None:
        self.publish_fake_activation()
        self.layout.launcher_path.symlink_to(self.layout.launcher_target)
        self.layout.admin_path.symlink_to(self.layout.admin_target)
        previous_receipt = self.installer._build_installer_receipt(
            self.layout,
            source_digest="d" * 64,
            identity={
                "installationId": self.installation_id,
                "activationId": self.activation_id,
            },
        )
        candidate_id = "act2_" + "e" * 64
        candidate_activation = (
            self.layout.gateway_layout.managed_root / "activations" / candidate_id
        )
        candidate_bin = (
            candidate_activation
            / "marketplace"
            / "plugins"
            / "codex-smart-subagents"
            / "bin"
        )
        candidate_bin.mkdir(parents=True, mode=0o700)
        for name in ("codex-smart", "codex-smart-subagents-admin"):
            target = candidate_bin / name
            target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            target.chmod(0o500)
        preparation_receipt = SimpleNamespace(
            installation_id=self.installation_id,
            activation_intent=SimpleNamespace(activation_dir=candidate_activation),
        )

        plan = self.installer._build_update_launcher_plan_v2(
            self.layout,
            previous_receipt=previous_receipt,
            preparation_receipt=preparation_receipt,
            operation_id="op2_" + "f" * 32,
        )

        self.assertEqual(2, len(plan.bindings))
        self.assertEqual({"gateway", "admin"}, {item.role for item in plan.bindings})
        self.assertTrue(
            all(
                str(item.expected_resolved_target).startswith(str(candidate_activation))
                for item in plan.bindings
            )
        )

    def test_dry_run_has_no_schema1_mutable_tree_backup_or_highfd(self) -> None:
        result = self.installer.install(self.layout, apply=False)

        self.assertEqual("planned", result["status"])
        actions = "\n".join(result["actions"])
        self.assertIn("marketplace-current", actions)
        self.assertIn("--serve-v2", actions)
        self.assertNotIn("резервн", actions.lower())
        self.assertNotIn("codex-highfd", actions)
        self.assertFalse(self.layout.gateway_layout.manifest_path.exists())
        self.assertFalse(self.layout.installer_receipt_path.exists())
        self.assertFalse(self.layout.gateway_layout.managed_root.exists())
        self.assertFalse(self.layout.launcher_path.exists())

    def test_stable_links_are_lexically_routed_through_marketplace_current(
        self,
    ) -> None:
        gateway = self.layout.gateway_layout

        self.assertEqual(
            gateway.marketplace_link
            / "plugins"
            / "codex-smart-subagents"
            / "bin"
            / "codex-smart",
            self.layout.launcher_target,
        )
        self.assertEqual(
            gateway.marketplace_link
            / "plugins"
            / "codex-smart-subagents"
            / "bin"
            / "codex-smart-subagents-admin",
            self.layout.admin_target,
        )
        self.assertNotEqual(
            gateway.manifest_path,
            self.layout.installer_receipt_path,
        )

    def test_initial_controller_environment_is_closed_and_requires_all_inputs(
        self,
    ) -> None:
        (self.root / "tmp").mkdir(mode=0o700)
        source = {
            "HOME": str(self.root),
            "TMPDIR": str(self.root / "tmp"),
            "LANG": "ru_RU.UTF-8",
            "PATH": "/attacker/bin",
            "PYTHONPATH": "/tmp/injection",
            "OPENAI_API_KEY": "secret",
            "HTTPS_PROXY": "http://secret.invalid",
            "CODEX_SMART_SECRET": "secret",
        }

        environment = self.installer.initial_controller_environment(
            self.layout,
            source,
        )

        self.assertEqual(str(self.codex_home), environment["CODEX_HOME"])
        self.assertEqual("1", environment.get("PYTHONDONTWRITEBYTECODE"))
        self.assertEqual(str(ROOT.resolve()), environment["CODEX_V2_SOURCE_ROOT"])
        self.assertEqual(str(self.fake_codex), environment["CODEX_V2_CODEX_BIN"])
        self.assertEqual(
            str(self.layout.bootstrap_wrapper),
            environment["CODEX_V2_WRAPPER_PATH"],
        )
        self.assertEqual(
            str(self.layout.state_home), environment["CODEX_V2_STATE_HOME"]
        )
        self.assertEqual(os.defpath, environment["PATH"])
        for forbidden in (
            "PYTHONPATH",
            "OPENAI_API_KEY",
            "HTTPS_PROXY",
            "CODEX_SMART_SECRET",
        ):
            self.assertNotIn(forbidden, environment)
        for required in (
            "CODEX_V2_SOURCE_ROOT",
            "CODEX_V2_CODEX_BIN",
            "CODEX_V2_WRAPPER_PATH",
            "CODEX_V2_STATE_HOME",
            "PYTHONDONTWRITEBYTECODE",
        ):
            damaged = dict(environment)
            damaged.pop(required)
            with self.subTest(required=required):
                with self.assertRaises(self.installer.InstallError) as captured:
                    self.installer.require_initial_controller_environment(
                        self.layout,
                        damaged,
                    )
                self.assertEqual(
                    "INITIAL_CONTROLLER_ENVIRONMENT_INVALID",
                    captured.exception.code,
                )

        from codex_smart_subagents.controller_entrypoint_v2 import (
            load_controller_entrypoint_config_v2,
        )

        config = load_controller_entrypoint_config_v2(
            plugin_root=self.layout.plugin_source,
            environment=environment,
        )
        self.assertEqual(self.layout.bootstrap_wrapper, config.wrapper)

    def test_initial_controller_environment_rejects_changed_bytecode_guard(
        self,
    ) -> None:
        environment = self.installer.initial_controller_environment(
            self.layout,
            {"HOME": str(self.root)},
        )
        environment["PYTHONDONTWRITEBYTECODE"] = "0"

        with self.assertRaises(self.installer.InstallError) as captured:
            self.installer.require_initial_controller_environment(
                self.layout,
                environment,
            )

        self.assertEqual(
            "INITIAL_CONTROLLER_ENVIRONMENT_INVALID",
            captured.exception.code,
        )

    def test_explicit_state_home_is_bound_to_bootstrap_and_receipt(self) -> None:
        state_home = self.root / "short-state"
        layout = self.installer.InstallLayout(
            source_root=ROOT.resolve(),
            codex_home=self.codex_home,
            bin_dir=self.bin_dir,
            codex_binary=self.fake_codex,
            state_home=state_home,
        )

        environment = self.installer.initial_controller_environment(
            layout,
            {"HOME": str(self.root)},
        )
        self.assertEqual(str(state_home), environment["CODEX_V2_STATE_HOME"])

        from codex_smart_subagents.controller_entrypoint_v2 import (
            load_controller_entrypoint_config_v2,
        )

        config = load_controller_entrypoint_config_v2(
            plugin_root=layout.plugin_source,
            environment=environment,
        )
        self.assertEqual(state_home, config.state_home)
        self.publish_fake_activation()
        receipt = self.installer._build_installer_receipt(
            layout,
            source_digest="1" * 64,
            identity={
                "installationId": self.installation_id,
                "activationId": self.activation_id,
            },
        )
        self.assertEqual(str(state_home), receipt["stateHome"])

    def test_installer_receipt_matches_its_machine_schema(self) -> None:
        from jsonschema import Draft202012Validator

        self.publish_fake_activation()
        receipt = self.installer._build_installer_receipt(
            self.layout,
            source_digest="1" * 64,
            identity={
                "installationId": self.installation_id,
                "activationId": self.activation_id,
            },
        )
        schema = json.loads(
            self.layout.installer_receipt_schema_source.read_text(encoding="utf-8")
        )

        Draft202012Validator.check_schema(schema)
        errors = sorted(
            Draft202012Validator(schema).iter_errors(receipt),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        self.assertEqual([], [error.message for error in errors])
        self.assertEqual(
            str(self.layout.gateway_layout.marketplace_link),
            receipt["marketplacePath"],
        )
        self.assertEqual(
            str(self.layout.gateway_layout.marketplace_link.resolve(strict=True)),
            receipt["registeredMarketplacePath"],
        )

    def test_installer_receipt_loader_rejects_unsafe_path_and_link_shapes(
        self,
    ) -> None:
        self.publish_fake_activation()
        receipt = self.installer._build_installer_receipt(
            self.layout,
            source_digest="1" * 64,
            identity={
                "installationId": self.installation_id,
                "activationId": self.activation_id,
            },
        )
        mutations = (
            ("relative-codex-home", {**receipt, "codexHome": "relative"}),
            (
                "relative-registered-marketplace",
                {**receipt, "registeredMarketplacePath": "relative"},
            ),
            (
                "scalar-link",
                {**receipt, "links": [receipt["links"][0], "not-an-object"]},
            ),
            (
                "extra-link-field",
                {
                    **receipt,
                    "links": [
                        {**receipt["links"][0], "unexpected": True},
                        receipt["links"][1],
                    ],
                },
            ),
            (
                "duplicate-link",
                {**receipt, "links": [receipt["links"][0]] * 2},
            ),
        )

        for label, damaged in mutations:
            with self.subTest(label=label):
                path = self.root / f"{label}.json"
                path.write_text(
                    json.dumps(damaged, sort_keys=True, separators=(",", ":")),
                    encoding="utf-8",
                )
                path.chmod(0o600)
                with self.assertRaises(self.installer.InstallError) as captured:
                    self.installer._load_installer_receipt(path)
                self.assertEqual(
                    "INSTALLER_RECEIPT_INVALID",
                    captured.exception.code,
                )

    def test_contract_artifact_changes_change_the_source_digest(self) -> None:
        baseline = self.installer._source_digest(self.layout)
        original_file_digest = self.installer.file_digest
        for changed_path in (
            self.layout.marketplace_source,
            self.layout.codex_marketplace_source,
            self.layout.installer_receipt_schema_source,
        ):
            with self.subTest(path=changed_path):

                def changed_file_digest(path: Path) -> str:
                    if path == changed_path:
                        return "f" * 64
                    return original_file_digest(path)

                with mock.patch.object(
                    self.installer,
                    "file_digest",
                    side_effect=changed_file_digest,
                ):
                    changed = self.installer._source_digest(self.layout)

                self.assertNotEqual(baseline, changed)

    def test_selected_codex_binary_changes_change_the_source_digest(self) -> None:
        baseline = self.installer._source_digest(self.layout)
        original = self.fake_codex.read_bytes()

        self.fake_codex.write_bytes(original + b"\n# changed codex binary\n")
        self.fake_codex.chmod(0o700)
        changed_content = self.installer._source_digest(self.layout)

        alternate_codex = self.root / "alternate-codex"
        alternate_codex.write_bytes(original)
        alternate_codex.chmod(0o700)
        alternate_layout = dataclasses.replace(
            self.layout,
            codex_binary=alternate_codex,
        )
        changed_path = self.installer._source_digest(alternate_layout)

        self.assertNotEqual(baseline, changed_content)
        self.assertNotEqual(baseline, changed_path)

    def test_bound_python_runtime_changes_change_the_source_digest(self) -> None:
        first_python = self.root / "python-first"
        first_python.write_bytes(b"first-python-runtime\n")
        first_python.chmod(0o700)
        second_python = self.root / "python-second"
        second_python.write_bytes(first_python.read_bytes())
        second_python.chmod(0o700)

        with mock.patch.object(self.installer.sys, "executable", str(first_python)):
            baseline = self.installer._source_digest(self.layout)
            first_python.write_bytes(b"changed-python-runtime\n")
            first_python.chmod(0o700)
            changed_content = self.installer._source_digest(self.layout)

        with mock.patch.object(self.installer.sys, "executable", str(second_python)):
            changed_path = self.installer._source_digest(self.layout)

        self.assertNotEqual(baseline, changed_content)
        self.assertNotEqual(baseline, changed_path)

    def test_bound_python_runtime_rejects_a_path_with_spaces(self) -> None:
        spaced_directory = self.root / "python runtime"
        spaced_directory.mkdir()
        interpreter = spaced_directory / "python3"
        interpreter.write_bytes(b"not executed\n")
        interpreter.chmod(0o700)

        with (
            mock.patch.object(self.installer.sys, "executable", str(interpreter)),
            self.assertRaises(self.installer.InstallError) as captured,
        ):
            self.installer._bound_python_runtime_v2()

        self.assertEqual("PYTHON_RUNTIME_INVALID", captured.exception.code)

    def test_first_activation_reproduces_the_exact_source_digest(self) -> None:
        self.publish_fake_activation()
        identity = self.installer._load_lifecycle_identity(
            self.layout,
            require_first_activation=True,
        )

        observed = self.installer._materialized_source_digest_v2(
            self.layout,
            identity=identity,
        )

        self.assertEqual(self.installer._source_digest(self.layout), observed)

    def test_first_install_rejects_a_stale_source_digest_before_registration(
        self,
    ) -> None:
        process = SimpleNamespace(
            poll=lambda: None,
            terminate=mock.Mock(),
            wait=mock.Mock(return_value=0),
            kill=mock.Mock(),
        )

        def wait(_layout, _process):
            self.publish_fake_activation()
            return self.ready_decision()

        def cleanup(*, codex_home, installation_id, activation_id):
            self.assertEqual(self.codex_home, codex_home)
            self.assertEqual(self.installation_id, installation_id)
            self.assertEqual(self.activation_id, activation_id)
            gateway = self.layout.gateway_layout
            gateway.marketplace_link.unlink()
            gateway.manifest_path.unlink()
            return SimpleNamespace(status="ACCEPTED_ACTIVATION_REMOVED")

        with (
            mock.patch.object(self.installer, "_source_digest", return_value="0" * 64),
            mock.patch.object(
                self.installer,
                "_spawn_initial_controller",
                return_value=process,
            ),
            mock.patch.object(self.installer, "_wait_for_full_ready", side_effect=wait),
            mock.patch.object(
                self.installer,
                "cleanup_accepted_activation_v2",
                side_effect=cleanup,
            ),
        ):
            with self.assertRaises(self.installer.InstallError) as captured:
                self.installer.install(self.layout, apply=True)

        self.assertEqual("INITIAL_PREPARED_SOURCE_MISMATCH", captured.exception.code)
        self.assertFalse(self.layout.installer_receipt_path.exists())
        self.assertFalse(self.layout.launcher_path.exists())
        self.assertFalse(self.layout.admin_path.exists())
        process.terminate.assert_called_once_with()

    def test_initial_spawn_uses_only_serve_v2_and_the_closed_environment(self) -> None:
        with mock.patch.object(
            self.installer.subprocess,
            "Popen",
            return_value=object(),
        ) as popen:
            self.installer._spawn_initial_controller(
                self.layout,
                source_environment={"HOME": str(self.root)},
            )

        arguments = popen.call_args.args[0]
        options = popen.call_args.kwargs
        self.assertEqual(
            (
                str(Path(sys.executable).resolve()),
                str(self.layout.controller_entrypoint),
                "--serve-v2",
            ),
            arguments,
        )
        self.assertEqual(self.layout.plugin_source, options["cwd"])
        self.assertTrue(options["start_new_session"])
        self.assertTrue(options["close_fds"])
        self.assertIs(self.installer.subprocess.PIPE, options["stderr"])
        self.assertIs(self.installer.subprocess.DEVNULL, options["stdout"])
        self.assertTrue(options["text"])
        self.assertEqual("utf-8", options["encoding"])
        self.assertEqual("replace", options["errors"])
        self.assertEqual("1", options["env"].get("PYTHONDONTWRITEBYTECODE"))
        self.assertEqual(
            {
                "CODEX_V2_SOURCE_ROOT",
                "CODEX_V2_CODEX_BIN",
                "CODEX_V2_WRAPPER_PATH",
                "CODEX_V2_STATE_HOME",
            },
            set(options["env"]).intersection(
                {
                    "CODEX_V2_SOURCE_ROOT",
                    "CODEX_V2_CODEX_BIN",
                    "CODEX_V2_WRAPPER_PATH",
                    "CODEX_V2_STATE_HOME",
                }
            ),
        )

    def test_supervised_initial_spawn_uses_durable_publication_gate(self) -> None:
        process = SimpleNamespace()
        supervisor = (
            self.installer.operation_process_group_supervisor_v2.
            OperationProcessGroupSupervisorV2()
        )
        lease = (
            self.installer.operation_process_group_supervisor_v2.
            TransientProcessLeaseV2(
                lease_id="transient-" + "f" * 32,
                label="initial-controller",
                pid=8111,
                process_group_id=8111,
                session_id=8111,
                process_start_marker="initial-controller-marker",
                process=process,
            )
        )
        deadline = self.installer.operation_deadline_v2.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=20,
            timeout_code="APPLY_OPERATION_DEADLINE_EXCEEDED",
        )

        with (
            self.installer.operation_deadline_v2.scoped_current_deadline_v2(
                deadline
            ),
            self.installer.operation_process_group_supervisor_v2.
            scoped_current_process_group_supervisor_v2(supervisor),
            mock.patch.object(
                self.installer.supervised_subprocess_v2,
                "spawn_gated_transient_v2",
                return_value=lease,
            ) as gated_spawn,
            mock.patch.object(self.installer.subprocess, "Popen") as popen,
        ):
            returned = self.installer._spawn_initial_controller(
                self.layout,
                source_environment={"HOME": str(self.root)},
            )

        self.assertIs(process, returned)
        popen.assert_not_called()
        gated_spawn.assert_called_once()
        options = gated_spawn.call_args.kwargs
        self.assertEqual(
            (
                str(Path(sys.executable).resolve()),
                str(self.layout.controller_entrypoint),
                "--serve-v2",
            ),
            options["argv"],
        )
        self.assertIs(supervisor, options["supervisor"])
        self.assertIs(deadline, options["cleanup_deadline"])
        self.assertEqual(
            "initial-controller-bootstrap",
            options["gate_deadline"].phase,
        )
        self.assertEqual(self.layout.plugin_source, options["cwd"])
        self.assertIs(self.installer.subprocess.DEVNULL, options["stdin"])
        self.assertIs(self.installer.subprocess.PIPE, options["stderr"])
        self.assertIs(
            supervisor,
            process._codex_process_supervisor_v2,
        )
        self.assertIs(lease, process._codex_process_lease_v2)

    def test_full_ready_wait_requires_resolver_and_command_socket_together(
        self,
    ) -> None:
        decisions = [
            self.ordinary_decision(),
            self.ready_decision(),
            self.ready_decision(),
        ]
        process = SimpleNamespace(poll=mock.Mock(return_value=None))
        with (
            mock.patch.object(
                self.installer,
                "_resolve_activation",
                side_effect=decisions,
            ) as resolver,
            mock.patch.object(
                self.installer,
                "_probe_command_socket",
                side_effect=[False, False, False, True, True],
            ) as command_probe,
            mock.patch.object(self.installer.time, "sleep", return_value=None),
        ):
            result = self.installer._wait_for_full_ready(self.layout, process)

        self.assertEqual(self.activation_id, result.activation_id)
        self.assertEqual(3, resolver.call_count)
        self.assertEqual(5, command_probe.call_count)

    def test_initial_controller_exit_preserves_the_real_startup_error(self) -> None:
        process = SimpleNamespace(
            poll=mock.Mock(return_value=1),
            communicate=mock.Mock(
                return_value=(
                    "",
                    (
                        "codex-smart-subagents-controller: "
                        "SOCKET_PATH_TOO_LONG: Unix socket path is too long\n"
                    ),
                )
            ),
        )
        with mock.patch.object(
            self.installer,
            "_resolve_activation",
            side_effect=self.installer.InstallError(
                "FALLBACK_UNAVAILABLE",
                "аварийная капсула ещё не опубликована",
            ),
        ):
            with self.assertRaises(self.installer.InstallError) as captured:
                self.installer._wait_for_full_ready(self.layout, process)

        self.assertEqual("INITIAL_CONTROLLER_EXITED", captured.exception.code)
        self.assertIn("FALLBACK_UNAVAILABLE", captured.exception.message)
        self.assertIn("SOCKET_PATH_TOO_LONG", captured.exception.message)
        process.communicate.assert_called_once_with(timeout=1.0)


class InstallerV2ApplyTests(_InstallerBase):
    def test_capsule_applies_upgrade_twice_without_the_live_source_tree(
        self,
    ) -> None:
        from codex_smart_subagents.activation_materializer_v2 import (
            _materialize_marketplace,
        )

        root = Path(
            tempfile.mkdtemp(dir=ROOT.parent, prefix=".ce2-")
        ).resolve()
        self.addCleanup(shutil.rmtree, root, True)
        codex_home = root / "c"
        codex_home.mkdir(mode=0o700)
        bin_dir = root / "b"
        bin_dir.mkdir(mode=0o700)
        state_home = root / "s"
        codex_locator = shutil.which("codex")
        self.assertIsNotNone(codex_locator)
        codex_binary = Path(str(codex_locator)).resolve(strict=True)
        layout = self.installer.InstallLayout(
            source_root=ROOT,
            codex_home=codex_home,
            bin_dir=bin_dir,
            codex_binary=codex_binary,
            state_home=state_home,
        )

        def copy_source(destination: Path) -> None:
            for relative in (
                Path(".agents"),
                Path(".claude-plugin"),
                Path(".codex"),
                Path("docs/contracts"),
                Path("plugins/codex-smart-subagents"),
            ):
                shutil.copytree(ROOT / relative, destination / relative)
            installer = destination / "scripts" / "install_adaptive_subagents.py"
            installer.parent.mkdir(mode=0o700)
            shutil.copy2(INSTALLER_PATH, installer)

        def command(source_root: Path) -> list[str]:
            return [
                sys.executable,
                "-B",
                str(source_root / "scripts" / "install_adaptive_subagents.py"),
                "--source-root",
                str(source_root),
                "--codex-home",
                str(codex_home),
                "--bin-dir",
                str(bin_dir),
                "--state-home",
                str(state_home),
                "--codex-binary",
                str(codex_binary),
                "--apply",
                "--json",
            ]

        def recovery_command(source_root: Path, *, apply: bool) -> list[str]:
            return [
                sys.executable,
                str(source_root / "scripts" / "install_adaptive_subagents.py"),
                "--source-root",
                str(source_root),
                "--codex-home",
                str(codex_home),
                "--bin-dir",
                str(bin_dir),
                "--state-home",
                str(state_home),
                "--codex-binary",
                str(codex_binary),
                "--recover",
                "--apply" if apply else "--preview",
                "--json",
            ]

        unrelated = root / "unrelated-workdir"
        unrelated.mkdir(mode=0o700)
        environment = {
            **os.environ,
            "PYTHONPATH": "",
            "PYTHONNOUSERSITE": "1",
        }
        old_source = root / "old-source"
        fixture_source = root / "fixture-source"
        copy_source(old_source)
        copy_source(fixture_source)
        old_readme = old_source / "plugins" / "codex-smart-subagents" / "README.md"
        old_readme.write_bytes(old_readme.read_bytes() + b"\nold fixture source\n")

        initial = subprocess.run(
            command(old_source),
            cwd=unrelated,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(
            0,
            initial.returncode,
            initial.stderr or initial.stdout,
        )
        initial_result = json.loads(initial.stdout)
        self.assertEqual("installed", initial_result["status"])
        self.assertEqual("READY", initial_result["readiness"])

        capsule_activation = root / "capsule-activation"
        capsule_source = capsule_activation / "marketplace"
        capsule_plugin = (
            capsule_source / "plugins" / "codex-smart-subagents"
        )
        capsule_activation.mkdir(mode=0o700)
        _materialize_marketplace(
            source_root=fixture_source,
            marketplace=capsule_source,
            plugin_root=capsule_plugin,
            bundled_catalog={},
        )
        capsule_installer = (
            capsule_source / "scripts" / "install_adaptive_subagents.py"
        )
        self.assertTrue(capsule_installer.is_file())

        old_source.rename(root / "old-source-made-unavailable")
        fixture_source.rename(root / "source-made-unavailable")
        activations_root = layout.gateway_layout.managed_root / "activations"
        before = set(activations_root.iterdir())

        try:
            first = subprocess.run(
                command(capsule_source),
                cwd=unrelated,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=180,
            )
            self.assertEqual(0, first.returncode, first.stderr or first.stdout)
            first_result = json.loads(first.stdout)

            second = subprocess.run(
                command(capsule_source),
                cwd=unrelated,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=180,
            )
            self.assertEqual(0, second.returncode, second.stderr or second.stdout)
            second_result = json.loads(second.stdout)

            self.assertEqual("upgraded", first_result["status"])
            self.assertEqual("READY", first_result["readiness"])
            self.assertEqual("unchanged", second_result["status"])
            self.assertEqual("READY", second_result["readiness"])
            self.assertEqual(
                1,
                len(set(activations_root.iterdir()) - before),
            )
            self.assertEqual(
                first_result["extensions"]["doctor"]["activationId"],
                second_result["extensions"]["doctor"]["activationId"],
            )

            active_activation = (
                activations_root
                / first_result["extensions"]["doctor"]["activationId"]
            )
            package_root = (
                active_activation
                / "marketplace"
                / "plugins"
                / "codex-smart-subagents"
                / "src"
                / "codex_smart_subagents"
            )
            cache = package_root / "__pycache__"
            package_root.chmod(0o700)
            cache.mkdir(mode=0o700)
            bytecode = cache / "catalog.cpython-313.pyc"
            bytecode.write_bytes(b"test-only-bytecode")
            bytecode.chmod(0o600)
            package_root.chmod(0o500)

            preview = subprocess.run(
                recovery_command(capsule_source, apply=False),
                cwd=unrelated,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=180,
            )
            self.assertEqual(2, preview.returncode, preview.stderr or preview.stdout)
            preview_result = json.loads(preview.stdout)
            self.assertEqual("planned", preview_result["status"])
            self.assertEqual(
                "ACTIVATION_BYTECODE_REPAIR_REQUIRED",
                preview_result["extensions"]["bytecodeRepair"]["reasonCode"],
            )

            recovery = subprocess.run(
                recovery_command(capsule_source, apply=True),
                cwd=unrelated,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=180,
            )
            self.assertEqual(
                0,
                recovery.returncode,
                recovery.stderr or recovery.stdout,
            )
            recovery_result = json.loads(recovery.stdout)
            self.assertEqual("recovered", recovery_result["status"])
            self.assertFalse(cache.exists())
            self.assertEqual(0o500, stat.S_IMODE(package_root.stat().st_mode))
        finally:
            admin = bin_dir / "codex-smart-subagents-admin"
            if admin.exists():
                subprocess.run(
                    [str(admin), "stop"],
                    cwd=unrelated,
                    env={**environment, "CODEX_HOME": str(codex_home)},
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

    def test_first_apply_waits_for_full_ready_then_registers_current_link(self) -> None:
        result, events = self.successful_first_apply()

        self.assertEqual("installed", result["status"])
        self.assertEqual("FULL_READY", result["readiness"])
        self.assertEqual(["spawn", "ready"], events)
        manifest = json.loads(
            self.layout.gateway_layout.manifest_path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            manifest["lastCommittedOperation"],
            result["operationId"],
        )
        receipt = json.loads(
            self.layout.installer_receipt_path.read_text(encoding="utf-8")
        )
        self.assertEqual(2, receipt["schemaVersion"])
        self.assertEqual("codex-smart-installer-receipt/v2", receipt["kind"])
        self.assertEqual(self.activation_id, receipt["activationId"])
        self.assertEqual(
            str(self.layout.gateway_layout.marketplace_link),
            receipt["marketplacePath"],
        )
        self.assertEqual(
            str(self.layout.gateway_layout.marketplace_link.resolve(strict=True)),
            receipt["registeredMarketplacePath"],
        )
        self.assertEqual(
            0o600,
            stat.S_IMODE(self.layout.installer_receipt_path.stat().st_mode),
        )
        self.assertTrue(self.layout.launcher_path.is_symlink())
        self.assertEqual(
            str(self.layout.launcher_target),
            os.readlink(self.layout.launcher_path),
        )
        state = json.loads(
            (self.codex_home / "fake-plugin-state.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            str(self.layout.gateway_layout.marketplace_link.resolve(strict=True)),
            state["marketplaces"][0]["root"],
        )
        serialized = json.dumps(result, ensure_ascii=False) + json.dumps(receipt)
        self.assertNotIn("CODEX_V2_SOURCE_ROOT", serialized)
        self.assertNotIn("CODEX_V2_CODEX_BIN", serialized)
        self.assertNotIn("CODEX_V2_WRAPPER_PATH", serialized)
        self.assertNotIn("CODEX_V2_STATE_HOME", serialized)
        commands = [
            json.loads(line)
            for line in (self.codex_home / "fake-command-log.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        self.assertFalse(any("update" in command for command in commands))

    def test_plugin_registration_exactly_matches_primary_manifest(self) -> None:
        self.successful_first_apply()
        state = json.loads(
            (self.codex_home / "fake-plugin-state.json").read_text(encoding="utf-8")
        )
        registration = state["installed"][0]
        self.assertTrue(self.installer._plugin_entry_matches(registration, self.layout))
        mutations = {
            "name": "other-plugin",
            "version": "9.9.9",
            "installPolicy": "UNAVAILABLE",
            "authPolicy": "NEVER",
            "source": {
                "source": "local",
                "path": str(self.root / "other-plugin"),
            },
        }

        for field, value in mutations.items():
            with self.subTest(field=field):
                damaged = copy.deepcopy(registration)
                damaged[field] = value
                self.assertFalse(
                    self.installer._plugin_entry_matches(damaged, self.layout)
                )

    def test_installed_registration_does_not_depend_on_live_source_tree(self) -> None:
        self.successful_first_apply()
        state = json.loads(
            (self.codex_home / "fake-plugin-state.json").read_text(encoding="utf-8")
        )
        registration = state["installed"][0]
        relocated = self.installer.InstallLayout(
            source_root=self.root / "source-no-longer-present",
            codex_home=self.layout.codex_home,
            bin_dir=self.layout.bin_dir,
            codex_binary=self.layout.codex_binary,
            state_home=self.layout.state_home,
        )

        self.assertTrue(
            self.installer._plugin_entry_matches(registration, relocated)
        )

    def test_registration_observation_uses_the_active_immutable_codex_snapshot(
        self,
    ) -> None:
        self.successful_first_apply()
        relocated = self.installer.InstallLayout(
            source_root=self.root / "source-no-longer-present",
            codex_home=self.layout.codex_home,
            bin_dir=self.layout.bin_dir,
            codex_binary=self.root / "selected-codex-no-longer-present",
            state_home=self.layout.state_home,
        )

        problems = self.installer._registration_problems(relocated, None)

        self.assertEqual([], problems)
        runtime_layout = self.installer._registration_runtime_layout_v2(relocated)
        self.assertTrue(runtime_layout.codex_binary.is_file())
        self.assertTrue(os.access(runtime_layout.codex_binary, os.X_OK))
        self.assertEqual(
            self.layout.gateway_layout.managed_root,
            runtime_layout.codex_binary.parents[2],
        )
        self.assertEqual(
            self.layout.gateway_layout.managed_root / "activations" / self.activation_id,
            runtime_layout.source_root,
        )

    def test_registration_observation_rejects_a_changed_active_codex_snapshot(
        self,
    ) -> None:
        self.successful_first_apply()
        runtime_layout = self.installer._registration_runtime_layout_v2(self.layout)
        runtime_layout.codex_binary.chmod(0o700)
        runtime_layout.codex_binary.write_bytes(b"changed")
        runtime_layout.codex_binary.chmod(0o500)

        with self.assertRaises(self.installer.InstallError) as captured:
            self.installer._registration_problems(self.layout, None)

        self.assertEqual("REGISTRATION_RUNTIME_INVALID", captured.exception.code)

    def test_plugin_registration_failure_compensates_only_created_artifacts(
        self,
    ) -> None:
        process = SimpleNamespace(
            poll=lambda: None,
            terminate=mock.Mock(),
            wait=mock.Mock(return_value=0),
            kill=mock.Mock(),
        )

        def wait(_layout, _process):
            self.publish_fake_activation()
            return self.ready_decision()

        def cleanup(*, codex_home, installation_id, activation_id):
            self.assertEqual(self.codex_home, codex_home)
            self.assertEqual(self.installation_id, installation_id)
            self.assertEqual(self.activation_id, activation_id)
            gateway = self.layout.gateway_layout
            gateway.marketplace_link.unlink()
            gateway.manifest_path.unlink()
            return SimpleNamespace(status="ACCEPTED_ACTIVATION_REMOVED")

        with (
            mock.patch.object(
                self.installer,
                "_spawn_initial_controller",
                return_value=process,
            ),
            mock.patch.object(self.installer, "_wait_for_full_ready", wait),
            mock.patch.object(
                self.installer,
                "cleanup_accepted_activation_v2",
                side_effect=cleanup,
            ),
        ):
            with self.assertRaises(self.installer.InstallError) as captured:
                self.installer.install(
                    self.layout,
                    apply=True,
                    extra_environment={"FAKE_CODEX_FAIL_PLUGIN_ADD": "1"},
                )

        self.assertEqual("PLUGIN_ADD_FAILED", captured.exception.code)
        process.terminate.assert_called_once_with()
        self.assertFalse(self.layout.launcher_path.exists())
        self.assertFalse(self.layout.admin_path.exists())
        self.assertFalse(self.layout.installer_receipt_path.exists())
        state = json.loads(
            (self.codex_home / "fake-plugin-state.json").read_text(encoding="utf-8")
        )
        self.assertEqual([], state["marketplaces"])
        self.assertEqual([], state["installed"])

    def test_foreign_stable_link_closes_without_replacing_or_removing_it(self) -> None:
        foreign = self.root / "foreign"
        foreign.write_text("foreign", encoding="utf-8")
        self.layout.launcher_path.symlink_to(foreign)

        with self.assertRaises(self.installer.InstallError) as captured:
            self.installer.install(self.layout, apply=True)

        self.assertEqual("STABLE_LINK_CONFLICT", captured.exception.code)
        self.assertEqual(str(foreign), os.readlink(self.layout.launcher_path))
        self.assertFalse(self.layout.admin_path.exists())
        self.assertFalse(self.layout.gateway_layout.manifest_path.exists())

    def test_schema1_manifest_is_rejected_without_creating_new_artifacts(self) -> None:
        gateway = self.layout.gateway_layout
        gateway.manifest_root.mkdir(mode=0o700)
        gateway.manifest_path.write_text(
            json.dumps({"schemaVersion": 1}),
            encoding="utf-8",
        )
        gateway.manifest_path.chmod(0o600)

        with self.assertRaises(self.installer.InstallError) as captured:
            self.installer.install(self.layout, apply=True)

        self.assertEqual("LEGACY_INSTALLATION_CONFLICT", captured.exception.code)
        self.assertFalse(self.layout.launcher_path.exists())
        self.assertFalse(self.layout.admin_path.exists())
        self.assertFalse(self.layout.installer_receipt_path.exists())


class InstallerV2RepeatTests(_InstallerBase):
    def test_upgrade_with_proven_source_drift_captures_before_supervision(
        self,
    ) -> None:
        events: list[str] = []
        proof = SimpleNamespace(
            activation_id=self.activation_id,
            controller_row={"control_epoch": 4},
        )
        binding = SimpleNamespace(
            activation_id=self.activation_id,
            controller_row={"control_epoch": 4},
        )
        persisted = SimpleNamespace(
            state=self.installer.GatewayState.READY,
            runtime_binding=binding,
            source_drift=object(),
        )
        resolver = mock.Mock()
        resolver.resolve_persisted_activation.return_value = persisted

        def capture(**_kwargs):
            events.append("capture")
            return proof

        with (
            mock.patch.object(
                self.installer,
                "ActivationResolver",
                return_value=resolver,
            ),
            mock.patch.object(
                self.installer,
                "_supervise_existing",
                side_effect=AssertionError(
                    "proven source drift must not require the old controller"
                ),
            ),
            mock.patch.object(
                self.installer,
                "capture_activation_transition_proof_v2",
                side_effect=capture,
            ),
            mock.patch.object(
                self.installer,
                "_try_reconcile_pending_committed_upgrade_v2",
                return_value=None,
            ),
        ):
            result = self.installer._capture_upgrade_transition_proof_v2(
                self.layout,
                extra_environment=None,
            )

        self.assertIs(proof, result.proof)
        self.assertTrue(result.source_drift)
        self.assertEqual(2, resolver.resolve_persisted_activation.call_count)
        self.assertEqual(["capture"], events)

    def test_drift_disappearing_during_capture_restores_supervision(self) -> None:
        proof = SimpleNamespace(
            activation_id=self.activation_id,
            controller_row={"control_epoch": 4},
        )
        binding = SimpleNamespace(
            activation_id=self.activation_id,
            controller_row={"control_epoch": 4},
        )
        drifted = SimpleNamespace(
            state=self.installer.GatewayState.READY,
            runtime_binding=binding,
            source_drift=object(),
        )
        steady = SimpleNamespace(
            state=self.installer.GatewayState.READY,
            runtime_binding=binding,
            source_drift=None,
        )
        resolver = mock.Mock()
        resolver.resolve_persisted_activation.side_effect = [drifted, steady]

        with (
            mock.patch.object(
                self.installer,
                "ActivationResolver",
                return_value=resolver,
            ),
            mock.patch.object(
                self.installer,
                "capture_activation_transition_proof_v2",
                return_value=proof,
            ) as capture,
            mock.patch.object(
                self.installer,
                "_supervise_existing",
                return_value=self.ready_decision(),
            ) as supervise,
        ):
            result = self.installer._capture_upgrade_transition_proof_v2(
                self.layout,
                extra_environment=None,
            )

        self.assertIs(proof, result.proof)
        self.assertFalse(result.source_drift)
        self.assertEqual(2, capture.call_count)
        supervise.assert_called_once_with(
            self.layout,
            extra_environment=None,
        )

    def test_drift_recovery_uses_the_prepared_immutable_candidate(self) -> None:
        candidate = self.root / "candidate"
        plugin_root = (
            candidate
            / "marketplace"
            / "plugins"
            / self.installer.PLUGIN_NAME
        )
        proof = SimpleNamespace(activation_id=self.activation_id)
        receipt = SimpleNamespace(
            activation_intent=SimpleNamespace(activation_dir=candidate),
        )
        decision = dataclasses.replace(
            self.ready_decision(),
            runtime_binding=SimpleNamespace(activation_id=self.activation_id),
            source_drift=object(),
        )

        with mock.patch.object(
            self.installer,
            "_supervise_existing",
            return_value=decision,
        ) as supervise:
            observed = self.installer._recover_drifted_controller_from_candidate_v2(
                self.layout,
                proof=proof,
                preparation_receipt=receipt,
                extra_environment={"TEST_BOUNDARY": "closed"},
            )

        self.assertIs(decision, observed)
        supervise.assert_called_once_with(
            self.layout,
            extra_environment={"TEST_BOUNDARY": "closed"},
            plugin_root=plugin_root,
        )

    def test_drift_recovery_rejects_foreign_runtime_binding(self) -> None:
        candidate = self.root / "candidate"
        proof = SimpleNamespace(activation_id=self.activation_id)
        receipt = SimpleNamespace(
            activation_intent=SimpleNamespace(activation_dir=candidate),
        )
        decision = dataclasses.replace(
            self.ready_decision(),
            runtime_binding=SimpleNamespace(
                activation_id="act2_" + "f" * 64,
            ),
            source_drift=object(),
        )

        with (
            mock.patch.object(
                self.installer,
                "_supervise_existing",
                return_value=decision,
            ),
            self.assertRaises(self.installer.InstallError) as captured,
        ):
            self.installer._recover_drifted_controller_from_candidate_v2(
                self.layout,
                proof=proof,
                preparation_receipt=receipt,
                extra_environment=None,
            )

        self.assertEqual(
            "DRIFT_CONTROLLER_RECOVERY_INVALID",
            captured.exception.code,
        )

    def test_upgrade_orders_historical_proof_recovery_before_composition(
        self,
    ) -> None:
        events: list[str] = []
        current_proof = SimpleNamespace(
            installation_id=self.installation_id,
            current_operation_id=self.operation_id,
            activation_id=self.activation_id,
        )
        historical_proof = SimpleNamespace(name="historical-proof")
        preparation = SimpleNamespace(name="preparation")
        preparation_receipt = SimpleNamespace(name="preparation-receipt")

        def capture(*_args, **_kwargs):
            events.append("capture")
            return self.installer._UpgradeTransitionCaptureV2(
                proof=current_proof,
                source_drift=True,
            )

        def reuse(_layout, *, proof, operation_id):
            self.assertIs(current_proof, proof)
            self.assertTrue(operation_id.startswith("op2_"))
            events.append("reuse-historical-proof")
            return historical_proof

        def build(**kwargs):
            self.assertIs(historical_proof, kwargs["proof"])
            events.append("build-preparation")
            return preparation

        def prepare(**kwargs):
            self.assertIs(historical_proof, kwargs["proof"])
            self.assertIs(preparation, kwargs["preparation"])
            events.append("verify-preparation")
            return preparation_receipt

        def recover(_layout, **kwargs):
            self.assertIs(historical_proof, kwargs["proof"])
            self.assertIs(preparation_receipt, kwargs["preparation_receipt"])
            events.append("recover-controller")

        def compose(_layout, **kwargs):
            self.assertIs(historical_proof, kwargs["proof"])
            self.assertIs(preparation, kwargs["preparation"])
            self.assertIs(preparation_receipt, kwargs["preparation_receipt"])
            events.append("compose")
            return SimpleNamespace(attempt_id="att2_test")

        with (
            mock.patch.object(
                self.installer,
                "_try_reconcile_pending_committed_upgrade_v2",
                return_value=None,
            ),
            mock.patch.object(
                self.installer,
                "_capture_upgrade_transition_proof_v2",
                side_effect=capture,
            ),
            mock.patch.object(
                self.installer,
                "_reuse_persisted_upgrade_transition_proof_v2",
                side_effect=reuse,
            ),
            mock.patch.object(
                self.installer,
                "build_upgrade_preparation_v2",
                side_effect=build,
            ),
            mock.patch.object(
                self.installer,
                "execute_and_verify_upgrade_preparation_v2",
                side_effect=prepare,
            ),
            mock.patch.object(
                self.installer,
                "_recover_drifted_controller_from_candidate_v2",
                side_effect=recover,
            ),
            mock.patch.object(
                self.installer,
                "_execute_fresh_update_composition_v2",
                side_effect=compose,
            ),
            mock.patch.object(
                self.installer,
                "_try_reconcile_committed_upgrade_v2",
                return_value={"sourceDigest": "a" * 64},
            ),
        ):
            result = self.installer._upgrade_install(
                self.layout,
                previous_receipt={},
                source_digest="a" * 64,
                codex_version="0.146.0",
                extra_environment=None,
            )

        self.assertEqual(
            [
                "capture",
                "reuse-historical-proof",
                "build-preparation",
                "verify-preparation",
                "recover-controller",
                "compose",
            ],
            events,
        )
        self.assertEqual("upgraded", result["status"])

    def test_upgrade_recovers_current_controller_before_preparation(self) -> None:
        events: list[str] = []
        persisted = SimpleNamespace(
            state=self.installer.GatewayState.READY,
            runtime_binding=object(),
            source_drift=None,
        )
        resolver = mock.Mock()
        resolver.resolve_persisted_activation.return_value = persisted

        def supervise(*_args, **_kwargs):
            events.append("supervise")
            return self.ready_decision()

        def capture(**_kwargs):
            events.append("capture")
            raise RuntimeError("stop after ordering proof")

        with (
            mock.patch.object(
                self.installer,
                "ActivationResolver",
                return_value=resolver,
            ),
            mock.patch.object(
                self.installer,
                "_supervise_existing",
                side_effect=supervise,
            ),
            mock.patch.object(
                self.installer,
                "capture_activation_transition_proof_v2",
                side_effect=capture,
            ),
            mock.patch.object(
                self.installer,
                "_try_reconcile_pending_committed_upgrade_v2",
                return_value=None,
            ),
            self.assertRaisesRegex(RuntimeError, "ordering proof"),
        ):
            self.installer._upgrade_install(
                self.layout,
                previous_receipt={},
                source_digest="a" * 64,
                codex_version="0.144.4",
                extra_environment=None,
            )

        resolver.resolve_persisted_activation.assert_called_once_with()
        self.assertEqual(["supervise", "capture"], events)

    def test_apply_resumes_first_install_after_registration_before_receipt(
        self,
    ) -> None:
        source_digest = self.installer._source_digest(self.layout)
        journal = self.installer._build_first_install_journal_v2(
            self.layout,
            source_digest=source_digest,
            codex_version="0.144.4",
        )
        self.installer._atomic_create_json(
            self.layout.first_install_journal_path,
            journal,
            conflict_code="FIRST_INSTALL_JOURNAL_CONFLICT",
        )
        self.installer._create_stable_link(
            self.layout.launcher_path,
            self.layout.launcher_target,
        )
        self.installer._create_stable_link(
            self.layout.admin_path,
            self.layout.admin_target,
        )
        self.publish_fake_activation()
        self.installer._add_marketplace(self.layout, None)
        self.installer._add_plugin(self.layout, None)

        with mock.patch.object(
            self.installer,
            "_supervise_existing",
            return_value=self.ready_decision(),
        ) as supervise:
            resumed = self.installer.install(self.layout, apply=True)
            repeated = self.installer.install(self.layout, apply=True)

        self.assertEqual("installed", resumed["status"])
        self.assertEqual("unchanged", repeated["status"])
        self.assertFalse(self.layout.first_install_journal_path.exists())
        self.assertTrue(self.layout.installer_receipt_path.exists())
        self.assertEqual(2, supervise.call_count)
        state = json.loads(
            (self.codex_home / "fake-plugin-state.json").read_text(encoding="utf-8")
        )
        self.assertEqual(1, len(state["marketplaces"]))
        self.assertEqual(1, len(state["installed"]))

    def test_recover_previews_and_finishes_the_same_first_install_journal(
        self,
    ) -> None:
        source_digest = self.installer._source_digest(self.layout)
        journal = self.installer._build_first_install_journal_v2(
            self.layout,
            source_digest=source_digest,
            codex_version="0.144.4",
        )
        self.installer._atomic_create_json(
            self.layout.first_install_journal_path,
            journal,
            conflict_code="FIRST_INSTALL_JOURNAL_CONFLICT",
        )
        self.installer._create_stable_link(
            self.layout.launcher_path,
            self.layout.launcher_target,
        )
        self.installer._create_stable_link(
            self.layout.admin_path,
            self.layout.admin_target,
        )
        self.publish_fake_activation()
        self.installer._add_marketplace(self.layout, None)
        self.installer._add_plugin(self.layout, None)

        preview = self.installer.recover_installation_v2(
            self.layout,
            execute=False,
        )
        self.assertEqual("planned", preview["status"])
        self.assertEqual(
            "first-install",
            preview["extensions"]["lifecycleAdapter"]["journalKind"],
        )
        self.assertEqual(
            journal["operationId"],
            preview["extensions"]["lifecycleAdapter"]["internalOperationId"],
        )

        self.installer._ensure_lock_file(self.layout.lock_path)
        with mock.patch.object(
            self.installer,
            "_supervise_existing",
            return_value=self.ready_decision(),
        ):
            recovered = self.installer.recover_installation_v2(
                self.layout,
                execute=True,
            )

        self.assertEqual("recovered", recovered["status"])
        self.assertEqual(journal["operationId"], recovered["operationId"])
        self.assertFalse(self.layout.first_install_journal_path.exists())
        self.assertTrue(self.layout.installer_receipt_path.exists())

    def test_same_digest_and_full_ready_returns_unchanged_via_supervisor(self) -> None:
        first, _events = self.successful_first_apply()
        receipt_before = self.layout.installer_receipt_path.read_bytes()
        supervised: list[Path] = []

        def supervise(layout, extra_environment=None):
            supervised.append(layout.installed_plugin_root)
            return self.ready_decision()

        with (
            mock.patch.object(
                self.installer,
                "_supervise_existing",
                side_effect=supervise,
            ),
            mock.patch.object(
                self.installer,
                "_spawn_initial_controller",
                side_effect=AssertionError("repeat must not direct-spawn"),
            ),
        ):
            second = self.installer.install(self.layout, apply=True)

        self.assertEqual("installed", first["status"])
        self.assertEqual("unchanged", second["status"])
        self.assertEqual([self.layout.installed_plugin_root], supervised)
        self.assertEqual(
            receipt_before,
            self.layout.installer_receipt_path.read_bytes(),
        )

    def test_changed_codex_binary_enters_upgrade_before_supervisor(self) -> None:
        self.successful_first_apply()
        previous_receipt = self.installer._load_installer_receipt(
            self.layout.installer_receipt_path
        )
        self.fake_codex.write_bytes(
            self.fake_codex.read_bytes() + b"\n# upgraded codex binary\n"
        )
        self.fake_codex.chmod(0o700)
        expected_digest = self.installer._source_digest(self.layout)

        with (
            mock.patch.object(
                self.installer,
                "_upgrade_install",
                return_value={"status": "upgraded"},
            ) as upgrade,
            mock.patch.object(
                self.installer,
                "_supervise_existing",
                side_effect=AssertionError("upgrade must precede supervisor"),
            ),
        ):
            result = self.installer.install(self.layout, apply=True)

        self.assertEqual({"status": "upgraded"}, result)
        upgrade.assert_called_once_with(
            self.layout,
            previous_receipt=previous_receipt,
            source_digest=expected_digest,
            codex_version="0.144.4",
            extra_environment=None,
        )

    def test_lifecycle_without_installer_receipt_is_not_adopted(self) -> None:
        self.publish_fake_activation()

        with self.assertRaises(self.installer.InstallError) as captured:
            self.installer.install(self.layout, apply=True)

        self.assertEqual("INSTALLER_RECEIPT_MISSING", captured.exception.code)

    def test_changed_registration_closes_repeat(self) -> None:
        self.successful_first_apply()
        state_path = self.codex_home / "fake-plugin-state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["marketplaces"][0]["root"] = str(self.root / "other")
        state_path.write_text(json.dumps(state), encoding="utf-8")

        with self.assertRaises(self.installer.InstallError) as captured:
            self.installer.install(self.layout, apply=True)

        self.assertEqual("INSTALLATION_MISMATCH", captured.exception.code)

    def test_changed_canonical_path_in_receipt_closes_repeat(self) -> None:
        self.successful_first_apply()
        receipt = json.loads(
            self.layout.installer_receipt_path.read_text(encoding="utf-8")
        )
        receipt["registeredMarketplacePath"] = str(self.root / "other-marketplace")
        self.layout.installer_receipt_path.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        self.layout.installer_receipt_path.chmod(0o600)

        with self.assertRaises(self.installer.InstallError) as captured:
            self.installer.install(self.layout, apply=True)

        self.assertEqual("INSTALLATION_MISMATCH", captured.exception.code)

    def test_supervisor_adapter_uses_the_installed_activation_contract(self) -> None:
        self.successful_first_apply()
        captured: dict[str, object] = {}

        class FakeSupervisor:
            def __init__(_self, **kwargs):
                captured.update(kwargs)

            def ensure(_self):
                from codex_smart_subagents.controller_supervisor_v2 import (
                    SupervisorStateV2,
                )

                return SimpleNamespace(
                    state=SupervisorStateV2.READY,
                    gateway_decision=self.ready_decision(),
                    reason_code="READY",
                )

        with mock.patch.object(
            self.installer,
            "ControllerSupervisorV2",
            FakeSupervisor,
        ):
            decision = self.installer._supervise_existing(self.layout)

        self.assertEqual(self.activation_id, decision.activation_id)
        self.assertEqual(
            self.layout.installed_plugin_root.resolve(),
            captured["plugin_root"],
        )
        self.assertEqual(
            self.layout.gateway_layout.manifest_path,
            captured["manifest_path"],
        )
        self.assertEqual(self.layout.state_home, captured["state_home"])
        self.assertEqual(self.codex_home, captured["codex_home"])
        self.assertEqual(
            self.installer._FULL_READY_TIMEOUT_SECONDS,
            captured["wait_timeout_seconds"],
        )


class InstallerV2DoctorTests(_InstallerBase):
    def setUp(self) -> None:
        super().setUp()
        self.successful_first_apply()

    def test_doctor_distinguishes_ordinary_health_only_and_full_ready(self) -> None:
        cases = (
            (self.ordinary_decision(), False, "ORDINARY", False),
            (self.ready_decision(), False, "HEALTH_ONLY", False),
            (self.ready_decision(), True, "FULL_READY", True),
        )
        for decision, command_ready, status, ok in cases:
            with self.subTest(status=status):
                with (
                    mock.patch.object(
                        self.installer,
                        "_resolve_activation",
                        return_value=decision,
                    ),
                    mock.patch.object(
                        self.installer,
                        "_probe_command_socket",
                        return_value=command_ready,
                    ),
                ):
                    result = self.installer.doctor(self.layout)
                self.assertEqual(status, result["status"])
                self.assertIs(ok, result["ok"])

    def test_health_only_never_allows_smoke(self) -> None:
        with (
            mock.patch.object(
                self.installer,
                "_resolve_activation",
                return_value=self.ready_decision(),
            ),
            mock.patch.object(
                self.installer,
                "_probe_command_socket",
                return_value=False,
            ),
        ):
            with self.assertRaises(self.installer.InstallError) as captured:
                self.installer.smoke(self.layout)

        self.assertEqual("INSTALLATION_NOT_FULL_READY", captured.exception.code)

    def test_doctor_checks_the_committed_codex_path_not_the_next_desired_path(
        self,
    ) -> None:
        relocated = self.installer.InstallLayout(
            source_root=self.root / "next-source",
            codex_home=self.layout.codex_home,
            bin_dir=self.layout.bin_dir,
            codex_binary=self.root / "next-codex",
            state_home=self.layout.state_home,
        )
        with (
            mock.patch.object(
                self.installer,
                "_resolve_activation",
                return_value=self.ready_decision(),
            ),
            mock.patch.object(
                self.installer,
                "_probe_command_socket",
                return_value=True,
            ),
        ):
            result = self.installer.doctor(relocated)

        self.assertTrue(result["ok"])
        self.assertNotIn("INSTALLER_RECEIPT_MISMATCH", result["problems"])


if __name__ == "__main__":
    unittest.main()

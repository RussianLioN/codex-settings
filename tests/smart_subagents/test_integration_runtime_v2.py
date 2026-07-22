from __future__ import annotations

import copy
import json
import importlib.util
import os
import sqlite3
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN / "scripts"))
sys.path.insert(0, str(PLUGIN / "src"))

from integration_runtime_v2 import (  # noqa: E402
    FreshActivationProviderV2,
    HookTurnContextV2,
    IntegrationConfigV2,
    IntegrationV2Error,
    TurnContextStoreV2,
)
from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    GatewayDecision,
    GatewayRuntimeBindingV2,
    GatewayState,
)
from codex_smart_subagents import operation_deadline_v2  # noqa: E402
from codex_smart_subagents.mcp_contracts_v2 import (  # noqa: E402
    get_tool_definitions_v2,
)
from codex_smart_subagents.mcp_runtime_proof_v2 import (  # noqa: E402
    MCPRuntimeAttestationPublisherV2,
    MCP_SESSION_NONCE_ENV_V2,
    USER_MCP_POLICY_PROOF_ENV_V2,
    build_user_mcp_policy_proof_v2,
)
from codex_smart_subagents.mcp_server_v2 import (  # noqa: E402
    MCP_PROTOCOL,
    SERVER_NAME,
    SERVER_VERSION,
)


class _Resolver:
    def __init__(self, decision: GatewayDecision) -> None:
        self.decision = decision

    def resolve(self) -> GatewayDecision:
        return self.decision


class IntegrationRuntimeV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="csir2-")
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.user_config = self.codex_home / "config.toml"
        self.user_config.write_text(
            '[plugins."codex-smart-subagents@codex-settings-adaptive"]\n'
            "enabled = true\n",
            encoding="utf-8",
        )
        self.user_config.chmod(0o600)
        self.state_home = self.codex_home / "state" / "codex-smart-subagents-v2"
        self.state_home.mkdir(parents=True, mode=0o700)
        self.gateway = self.root / "codex-smart"
        self.gateway.write_bytes(b"#!/bin/sh\n")
        self.gateway.chmod(0o500)
        self.catalog = self.root / "adaptive-subagents.toml"
        self.catalog.write_text("schema_version = 1\n", encoding="utf-8")
        self.activation_fingerprint = "a" * 64
        self.compatibility_fingerprint = "b" * 64
        self.gate_fingerprint = "c" * 64
        self.activation_id = "act2_" + self.activation_fingerprint
        self.config = IntegrationConfigV2.from_environ(self._environment())
        self.record = HookTurnContextV2(
            shell_session_id="cas2_" + "s" * 32,
            session_id="session-1",
            turn_id="turn-1",
            codex_home=str(self.codex_home),
            repo_root=str(self.root),
            base_sha="d" * 40,
            worktree_fingerprint="e" * 64,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _environment(self) -> dict[str, str]:
        return {
            "CODEX_SMART_LAUNCHER_ACTIVE": "1",
            "CODEX_ADAPTIVE_SESSION_ID": "cas2_" + "s" * 32,
            "CODEX_HOME": str(self.codex_home),
            "CODEX_SMART_STATE_HOME": str(self.state_home),
            "CODEX_SMART_GATEWAY_PATH": str(self.gateway),
            "CODEX_SMART_ACTIVATION_ID": self.activation_id,
            "CODEX_SMART_GATE_FINGERPRINT": self.gate_fingerprint,
            "CODEX_ADAPTIVE_CATALOG": str(self.catalog),
        }

    def _decision(self) -> GatewayDecision:
        database = self.state_home / "databases" / ("db2_" + "f" * 32)
        database.mkdir(parents=True, mode=0o700)
        database_path = database / "smart-subagents.sqlite3"
        marketplace = self.root / "marketplace"
        marketplace.mkdir(exist_ok=True, mode=0o700)
        database_row = {
            "activation_id": self.activation_id,
            "activation_fingerprint": self.activation_fingerprint,
        }
        controller_row = {
            "activation_id": self.activation_id,
            "activation_fingerprint": self.activation_fingerprint,
            "compatibility_fingerprint": self.compatibility_fingerprint,
            "control_epoch": 7,
        }
        binding = GatewayRuntimeBindingV2(
            activation_id=self.activation_id,
            activation_fingerprint=self.activation_fingerprint,
            compatibility_fingerprint=self.compatibility_fingerprint,
            control_epoch=7,
            state_home=self.state_home,
            marketplace_path=marketplace,
            database_path=database_path,
            database_identity_row=database_row,
            controller_row=controller_row,
            interface_evidence={"compatibilityFingerprint": self.compatibility_fingerprint},
            activation_identity={"codexSnapshot": {"absolutePath": str(self.gateway)}},
        )
        return GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.gateway,
            coordinator={"model": "coordinator", "reasoning_effort": "medium"},
            activation_id=self.activation_id,
            gate_fingerprint=self.gate_fingerprint,
            activation_gate={
                "manifestSemanticFingerprint": "1" * 64,
                "activationReceiptFingerprint": "2" * 64,
                "journalAbsenceProof": {},
                "gateFingerprint": self.gate_fingerprint,
            },
            catalog_path=self.catalog,
            runtime_binding=binding,
        )

    def _proven_environment(
        self,
    ) -> tuple[dict[str, str], MCPRuntimeAttestationPublisherV2]:
        environment = self._environment()
        environment[MCP_SESSION_NONCE_ENV_V2] = "mcpn2_" + "f" * 64
        environment[USER_MCP_POLICY_PROOF_ENV_V2] = (
            build_user_mcp_policy_proof_v2(self.codex_home)
        )
        publisher = MCPRuntimeAttestationPublisherV2.from_environ(environment)
        publisher.publish(
            get_tool_definitions_v2(),
            server_name=SERVER_NAME,
            server_version=SERVER_VERSION,
            protocol_version=MCP_PROTOCOL,
        )
        return environment, publisher

    def test_private_turn_record_round_trips_and_rejects_tampering(self) -> None:
        store = TurnContextStoreV2(self.config)
        store.save(self.record)

        self.assertEqual(self.record, store.load())
        self.assertEqual(0o600, stat.S_IMODE(store.path.stat().st_mode))
        encoded = json.loads(store.path.read_text(encoding="utf-8"))
        encoded["turnId"] = "other-turn"
        store.path.write_text(json.dumps(encoded), encoding="utf-8")
        store.path.chmod(0o600)

        with self.assertRaisesRegex(IntegrationV2Error, "отпечаток"):
            store.load()

    def test_required_mcp_contract_is_closed_and_uses_effective_approve(self) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        plugin_root = self.root / "plugin"
        plugin_root.mkdir()
        config = json.loads((PLUGIN / ".mcp.json").read_text(encoding="utf-8"))
        (plugin_root / ".mcp.json").write_text(
            json.dumps(config),
            encoding="utf-8",
        )
        runtime.require_mcp_contract_v2(plugin_root)

        def server(value: dict[str, object]) -> dict[str, object]:
            return value["mcpServers"]["codex-smart-subagents"]

        cases: list[tuple[str, object]] = [
            ("required-false", lambda value: server(value).__setitem__("required", False)),
            ("required-int", lambda value: server(value).__setitem__("required", 1)),
            (
                "approval-auto",
                lambda value: server(value).__setitem__(
                    "default_tools_approval_mode", "auto"
                ),
            ),
            (
                "env-extra",
                lambda value: server(value)["env_vars"].append("UNEXPECTED"),
            ),
            (
                "disabled-tool",
                lambda value: server(value).__setitem__(
                    "disabled_tools", ["smart_plan"]
                ),
            ),
            ("server-disabled", lambda value: server(value).__setitem__("enabled", False)),
            (
                "tool-auto",
                lambda value: server(value).__setitem__(
                    "tools", {"smart_plan": {"approval_mode": "auto"}}
                ),
            ),
            ("unknown", lambda value: server(value).__setitem__("unexpected", True)),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                invalid = copy.deepcopy(config)
                mutate(invalid)
                (plugin_root / ".mcp.json").write_text(
                    json.dumps(invalid),
                    encoding="utf-8",
                )
                with self.assertRaises(IntegrationV2Error):
                    runtime.require_mcp_contract_v2(plugin_root)

    def test_provider_combines_hook_identity_with_fresh_gateway_binding(self) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        decision = self._decision()
        provider = FreshActivationProviderV2(
            self.config,
            resolver_factory=lambda _config: _Resolver(decision),
        )

        context = provider.request_context()

        self.assertEqual(self.record.turn_id, context.turn_id)
        self.assertEqual(self.activation_fingerprint, context.activation_fingerprint)
        self.assertEqual(self.compatibility_fingerprint, context.compatibility_fingerprint)
        self.assertEqual(7, context.issued_control_epoch)
        self.assertEqual(decision.activation_gate, provider.activation_gate())
        self.assertEqual(decision.runtime_binding, provider.runtime_binding())

    def test_provider_rejects_activation_changed_after_root_session_launch(self) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        decision = self._decision()
        decision = GatewayDecision(
            **{
                **decision.__dict__,
                "gate_fingerprint": "9" * 64,
                "activation_gate": {
                    **dict(decision.activation_gate or {}),
                    "gateFingerprint": "9" * 64,
                },
            }
        )
        provider = FreshActivationProviderV2(
            self.config,
            resolver_factory=lambda _config: _Resolver(decision),
        )

        with self.assertRaisesRegex(IntegrationV2Error, "после запуска"):
            provider.request_context()

    def test_live_controller_check_repeats_ready_resolution_in_hook_deadline(
        self,
    ) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        observed_deadlines: list[object] = []

        class ObservingResolver(_Resolver):
            def resolve(self) -> GatewayDecision:
                observed_deadlines.append(
                    operation_deadline_v2.current_operation_deadline_v2()
                )
                return super().resolve()

        runtime.require_live_controller_v2(
            self.config,
            deadline=time.monotonic() + 1,
            resolver_factory=lambda _config: ObservingResolver(self._decision()),
        )

        self.assertEqual(1, len(observed_deadlines))
        self.assertIsNotNone(observed_deadlines[0])
        self.assertIsNone(operation_deadline_v2.current_operation_deadline_v2())

        ordinary = GatewayDecision(
            state=GatewayState.ORDINARY,
            reason_code="CONTROLLER_UNAVAILABLE",
            executable=self.gateway,
        )
        with self.assertRaisesRegex(IntegrationV2Error, "контроллер"):
            runtime.require_live_controller_v2(
                self.config,
                deadline=time.monotonic() + 1,
                resolver_factory=lambda _config: _Resolver(ordinary),
            )

    def test_config_rejects_relative_or_incomplete_adaptive_environment(self) -> None:
        environment = self._environment()
        environment["CODEX_SMART_STATE_HOME"] = "relative"
        with self.assertRaises(IntegrationV2Error):
            IntegrationConfigV2.from_environ(environment)

    def test_durable_turn_state_is_read_from_the_proven_turn_database(self) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        self.assertTrue(
            hasattr(runtime, "durable_smart_turn_state_v2"),
            "нужен проверяемый читатель полного состояния умного хода",
        )
        decision = self._decision()
        database_path = decision.runtime_binding.database_path
        connection = sqlite3.connect(database_path)
        try:
            connection.execute(
                "create table routes ("
                "shell_session_id text not null,"
                "session_id text not null,"
                "turn_id text not null,"
                "disposition text not null,"
                "state text not null)"
            )
            connection.commit()
        finally:
            connection.close()
        database_path.chmod(0o600)
        observed_deadlines: list[object] = []

        class ObservingResolver(_Resolver):
            def resolve(self) -> GatewayDecision:
                observed_deadlines.append(
                    operation_deadline_v2.current_operation_deadline_v2()
                )
                return super().resolve()

        resolver = lambda _config: ObservingResolver(decision)

        self.assertEqual(
            "MISSING",
            runtime.durable_smart_turn_state_v2(
                self.config,
                self.record,
                resolver_factory=resolver,
                deadline=time.monotonic() + 1,
            )
        )
        self.assertIsNotNone(observed_deadlines[-1])
        self.assertIsNone(operation_deadline_v2.current_operation_deadline_v2())

        connection = sqlite3.connect(database_path)
        try:
            cursor = connection.execute(
                "insert into routes values (?,?,?,?,?)",
                (
                    self.record.shell_session_id,
                    self.record.session_id,
                    self.record.turn_id,
                    "delegate",
                    "PLANNED",
                ),
            )
            connection.commit()
        finally:
            connection.close()

        self.assertEqual(
            "DELEGATE_PENDING",
            runtime.durable_smart_turn_state_v2(
                self.config,
                self.record,
                resolver_factory=resolver,
                deadline=time.monotonic() + 1,
            ),
        )
        self.assertTrue(
            runtime.durable_smart_plan_exists_v2(
                self.config,
                self.record,
                resolver_factory=resolver,
                deadline=time.monotonic() + 1,
            )
        )

        connection = sqlite3.connect(database_path)
        try:
            connection.execute(
                "update routes set state='SUCCEEDED' where rowid=?",
                (cursor.lastrowid,),
            )
            connection.commit()
        finally:
            connection.close()
        self.assertEqual(
            "DELEGATE_TERMINAL",
            runtime.durable_smart_turn_state_v2(
                self.config,
                self.record,
                resolver_factory=resolver,
                deadline=time.monotonic() + 1,
            ),
        )

        connection = sqlite3.connect(database_path)
        try:
            connection.execute(
                "update routes set disposition='direct',state='DIRECT' "
                "where rowid=?",
                (cursor.lastrowid,),
            )
            connection.commit()
        finally:
            connection.close()
        self.assertEqual(
            "DIRECT",
            runtime.durable_smart_turn_state_v2(
                self.config,
                self.record,
                resolver_factory=resolver,
                deadline=time.monotonic() + 1,
            ),
        )

        connection = sqlite3.connect(database_path)
        try:
            connection.execute(
                "update routes set disposition='clarify',state='CLARIFY' "
                "where rowid=?",
                (cursor.lastrowid,),
            )
            connection.commit()
        finally:
            connection.close()
        self.assertEqual(
            "CLARIFY",
            runtime.durable_smart_turn_state_v2(
                self.config,
                self.record,
                resolver_factory=resolver,
                deadline=time.monotonic() + 1,
            ),
        )

    def test_user_prompt_falls_back_when_required_mcp_contract_is_unproved(
        self,
    ) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location("smart_prompt_unproved_test", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        payload = {
            "session_id": "session-from-hook",
            "turn_id": "turn-from-hook",
            "cwd": str(ROOT),
            "hook_event_name": "UserPromptSubmit",
        }

        def unproved(_plugin_root: Path) -> None:
            raise IntegrationV2Error("обязательные инструменты не доказаны")

        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        response = module.handle(
            payload,
            environment,
            v2_mcp_contract_checker=unproved,
            v2_controller_checker=lambda _config, *, deadline: None,
        )

        self.assertTrue(response["continue"])
        self.assertNotIn("hookSpecificOutput", response)
        self.assertIn("обычном режиме", response["systemMessage"].lower())
        with self.assertRaises(IntegrationV2Error):
            TurnContextStoreV2(self.config).load()

    def test_user_prompt_requires_live_controller_before_writing_turn(self) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location(
            "smart_prompt_dead_controller_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)

        def dead_controller(
            _config: IntegrationConfigV2,
            *,
            deadline: float,
        ) -> None:
            self.assertGreater(deadline, time.monotonic())
            raise IntegrationV2Error("контроллер завершился после tools/list")

        response = module.handle(
            {
                "session_id": "session-from-hook",
                "turn_id": "turn-from-hook",
                "cwd": str(ROOT),
                "hook_event_name": "UserPromptSubmit",
            },
            environment,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=dead_controller,
        )

        self.assertTrue(response["continue"])
        self.assertNotIn("hookSpecificOutput", response)
        self.assertIn("обычном режиме", response["systemMessage"].lower())
        self.assertFalse(TurnContextStoreV2(self.config).path.exists())

    def test_user_prompt_requires_current_policy_and_live_mcp_attestation(
        self,
    ) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location("smart_prompt_proofs_test", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        payload = {
            "session_id": "session-from-hook",
            "turn_id": "turn-from-hook",
            "cwd": str(ROOT),
            "hook_event_name": "UserPromptSubmit",
        }
        store = TurnContextStoreV2(self.config)

        valid, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        response = module.handle(
            payload,
            valid,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=lambda _config, *, deadline: None,
        )
        self.assertIn("hookSpecificOutput", response)
        self.assertEqual("turn-from-hook", store.load().turn_id)
        store.path.unlink()

        missing_proof = dict(valid)
        missing_proof.pop(USER_MCP_POLICY_PROOF_ENV_V2)
        response = module.handle(
            payload,
            missing_proof,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=lambda _config, *, deadline: None,
        )
        self.assertNotIn("hookSpecificOutput", response)
        self.assertIn("обычном режиме", response["systemMessage"].lower())
        self.assertFalse(store.path.exists())

        damaged_proof = dict(valid)
        damaged_proof[USER_MCP_POLICY_PROOF_ENV_V2] = "damaged"
        response = module.handle(
            payload,
            damaged_proof,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=lambda _config, *, deadline: None,
        )
        self.assertNotIn("hookSpecificOutput", response)
        self.assertFalse(store.path.exists())

        publisher.cleanup()
        response = module.handle(
            payload,
            valid,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=lambda _config, *, deadline: None,
        )
        self.assertNotIn("hookSpecificOutput", response)
        self.assertFalse(store.path.exists())

    def test_changed_config_and_missing_proof_never_enter_stop_cycle(self) -> None:
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        self.user_config.write_bytes(self.user_config.read_bytes() + b"\n")
        self.user_config.chmod(0o600)
        prompt_path = PLUGIN / "hooks" / "user_prompt_submit.py"
        prompt_spec = importlib.util.spec_from_file_location(
            "smart_prompt_changed_policy_test",
            prompt_path,
        )
        assert prompt_spec is not None and prompt_spec.loader is not None
        prompt_module = importlib.util.module_from_spec(prompt_spec)
        sys.modules[prompt_spec.name] = prompt_module
        prompt_spec.loader.exec_module(prompt_module)
        response = prompt_module.handle(
            {
                "session_id": self.record.session_id,
                "turn_id": self.record.turn_id,
                "cwd": str(ROOT),
                "hook_event_name": "UserPromptSubmit",
            },
            environment,
            v2_mcp_contract_checker=lambda _plugin_root: None,
        )
        self.assertNotIn("hookSpecificOutput", response)

        TurnContextStoreV2(self.config).save(self.record)
        environment.pop(USER_MCP_POLICY_PROOF_ENV_V2)
        stop_path = PLUGIN / "hooks" / "stop.py"
        stop_spec = importlib.util.spec_from_file_location(
            "smart_stop_missing_proof_test",
            stop_path,
        )
        assert stop_spec is not None and stop_spec.loader is not None
        stop_module = importlib.util.module_from_spec(stop_spec)
        sys.modules[stop_spec.name] = stop_module
        stop_spec.loader.exec_module(stop_module)

        self.assertIsNone(
            stop_module.handle(
                {
                    "session_id": self.record.session_id,
                    "turn_id": self.record.turn_id,
                    "hook_event_name": "Stop",
                },
                environment,
                v2_plan_state_provider=lambda *_args, **_kwargs: self.fail(
                    "Stop не должен читать план без proof"
                ),
            )
        )
        self.assertEqual(0, TurnContextStoreV2(self.config).load().continuation_count)

    def test_user_prompt_hook_writes_v2_turn_and_names_only_v2_tools(self) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location("smart_prompt_hook_v2_test", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        payload = {
            "session_id": "session-from-hook",
            "turn_id": "turn-from-hook",
            "cwd": str(ROOT),
            "hook_event_name": "UserPromptSubmit",
        }

        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        response = module.handle(
            payload,
            environment,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=lambda _config, *, deadline: None,
        )

        self.assertTrue(response["continue"])
        context = response["hookSpecificOutput"]["additionalContext"]
        self.assertIn("route_start", context)
        self.assertNotIn("smart_start", context)
        saved = TurnContextStoreV2(self.config).load()
        self.assertEqual("session-from-hook", saved.session_id)
        self.assertEqual("turn-from-hook", saved.turn_id)

        stop_path = PLUGIN / "hooks" / "stop.py"
        stop_spec = importlib.util.spec_from_file_location(
            "smart_stop_hook_v2_test", stop_path
        )
        assert stop_spec is not None and stop_spec.loader is not None
        stop_module = importlib.util.module_from_spec(stop_spec)
        sys.modules[stop_spec.name] = stop_module
        stop_spec.loader.exec_module(stop_module)
        stop_payload = {
            "session_id": "session-from-hook",
            "turn_id": "turn-from-hook",
            "hook_event_name": "Stop",
        }
        for expected_count in (1, 2):
            continuation = stop_module.handle(
                stop_payload,
                environment,
                v2_plan_state_provider=(
                    lambda _config, _record, *, deadline: "MISSING"
                ),
            )
            self.assertEqual("block", continuation["decision"])
            self.assertIn("smart_plan", continuation["reason"])
            self.assertNotIn("continue", continuation)
            self.assertNotIn("hookSpecificOutput", continuation)
            self.assertEqual(
                expected_count,
                TurnContextStoreV2(self.config).load().continuation_count,
            )

        bounded = stop_module.handle(
            stop_payload,
            environment,
            v2_plan_state_provider=lambda _config, _record, *, deadline: "MISSING",
        )
        self.assertTrue(bounded["continue"])
        self.assertIn("двух попыток", bounded["systemMessage"].lower())
        self.assertEqual(2, TurnContextStoreV2(self.config).load().continuation_count)

        self.assertIsNone(
            stop_module.handle(
                stop_payload,
                environment,
                v2_plan_state_provider=lambda _config, _record, *, deadline: "DIRECT",
            )
        )
        environment = self._environment()
        del environment["CODEX_SMART_GATE_FINGERPRINT"]
        with self.assertRaises(IntegrationV2Error):
            IntegrationConfigV2.from_environ(environment)

    def test_v2_stop_uses_one_bounded_turn_lock_acquisition(self) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        path = PLUGIN / "hooks" / "stop.py"
        spec = importlib.util.spec_from_file_location("smart_stop_one_lock_test", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        runtime = sys.modules["integration_runtime_v2"]
        original = runtime.finite_file_lock_v2.acquire_flock_v2

        with mock.patch.object(
            runtime.finite_file_lock_v2,
            "acquire_flock_v2",
            wraps=original,
        ) as acquire:
            response = module.handle(
                {
                    "session_id": self.record.session_id,
                    "turn_id": self.record.turn_id,
                    "hook_event_name": "Stop",
                },
                environment,
                v2_plan_state_provider=(
                    lambda _config, _record, *, deadline: "MISSING"
                ),
            )

        self.assertEqual("block", response["decision"])
        self.assertEqual(1, acquire.call_count)
        self.assertLessEqual(
            acquire.call_args.kwargs["timeout_seconds"],
            runtime.HOOK_TOTAL_BUDGET_SECONDS,
        )

    def test_v2_stop_shares_one_absolute_deadline_with_plan_check(self) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        path = PLUGIN / "hooks" / "stop.py"
        spec = importlib.util.spec_from_file_location("smart_stop_deadline_test", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        runtime = sys.modules["integration_runtime_v2"]
        original = runtime.finite_file_lock_v2.acquire_flock_v2
        lock_timeouts: list[float] = []
        provider_remaining: list[float] = []

        def delayed_lock(descriptor: int, **kwargs: object) -> None:
            timeout_seconds = float(kwargs["timeout_seconds"])
            lock_timeouts.append(timeout_seconds)
            time.sleep(0.12)
            original(
                descriptor,
                exclusive=bool(kwargs["exclusive"]),
                timeout_seconds=max(0.001, timeout_seconds - 0.12),
                timeout_code=str(kwargs["timeout_code"]),
            )

        def delayed_plan_check(
            _config: IntegrationConfigV2,
            _record: HookTurnContextV2,
            *,
            deadline: float,
        ) -> str:
            provider_remaining.append(deadline - time.monotonic())
            time.sleep(0.02)
            return "MISSING"

        started = time.monotonic()
        with (
            mock.patch.object(
                module,
                "HOOK_TOTAL_BUDGET_SECONDS_V2",
                0.20,
                create=True,
            ),
            mock.patch.object(
                runtime.finite_file_lock_v2,
                "acquire_flock_v2",
                side_effect=delayed_lock,
            ),
        ):
            response = module.handle(
                {
                    "session_id": self.record.session_id,
                    "turn_id": self.record.turn_id,
                    "hook_event_name": "Stop",
                },
                environment,
                v2_plan_state_provider=delayed_plan_check,
            )
        elapsed = time.monotonic() - started

        self.assertEqual("block", response["decision"])
        self.assertEqual(1, len(lock_timeouts))
        self.assertLessEqual(lock_timeouts[0], 0.20)
        self.assertEqual(1, len(provider_remaining))
        self.assertGreater(provider_remaining[0], 0)
        self.assertLess(provider_remaining[0], 0.10)
        self.assertLess(elapsed, 0.30)

    def test_v2_stop_blocks_unfinished_delegate_and_allows_terminal_route(
        self,
    ) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        path = PLUGIN / "hooks" / "stop.py"
        spec = importlib.util.spec_from_file_location(
            "smart_stop_delegate_state_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        payload = {
            "session_id": self.record.session_id,
            "turn_id": self.record.turn_id,
            "hook_event_name": "Stop",
        }

        pending = module.handle(
            payload,
            environment,
            v2_plan_state_provider=(
                lambda _config, _record, *, deadline: "DELEGATE_PENDING"
            ),
        )

        self.assertEqual("block", pending["decision"])
        self.assertIn("route_start", pending["reason"])
        self.assertIn("smart_wait", pending["reason"])
        self.assertIsNone(
            module.handle(
                payload,
                environment,
                v2_plan_state_provider=(
                    lambda _config, _record, *, deadline: "DELEGATE_TERMINAL"
                ),
            )
        )


if __name__ == "__main__":
    unittest.main()

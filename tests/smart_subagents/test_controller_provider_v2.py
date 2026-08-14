from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.controller_provider_v2 import (  # noqa: E402
    ControllerProviderV2Error,
    PinnedControllerProviderV2,
    ScopedControllerProviderV2,
)


def _binding():
    return SimpleNamespace(
        activation_fingerprint="a" * 64,
        compatibility_fingerprint="b" * 64,
        control_epoch=7,
    )


def _record(shell_session_id: str = "cas2_" + "A" * 32):
    return SimpleNamespace(
        shell_session_id=shell_session_id,
        session_id="session",
        turn_id="turn",
        codex_home="/private/codex-home",
        repo_root="/private/repo",
        base_sha="1" * 64,
        worktree_fingerprint="2" * 64,
    )


class ScopedControllerProviderV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.shell = "cas2_" + "A" * 32
        self.loads: list[str] = []
        self.binding = _binding()
        self.provider = ScopedControllerProviderV2(
            runtime_binding_provider=lambda: self.binding,
            activation_gate_provider=lambda: {
                "activationId": "act2_" + "c" * 64,
                "nested": {"value": 1},
            },
            turn_context_loader=self._load,
        )

    def _load(self, shell_session_id: str):
        self.loads.append(shell_session_id)
        return _record(shell_session_id)

    def test_request_context_requires_an_explicit_command_scope(self) -> None:
        with self.assertRaisesRegex(ControllerProviderV2Error, "SCOPE_MISSING"):
            self.provider.request_context()

    def test_scope_loads_only_the_named_turn_record_and_binds_fresh_activation(self) -> None:
        with self.provider.bind(self.shell):
            context = self.provider.request_context()

        self.assertEqual([self.shell], self.loads)
        self.assertEqual(self.shell, context.shell_session_id)
        self.assertEqual("session", context.session_id)
        self.assertEqual("a" * 64, context.activation_fingerprint)
        self.assertEqual("b" * 64, context.compatibility_fingerprint)
        self.assertEqual(7, context.issued_control_epoch)

    def test_scope_is_reset_even_when_the_command_fails(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "boom"):
            with self.provider.bind(self.shell):
                raise RuntimeError("boom")
        with self.assertRaisesRegex(ControllerProviderV2Error, "SCOPE_MISSING"):
            self.provider.request_context()

    def test_context_loader_cannot_substitute_another_shell(self) -> None:
        provider = ScopedControllerProviderV2(
            runtime_binding_provider=lambda: self.binding,
            activation_gate_provider=lambda: {"gate": "value"},
            turn_context_loader=lambda _shell: _record("cas2_" + "B" * 32),
        )
        with provider.bind(self.shell):
            with self.assertRaisesRegex(
                ControllerProviderV2Error,
                "CONTEXT_OWNER_MISMATCH",
            ):
                provider.request_context()

    def test_activation_gate_is_copied_for_each_call(self) -> None:
        first = self.provider.activation_gate()
        first["nested"]["value"] = 99
        second = self.provider.activation_gate()
        self.assertEqual(1, second["nested"]["value"])


def _decision(
    *,
    activation_id: str = "act2_" + "a" * 64,
    gate_fingerprint: str = "c" * 64,
    control_epoch: int = 7,
    controller_start_id: str = "cs2_" + "d" * 32,
):
    binding = SimpleNamespace(
        activation_id=activation_id,
        activation_fingerprint=activation_id.removeprefix("act2_"),
        compatibility_fingerprint="b" * 64,
        control_epoch=control_epoch,
        state_home=Path("/private/codex-home/state/codex-smart-subagents-v2"),
        controller_row={"controller_start_id": controller_start_id},
    )
    return SimpleNamespace(
        state="READY",
        activation_id=activation_id,
        gate_fingerprint=gate_fingerprint,
        activation_gate={
            "manifestSemanticFingerprint": "1" * 64,
            "activationReceiptFingerprint": "2" * 64,
            "journalAbsenceProof": {"proof": "stable"},
            "gateFingerprint": gate_fingerprint,
        },
        catalog_path=Path("/private/catalog.toml"),
        runtime_binding=binding,
    )


class PinnedControllerProviderV2Tests(unittest.TestCase):
    def test_reproves_same_activation_and_controller_for_each_access(self) -> None:
        launch = _decision()
        calls: list[str] = []

        def fresh():
            calls.append("resolve")
            return _decision()

        provider = PinnedControllerProviderV2(
            launch_decision=launch,
            decision_provider=fresh,
            turn_context_loader=lambda shell: _record(shell),
        )
        with provider.bind("cas2_" + "A" * 32):
            context = provider.request_context()
            gate = provider.activation_gate()
        self.assertEqual(launch.activation_gate, gate)
        self.assertEqual(7, context.issued_control_epoch)
        self.assertGreaterEqual(len(calls), 2)

    def test_rejects_activation_or_controller_takeover(self) -> None:
        cases = (
            _decision(activation_id="act2_" + "e" * 64),
            _decision(control_epoch=8),
            _decision(controller_start_id="cs2_" + "f" * 32),
        )
        for fresh in cases:
            with self.subTest(fresh=fresh):
                provider = PinnedControllerProviderV2(
                    launch_decision=_decision(),
                    decision_provider=lambda fresh=fresh: fresh,
                    turn_context_loader=lambda shell: _record(shell),
                )
                with self.assertRaisesRegex(
                    ControllerProviderV2Error,
                    "ACTIVATION_CHANGED",
                ):
                    provider.runtime_binding()

    def test_rejects_non_ready_fresh_decision(self) -> None:
        provider = PinnedControllerProviderV2(
            launch_decision=_decision(),
            decision_provider=lambda: SimpleNamespace(state="ORDINARY"),
            turn_context_loader=lambda shell: _record(shell),
        )
        with self.assertRaisesRegex(
            ControllerProviderV2Error,
            "ACTIVATION_CHANGED",
        ):
            provider.activation_gate()


if __name__ == "__main__":
    unittest.main()

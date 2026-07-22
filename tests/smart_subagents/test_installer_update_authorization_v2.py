from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.installer_update_composition_v2 import (  # noqa: E402
    CandidateSpawnAuthorizationStoreV2,
    InstallerUpdateCompositionV2Error,
    _ensure_pre_main_candidate_authorization_v2,
    _wrap_candidate_authorization_port_v2,
    build_candidate_spawn_action_v2,
    build_update_matched_active_composition_v2,
)
from codex_smart_subagents.installer_update_operation_v2 import (  # noqa: E402
    UpdateStepPortV2,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    OperationJournalStoreV2,
)


INSTALLATION_ID = "ins2_" + "1" * 32
OPERATION_ID = "op2_" + "2" * 32


class InstallerUpdateAuthorizationV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="installer-update-authorization-v2-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.control = self.root / "control"
        self.control.mkdir(mode=0o700)
        self.receipt_directory = self.root / "receipts" / INSTALLATION_ID
        self.receipt_directory.mkdir(parents=True, mode=0o700)
        (self.root / "receipts").chmod(0o700)
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        (self.codex_home / "install-manifests").mkdir(mode=0o700)
        self.journal_store = OperationJournalStoreV2(
            journal_path=self.control / "operation.transaction.json",
            lock_path=self.control / "operation.lock",
            validate_document=lambda _document: None,
        )
        self.authorization_path = (
            self.receipt_directory
            / f"{OPERATION_ID}.candidate-spawn.authorization.json"
        )
        self.commit_receipt_path = (
            self.receipt_directory / f"{OPERATION_ID}.commit.json"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _token(character: str) -> str:
        return character * 40

    def _store(self, *, token: str, action_character: str):
        return CandidateSpawnAuthorizationStoreV2(
            path=self.authorization_path,
            installation_id=INSTALLATION_ID,
            operation_id=OPERATION_ID,
            action_fingerprint=action_character * 64,
            readiness_token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        )

    def test_crash_before_main_journal_allows_fresh_retry_without_spawn(self) -> None:
        old_token = self._token("a")
        new_token = self._token("b")
        self._store(token=old_token, action_character="3").ensure(old_token)

        retried = _ensure_pre_main_candidate_authorization_v2(
            journal_store=self.journal_store,
            authorization_store=self._store(
                token=new_token,
                action_character="4",
            ),
            readiness_token=new_token,
            commit_receipt_path=self.commit_receipt_path,
            codex_home=self.codex_home,
        )

        self.assertEqual(new_token, retried)
        self.assertFalse(
            (
                self.codex_home / "install-manifests" / "candidate-dispatch-intents-v2"
            ).exists()
        )
        self.assertFalse(
            (
                self.codex_home / "install-manifests" / "candidate-registrations-v2"
            ).exists()
        )
        persisted = json.loads(self.authorization_path.read_text(encoding="utf-8"))
        self.assertEqual("4" * 64, persisted["actionFingerprint"])
        self.assertEqual(
            hashlib.sha256(new_token.encode("utf-8")).hexdigest(),
            persisted["readinessTokenHash"],
        )
        self.assertEqual(new_token, persisted["readinessToken"])

    def test_candidate_effect_blocks_pre_main_authorization_replacement(self) -> None:
        old_token = self._token("a")
        new_token = self._token("b")
        self._store(token=old_token, action_character="3").ensure(old_token)
        dispatch_directory = (
            self.codex_home / "install-manifests" / "candidate-dispatch-intents-v2"
        )
        dispatch_directory.mkdir(mode=0o700)
        effect = dispatch_directory / f"{OPERATION_ID}.cand2_{'5' * 32}.json"
        effect.write_text("{}", encoding="utf-8")
        effect.chmod(0o600)

        with self.assertRaises(InstallerUpdateCompositionV2Error) as caught:
            _ensure_pre_main_candidate_authorization_v2(
                journal_store=self.journal_store,
                authorization_store=self._store(
                    token=new_token,
                    action_character="4",
                ),
                readiness_token=new_token,
                commit_receipt_path=self.commit_receipt_path,
                codex_home=self.codex_home,
            )

        self.assertEqual("CANDIDATE_PRE_MAIN_EFFECT_PRESENT", caught.exception.code)
        self.assertEqual(
            old_token,
            self._store(token=old_token, action_character="3").load(),
        )

    def test_main_journal_blocks_pre_main_authorization_replacement(self) -> None:
        old_token = self._token("a")
        new_token = self._token("b")
        self._store(token=old_token, action_character="3").ensure(old_token)
        self.journal_store.journal_path.write_text("{}", encoding="utf-8")
        self.journal_store.journal_path.chmod(0o600)

        with self.assertRaises(InstallerUpdateCompositionV2Error) as caught:
            _ensure_pre_main_candidate_authorization_v2(
                journal_store=self.journal_store,
                authorization_store=self._store(
                    token=new_token,
                    action_character="4",
                ),
                readiness_token=new_token,
                commit_receipt_path=self.commit_receipt_path,
                codex_home=self.codex_home,
            )

        self.assertEqual("UPDATE_MAIN_JOURNAL_ALREADY_EXISTS", caught.exception.code)
        self.assertEqual(
            old_token,
            self._store(token=old_token, action_character="3").load(),
        )

    def test_commit_receipt_blocks_pre_main_authorization_replacement(self) -> None:
        old_token = self._token("a")
        new_token = self._token("b")
        self._store(token=old_token, action_character="3").ensure(old_token)
        self.commit_receipt_path.write_text("{}", encoding="utf-8")
        self.commit_receipt_path.chmod(0o600)

        with self.assertRaises(InstallerUpdateCompositionV2Error) as caught:
            _ensure_pre_main_candidate_authorization_v2(
                journal_store=self.journal_store,
                authorization_store=self._store(
                    token=new_token,
                    action_character="4",
                ),
                readiness_token=new_token,
                commit_receipt_path=self.commit_receipt_path,
                codex_home=self.codex_home,
            )

        self.assertEqual("CANDIDATE_PRE_MAIN_COMMIT_PRESENT", caught.exception.code)
        self.assertEqual(
            old_token,
            self._store(token=old_token, action_character="3").load(),
        )

    def test_wrapper_retains_authorization_until_after_projection(self) -> None:
        token = self._token("a")
        store = self._store(token=token, action_character="3")
        store.ensure(token)
        observations = iter(("before", "after"))
        wrapped = _wrap_candidate_authorization_port_v2(
            port=UpdateStepPortV2(
                observe=lambda _definition: next(observations),
                apply=lambda _definition: None,
                matches_before=lambda observed, _definition: observed == "before",
                matches_after=lambda observed, _definition: observed == "after",
            ),
            store=store,
        )

        wrapped.apply(object())  # type: ignore[arg-type]
        self.assertEqual(token, store.load())
        self.assertEqual("before", wrapped.observe(object()))  # type: ignore[arg-type]
        self.assertEqual(token, store.load())
        self.assertEqual("after", wrapped.observe(object()))  # type: ignore[arg-type]
        self.assertFalse(self.authorization_path.exists())


class InstallerUpdateAuthorizationCompositionV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.smart_subagents.test_activation_transition_v2 import (
            ActivationTransitionV2Tests,
        )
        from tests.smart_subagents.test_installer_update_composition_v2 import (
            _build_fresh_composition_inputs_v2,
        )

        self.fixture = ActivationTransitionV2Tests(methodName="runTest")
        self.fixture.setUp()
        self.inputs = _build_fresh_composition_inputs_v2(self.fixture)

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def _build(self, *, action, token: str, popen_factory):
        return build_update_matched_active_composition_v2(
            registry=self.inputs.registry,
            proof=self.inputs.proof,
            preparation=self.inputs.preparation,
            preparation_receipt=self.inputs.receipt,
            source_binding=self.inputs.source_binding,
            registry_plan=self.inputs.registry_plan,
            launcher_plan=self.inputs.launcher_plan,
            candidate_action=action,
            readiness_token=token,
            wrapper_path=self.inputs.wrapper_path,
            schema_directory=ROOT / "docs/contracts/schemas",
            candidate_port_options={"popen_factory": popen_factory},
        )

    def test_fresh_build_retry_replaces_orphan_without_second_popen(self) -> None:
        popen_calls: list[tuple[object, ...]] = []

        def popen_factory(*arguments, **_options):
            popen_calls.append(arguments)
            raise AssertionError("fresh composition must not start a process")

        first = self._build(
            action=self.inputs.candidate_action,
            token=self.inputs.readiness_token,
            popen_factory=popen_factory,
        )
        recovery_context = first.as_main_journal_recovery_v2(
            installation_lock=nullcontext,
        )
        self.assertEqual(first.operation.execute, recovery_context.execute_operation)
        replacement_token = "replacement-candidate-secret-000000000"
        replacement_action = build_candidate_spawn_action_v2(
            preparation_receipt=self.inputs.receipt,
            readiness_token=replacement_token,
            interpreter=Path(sys.executable),
            server_entrypoint=(
                self.inputs.receipt.activation_intent.activation_dir
                / "marketplace/plugins/codex-smart-subagents/controller/server.py"
            ),
            private_ready_channel_path=(
                self.inputs.receipt.activation_intent.state_home
                / "candidate-test.ready.sock"
            ),
            readiness_window_ms=30_000,
        )

        retried = self._build(
            action=replacement_action,
            token=replacement_token,
            popen_factory=popen_factory,
        )

        self.assertEqual([], popen_calls)
        self.assertEqual(
            first.candidate_authorization_store.path,
            retried.candidate_authorization_store.path,
        )
        self.assertEqual(
            replacement_token,
            retried.candidate_authorization_store.load(),
        )
        self.assertFalse(self.inputs.proof.layout.journal_path.exists())
        self.assertFalse(
            (
                self.inputs.proof.layout.receipts_root
                / self.inputs.proof.installation_id
                / f"{self.inputs.operation_id}.commit.json"
            ).exists()
        )


if __name__ == "__main__":
    unittest.main()

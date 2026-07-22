from __future__ import annotations

import copy
import hashlib
import sys
import unittest
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    ActivationCommitPayloadIntentV2,
    ActivationTransitionLineageV2,
    ControllerShutdownLineageV2,
    JournalIntegrityErrorV2,
    ProjectionV2,
    StepDefinitionV2,
    StoppedControllerLineageV2,
    TerminalDefinitionV2,
    TransitionSourceReceiptV2,
)


INSTALLATION_ID = "ins2_" + "1" * 32
OPERATION_ID = "op2_" + "2" * 32
PREDECESSOR_OPERATION_ID = OPERATION_ID
ACTIVATION_ID = "act2_" + "4" * 64
ACTIVE_ACTIVATION_ID = "act2_" + "e" * 64
DATABASE_ID = "db2_" + "5" * 32
CONTROLLER_IDENTITY = "6" * 64


def projection(schema_id: str, value: dict[str, object], domain: str) -> ProjectionV2:
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": "a" * 64,
        "value": copy.deepcopy(value),
    }
    return ProjectionV2(
        schema_id=schema_id,
        schema_sha256="a" * 64,
        value=envelope["value"],
        value_fingerprint=domain_fingerprint(domain, envelope),
    )


def manifest_document() -> dict[str, object]:
    return {
        "schemaVersion": 2,
        "installationId": INSTALLATION_ID,
        "release": "0.2.0",
        "pluginId": "codex-smart-subagents",
        "marketplaceName": "codex-settings-adaptive",
        "stateHome": "/tmp/state",
        "activeActivation": {
            "activationId": ACTIVE_ACTIVATION_ID,
            "activationFingerprint": "e" * 64,
            "symlinkTarget": "activations/active/marketplace",
            "generationId": "gen2_" + "8" * 64,
            "databaseId": "db2_" + "f" * 32,
        },
        "previousActivation": {
            "activationId": ACTIVATION_ID,
            "activationFingerprint": "7" * 64,
            "symlinkTarget": "activations/previous/marketplace",
            "generationId": "gen2_" + "9" * 64,
            "databaseId": DATABASE_ID,
        },
        "lastCommittedOperation": OPERATION_ID,
        "sourceLocator": {"kind": "local", "value": "/tmp/source"},
        "codexSnapshot": {"absolutePath": "/tmp/codex", "sha256": "1" * 64},
        "interfaceEvidence": {"schemaVersion": 1},
        "routingPolicyFingerprint": "2" * 64,
        "bundledCatalogFingerprint": "3" * 64,
        "artifacts": [{"type": "file", "sha256": "9" * 64}],
        "originalBackup": {
            "type": "absent",
            "path": "/tmp/original",
            "parentPath": "/tmp",
            "name": "original",
        },
        "extensions": {},
        "databaseSchemaVersion": 2,
    }


def manifest_projection(document: dict[str, object]) -> ProjectionV2:
    active = document["activeActivation"]
    assert isinstance(active, dict)
    previous = document["previousActivation"]
    file_value = {
        "path": "/tmp/manifest.json",
        "device": 1,
        "inode": 2,
        "ownerUid": 501,
        "ownerGid": 20,
        "mode": "0600",
        "linkCount": 1,
        "size": len(canonical_json_bytes(document)),
        "sha256": hashlib.sha256(canonical_json_bytes(document)).hexdigest(),
    }
    value = {
        "file": file_value,
        "schemaVersion": 2,
        "installationId": document["installationId"],
        "release": document["release"],
        "pluginId": document["pluginId"],
        "stateHome": document["stateHome"],
        "activeActivationId": active["activationId"],
        "previousActivationId": (
            None if previous is None else previous["activationId"]
        ),
        "lastCommittedOperation": document["lastCommittedOperation"],
        "sourceLocatorFingerprint": hashlib.sha256(
            canonical_json_bytes(document["sourceLocator"])
        ).hexdigest(),
        "artifactsFingerprint": hashlib.sha256(
            canonical_json_bytes(document["artifacts"])
        ).hexdigest(),
        "semanticFingerprint": domain_fingerprint(
            "codex-smart/manifest-semantic/v2",
            {key: value for key, value in document.items() if key != "extensions"},
        ),
    }
    return projection("manifest-v2", value, "codex-smart/journal-state/v2")


def update_lineage() -> ActivationTransitionLineageV2:
    return ActivationTransitionLineageV2(
        transition_kind="update",
        source_receipt=TransitionSourceReceiptV2(
            receipt_kind="activation-preparation",
            path=Path(f"/tmp/receipts/{OPERATION_ID}.preparation.json"),
            raw_sha256="b" * 64,
            receipt_fingerprint="c" * 64,
        ),
        activation_proof_fingerprint="d" * 64,
        shutdown_command_ids=ControllerShutdownLineageV2(
            maintenance_begin="cc2_" + "1" * 32,
            maintenance_strengthen="cc2_" + "2" * 32,
            shutdown="cc2_" + "3" * 32,
        ),
        stopped_controller=StoppedControllerLineageV2(
            operation_id=PREDECESSOR_OPERATION_ID,
            activation_id=ACTIVATION_ID,
            database_id=DATABASE_ID,
            controller_identity=CONTROLLER_IDENTITY,
            control_epoch=10,
        ),
    )


class ActivationCommitLineageV2Tests(unittest.TestCase):
    def intent(self) -> ActivationCommitPayloadIntentV2:
        document = manifest_document()
        return ActivationCommitPayloadIntentV2(
            manifest=manifest_projection(document),
            manifest_document=document,
            transition_lineage=update_lineage(),
            activation=projection(
                "activation-v2",
                {"activationId": ACTIVATION_ID},
                "codex-smart/journal-state/v2",
            ),
            database_binding=projection(
                "database-binding-v2",
                {"databaseId": DATABASE_ID},
                "codex-smart/database-binding/v2",
            ),
            journal_absence_target=projection(
                "absence-proof-v2",
                {"operationId": OPERATION_ID},
                "codex-smart/absence-proof-projection/v2",
            ),
            controller_identity=CONTROLLER_IDENTITY,
        )

    def test_manifest_document_and_lineage_are_frozen_in_payload(self) -> None:
        intent = self.intent()

        self.assertEqual(manifest_document(), intent.manifest_document)
        lineage = intent.transition_lineage.to_document()
        unsigned = {key: value for key, value in lineage.items() if key != "lineageFingerprint"}
        self.assertEqual(
            domain_fingerprint("codex-smart/activation-transition-lineage/v2", unsigned),
            lineage["lineageFingerprint"],
        )

    def test_manifest_document_must_recompute_exact_manifest_projection(self) -> None:
        valid = self.intent()
        changed = copy.deepcopy(dict(valid.manifest_document))
        changed["release"] = "9.9.9"

        with self.assertRaises(JournalIntegrityErrorV2):
            replace(valid, manifest_document=changed)

    def test_transition_lineage_is_closed_and_kind_specific(self) -> None:
        valid = update_lineage().to_document()
        damaged = copy.deepcopy(valid)
        damaged["extra"] = True
        with self.assertRaises(JournalIntegrityErrorV2):
            ActivationTransitionLineageV2.from_document(damaged)

        initial = ActivationTransitionLineageV2(
            transition_kind="initial",
            source_receipt=None,
            activation_proof_fingerprint=None,
            shutdown_command_ids=None,
            stopped_controller=None,
        )
        self.assertTrue(initial.complete)
        with self.assertRaises(JournalIntegrityErrorV2):
            replace(initial, activation_proof_fingerprint="d" * 64)

    def test_lineage_fingerprint_and_predecessor_identity_are_verified(self) -> None:
        valid = update_lineage().to_document()
        damaged = copy.deepcopy(valid)
        damaged["lineageFingerprint"] = "0" * 64
        with self.assertRaises(JournalIntegrityErrorV2):
            ActivationTransitionLineageV2.from_document(damaged)

        intent = self.intent()
        with self.assertRaises(JournalIntegrityErrorV2):
            replace(
                intent,
                transition_lineage=replace(
                    update_lineage(),
                    stopped_controller=replace(
                        update_lineage().stopped_controller,
                        operation_id="op2_" + "3" * 32,
                    ),
                ),
            )

    def test_stopped_controller_matches_manifest_previous_activation(self) -> None:
        valid = self.intent()
        assert valid.transition_lineage.stopped_controller is not None
        for mutation in (
            {"activation_id": "act2_" + "0" * 64},
            {"database_id": "db2_" + "0" * 32},
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(JournalIntegrityErrorV2):
                    replace(
                        valid,
                        transition_lineage=replace(
                            valid.transition_lineage,
                            stopped_controller=replace(
                                valid.transition_lineage.stopped_controller,
                                **mutation,
                            ),
                        ),
                    )

    def test_initial_lineage_requires_manifest_without_previous_activation(self) -> None:
        valid = self.intent()
        initial = ActivationTransitionLineageV2(
            transition_kind="initial",
            source_receipt=None,
            activation_proof_fingerprint=None,
            shutdown_command_ids=None,
            stopped_controller=None,
        )
        with self.assertRaises(JournalIntegrityErrorV2):
            replace(valid, transition_lineage=initial)

        document = copy.deepcopy(dict(valid.manifest_document))
        document["previousActivation"] = None
        committed = replace(
            valid,
            manifest=manifest_projection(document),
            manifest_document=document,
            transition_lineage=initial,
        )
        self.assertTrue(committed.transition_lineage.complete)

    def test_terminal_rejects_source_receipt_outside_canonical_receipts_root(self) -> None:
        valid = self.intent()
        freeze_state = projection(
            "journal-state-v2",
            {"token": "freeze"},
            "codex-smart/journal-state/v2",
        )
        freeze = StepDefinitionV2(
            kind="terminal_journal_freeze",
            command_id=None,
            action={"actionKind": "journal-transition"},
            before=freeze_state,
            expected_after=freeze_state,
        )
        terminal = TerminalDefinitionV2(
            terminal_kind="COMMIT",
            receipt_kind="activation-commit",
            receipt_path=Path(f"/tmp/receipts/{OPERATION_ID}.commit.json"),
            freeze=freeze,
            journal_absence_target=valid.journal_absence_target,
            receipt_payload=valid,
        )
        self.assertEqual("COMMIT", terminal.terminal_kind)

        assert valid.transition_lineage.source_receipt is not None
        escaped = replace(
            valid,
            transition_lineage=replace(
                valid.transition_lineage,
                source_receipt=replace(
                    valid.transition_lineage.source_receipt,
                    path=Path("/tmp/outside/update.preparation.json"),
                ),
            ),
        )
        with self.assertRaises(JournalIntegrityErrorV2):
            replace(terminal, receipt_payload=escaped)


if __name__ == "__main__":
    unittest.main()

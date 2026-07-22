"""Строгий разбор полного определения операции из основного журнала v2."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Mapping

from .canonical_json import domain_fingerprint
from .lifecycle_operation_v2 import (
    ActivationCommitPayloadIntentV2,
    ActivationTransitionLineageV2,
    ExecutionPlanV2,
    InstallationUninstallPayloadIntentV2,
    JournalIntegrityErrorV2,
    OperationAbortPayloadIntentV2,
    OperationDefinitionV2,
    PriorInstallationEvidenceV2,
    ProjectionV2,
    StateBundleV2,
    StepDefinitionV2,
    TerminalDefinitionV2,
    TombstonePayloadIntentV2,
    terminal_definition_snapshot_v2,
)


_JOURNAL_DOMAIN = "codex-smart/operation-journal/v2"


def operation_definition_from_journal_v2(
    document: Mapping[str, Any],
) -> OperationDefinitionV2:
    """Восстановить только сохранённое определение, ничего не пересчитывая."""

    journal = _object(document, "operation journal")
    expected_top = {
        "schemaVersion", "kind", "installationId", "operationId", "operation",
        "phase", "recoveryPolicy", "executionPlan", "abortPlan",
        "recoveryPlans", "discoveryBefore", "fencedBefore", "desired",
        "attempts", "steps", "changes", "terminalDefinitionSnapshot",
        "terminalDeleteIntent", "createdAt", "updatedAt", "journalFingerprint",
    }
    _exact_keys(journal, expected_top, "operation journal")
    if journal["schemaVersion"] != 2:
        _fail("operation journal schemaVersion is invalid")
    unsigned = {
        key: copy.deepcopy(value)
        for key, value in journal.items()
        if key != "journalFingerprint"
    }
    if journal["journalFingerprint"] != domain_fingerprint(
        _JOURNAL_DOMAIN,
        unsigned,
    ):
        _fail("operation journal fingerprint mismatch")

    plan_document = _object(journal["executionPlan"], "executionPlan")
    _exact_keys(
        plan_document,
        {
            "planId", "machineId", "selectedBranchId", "selectionSource",
            "composedStepKinds", "firstIncompleteOrdinal",
            "planDefinitionFingerprint",
        },
        "executionPlan",
    )
    kinds = plan_document["composedStepKinds"]
    if type(kinds) is not list or not all(type(item) is str for item in kinds):
        _fail("executionPlan composedStepKinds is invalid")
    selected_branch = plan_document["selectedBranchId"]
    if selected_branch is not None and type(selected_branch) is not str:
        _fail("executionPlan selectedBranchId is invalid")
    plan = ExecutionPlanV2(
        plan_id=_string(plan_document["planId"], "planId"),
        machine_id=_string(plan_document["machineId"], "machineId"),
        selected_branch_id=selected_branch,
        composed_step_kinds=tuple(kinds),
        selection_source=_string(
            plan_document["selectionSource"], "selectionSource"
        ),
    )
    cursor = plan_document["firstIncompleteOrdinal"]
    if type(cursor) is not int or cursor < 1:
        _fail("executionPlan cursor is invalid")
    if plan.to_document(cursor) != plan_document:
        _fail("executionPlan definition fingerprint mismatch")

    terminal_snapshot = journal["terminalDefinitionSnapshot"]
    terminal = (
        None
        if terminal_snapshot is None
        else _terminal_from_snapshot(_object(terminal_snapshot, "terminal snapshot"))
    )
    terminal_kinds: tuple[str, ...] = ()
    if terminal is not None:
        terminal_kinds = (
            terminal.freeze.kind,
            *terminal.post_freeze_action_kinds,
        )
    if not kinds or kinds[0] != "gate_close":
        _fail("executionPlan does not begin with gate_close")
    if terminal_kinds:
        if tuple(kinds[-len(terminal_kinds):]) != terminal_kinds:
            _fail("terminal snapshot differs from executionPlan tail")
        mutable_kinds = tuple(kinds[1:-len(terminal_kinds)])
    else:
        mutable_kinds = tuple(kinds[1:])

    steps = journal["steps"]
    if type(steps) is not list or not steps:
        _fail("operation journal steps are missing")
    expected_persisted_count = 1 + len(mutable_kinds)
    frozen = journal["phase"] == "TERMINAL_FROZEN"
    if len(steps) != expected_persisted_count + (1 if frozen else 0):
        _fail("operation journal does not persist the full mutable definition")
    gate = _step_definition(
        steps[0],
        expected_kind="gate_close",
        expected_plan_id=plan.plan_id,
        expected_record_carrier="JOURNAL_ATOMIC_BOUNDARY",
        ordinal=0,
    )
    if steps[0].get("state") != "COMPLETED":
        _fail("gate_close is not completed")
    mutable = tuple(
        _step_definition(
            step,
            expected_kind=kind,
            expected_plan_id=plan.plan_id,
            expected_record_carrier="JOURNAL_MUTABLE",
            ordinal=ordinal,
        )
        for ordinal, (step, kind) in enumerate(
            zip(steps[1:expected_persisted_count], mutable_kinds, strict=True),
            start=1,
        )
    )
    if frozen:
        if terminal is None:
            _fail("terminal frozen journal has no terminal snapshot")
        persisted_freeze = _step_definition(
            steps[-1],
            expected_kind="terminal_journal_freeze",
            expected_plan_id=plan.plan_id,
            expected_record_carrier="JOURNAL_ATOMIC_BOUNDARY",
            ordinal=expected_persisted_count,
        )
        if steps[-1].get("state") != "COMPLETED":
            _fail("persisted terminal freeze is not completed")
        if persisted_freeze != terminal.freeze:
            _fail("persisted terminal freeze differs from terminal snapshot")
        if journal["terminalDeleteIntent"] is None:
            _fail("terminal frozen journal has no delete intent")
    elif journal["terminalDeleteIntent"] is not None:
        _fail("mutable journal contains a terminal delete intent")

    mutable_states = [step["state"] for step in steps[1:expected_persisted_count]]
    for ordinal, state in enumerate(mutable_states, start=1):
        if ordinal < cursor and state != "COMPLETED":
            _fail("step before executionPlan cursor is not completed")
        if ordinal == cursor and state not in {"PLANNED", "INTENT_DURABLE"}:
            _fail("step at executionPlan cursor has an invalid state")
        if ordinal > cursor and state != "PLANNED":
            _fail("future step after executionPlan cursor is not planned")
    expected_cursor_max = len(mutable) + (2 if frozen else 1)
    if cursor > expected_cursor_max:
        _fail("executionPlan cursor exceeds the persisted definition")
    if frozen and cursor != len(mutable) + 2:
        _fail("terminal frozen cursor does not follow the freeze step")

    definition = OperationDefinitionV2(
        kind=_string(journal["kind"], "kind"),
        installation_id=_string(journal["installationId"], "installationId"),
        operation_id=_string(journal["operationId"], "operationId"),
        operation=_string(journal["operation"], "operation"),
        execution_plan=plan,
        discovery_before=StateBundleV2.from_document(
            _object(journal["discoveryBefore"], "discoveryBefore")
        ),
        fenced_before=(
            None
            if journal["fencedBefore"] is None
            else StateBundleV2.from_document(
                _object(journal["fencedBefore"], "fencedBefore")
            )
        ),
        desired=(
            None
            if journal["desired"] is None
            else StateBundleV2.from_document(
                _object(journal["desired"], "desired")
            )
        ),
        gate_close=gate,
        mutable_steps=mutable,
        terminal=terminal,
    )
    return definition


def _step_definition(
    document: object,
    *,
    expected_kind: str,
    expected_plan_id: str,
    expected_record_carrier: str,
    ordinal: int,
) -> StepDefinitionV2:
    step = _object(document, f"step {ordinal}")
    required = {
        "stepId", "ordinal", "planId", "planOrdinal", "recordCarrier",
        "kind", "state", "commandId", "action", "actionFingerprint",
        "before", "expectedAfter", "observedAfter", "intentAt", "completedAt",
    }
    _exact_keys(step, required, f"step {ordinal}")
    if (
        step["ordinal"] != ordinal
        or step["planOrdinal"] != ordinal
        or step["planId"] != expected_plan_id
        or step["recordCarrier"] != expected_record_carrier
        or step["kind"] != expected_kind
        or step["state"] not in {"PLANNED", "INTENT_DURABLE", "COMPLETED"}
    ):
        _fail(f"step {ordinal} header differs from the persisted plan")
    definition = StepDefinitionV2(
        kind=expected_kind,
        command_id=step["commandId"],
        action=_object(step["action"], f"step {ordinal}.action"),
        before=ProjectionV2.from_document(
            _object(step["before"], f"step {ordinal}.before")
        ),
        expected_after=ProjectionV2.from_document(
            _object(step["expectedAfter"], f"step {ordinal}.expectedAfter")
        ),
    )
    if definition.action_fingerprint != step["actionFingerprint"]:
        _fail(f"step {ordinal} action fingerprint mismatch")
    if step["state"] == "COMPLETED" and step["observedAfter"] is None:
        _fail(f"completed step {ordinal} has no observedAfter")
    if step["state"] != "COMPLETED" and step["completedAt"] is not None:
        _fail(f"incomplete step {ordinal} has completedAt")
    return definition


def _terminal_from_snapshot(document: Mapping[str, Any]) -> TerminalDefinitionV2:
    unsigned = {
        key: copy.deepcopy(value)
        for key, value in document.items()
        if key != "snapshotFingerprint"
    }
    if document.get("snapshotFingerprint") != domain_fingerprint(
        "codex-smart/terminal-definition-snapshot/v2",
        unsigned,
    ):
        _fail("terminal definition snapshot fingerprint mismatch")
    freeze_document = _object(document.get("freeze"), "terminal freeze")
    _exact_keys(
        freeze_document,
        {"kind", "commandId", "action", "actionFingerprint", "before", "expectedAfter"},
        "terminal freeze",
    )
    freeze = StepDefinitionV2(
        kind=_string(freeze_document["kind"], "terminal freeze kind"),
        command_id=freeze_document["commandId"],
        action=_object(freeze_document["action"], "terminal freeze action"),
        before=ProjectionV2.from_document(
            _object(freeze_document["before"], "terminal freeze before")
        ),
        expected_after=ProjectionV2.from_document(
            _object(
                freeze_document["expectedAfter"],
                "terminal freeze expectedAfter",
            )
        ),
    )
    if freeze.action_fingerprint != freeze_document["actionFingerprint"]:
        _fail("terminal freeze action fingerprint mismatch")
    absence_target = ProjectionV2.from_document(
        _object(document.get("journalAbsenceTarget"), "journalAbsenceTarget")
    )
    payload_document = _object(
        document.get("receiptPayloadStaticIntent"),
        "receiptPayloadStaticIntent",
    )
    payload_kind = payload_document.get("payloadKind")
    if payload_kind == "activation-commit":
        payload = ActivationCommitPayloadIntentV2(
            manifest=ProjectionV2.from_document(
                _object(payload_document.get("manifest"), "manifest")
            ),
            manifest_document=_object(
                payload_document.get("manifestDocument"),
                "manifestDocument",
            ),
            transition_lineage=ActivationTransitionLineageV2.from_document(
                _object(
                    payload_document.get("transitionLineage"),
                    "transitionLineage",
                )
            ),
            activation=ProjectionV2.from_document(
                _object(payload_document.get("activation"), "activation")
            ),
            database_binding=ProjectionV2.from_document(
                _object(payload_document.get("databaseBinding"), "databaseBinding")
            ),
            journal_absence_target=ProjectionV2.from_document(
                _object(
                    payload_document.get("journalAbsenceTarget"),
                    "payload journalAbsenceTarget",
                )
            ),
            controller_identity=_string(
                payload_document.get("controllerIdentity"),
                "controllerIdentity",
            ),
        )
    elif payload_kind == "operation-abort":
        payload = OperationAbortPayloadIntentV2(
            restored_state=StateBundleV2.from_document(
                _object(payload_document.get("restoredState"), "restoredState")
            ),
            journal_absence_target=ProjectionV2.from_document(
                _object(
                    payload_document.get("journalAbsenceTarget"),
                    "payload journalAbsenceTarget",
                )
            ),
            reason_code=_string(payload_document.get("reasonCode"), "reasonCode"),
        )
    elif payload_kind == "installation-uninstall":
        payload = InstallationUninstallPayloadIntentV2(
            removed_state=StateBundleV2.from_document(
                _object(payload_document.get("removedState"), "removedState")
            ),
            restored_original_backup=ProjectionV2.from_document(
                _object(
                    payload_document.get("restoredOriginalBackup"),
                    "restoredOriginalBackup",
                )
            ),
            absence_proof=ProjectionV2.from_document(
                _object(payload_document.get("absenceProof"), "absenceProof")
            ),
            retained_data=_object(
                payload_document.get("retainedData"), "retainedData"
            ),
            activation_proof_fingerprint=_string(
                payload_document.get("activationProofFingerprint"),
                "activationProofFingerprint",
            ),
        )
    else:
        _fail("terminal receipt payload kind is invalid")
    tombstone_document = document.get("tombstonePayloadIntent")
    tombstone = None
    if tombstone_document is not None:
        tombstone_value = _object(tombstone_document, "tombstonePayloadIntent")
        prior_value = tombstone_value.get("priorInstallationEvidence")
        prior = None
        if prior_value is not None:
            prior_document = _object(prior_value, "priorInstallationEvidence")
            prior = PriorInstallationEvidenceV2(
                before_file_projection_fingerprint=_string(
                    prior_document.get("beforeFileProjectionFingerprint"),
                    "beforeFileProjectionFingerprint",
                )
            )
        tombstone = TombstonePayloadIntentV2(
            path=Path(_string(tombstone_value.get("path"), "tombstone path")),
            before=ProjectionV2.from_document(
                _object(tombstone_value.get("before"), "tombstone before")
            ),
            replacement_authorization=_string(
                tombstone_value.get("replacementAuthorization"),
                "replacementAuthorization",
            ),
            prior_installation_evidence=prior,
        )
    terminal = TerminalDefinitionV2(
        terminal_kind=_string(document.get("terminalKind"), "terminalKind"),
        receipt_kind=_string(document.get("receiptKind"), "receiptKind"),
        receipt_path=Path(_string(document.get("receiptPath"), "receiptPath")),
        freeze=freeze,
        journal_absence_target=absence_target,
        receipt_payload=payload,
        tombstone_payload=tombstone,
    )
    if terminal_definition_snapshot_v2(terminal) != document:
        _fail("terminal definition snapshot is not canonical")
    return terminal


def _object(value: object, name: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"{name} must be an object")
    return copy.deepcopy(value)


def _exact_keys(value: Mapping[str, Any], keys: set[str], name: str) -> None:
    if set(value) != keys:
        _fail(f"{name} has unexpected fields")


def _string(value: object, name: str) -> str:
    if type(value) is not str or not value:
        _fail(f"{name} must be a non-empty string")
    return value


def _fail(message: str) -> None:
    raise JournalIntegrityErrorV2(message)


__all__ = ["operation_definition_from_journal_v2"]

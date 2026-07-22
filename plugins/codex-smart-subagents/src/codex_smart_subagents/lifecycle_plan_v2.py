"""Закрытый выбор плана публичных операций жизненного цикла версии 2.

Исполнитель журнала принимает уже составленную последовательность. Этот
модуль является границей между результатом обнаружения состояния и этим
исполнителем: он допускает только нормативную ветвь, составляет условный
префикс перед общей машиной и закрыто отвергает неоднозначное состояние.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Mapping

from .lifecycle_operation_v2 import ExecutionPlanV2


class LifecyclePlanV2Error(RuntimeError):
    """Базовая ошибка выбора плана жизненного цикла."""


class LifecyclePlanContractErrorV2(LifecyclePlanV2Error):
    """Переданный автомат не равен закрытому договору выпуска 0.2.0."""


class LifecyclePlanBlockedV2(LifecyclePlanV2Error):
    """Наблюдаемое состояние предписывает не выполнять никаких действий."""


@dataclass(frozen=True)
class _BranchContractV2:
    disposition: str
    ordered_steps: tuple[str, ...]


@dataclass(frozen=True)
class _MachineContractV2:
    recovery_policy: str
    ordered_steps: tuple[str, ...]
    branches: Mapping[str, _BranchContractV2]


_CONTINUE = "CONTINUE_COMMON_MACHINE"
_AMBIGUOUS = "RECOVERY_STATE_AMBIGUOUS"
_FORWARD_PIVOT = "recovery_forward_only"
_PUBLIC_MACHINE_CONTRACTS: Mapping[str, _MachineContractV2] = {
    "apply": _MachineContractV2(
        recovery_policy="REVERSIBLE_THEN_FORWARD_ONLY",
        ordered_steps=(
            "database_prepare",
            "activation_link",
            _FORWARD_PIVOT,
            "marketplace_registry",
            "plugin_registry",
            "launchers",
            "controller_candidate_spawn",
            "controller_accept",
            "verify_candidate",
            "manifest_commit",
            "maintenance_resume",
            "terminal_journal_freeze",
            "commit_receipt_publish",
            "gate_open",
        ),
        branches={
            "fresh-proven-absent": _BranchContractV2(
                disposition=_CONTINUE,
                ordered_steps=("gate_close", "stage", "verify_staged"),
            ),
            "update-matched-active": _BranchContractV2(
                disposition=_CONTINUE,
                ordered_steps=(
                    "gate_close",
                    "maintenance_begin",
                    "wait_runtime_quiescent",
                    "maintenance_strengthen",
                    "controller_shutdown",
                    "shutdown_socket_cleanup",
                ),
            ),
            "mismatched-live-or-socket": _BranchContractV2(
                disposition=_AMBIGUOUS,
                ordered_steps=(),
            ),
        },
    ),
    "rollback": _MachineContractV2(
        recovery_policy="REVERSIBLE_THEN_FORWARD_ONLY",
        ordered_steps=(
            "activation_link_restore",
            _FORWARD_PIVOT,
            "registry_restore",
            "launchers_restore",
            "controller_candidate_spawn",
            "controller_previous_accept",
            "verify_candidate",
            "manifest_restore",
            "maintenance_resume",
            "terminal_journal_freeze",
            "commit_receipt_publish",
            "gate_open",
        ),
        branches={
            "rollback-matched-active": _BranchContractV2(
                disposition=_CONTINUE,
                ordered_steps=(
                    "gate_close",
                    "maintenance_begin",
                    "wait_runtime_quiescent",
                    "maintenance_strengthen",
                    "controller_shutdown",
                    "shutdown_socket_cleanup",
                ),
            ),
            "mismatched-live-or-socket": _BranchContractV2(
                disposition=_AMBIGUOUS,
                ordered_steps=(),
            ),
        },
    ),
    "uninstall": _MachineContractV2(
        recovery_policy="REVERSIBLE_THEN_FORWARD_ONLY",
        ordered_steps=(
            _FORWARD_PIVOT,
            "uninstall_plugin_remove",
            "uninstall_marketplace_remove",
            "uninstall_launchers_restore",
            "uninstall_activation_link_remove",
            "uninstall_activation_remove",
            "uninstall_manifest_remove",
            "terminal_journal_freeze",
            "uninstall_receipt_publish",
            "uninstall_tombstone_publish",
            "uninstall_journal_close",
        ),
        branches={
            "active-matched-controller": _BranchContractV2(
                disposition=_CONTINUE,
                ordered_steps=(
                    "gate_close",
                    "maintenance_begin",
                    "wait_runtime_quiescent",
                    "maintenance_strengthen",
                    "controller_shutdown",
                    "shutdown_socket_cleanup",
                ),
            ),
            "disabled-or-missing-proven": _BranchContractV2(
                disposition=_CONTINUE,
                ordered_steps=("gate_close",),
            ),
            "mismatched-live-or-socket": _BranchContractV2(
                disposition=_AMBIGUOUS,
                ordered_steps=(),
            ),
        },
    ),
}


class LifecyclePlanRegistryV2:
    """Неизменяемый проверенный реестр публичных планов выпуска 0.2.0."""

    def __init__(self, document: Mapping[str, Any]) -> None:
        self._document = copy.deepcopy(dict(document))

    @classmethod
    def from_document(
        cls, document: Mapping[str, Any]
    ) -> LifecyclePlanRegistryV2:
        if type(document) is not dict:
            raise LifecyclePlanContractErrorV2("automaton must be an object")
        copied = copy.deepcopy(document)
        if copied.get("schemaVersion") != 2:
            raise LifecyclePlanContractErrorV2(
                "automaton schemaVersion must be 2"
            )
        selection = copied.get("planSelectionRule")
        if type(selection) is not dict:
            raise LifecyclePlanContractErrorV2(
                "planSelectionRule must be an object"
            )
        required_selection = {
            "selectionTiming": "ONCE_AFTER_DISCOVERY_BEFORE_FIRST_EFFECT",
            "compositionOrder": "SELECTED_BRANCH_PREFIX_THEN_MACHINE_COMMON_STEPS",
            "selectionImmutable": True,
            "ambiguousSelectionDisposition": "NO_EXECUTION_RECOVERY_STATE_AMBIGUOUS",
        }
        for name, expected in required_selection.items():
            if selection.get(name) != expected:
                raise LifecyclePlanContractErrorV2(
                    f"unexpected plan selection rule: {name}"
                )

        machines = copied.get("machines")
        if type(machines) is not dict:
            raise LifecyclePlanContractErrorV2("machines must be an object")
        for machine_id, expected in _PUBLIC_MACHINE_CONTRACTS.items():
            _validate_machine(machine_id, machines.get(machine_id), expected)
        return cls(copied)

    def select(
        self,
        *,
        machine_id: str,
        branch_id: str | None,
        plan_id: str,
    ) -> ExecutionPlanV2:
        expected = _PUBLIC_MACHINE_CONTRACTS.get(machine_id)
        if expected is None:
            raise LifecyclePlanContractErrorV2(
                f"unsupported public lifecycle machine: {machine_id}"
            )
        if not isinstance(branch_id, str) or not branch_id:
            raise LifecyclePlanContractErrorV2(
                f"{machine_id} requires a selected branch"
            )
        branch = expected.branches.get(branch_id)
        if branch is None:
            raise LifecyclePlanContractErrorV2(
                f"unknown {machine_id} branch: {branch_id}"
            )
        if branch.disposition == _AMBIGUOUS:
            raise LifecyclePlanBlockedV2(
                f"{machine_id}/{branch_id} requires RECOVERY_STATE_AMBIGUOUS"
            )
        if branch.disposition != _CONTINUE:
            raise LifecyclePlanContractErrorV2(
                f"unsupported branch disposition: {branch.disposition}"
            )
        composed = branch.ordered_steps + expected.ordered_steps
        _validate_composed(machine_id, composed)
        return ExecutionPlanV2(
            plan_id=plan_id,
            machine_id=machine_id,
            selected_branch_id=branch_id,
            composed_step_kinds=composed,
        )


def _validate_machine(
    machine_id: str,
    value: Any,
    expected: _MachineContractV2,
) -> None:
    if type(value) is not dict:
        raise LifecyclePlanContractErrorV2(
            f"missing lifecycle machine: {machine_id}"
        )
    if value.get("recoveryPolicy") != expected.recovery_policy:
        raise LifecyclePlanContractErrorV2(
            f"unexpected recovery policy for {machine_id}"
        )
    common = _string_tuple(value.get("orderedSteps"), f"{machine_id}.orderedSteps")
    if common != expected.ordered_steps:
        raise LifecyclePlanContractErrorV2(
            f"unexpected common steps for {machine_id}"
        )
    branches = value.get("conditionalBranches")
    if type(branches) is not dict or set(branches) != set(expected.branches):
        raise LifecyclePlanContractErrorV2(
            f"unexpected conditional branches for {machine_id}"
        )
    for branch_id, expected_branch in expected.branches.items():
        actual = branches[branch_id]
        if type(actual) is not dict:
            raise LifecyclePlanContractErrorV2(
                f"branch must be an object: {machine_id}/{branch_id}"
            )
        if actual.get("disposition") != expected_branch.disposition:
            raise LifecyclePlanContractErrorV2(
                f"unexpected disposition: {machine_id}/{branch_id}"
            )
        steps = _string_tuple(
            actual.get("orderedSteps"),
            f"{machine_id}/{branch_id}.orderedSteps",
        )
        if steps != expected_branch.ordered_steps:
            raise LifecyclePlanContractErrorV2(
                f"unexpected branch steps: {machine_id}/{branch_id}"
            )
        if expected_branch.disposition == _CONTINUE:
            _validate_composed(machine_id, steps + common)
        elif steps:
            raise LifecyclePlanContractErrorV2(
                f"blocked branch must not contain steps: {machine_id}/{branch_id}"
            )


def _validate_composed(machine_id: str, steps: tuple[str, ...]) -> None:
    if not steps or steps[0] != "gate_close":
        raise LifecyclePlanContractErrorV2(
            f"{machine_id} must start with gate_close"
        )
    if steps.count(_FORWARD_PIVOT) != 1:
        raise LifecyclePlanContractErrorV2(
            f"{machine_id} must contain exactly one forward-only pivot"
        )
    if len(set(steps)) != len(steps):
        raise LifecyclePlanContractErrorV2(
            f"{machine_id} plan contains duplicate step kinds"
        )


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if type(value) is not list or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise LifecyclePlanContractErrorV2(f"{label} must be a string array")
    return tuple(value)

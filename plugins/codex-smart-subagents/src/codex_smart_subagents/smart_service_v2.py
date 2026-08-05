"""Служба смыслового планирования адаптивных субагентов версии 2."""

from __future__ import annotations

import copy
import re
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .canonical_json import domain_fingerprint
from .evidence import (
    AccountEvidenceCollector,
    EvidenceError,
    verify_interface_evidence,
)
from .graph import GraphError, TaskNode, validate_graph
from .managed_requirements_v1 import (
    ManagedRequirementsError,
    verify_managed_requirements_compatibility,
)
from .policy_bundle_v2 import PolicyBundleV2
from .plan_projection_v2 import PlanProjectionV2Error, node_routing_input_v2
from .public_routing_input_v2 import (
    PublicRoutingInputV2Error,
    SERVER_PERMISSION_EVIDENCE_REF,
    validate_public_routing_input_v2,
)
from .semantic_routing_v2 import ContractError
from .state_store_v2 import (
    AdmissionV2,
    PlannedNodeV2,
    RequestContextV2,
    SmartStoreV2,
    StartRequestV2,
    TurnBindingV2,
)


_CLIENT_NODE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,63}$")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


@dataclass
class SmartServiceV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class SmartPlanNodeDecisionV2:
    client_node_id: str
    node_id: str
    dependency_node_ids: tuple[str, ...]
    disposition: str
    selected_pair: dict[str, str] | None
    score: int | None
    factors: dict[str, int] | None


@dataclass(frozen=True)
class SmartPlanResultV2:
    route_id: str
    disposition: str
    node_decisions: tuple[SmartPlanNodeDecisionV2, ...]
    clarification: tuple[str, ...]
    plan_fingerprint: str
    route_state: str | None = None
    replayed: bool = False


class SmartServiceV2:
    """Связывает чистый маршрутизатор с долговечным хранилищем."""

    def __init__(
        self,
        *,
        store: SmartStoreV2,
        policy_bundle: PolicyBundleV2,
        bundled_catalog_projection: Mapping[str, Any],
        activation_gate_verifier: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        live_control_epoch_provider: Callable[[], int] | None = None,
        clock: Callable[[], datetime] | None = None,
        interface_evidence: Mapping[str, Any],
        account_evidence_executor: Any,
        verify_snapshot_subject: Callable[[dict[str, Any]], None],
        account_home: str,
        account_tmpdir: str,
        resume_plan_guard: Callable[[RequestContextV2], None] | None = None,
    ) -> None:
        self.store = store
        self.policy_bundle = policy_bundle
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.activation_gate_verifier = activation_gate_verifier
        if live_control_epoch_provider is not None and not callable(
            live_control_epoch_provider
        ):
            raise TypeError("live_control_epoch_provider must be callable")
        self.live_control_epoch_provider = live_control_epoch_provider
        self.interface_evidence = verify_interface_evidence(interface_evidence)
        (
            self.bundled_catalog_projection,
            self.bundled_snapshot_pairs,
        ) = self._validated_bundled_catalog_projection(bundled_catalog_projection)
        if (
            self.interface_evidence["semantic"]["routingPolicyFingerprint"]
            != policy_bundle.router.policy_fingerprint
        ):
            self._fail(
                "ROUTING_POLICY_INTERFACE_DRIFT",
                "политика маршрутизации расходится с InterfaceEvidence",
            )
        if self.interface_evidence["semantic"][
            "bundledCatalogFingerprint"
        ] != domain_fingerprint(
            "codex-smart/bundled-catalog/v1",
            self.bundled_catalog_projection,
        ):
            self._fail(
                "BUNDLED_CATALOG_INTERFACE_DRIFT",
                "встроенный каталог расходится с InterfaceEvidence",
            )
        if self.interface_evidence["semantic"]["childProfiles"] != dict(
            policy_bundle.child_profile_fingerprints
        ):
            self._fail(
                "CHILD_PROFILE_INTERFACE_DRIFT",
                "профили запуска расходятся с InterfaceEvidence",
            )
        if not callable(getattr(account_evidence_executor, "execute", None)):
            raise TypeError("account_evidence_executor must provide execute()")
        if not callable(verify_snapshot_subject):
            raise TypeError("verify_snapshot_subject must be callable")
        for name, value in (
            ("account_home", account_home),
            ("account_tmpdir", account_tmpdir),
        ):
            if (
                not isinstance(value, str)
                or not value
                or "\0" in value
                or not Path(value).is_absolute()
            ):
                raise ValueError(f"{name} must be an absolute path")
        self.account_evidence_executor = account_evidence_executor
        self.verify_snapshot_subject = verify_snapshot_subject
        self.account_home = account_home
        self.account_tmpdir = account_tmpdir
        if resume_plan_guard is not None and not callable(resume_plan_guard):
            raise TypeError("resume_plan_guard must be callable")
        self.resume_plan_guard = resume_plan_guard

    def issue_turn_binding(
        self,
        request_context: RequestContextV2,
        *,
        ttl_seconds: int,
        request_key: str | None = None,
    ) -> TurnBindingV2:
        self._verify_request_context(request_context)
        return self.store.issue_turn_binding(
            request_context,
            ttl_seconds=ttl_seconds,
            now=self._now(),
            request_key=request_key,
        )

    def smart_plan(
        self,
        *,
        binding_id: str,
        request_context: RequestContextV2,
        request_key: str,
        nodes: Sequence[Mapping[str, Any]],
    ) -> SmartPlanResultV2:
        self._verify_request_context(request_context)
        if self.resume_plan_guard is not None:
            self.resume_plan_guard(request_context)
        submitted_nodes = self._validated_plan_nodes(nodes)
        roles = [
            self._role(item["routingInput"]["roleTemplateId"])
            for item in submitted_nodes
        ]
        try:
            validate_graph(
                [
                    TaskNode(
                        node_id=str(item["clientNodeId"]),
                        role=str(role["semanticRole"]),
                        dependencies=tuple(
                            str(value) for value in item["dependencyIds"]
                        ),
                    )
                    for item, role in zip(submitted_nodes, roles)
                ],
                max_nodes=20,
                max_edges=60,
                max_depth=4,
            )
        except GraphError as exc:
            self._fail(exc.code, exc.message)

        evaluated: list[dict[str, Any]] = []
        for item, role in zip(submitted_nodes, roles):
            candidate = self._initial_routing_input(item["routingInput"])
            try:
                routing_result = self.policy_bundle.router.evaluate(candidate)
            except ContractError as exc:
                self._fail("ROUTING_INPUT_INVALID", str(exc))
            if "errorCode" in routing_result:
                self._fail(
                    str(routing_result["errorCode"]),
                    "маршрутизатор отклонил точную пару или доказательства",
                )
            evaluated.append(
                {
                    "clientNodeId": item["clientNodeId"],
                    "dependencyIds": item["dependencyIds"],
                    "routingInput": candidate,
                    "routingResult": copy.deepcopy(routing_result),
                    "role": role,
                }
            )

        dispositions = {
            str(item["routingResult"]["decision"]).upper() for item in evaluated
        }
        if "CLARIFY" in dispositions:
            disposition = "CLARIFY"
        elif dispositions == {"DELEGATE"}:
            disposition = "DELEGATE"
        else:
            disposition = "DIRECT"
        request_projection = {
            "nodes": [
                {
                    "clientNodeId": item["clientNodeId"],
                    "dependencyIds": item["dependencyIds"],
                    "routingInput": item["routingInput"],
                }
                for item in evaluated
            ],
            "policyBundleFingerprint": self.policy_bundle.bundle_fingerprint,
        }
        request_hash = domain_fingerprint(
            "codex-smart/smart-plan-request/v2",
            request_projection,
        )
        plan_projection = {
            "requestHash": request_hash,
            "disposition": disposition,
            "nodes": [
                {
                    "clientNodeId": item["clientNodeId"],
                    "dependencyIds": item["dependencyIds"],
                    "disposition": str(item["routingResult"]["decision"]).upper(),
                    "reasons": item["routingResult"]["reasons"],
                    "pair": item["routingResult"]["pair"],
                    "score": item["routingResult"]["score"],
                    "factors": item["routingResult"]["factors"],
                    "roleTemplateId": item["routingInput"]["roleTemplateId"],
                }
                for item in evaluated
            ],
        }
        plan_fingerprint = domain_fingerprint(
            "codex-smart/route-plan/v2",
            plan_projection,
        )
        node_ids_by_client = {
            str(item["clientNodeId"]): (
                "node2_"
                + domain_fingerprint(
                    "codex-smart/planned-node-id/v2",
                    {
                        "planFingerprint": plan_fingerprint,
                        "clientNodeId": item["clientNodeId"],
                    },
                )[:32]
            )
            for item in evaluated
        }
        node_decisions = tuple(
            SmartPlanNodeDecisionV2(
                client_node_id=str(item["clientNodeId"]),
                node_id=node_ids_by_client[str(item["clientNodeId"])],
                dependency_node_ids=tuple(
                    node_ids_by_client[str(dependency)]
                    for dependency in item["dependencyIds"]
                ),
                disposition=str(item["routingResult"]["decision"]).upper(),
                selected_pair=copy.deepcopy(item["routingResult"]["pair"]),
                score=item["routingResult"]["score"],
                factors=copy.deepcopy(item["routingResult"]["factors"]),
            )
            for item in evaluated
        )

        planned_nodes: tuple[PlannedNodeV2, ...] = ()
        if disposition == "DELEGATE":
            projected: list[PlannedNodeV2] = []
            for ordinal, (item, decision) in enumerate(zip(evaluated, node_decisions)):
                pair = decision.selected_pair
                if pair is None:
                    self._fail(
                        "ROUTING_PAIR_MISSING",
                        "делегируемый узел не имеет точной пары",
                    )
                role = item["role"]
                candidate = item["routingInput"]
                execution_profile = str(role["executionProfile"])
                child_profile = self._child_profile_for_execution(execution_profile)
                projected.append(
                    PlannedNodeV2(
                        node_id=decision.node_id,
                        ordinal=ordinal,
                        role=str(role["semanticRole"]),
                        mission=str(candidate["taskFacts"]["taskText"]),
                        dependencies=decision.dependency_node_ids,
                        context_refs=tuple(
                            entry["contextRefId"]
                            for entry in candidate["contextBundle"]["entries"]
                        ),
                        scope_id="scope-v2",
                        artifact_profile_id=execution_profile + "-artifact-v2",
                        validation_profile_id=execution_profile + "-validation-v2",
                        assessment=copy.deepcopy(decision.factors or {}),
                        risk_flags=tuple(
                            reason["reason"]
                            for reason in candidate["taskFacts"]["hardFloorReasons"]
                        ),
                        selected_model=str(pair["model"]),
                        reasoning_effort=str(pair["reasoningEffort"]),
                        permission_profile_id=str(child_profile["permissionProfileId"]),
                        disposition="DELEGATE",
                    )
                )
            planned_nodes = tuple(projected)

        plan_output = {
            "schemaVersion": 2,
            "overallDisposition": disposition,
            "nodes": [
                {
                    "clientNodeId": item["clientNodeId"],
                    "nodeId": decision.node_id,
                    "dependencyNodeIds": list(decision.dependency_node_ids),
                    "routingInput": item["routingInput"],
                    "routingResult": item["routingResult"],
                }
                for item, decision in zip(evaluated, node_decisions)
            ],
            "planFingerprint": plan_fingerprint,
        }
        now = self._now()
        route_commit = self.store.create_planned_route_receipt(
            binding_id=binding_id,
            request_context=request_context,
            request_key=request_key,
            request_hash=request_hash,
            catalog_generation=self.policy_bundle.bundle_fingerprint,
            algorithm_version=self.policy_bundle.algorithm_version,
            disposition=disposition,
            expires_at=now + timedelta(minutes=15),
            plan_output=plan_output,
            nodes=planned_nodes,
            now=now,
        )
        clarification = tuple(
            dict.fromkeys(
                str(reason)
                for item in evaluated
                if str(item["routingResult"]["decision"]).upper() == "CLARIFY"
                for reason in item["routingResult"]["reasons"]
            )
        )
        return SmartPlanResultV2(
            route_id=route_commit.route_id,
            disposition=disposition,
            node_decisions=node_decisions,
            clarification=clarification,
            plan_fingerprint=plan_fingerprint,
            route_state=route_commit.state,
            replayed=route_commit.replayed,
        )

    def route_start(
        self,
        *,
        route_id: str,
        node_id: str,
        request_context: RequestContextV2,
        activation_gate: Mapping[str, Any],
        request_key: str | None = None,
    ) -> StartRequestV2:
        """Создаёт только запрос запуска и очередь свежего AccountEvidence."""

        self._verify_request_context(request_context)
        try:
            verified_gate = self.activation_gate_verifier(activation_gate)
        except Exception as exc:
            self._fail("ACTIVATION_GATE_UNAVAILABLE", str(exc))
        if type(verified_gate) is not dict:
            self._fail(
                "ACTIVATION_GATE_UNAVAILABLE",
                "проверяющий шлюза не вернул закрытый объект",
            )
        now = self._now()
        return self.store.create_start_request(
            route_id=route_id,
            node_id=node_id,
            request_context=request_context,
            idempotency_key=request_key,
            activation_gate_fingerprint=str(verified_gate["gateFingerprint"]),
            deadline_at=now + timedelta(seconds=180),
            now=now,
        )

    def process_account_evidence(
        self,
        *,
        start_request: StartRequestV2,
        request_context: RequestContextV2,
        activation_gate: Mapping[str, Any],
        owner_id: str,
        pid: int,
        process_start_marker: str,
        admission_barrier: Callable[[], Any] | None = None,
    ) -> AdmissionV2:
        """Выполняет один свежий сбор, повторную оценку и атомарный допуск."""

        self._verify_request_context(request_context)
        authoritative = self.store.read_start_request(
            start_request.start_request_id,
            request_context,
        )
        if authoritative != start_request:
            self._fail(
                "START_REQUEST_OWNERSHIP_MISMATCH",
                "проекция запроса запуска расходится с долговечным состоянием",
            )
        plan = self.store.read_node_plan(
            authoritative.route_id,
            authoritative.node_id,
            request_context,
        )
        if plan.node_state != "PLANNED":
            self._fail("NODE_NOT_ATTESTABLE", "узел уже покинул состояние PLANNED")
        if (
            plan.catalog_generation != self.policy_bundle.bundle_fingerprint
            or plan.algorithm_version != self.policy_bundle.algorithm_version
            or plan.compatibility_fingerprint
            != self.interface_evidence["compatibilityFingerprint"]
        ):
            self.store.record_start_stale(
                authoritative.start_request_id,
                request_context,
                failure_code="ROUTE_POLICY_STALE",
                problem={
                    "category": "STALE",
                    "code": "ROUTE_STALE",
                    "message": "Сохранённый маршрут относится к другой политике или совместимости.",
                    "retryable": False,
                },
                now=self._now(),
            )
            self._fail(
                "ROUTE_POLICY_STALE",
                "сохранённый маршрут расходится с текущей политикой или интерфейсом",
            )
        self.store.claim_account_evidence_job(
            start_request.evidence_job_id,
            owner_id=owner_id,
            pid=pid,
            process_start_marker=process_start_marker,
            current_stage="requirements-a",
            now=self._now(),
        )
        try:
            remaining_seconds = (
                authoritative.deadline_at - self._now()
            ).total_seconds()
            if remaining_seconds <= 0:
                self._fail(
                    "REQUEST_DEADLINE_EXCEEDED",
                    "срок запуска истёк после захвата задания доказательств",
                )
            collector = AccountEvidenceCollector(
                interface_evidence=self.interface_evidence,
                codex_home=request_context.codex_home,
                home=self.account_home,
                tmpdir=self.account_tmpdir,
                executor=self.account_evidence_executor,
                verify_subject=self.verify_snapshot_subject,
                timeout_seconds=remaining_seconds,
                stage_callback=lambda stage: self.store.update_account_evidence_stage(
                    authoritative.evidence_job_id,
                    owner_id=owner_id,
                    current_stage=stage,
                    now=self._now(),
                ),
                cancel_check=lambda: self.store.account_evidence_cancel_requested(
                    authoritative.evidence_job_id,
                    owner_id=owner_id,
                ),
            )
            evidence = collector.collect()
            profile = self._child_profile_for_permission(
                plan.node.permission_profile_id
            )
            verify_managed_requirements_compatibility(
                evidence["requirements"],
                profile=profile,
                selected_pair={
                    "model": plan.node.selected_model,
                    "reasoningEffort": plan.node.reasoning_effort,
                },
                known_features=set(self.policy_bundle.known_child_features),
            )
            routing_input = self._routing_input_for_node(
                plan.plan_output,
                plan.node_id,
            )
            routing_input["phase"] = "node-attempt"
            routing_input["catalogs"] = {
                "policyPairs": [
                    copy.deepcopy(dict(pair))
                    for pair in self.policy_bundle.policy_pairs
                ],
                "bundledSnapshotPairs": [
                    copy.deepcopy(dict(pair)) for pair in self.bundled_snapshot_pairs
                ],
                "accountPairs": copy.deepcopy(evidence["availablePairs"]),
            }
            routing_input["accountEvidenceJobs"] = [
                {
                    "collectionJobId": authoritative.evidence_job_id,
                    "attemptId": authoritative.attempt_id,
                    "fullCollection": True,
                    "processCount": 5,
                    "cacheHit": False,
                    "hiddenRetry": False,
                }
            ]
            routing_input["reassessment"] = {
                "mode": "promote-only",
                "currentPair": {
                    "model": plan.node.selected_model,
                    "reasoningEffort": plan.node.reasoning_effort,
                },
                "explicitPolicyAllowed": True,
            }
            routing_result = self.policy_bundle.router.evaluate(routing_input)
            expected_pair = {
                "model": plan.node.selected_model,
                "reasoningEffort": plan.node.reasoning_effort,
            }
            if "errorCode" in routing_result:
                self._fail(
                    str(routing_result["errorCode"]),
                    "повторная оценка отклонила точную пару",
                )
            if (
                routing_result["decision"] != "delegate"
                or routing_result["accountEvidenceJobsConsumed"] != 1
                or routing_result["pair"] != expected_pair
            ):
                self._fail(
                    "NODE_REASSESSMENT_DRIFT",
                    "повторная оценка изменила утверждённый план",
                )
            barrier = admission_barrier or nullcontext
            if not callable(barrier):
                self._fail("ADMISSION_BARRIER_INVALID", "барьер допуска не вызывается")
            with barrier():
                try:
                    verified_gate = self.activation_gate_verifier(activation_gate)
                except Exception as exc:
                    self._fail("ACTIVATION_GATE_UNAVAILABLE", str(exc))
                if type(verified_gate) is not dict:
                    self._fail(
                        "ACTIVATION_GATE_UNAVAILABLE",
                        "проверяющий шлюза не вернул закрытый объект",
                    )
                now = self._now()
                return self.store.complete_account_evidence_and_admit(
                    start_request_id=authoritative.start_request_id,
                    evidence_job_id=authoritative.evidence_job_id,
                    route_id=authoritative.route_id,
                    node_id=authoritative.node_id,
                    account_catalog_fingerprint=evidence["accountCatalogFingerprint"],
                    account_context_fingerprint=evidence["accountContextFingerprint"],
                    record_fingerprint=evidence["recordFingerprint"],
                    activation_gate=verified_gate,
                    expected_control_epoch=self._live_control_epoch(request_context),
                    now=now,
                )
        except Exception as exc:
            code = self._error_code(exc)
            cancelled = code == "ACCOUNT_EVIDENCE_CANCELLED"
            self.store.record_account_evidence_terminal(
                authoritative.evidence_job_id,
                request_context,
                state="CANCELLED" if cancelled else "FAILED",
                failure_code="CANCEL_REQUESTED" if cancelled else code,
                problem=None if cancelled else self._public_problem(code),
                now=self._now(),
            )
            if isinstance(exc, SmartServiceV2Error):
                raise
            self._fail(code, str(exc))

    def _role(self, template_id: Any) -> Mapping[str, Any]:
        matches = [
            template
            for template in self.policy_bundle.role_templates
            if template["templateId"] == template_id
        ]
        if len(matches) != 1:
            self._fail("ROLE_TEMPLATE_UNKNOWN", "не найден точный шаблон роли")
        return matches[0]

    def _validated_plan_nodes(
        self,
        nodes: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        if type(nodes) is not list:
            self._fail("PLAN_GRAPH_INVALID", "nodes должен быть массивом")
        result: list[dict[str, Any]] = []
        for ordinal, raw in enumerate(nodes):
            if type(raw) is not dict or set(raw) != {
                "clientNodeId",
                "dependencyIds",
                "routingInput",
            }:
                self._fail(
                    "PLAN_GRAPH_INVALID",
                    f"узел {ordinal} имеет незакрытый набор полей",
                )
            client_node_id = raw["clientNodeId"]
            dependencies = raw["dependencyIds"]
            routing_input = raw["routingInput"]
            if (
                type(client_node_id) is not str
                or _CLIENT_NODE_ID.fullmatch(client_node_id) is None
            ):
                self._fail(
                    "PLAN_GRAPH_INVALID",
                    f"узел {ordinal} имеет неверный clientNodeId",
                )
            if (
                type(dependencies) is not list
                or len(dependencies) > 20
                or len(dependencies) != len(set(dependencies))
                or any(
                    type(dependency) is not str
                    or _CLIENT_NODE_ID.fullmatch(dependency) is None
                    for dependency in dependencies
                )
            ):
                self._fail(
                    "PLAN_GRAPH_INVALID",
                    f"узел {client_node_id} имеет неверные dependencyIds",
                )
            if type(routing_input) is not dict:
                self._fail(
                    "PLAN_GRAPH_INVALID",
                    f"узел {client_node_id} не имеет routingInput",
                )
            try:
                public_routing_input = validate_public_routing_input_v2(routing_input)
            except PublicRoutingInputV2Error as exc:
                self._fail("ROUTING_INPUT_INVALID", str(exc))
            item = copy.deepcopy(raw)
            item["routingInput"] = public_routing_input
            result.append(item)
        return result

    def _initial_routing_input(
        self,
        routing_input: Mapping[str, Any],
    ) -> dict[str, Any]:
        public = copy.deepcopy(dict(routing_input))
        task_facts = copy.deepcopy(public["taskFacts"])
        permission = self.policy_bundle.delegation_policy["delegateRequirements"].get(
            "permission"
        )
        if permission != "allow":
            self._fail(
                "DELEGATION_POLICY_INVALID",
                "политика не задаёт серверное разрешение умного хода",
            )
        permission_evidence_sha256 = domain_fingerprint(
            "codex-smart/delegation-permission-evidence/v2",
            {
                "policyBundleFingerprint": self.policy_bundle.bundle_fingerprint,
                "policyId": self.policy_bundle.delegation_policy["policyId"],
                "permission": permission,
            },
        )
        task_facts["schemaVersion"] = 1
        task_facts["contractVersion"] = "codex-task-facts-v1"
        task_facts["evidence"].append(
            {
                "evidenceRefId": SERVER_PERMISSION_EVIDENCE_REF,
                "kind": "explicit-policy",
                "statement": (
                    "Активный умный ход разрешает делегирование независимо "
                    "проверяемого узла."
                ),
                "sha256": permission_evidence_sha256,
            }
        )
        task_facts["delegation"]["permission"] = {
            "value": permission,
            "evidenceRefIds": [SERVER_PERMISSION_EVIDENCE_REF],
        }
        candidate = {
            "schemaVersion": 2,
            "contractVersion": "codex-routing-input-v2",
            "semanticVersion": "q+p+v+o-v2",
            "phase": "smart-plan",
            "taskFacts": task_facts,
            "delegationPolicyRef": self.policy_bundle.delegation_policy["policyId"],
            "contextBundle": copy.deepcopy(public["contextBundle"]),
            "roleTemplateId": public["roleTemplateId"],
        }
        candidate["catalogs"] = {
            "policyPairs": [
                copy.deepcopy(dict(pair)) for pair in self.policy_bundle.policy_pairs
            ],
            "bundledSnapshotPairs": [
                copy.deepcopy(dict(pair)) for pair in self.bundled_snapshot_pairs
            ],
            "accountPairs": None,
        }
        candidate["accountEvidenceJobs"] = []
        candidate["reassessment"] = {
            "mode": "initial",
            "currentPair": None,
            "explicitPolicyAllowed": False,
        }
        return candidate

    def _routing_input_for_node(
        self,
        plan_output: Mapping[str, Any],
        node_id: str,
    ) -> dict[str, Any]:
        try:
            return node_routing_input_v2(plan_output, node_id)
        except PlanProjectionV2Error as exc:
            self._fail(exc.code, exc.message)

    def _child_profile_for_execution(self, execution_profile: str) -> Mapping[str, Any]:
        matches = [
            profile
            for profile in self.policy_bundle.child_profiles
            if profile["role"] == execution_profile
        ]
        if len(matches) != 1:
            self._fail("CHILD_PROFILE_UNKNOWN", "не найден профиль выполнения")
        return matches[0]

    def _child_profile_for_permission(
        self, permission_profile_id: str
    ) -> dict[str, Any]:
        matches = [
            profile
            for profile in self.policy_bundle.child_profiles
            if profile["permissionProfileId"] == permission_profile_id
        ]
        if len(matches) != 1:
            self._fail("CHILD_PROFILE_UNKNOWN", "не найден профиль разрешений")
        return copy.deepcopy(dict(matches[0]))

    def _verify_request_context(self, request_context: RequestContextV2) -> None:
        if (
            request_context.compatibility_fingerprint
            != self.interface_evidence["compatibilityFingerprint"]
        ):
            self._fail(
                "REQUEST_CONTEXT_COMPATIBILITY_DRIFT",
                "контекст запроса относится к другому снимку интерфейса",
            )

    @staticmethod
    def _error_code(exc: Exception) -> str:
        if isinstance(
            exc, (SmartServiceV2Error, EvidenceError, ManagedRequirementsError)
        ):
            return str(exc.code)
        if isinstance(exc, ContractError):
            return "ROUTING_INPUT_INVALID"
        return "ACCOUNT_EVIDENCE_UNAVAILABLE"

    @staticmethod
    def _public_problem(internal_code: str) -> dict[str, Any]:
        if internal_code in {
            "ACCOUNT_DEADLINE_EXCEEDED",
            "ACCOUNT_EVIDENCE_DEADLINE",
            "REQUEST_DEADLINE_EXCEEDED",
        }:
            return {
                "category": "UNAVAILABLE",
                "code": "REQUEST_DEADLINE_EXCEEDED",
                "message": "Истёк общий срок сбора доказательств учётной среды.",
                "retryable": True,
            }
        if internal_code in {
            "ROUTING_PAIR_UNAVAILABLE",
            "EXACT_PAIR_UNAVAILABLE",
        }:
            return {
                "category": "UNAVAILABLE",
                "code": "ROUTING_PAIR_UNAVAILABLE",
                "message": "Точная выбранная пара модели и рассуждения недоступна.",
                "retryable": False,
            }
        if internal_code in {
            "ACTIVATION_GATE_UNAVAILABLE",
            "ACTIVATION_GATE_INVALID",
            "ACTIVATION_GATE_CHANGED",
            "CONTROL_EPOCH_MISMATCH",
        }:
            return {
                "category": "UNAVAILABLE",
                "code": "ADAPTIVE_ACTIVATION_UNCOMMITTED",
                "message": "Не удалось подтвердить действующую активацию умного режима.",
                "retryable": True,
            }
        return {
            "category": "UNAVAILABLE",
            "code": "ACCOUNT_EVIDENCE_UNAVAILABLE",
            "message": "Не удалось получить согласованное доказательство учётной среды.",
            "retryable": True,
        }

    def _validated_bundled_pairs(
        self,
        pairs: Sequence[Mapping[str, str]],
    ) -> tuple[dict[str, str], ...]:
        result: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        policy = {
            (pair["model"], pair["reasoningEffort"])
            for pair in self.policy_bundle.policy_pairs
        }
        for raw in pairs:
            if type(raw) is not dict or set(raw) != {"model", "reasoningEffort"}:
                self._fail("BUNDLED_CATALOG_INVALID", "неверная форма пары")
            pair = {
                "model": raw["model"],
                "reasoningEffort": raw["reasoningEffort"],
            }
            key = (pair["model"], pair["reasoningEffort"])
            if key in seen or key not in policy:
                self._fail("BUNDLED_CATALOG_INVALID", "пара повторена или вне политики")
            seen.add(key)
            result.append(pair)
        if not result:
            self._fail("BUNDLED_CATALOG_INVALID", "каталог снимка пуст")
        return tuple(result)

    def _validated_bundled_catalog_projection(
        self,
        value: Mapping[str, Any],
    ) -> tuple[dict[str, Any], tuple[dict[str, str], ...]]:
        try:
            projection = copy.deepcopy(dict(value))
        except (TypeError, ValueError, RecursionError) as exc:
            self._fail("BUNDLED_CATALOG_INVALID", str(exc))
        if set(projection) != {"models"} or type(projection["models"]) is not list:
            self._fail("BUNDLED_CATALOG_INVALID", "неверная защитная проекция")
        models = projection["models"]
        if not 1 <= len(models) <= 256:
            self._fail("BUNDLED_CATALOG_INVALID", "неверное число моделей")
        observed_pairs: set[tuple[str, str]] = set()
        observed_models: list[str] = []
        for record in models:
            if type(record) is not dict or set(record) != {"model", "reasoningEfforts"}:
                self._fail("BUNDLED_CATALOG_INVALID", "неверная запись модели")
            model = record["model"]
            efforts = record["reasoningEfforts"]
            if (
                type(model) is not str
                or not model
                or len(model.encode("utf-8")) > 128
                or type(efforts) is not list
                or not 1 <= len(efforts) <= 32
                or any(
                    type(effort) is not str
                    or not effort
                    or len(effort.encode("utf-8")) > 32
                    for effort in efforts
                )
                or efforts
                != sorted(set(efforts), key=lambda item: item.encode("utf-8"))
            ):
                self._fail("BUNDLED_CATALOG_INVALID", "неверная модель или уровни")
            observed_models.append(model)
            observed_pairs.update((model, effort) for effort in efforts)
        if observed_models != sorted(
            set(observed_models), key=lambda item: item.encode("utf-8")
        ):
            self._fail(
                "BUNDLED_CATALOG_INVALID", "модели не отсортированы или повторены"
            )
        policy_pairs = tuple(
            copy.deepcopy(dict(pair))
            for pair in self.policy_bundle.policy_pairs
            if (pair["model"], pair["reasoningEffort"]) in observed_pairs
        )
        if not policy_pairs:
            self._fail("BUNDLED_CATALOG_INVALID", "нет ни одной разрешённой пары")
        return projection, policy_pairs

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            self._fail("CLOCK_INVALID", "часы должны возвращать время с поясом")
        return value.astimezone(timezone.utc)

    def _live_control_epoch(self, request_context: RequestContextV2) -> int:
        if self.live_control_epoch_provider is None:
            return request_context.issued_control_epoch
        try:
            value = self.live_control_epoch_provider()
        except Exception as exc:
            self._fail("CONTROL_EPOCH_UNAVAILABLE", str(exc))
        if type(value) is not int or not 1 <= value <= _MAX_SAFE_INTEGER:
            self._fail(
                "CONTROL_EPOCH_INVALID",
                "поставщик вернул неверную текущую эпоху контроллера",
            )
        return value

    @staticmethod
    def _fail(code: str, message: str) -> None:
        raise SmartServiceV2Error(code, message)

"""Application service behind the four public smart-subagent tools."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import AbstractSet, Any, Callable, Iterator, Mapping

from .catalog import Catalog
from .contracts import (
    ContractError,
    SCHEMA_VERSION,
    validate_tool_input,
    validate_tool_output,
)
from .graph import GraphError, TaskNode, validate_graph
from .identity import RequestContext, canonical_sha256, new_opaque_id
from .routing import (
    ComplexityFactors,
    DelegationAssessment,
    Disposition,
    Interval,
    ModelUnavailable,
    ReasoningFactors,
    classify_delegation,
    resolve_boundary,
    select_available_model_effort,
)
from .state import RouteState, is_terminal
from .store import (
    IdempotencyConflict,
    QueueFull,
    RouteExpired,
    RouteForbidden,
    RouteNotFound,
    RouteNotStartable,
    SmartStore,
    StoreError,
    TurnBindingError,
)


@dataclass
class ServiceError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


Reclassifier = Callable[[dict[str, Any]], DelegationAssessment | None]


@dataclass
class _PlanFlight:
    lock: threading.Lock = field(default_factory=threading.Lock)
    users: int = 0


_PLAN_FLIGHTS_GUARD = threading.Lock()
_PLAN_FLIGHTS: dict[tuple[str, str], _PlanFlight] = {}


@contextmanager
def _single_plan_flight(
    key: tuple[str, str],
) -> Iterator[None]:
    with _PLAN_FLIGHTS_GUARD:
        flight = _PLAN_FLIGHTS.setdefault(key, _PlanFlight())
        flight.users += 1
    acquired = False
    try:
        flight.lock.acquire()
        acquired = True
        yield
    finally:
        if acquired:
            flight.lock.release()
        with _PLAN_FLIGHTS_GUARD:
            flight.users -= 1
            if flight.users == 0 and _PLAN_FLIGHTS.get(key) is flight:
                del _PLAN_FLIGHTS[key]


class SmartService:
    def __init__(
        self,
        store: SmartStore,
        catalog: Catalog,
        *,
        reclassifier: Reclassifier | None = None,
        available_model_efforts: (
            Mapping[str, AbstractSet[str]] | None
        ) = None,
        max_reclassifier_workers: int = 1,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.catalog = catalog
        self.reclassifier = reclassifier
        source = (
            {
                model: frozenset(settings["reasoning_efforts"])
                for model, settings in catalog.models.items()
            }
            if available_model_efforts is None
            else dict(available_model_efforts)
        )
        trusted: dict[str, frozenset[str]] = {}
        for model, efforts in source.items():
            if model not in catalog.models:
                raise ValueError("available model is absent from the catalog")
            selected = frozenset(efforts)
            policy = frozenset(
                catalog.models[model]["reasoning_efforts"]
            )
            if not selected or not selected <= policy:
                raise ValueError(
                    "available reasoning efforts exceed the catalog policy"
                )
            trusted[model] = selected
        if not trusted:
            raise ValueError("at least one routing model must be available")
        if (
            type(max_reclassifier_workers) is not int
            or not 1 <= max_reclassifier_workers <= catalog.limits["max_nodes"]
        ):
            raise ValueError(
                "max_reclassifier_workers is outside the graph limit"
            )
        self.available_model_efforts = trusted
        self.max_reclassifier_workers = max_reclassifier_workers
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def smart_plan(
        self,
        payload: dict[str, Any],
        request_context: RequestContext,
    ) -> dict[str, Any]:
        arguments = self._validate("smart_plan", payload)
        if arguments["catalogGeneration"] != self.catalog.generation:
            raise ServiceError(
                "CATALOG_STALE",
                "requested catalog generation is not active",
            )
        self._validate_catalog_references(arguments["nodes"])
        flight_key = (
            str(self.store.path.resolve()),
            request_context.digest(),
        )
        with _single_plan_flight(flight_key):
            return self._smart_plan_validated(arguments, request_context)

    def _smart_plan_validated(
        self,
        arguments: dict[str, Any],
        request_context: RequestContext,
    ) -> dict[str, Any]:
        request_material = {
            key: value
            for key, value in arguments.items()
            if key not in {"turnBinding", "requestKey"}
        }
        request_hash = canonical_sha256(request_material)
        try:
            self.store.require_turn_binding_usable(
                arguments["turnBinding"],
                request_context,
                request_key=arguments["requestKey"],
                request_hash=request_hash,
            )
        except TurnBindingError as exc:
            raise ServiceError(exc.code, exc.message) from exc
        existing = self.store.find_route_by_request_key(
            request_context,
            arguments["requestKey"],
        )
        if existing is not None:
            self._consume_binding(
                arguments["turnBinding"],
                request_context,
                arguments["requestKey"],
                request_hash,
            )
            if existing.request_hash != request_hash:
                raise ServiceError(
                    "IDEMPOTENCY_CONFLICT",
                    "request key is already bound to another plan",
                )
            return validate_tool_output("smart_plan", existing.plan_output)

        split_generation = arguments.get("lineage", {}).get("generation", 0)
        try:
            validate_graph(
                [
                    TaskNode(
                        node["clientNodeId"],
                        node["role"],
                        tuple(node["dependencyIds"]),
                    )
                    for node in arguments["nodes"]
                ],
                split_generation=split_generation,
                max_nodes=self.catalog.limits["max_nodes"],
                max_edges=self.catalog.limits["max_edges"],
                max_depth=self.catalog.limits["max_depth"],
            )
        except GraphError as exc:
            raise ServiceError(exc.code, exc.message) from exc

        node_decisions: list[dict[str, Any]] = []
        stored_nodes: list[dict[str, Any]] = []
        clarification_questions: list[str] = []
        secondary_assessments = self._reclassify_boundaries(
            arguments["nodes"]
        )
        for index, node in enumerate(arguments["nodes"]):
            decision = self._route_node(
                node,
                secondary_assessments.get(index),
            )
            node_decisions.append(decision)
            stored_nodes.append({**node, **decision})
            if decision["disposition"] == "clarify":
                question = node.get("clarificationQuestion")
                if not isinstance(question, str) or not question:
                    question = (
                        "Уточните ограничения для подзадачи "
                        f"{node['clientNodeId']}."
                    )
                if question not in clarification_questions:
                    clarification_questions.append(question)

        dispositions = {
            decision["disposition"] for decision in node_decisions
        }
        if "clarify" in dispositions:
            overall = "clarify"
        elif dispositions == {"delegate"}:
            overall = "delegate"
        else:
            overall = "direct"
        startable = overall == "delegate"

        now = self.clock()
        expires_at = now + timedelta(minutes=15)
        route_id = new_opaque_id("rt1")
        output = {
            "schemaVersion": SCHEMA_VERSION,
            "ok": True,
            "code": "PLAN_READY" if startable else overall.upper(),
            "message": "",
            "routeId": route_id,
            "routeGeneration": 1,
            "expiresAt": expires_at.isoformat(),
            "startable": startable,
            "overallDisposition": overall,
            "nodeDecisions": node_decisions,
            "clarificationQuestions": clarification_questions[:3],
            "catalogGeneration": self.catalog.generation,
        }
        output = validate_tool_output("smart_plan", output)
        try:
            stored_route_id = self.store.create_route(
                request_context=request_context,
                request_key=arguments["requestKey"],
                request_hash=request_hash,
                catalog_generation=self.catalog.generation,
                algorithm_version=self.catalog.algorithm_version,
                disposition=overall,
                startable=startable,
                expires_at=expires_at,
                plan_output=output,
                nodes=stored_nodes,
                route_id=route_id,
                turn_binding=arguments["turnBinding"],
                max_active_nodes=self.catalog.limits["queue_nodes"],
            )
        except (IdempotencyConflict, QueueFull, TurnBindingError) as exc:
            raise ServiceError(exc.code, exc.message) from exc
        if stored_route_id != route_id:
            route = self.store.get_route(stored_route_id, request_context)
            return validate_tool_output("smart_plan", route.plan_output)
        return output

    def smart_start(
        self,
        payload: dict[str, Any],
        request_context: RequestContext,
    ) -> dict[str, Any]:
        arguments = self._validate("smart_start", payload)
        try:
            route = self.store.start_route(
                arguments["routeId"],
                request_context,
                now=self.clock(),
            )
        except (
            RouteExpired,
            RouteForbidden,
            RouteNotFound,
            RouteNotStartable,
        ) as exc:
            raise ServiceError(exc.code, exc.message) from exc
        return validate_tool_output(
            "smart_start",
            {
                "schemaVersion": SCHEMA_VERSION,
                "ok": True,
                "code": "STARTED",
                "message": "",
                "routeId": route.route_id,
                "runId": route.run_id or "",
                "state": route.state.value,
                "acceptedAt": self.clock().isoformat(),
            },
        )

    def smart_wait(
        self,
        payload: dict[str, Any],
        request_context: RequestContext,
    ) -> dict[str, Any]:
        arguments = self._validate("smart_wait", payload)
        deadline = time.monotonic() + arguments["timeoutSeconds"]
        events: list[dict[str, Any]] = []
        route = None
        while True:
            try:
                route = self.store.get_route(
                    arguments["routeId"],
                    request_context,
                )
                events = self.store.events_after(
                    arguments["routeId"],
                    request_context,
                    arguments["afterSequence"],
                )
            except (RouteForbidden, RouteNotFound) as exc:
                raise ServiceError(exc.code, exc.message) from exc
            if events or is_terminal(route.state) or time.monotonic() >= deadline:
                break
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

        truncated = len(events) > 100
        visible_events = events[:100]
        sequence = (
            visible_events[-1]["sequence"]
            if visible_events
            else arguments["afterSequence"]
        )
        output: dict[str, Any] = {
            "schemaVersion": SCHEMA_VERSION,
            "ok": True,
            "code": "TERMINAL" if is_terminal(route.state) else "WAITING",
            "message": "",
            "routeId": route.route_id,
            "state": route.state.value,
            "sequence": sequence,
            "events": visible_events,
            "truncated": truncated,
        }
        if route.terminal_result is not None:
            output["terminalResult"] = route.terminal_result
        return validate_tool_output("smart_wait", output)

    def smart_cancel(
        self,
        payload: dict[str, Any],
        request_context: RequestContext,
    ) -> dict[str, Any]:
        arguments = self._validate("smart_cancel", payload)
        try:
            route, before, accepted = self.store.request_cancel(
                arguments["routeId"],
                request_context,
                arguments["reasonCode"],
            )
        except (RouteForbidden, RouteNotFound) as exc:
            raise ServiceError(exc.code, exc.message) from exc
        return validate_tool_output(
            "smart_cancel",
            {
                "schemaVersion": SCHEMA_VERSION,
                "ok": True,
                "code": "CANCEL_ACCEPTED" if accepted else "ALREADY_TERMINAL",
                "message": "",
                "routeId": route.route_id,
                "previousState": before.value,
                "newState": route.state.value,
                "accepted": accepted,
            },
        )

    def _route_node(
        self,
        node: dict[str, Any],
        secondary: DelegationAssessment | None = None,
    ) -> dict[str, Any]:
        raw = node["assessment"]
        assessment = _delegation_assessment(node)
        delegation = classify_delegation(assessment)
        if delegation.disposition is Disposition.BOUNDARY:
            delegation = resolve_boundary(assessment, secondary)

        complexity = raw["complexity"]
        risk_flags = set(node["riskFlags"])
        if node["role"] == "implementer":
            risk_flags.add("writer_final_validation")
        reasoning = raw["reasoning"]
        try:
            model, effort = select_available_model_effort(
                ComplexityFactors(
                    complexity["ambiguity"],
                    complexity["dependencyDepth"],
                    complexity["breadth"],
                    complexity["novelty"],
                    complexity["harm"],
                    complexity["crossDomain"],
                ),
                ReasoningFactors(
                    reasoning["evidence"],
                    reasoning["verification"],
                    reasoning["harm"],
                ),
                risk_flags=risk_flags,
                available_efforts=self.available_model_efforts,
            )
        except ModelUnavailable as exc:
            raise ServiceError(
                "MODEL_UNAVAILABLE",
                "no available model satisfies the requested task",
            ) from exc
        profile_alias = (
            "writer" if node["role"] == "implementer" else "reader"
        )
        return {
            "clientNodeId": node["clientNodeId"],
            "disposition": (
                "direct"
                if delegation.disposition is Disposition.BOUNDARY
                else delegation.disposition.value
            ),
            "selectedModel": model,
            "reasoningEffort": effort,
            "permissionProfileId": self.catalog.opaque_id(
                "permission",
                profile_alias,
            ),
            "reasonCode": delegation.reason,
        }

    def _reclassify_boundaries(
        self,
        nodes: list[dict[str, Any]],
    ) -> dict[int, DelegationAssessment | None]:
        if self.reclassifier is None:
            return {}
        boundary = [
            (index, node)
            for index, node in enumerate(nodes)
            if classify_delegation(
                _delegation_assessment(node)
            ).disposition
            is Disposition.BOUNDARY
        ]
        if not boundary:
            return {}
        workers = min(self.max_reclassifier_workers, len(boundary))
        if workers == 1:
            return {
                index: self._safe_reclassify(node)
                for index, node in boundary
            }
        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="codex-smart-boundary",
        ) as executor:
            futures = {
                index: executor.submit(self._safe_reclassify, node)
                for index, node in boundary
            }
            return {
                index: future.result()
                for index, future in futures.items()
            }

    def _safe_reclassify(
        self,
        node: dict[str, Any],
    ) -> DelegationAssessment | None:
        try:
            return None if self.reclassifier is None else self.reclassifier(node)
        except Exception:
            return None

    def _validate_catalog_references(
        self,
        nodes: list[dict[str, Any]],
    ) -> None:
        scope_default = self.catalog.opaque_id("scope", "default")
        artifact_report = self.catalog.opaque_id("artifact", "report")
        artifact_candidate = self.catalog.opaque_id(
            "artifact",
            "candidate",
        )
        validation_none = self.catalog.opaque_id("validation", "none")
        validation_ids = {
            self.catalog.opaque_id("validation", alias)
            for alias in self.catalog.validation
        }
        for node in nodes:
            if node["scopeId"] != scope_default:
                raise ServiceError(
                    "CATALOG_REFERENCE_INVALID",
                    "node scope is not present in the active catalog",
                )
            writer = node["role"] == "implementer"
            expected_artifact = (
                artifact_candidate if writer else artifact_report
            )
            if node["artifactProfileId"] != expected_artifact:
                raise ServiceError(
                    "CATALOG_REFERENCE_INVALID",
                    "node artifact profile is incompatible with its role",
                )
            validation_id = node["validationProfileId"]
            if validation_id not in validation_ids or (
                not writer and validation_id != validation_none
            ):
                raise ServiceError(
                    "CATALOG_REFERENCE_INVALID",
                    "node validation profile is incompatible with its role",
                )

    def _validate(
        self,
        tool: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            return validate_tool_input(tool, payload)
        except ContractError as exc:
            raise ServiceError(exc.code, str(exc)) from exc

    def _consume_binding(
        self,
        binding: str,
        request_context: RequestContext,
        request_key: str,
        request_hash: str,
    ) -> None:
        try:
            self.store.consume_turn_binding(
                binding,
                request_context,
                request_key=request_key,
                request_hash=request_hash,
            )
        except TurnBindingError as exc:
            raise ServiceError(exc.code, exc.message) from exc


def _interval(value: dict[str, int]) -> Interval:
    return Interval(value["min"], value["max"])


def _delegation_assessment(
    node: dict[str, Any],
) -> DelegationAssessment:
    raw = node["assessment"]["delegation"]
    return DelegationAssessment(
        q=_interval(raw["q"]),
        p=_interval(raw["p"]),
        v=_interval(raw["v"]),
        o=_interval(raw["o"]),
        hard_ban=(
            None
            if node.get("hardBan") is None
            else Disposition(node["hardBan"])
        ),
        writer=node["role"] == "implementer",
    )

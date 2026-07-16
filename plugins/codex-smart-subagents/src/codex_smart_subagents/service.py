"""Application service behind the four public smart-subagent tools."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

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
    ReasoningFactors,
    classify_delegation,
    normalize_model_effort,
    resolve_boundary,
    select_model,
    select_reasoning_effort,
)
from .state import RouteState, is_terminal
from .store import (
    IdempotencyConflict,
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


class SmartService:
    def __init__(
        self,
        store: SmartStore,
        catalog: Catalog,
        *,
        reclassifier: Reclassifier | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.catalog = catalog
        self.reclassifier = reclassifier
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

        request_material = {
            key: value
            for key, value in arguments.items()
            if key not in {"turnBinding", "requestKey"}
        }
        request_hash = canonical_sha256(request_material)
        existing = self.store.find_route_by_request_key(
            request_context,
            arguments["requestKey"],
        )
        if existing is not None:
            if existing.request_hash != request_hash:
                raise ServiceError(
                    "IDEMPOTENCY_CONFLICT",
                    "request key is already bound to another plan",
                )
            self._consume_binding(arguments["turnBinding"], request_context)
            return validate_tool_output("smart_plan", existing.plan_output)

        self._consume_binding(arguments["turnBinding"], request_context)
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
        for node in arguments["nodes"]:
            decision = self._route_node(node)
            node_decisions.append(decision)
            stored_nodes.append({**node, **decision})

        dispositions = {
            decision["disposition"] for decision in node_decisions
        }
        if "clarify" in dispositions:
            overall = "clarify"
        elif "delegate" in dispositions:
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
            "clarificationQuestions": [],
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
            )
        except IdempotencyConflict as exc:
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

    def _route_node(self, node: dict[str, Any]) -> dict[str, Any]:
        raw = node["assessment"]
        assessment = DelegationAssessment(
            q=_interval(raw["delegation"]["q"]),
            p=_interval(raw["delegation"]["p"]),
            v=_interval(raw["delegation"]["v"]),
            o=_interval(raw["delegation"]["o"]),
            writer=node["role"] == "implementer",
        )
        delegation = classify_delegation(assessment)
        if delegation.disposition is Disposition.BOUNDARY:
            secondary = (
                None if self.reclassifier is None else self.reclassifier(node)
            )
            delegation = resolve_boundary(assessment, secondary)

        complexity = raw["complexity"]
        model = select_model(
            ComplexityFactors(
                complexity["ambiguity"],
                complexity["dependencyDepth"],
                complexity["breadth"],
                complexity["novelty"],
                complexity["harm"],
                complexity["crossDomain"],
            ),
            risk_flags=set(node["riskFlags"]),
            available=set(self.catalog.models),
        )
        reasoning = raw["reasoning"]
        effort = select_reasoning_effort(
            ReasoningFactors(
                reasoning["evidence"],
                reasoning["verification"],
                reasoning["harm"],
            )
        )
        model, effort = normalize_model_effort(model, effort)
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
    ) -> None:
        try:
            self.store.consume_turn_binding(binding, request_context)
        except TurnBindingError as exc:
            raise ServiceError(exc.code, exc.message) from exc


def _interval(value: dict[str, int]) -> Interval:
    return Interval(value["min"], value["max"])

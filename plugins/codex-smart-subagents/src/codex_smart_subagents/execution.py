"""Durable dependency-aware execution loop for planned smart-subagent routes."""

from __future__ import annotations

import hashlib
import os
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from .identity import RequestContext, canonical_sha256, new_opaque_id
from .state import RouteState
from .store import ClaimedRoute, NodeRecord, SmartStore


TOKEN_USAGE_FIELDS = {
    "input_tokens": "inputTokens",
    "cached_input_tokens": "cachedInputTokens",
    "output_tokens": "outputTokens",
    "reasoning_output_tokens": "reasoningOutputTokens",
}
TOKEN_USAGE_KEYS = frozenset(TOKEN_USAGE_FIELDS.values())
MAX_TOKEN_COUNT = 10**12


@dataclass
class NodeExecutionError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class NodeExecutionOutcome:
    summary: str
    fingerprint: str
    validation_state: str
    artifact_id: str
    attestation: dict[str, Any]
    permission_probe_id: str
    argv_fingerprint: str
    usage: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if len(self.summary) > 4000:
            raise ValueError("node summary exceeds the limit")
        for name in ("fingerprint", "argv_fingerprint"):
            value = getattr(self, name)
            if (
                len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{name} must be lowercase SHA-256")
        if self.validation_state not in {
            "not_applicable",
            "passed",
            "failed",
            "quarantined",
        }:
            raise ValueError("validation_state is invalid")
        if not self.permission_probe_id:
            raise ValueError("permission_probe_id is required")
        if len(self.artifact_id) > 80:
            raise ValueError("artifact_id exceeds the limit")
        if (
            not isinstance(self.usage, dict)
            or not set(self.usage) <= TOKEN_USAGE_KEYS
        ):
            raise ValueError("usage contains unsupported fields")
        for value in self.usage.values():
            if (
                type(value) is not int
                or value < 0
                or value > MAX_TOKEN_COUNT
            ):
                raise ValueError("usage contains an invalid token count")
        object.__setattr__(
            self,
            "usage",
            {
                key: self.usage[key]
                for key in sorted(self.usage)
            },
        )


def extract_token_usage(events: object) -> dict[str, int]:
    """Return only bounded token counters from the final completed turn."""

    if not isinstance(events, (list, tuple)):
        return {}
    completed = next(
        (
            event
            for event in reversed(events)
            if isinstance(event, dict)
            and event.get("type") == "turn.completed"
        ),
        None,
    )
    if completed is None:
        return {}
    raw = completed.get("usage")
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise NodeExecutionError(
            "CHILD_USAGE_INVALID",
            "child token usage is not an object",
        )
    usage: dict[str, int] = {}
    for source, target in TOKEN_USAGE_FIELDS.items():
        value = raw.get(source)
        if value is None:
            continue
        if (
            type(value) is not int
            or value < 0
            or value > MAX_TOKEN_COUNT
        ):
            raise NodeExecutionError(
                "CHILD_USAGE_INVALID",
                "child token usage contains an invalid counter",
            )
        usage[target] = value
    return usage


@dataclass(frozen=True)
class NodeExecutionRequest:
    route_id: str
    context: RequestContext
    node: NodeRecord
    dependency_results: dict[str, NodeExecutionOutcome]


class NodeExecutor(Protocol):
    def execute(
        self,
        request: NodeExecutionRequest,
        cancellation: threading.Event,
    ) -> NodeExecutionOutcome:
        ...


class ExecutionEngine:
    """Claim one route, execute its DAG, and commit a terminal result."""

    def __init__(
        self,
        store: SmartStore,
        executor: NodeExecutor,
        *,
        max_workers: int,
        max_sol_workers: int,
        lease_seconds: int,
        heartbeat_seconds: int,
        shutdown_event: threading.Event | None = None,
    ) -> None:
        if (
            max_workers <= 0
            or max_sol_workers <= 0
            or lease_seconds <= 0
            or heartbeat_seconds <= 0
            or heartbeat_seconds >= lease_seconds
        ):
            raise ValueError("execution limits are invalid")
        self.store = store
        self.executor = executor
        self.max_workers = max_workers
        self.max_sol_workers = max_sol_workers
        self.lease_seconds = lease_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.owner_id = new_opaque_id("owner1")
        self.start_marker = f"{os.getpid()}:{time.monotonic_ns()}"
        self._sol_semaphore = threading.BoundedSemaphore(max_sol_workers)
        self.shutdown_event = shutdown_event

    def run_once(self) -> bool:
        if self.shutdown_event is not None and self.shutdown_event.is_set():
            return False
        claim = self.store.claim_next_route(
            owner_id=self.owner_id,
            pid=os.getpid(),
            start_marker=self.start_marker,
            now=datetime.now(timezone.utc),
            lease_seconds=self.lease_seconds,
        )
        if claim is None:
            return False
        cancellation = threading.Event()
        monitor = _LeaseMonitor(
            store=self.store,
            claim=claim,
            owner_id=self.owner_id,
            lease_seconds=self.lease_seconds,
            heartbeat_seconds=self.heartbeat_seconds,
            cancellation=cancellation,
            shutdown_event=self.shutdown_event,
        )
        monitor.start()
        try:
            self._run_claim(claim, cancellation)
        finally:
            monitor.stop()
            self.store.release_route_lease(
                route_id=claim.route.route_id,
                owner_id=self.owner_id,
                lease_token=claim.lease_token,
            )
        return True

    def run_forever(
        self,
        stop: threading.Event,
        *,
        poll_seconds: float = 0.2,
    ) -> None:
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")
        recovered = self.store.recover_stale_leases(
            now=datetime.now(timezone.utc)
        )
        for route_id in recovered:
            self.store.requeue_recovering(route_id)
        while not stop.is_set():
            if not self.run_once():
                stop.wait(poll_seconds)

    def _run_claim(
        self,
        claim: ClaimedRoute,
        cancellation: threading.Event,
    ) -> None:
        route_id = claim.route.route_id
        context = claim.context
        try:
            self.store.transition_route(
                route_id,
                context,
                RouteState.PREPARING,
                event="route_preparing",
                code="PREPARING",
                message="",
            )
            self.store.transition_route(
                route_id,
                context,
                RouteState.RUNNING,
                event="route_running",
                code="RUNNING",
                message="",
            )
            outcomes = self._execute_graph(claim, cancellation)
            if cancellation.is_set() or self.store.route_state(route_id) in {
                RouteState.CANCELLING,
                RouteState.CANCELLED,
            }:
                self._finish_cancelled(route_id, context)
                return
            for state, event in (
                (RouteState.COLLECTING, "route_collecting"),
                (RouteState.ATTESTING, "route_attesting"),
                (RouteState.VALIDATING, "route_validating"),
            ):
                self.store.transition_route(
                    route_id,
                    context,
                    state,
                    event=event,
                    code=state.value,
                    message="",
                )
            writer = next(
                (
                    outcomes[node.node_id]
                    for node in claim.nodes
                    if node.role == "implementer"
                ),
                None,
            )
            if writer is not None:
                self.store.transition_route(
                    route_id,
                    context,
                    RouteState.CANDIDATE_BUILDING,
                    event="candidate_building",
                    code="CANDIDATE_BUILDING",
                    message="",
                )
                terminal_state = (
                    RouteState.CANDIDATE_READY
                    if writer.validation_state == "passed"
                    else RouteState.QUARANTINED
                )
                artifact_id = writer.artifact_id
                validation_state = writer.validation_state
            else:
                terminal_state = RouteState.SUCCEEDED
                artifact_id = "report_" + canonical_sha256(
                    {
                        node_id: outcome.fingerprint
                        for node_id, outcome in sorted(outcomes.items())
                    }
                )[:24]
                validation_state = (
                    "passed"
                    if all(
                        outcome.validation_state
                        in {"passed", "not_applicable"}
                        for outcome in outcomes.values()
                    )
                    else "failed"
                )
            aggregate = canonical_sha256(
                {
                    node_id: {
                        "fingerprint": outcome.fingerprint,
                        "validationState": outcome.validation_state,
                        "artifactId": outcome.artifact_id,
                    }
                    for node_id, outcome in sorted(outcomes.items())
                }
            )
            summary = "\n".join(
                outcome.summary
                for _node_id, outcome in sorted(outcomes.items())
            )[:4000]
            usage = {
                key: sum(
                    outcome.usage.get(key, 0)
                    for outcome in outcomes.values()
                )
                for key in sorted(TOKEN_USAGE_KEYS)
                if any(key in outcome.usage for outcome in outcomes.values())
            }
            self.store.finish_route(
                route_id,
                context,
                terminal_state,
                terminal_result={
                    "artifactId": artifact_id,
                    "fingerprint": aggregate,
                    "summary": summary,
                    "validationState": validation_state,
                    "usage": usage,
                },
                event=terminal_state.value.lower(),
                code=terminal_state.value,
                message="",
            )
        except Exception as exc:
            state = self.store.route_state(route_id)
            if cancellation.is_set() or state in {
                RouteState.CANCELLING,
                RouteState.CANCELLED,
            }:
                self._finish_cancelled(route_id, context)
                return
            if state not in {
                RouteState.FAILED,
                RouteState.CANCELLED,
                RouteState.STALE,
            }:
                code = getattr(exc, "code", "EXECUTION_FAILED")
                message = getattr(exc, "message", "route execution failed")
                self.store.finish_route(
                    route_id,
                    context,
                    RouteState.FAILED,
                    terminal_result={
                        "artifactId": "failed_" + route_id[-16:],
                        "fingerprint": hashlib.sha256(
                            f"{route_id}:{code}".encode()
                        ).hexdigest(),
                        "summary": str(message)[:1000],
                        "validationState": "failed",
                    },
                    event="route_failed",
                    code=str(code)[:64],
                    message=str(message)[:1000],
                )

    def _execute_graph(
        self,
        claim: ClaimedRoute,
        cancellation: threading.Event,
    ) -> dict[str, NodeExecutionOutcome]:
        remaining = {node.node_id: node for node in claim.nodes}
        outcomes: dict[str, NodeExecutionOutcome] = {}
        while remaining:
            if cancellation.is_set():
                raise NodeExecutionError("CANCELLED", "route was cancelled")
            ready = [
                node
                for node in remaining.values()
                if set(node.dependencies) <= set(outcomes)
            ]
            if not ready:
                raise NodeExecutionError(
                    "DEPENDENCY_DEADLOCK",
                    "no executable nodes remain in the route graph",
                )
            failures: list[BaseException] = []
            with ThreadPoolExecutor(
                max_workers=self.max_workers,
                thread_name_prefix="codex-smart-node",
            ) as pool:
                futures: dict[Future[NodeExecutionOutcome], NodeRecord] = {
                    pool.submit(
                        self._execute_node,
                        claim,
                        node,
                        dict(outcomes),
                        cancellation,
                    ): node
                    for node in ready
                }
                for future in as_completed(futures):
                    node = futures[future]
                    try:
                        outcomes[node.node_id] = future.result()
                    except BaseException as exc:
                        failures.append(exc)
            if failures:
                first = failures[0]
                if isinstance(first, Exception):
                    raise first
                raise NodeExecutionError(
                    "NODE_ABORTED",
                    "node execution was aborted",
                )
            for node in ready:
                remaining.pop(node.node_id, None)
        return outcomes

    def _execute_node(
        self,
        claim: ClaimedRoute,
        node: NodeRecord,
        dependency_results: dict[str, NodeExecutionOutcome],
        cancellation: threading.Event,
    ) -> NodeExecutionOutcome:
        route_id = claim.route.route_id
        for state, event in (
            (RouteState.LEASED, "node_leased"),
            (RouteState.PREPARING, "node_preparing"),
            (RouteState.RUNNING, "node_running"),
        ):
            self.store.transition_node(
                route_id,
                node.node_id,
                state,
                event=event,
                code=state.value,
                message="",
            )
        expected_fingerprint = canonical_sha256(
            {
                "routeId": route_id,
                "nodeId": node.node_id,
                "model": node.selected_model,
                "reasoningEffort": node.reasoning_effort,
                "permissionProfileId": node.permission_profile_id,
            }
        )
        intent_id = self.store.record_intent(
            route_id=route_id,
            node_id=node.node_id,
            kind="execute_node",
            payload={
                "expectedFingerprint": expected_fingerprint,
                "model": node.selected_model,
                "reasoningEffort": node.reasoning_effort,
            },
        )
        attempt_id = self.store.begin_attempt(
            route_id=route_id,
            node_id=node.node_id,
            model=node.selected_model,
            reasoning_effort=node.reasoning_effort,
            permission_profile_id=node.permission_profile_id,
            pid=0,
            argv_fingerprint=expected_fingerprint,
            permission_probe_id="pending",
        )
        request = NodeExecutionRequest(
            route_id=route_id,
            context=claim.context,
            node=node,
            dependency_results=dependency_results,
        )
        semaphore = (
            self._sol_semaphore
            if node.selected_model == "gpt-5.6-sol"
            else _NullSemaphore()
        )
        try:
            with semaphore:
                outcome = self.executor.execute(request, cancellation)
        except Exception as exc:
            self.store.complete_intent(intent_id)
            cancelled = cancellation.is_set() or getattr(exc, "code", "") == "CANCELLED"
            self.store.complete_attempt(
                attempt_id,
                state="CANCELLED" if cancelled else "FAILED",
                result=None,
                attestation=None,
                error_code=str(getattr(exc, "code", "NODE_FAILED"))[:64],
                error_message=str(getattr(exc, "message", str(exc)))[:1000],
            )
            if cancelled:
                self.store.transition_node(
                    route_id,
                    node.node_id,
                    RouteState.CANCELLING,
                    event="node_cancelling",
                    code="CANCELLED",
                    message="",
                )
                self.store.transition_node(
                    route_id,
                    node.node_id,
                    RouteState.CANCELLED,
                    event="node_cancelled",
                    code="CANCELLED",
                    message="",
                )
            else:
                self.store.transition_node(
                    route_id,
                    node.node_id,
                    RouteState.FAILED,
                    event="node_failed",
                    code=str(getattr(exc, "code", "NODE_FAILED"))[:64],
                    message=str(getattr(exc, "message", str(exc)))[:1000],
                )
            if isinstance(exc, NodeExecutionError):
                raise
            raise NodeExecutionError(
                "NODE_EXECUTION_FAILED",
                "node executor failed",
            ) from exc
        self.store.complete_intent(intent_id)
        self.store.complete_attempt(
            attempt_id,
            state="SUCCEEDED",
            result={
                "summary": outcome.summary,
                "fingerprint": outcome.fingerprint,
                "validationState": outcome.validation_state,
                "artifactId": outcome.artifact_id,
                "usage": outcome.usage,
            },
            attestation=outcome.attestation,
            argv_fingerprint=outcome.argv_fingerprint,
            permission_probe_id=outcome.permission_probe_id,
        )
        for state, event in (
            (RouteState.COLLECTING, "node_collecting"),
            (RouteState.ATTESTING, "node_attesting"),
            (RouteState.VALIDATING, "node_validating"),
        ):
            self.store.transition_node(
                route_id,
                node.node_id,
                state,
                event=event,
                code=state.value,
                message="",
            )
        self.store.complete_node(
            route_id,
            node.node_id,
            result={
                "summary": outcome.summary,
                "fingerprint": outcome.fingerprint,
                "validationState": outcome.validation_state,
                "artifactId": outcome.artifact_id,
                "usage": outcome.usage,
            },
        )
        return outcome

    def _finish_cancelled(
        self,
        route_id: str,
        context: RequestContext,
    ) -> None:
        state = self.store.route_state(route_id)
        if state is RouteState.CANCELLED:
            return
        if state is not RouteState.CANCELLING:
            self.store.transition_route(
                route_id,
                context,
                RouteState.CANCELLING,
                event="route_cancelling",
                code="CANCELLED",
                message="",
            )
        self.store.finish_route(
            route_id,
            context,
            RouteState.CANCELLED,
            terminal_result={
                "artifactId": "cancelled_" + route_id[-16:],
                "fingerprint": hashlib.sha256(
                    f"{route_id}:cancelled".encode()
                ).hexdigest(),
                "summary": "Маршрут отменён.",
                "validationState": "not_applicable",
            },
            event="route_cancelled",
            code="CANCELLED",
            message="",
        )


class _LeaseMonitor:
    def __init__(
        self,
        *,
        store: SmartStore,
        claim: ClaimedRoute,
        owner_id: str,
        lease_seconds: int,
        heartbeat_seconds: int,
        cancellation: threading.Event,
        shutdown_event: threading.Event | None,
    ) -> None:
        self.store = store
        self.claim = claim
        self.owner_id = owner_id
        self.lease_seconds = lease_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.cancellation = cancellation
        self.shutdown_event = shutdown_event
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="codex-smart-lease",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def _run(self) -> None:
        next_heartbeat = time.monotonic() + self.heartbeat_seconds
        while not self._stop.wait(0.05):
            if self.shutdown_event is not None and self.shutdown_event.is_set():
                self.cancellation.set()
                return
            try:
                state = self.store.route_state(self.claim.route.route_id)
                if state in {RouteState.CANCELLING, RouteState.CANCELLED}:
                    self.cancellation.set()
                if time.monotonic() >= next_heartbeat:
                    self.store.heartbeat_route_lease(
                        route_id=self.claim.route.route_id,
                        owner_id=self.owner_id,
                        lease_token=self.claim.lease_token,
                        now=datetime.now(timezone.utc),
                        lease_seconds=self.lease_seconds,
                    )
                    next_heartbeat = time.monotonic() + self.heartbeat_seconds
            except Exception:
                self.cancellation.set()
                return


class _NullSemaphore:
    def __enter__(self) -> "_NullSemaphore":
        return self

    def __exit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        del exc_type, exc, traceback

"""Закрытый публичный переходник протокола умного хода версии 2."""

from __future__ import annotations

import copy
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .canonical_json import canonical_json_v1, domain_fingerprint
from .state_store_v2 import (
    CancellationV2,
    RequestContextV2,
    SmartStoreV2,
    StartEventV2,
    StartStatusV2,
    StartTerminalResultV2,
    TurnBindingV2,
)


PROTOCOL_VERSION = 2
RELEASE = "0.2.0"
PUBLIC_METHODS = (
    "issue_turn_binding",
    "smart_plan",
    "route_start",
    "smart_wait",
    "smart_cancel",
)
_REQUEST_FIELDS = {
    "messageType",
    "protocolVersion",
    "release",
    "requestId",
    "owner",
    "turnBinding",
    "idempotencyKey",
    "requestDeadlineAt",
    "method",
    "params",
    "requestFingerprint",
    "extensions",
}
_RESPONSE_FIELDS = {
    "messageType",
    "protocolVersion",
    "release",
    "requestId",
    "owner",
    "method",
    "responseKind",
    "requestFingerprint",
    "payload",
    "responseFingerprint",
    "extensions",
}
_OWNER_FIELDS = {
    "shellSessionId",
    "sessionId",
    "turnId",
    "ownerFingerprint",
}
_BINDING_FIELDS = {
    "bindingId",
    "owner",
    "contextFingerprint",
    "issuedControlEpoch",
    "issuedAt",
    "expiresAt",
    "state",
}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CLIENT_NODE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,63}$")
_IDENTIFIERS = {
    "requestId": re.compile(r"^strq2_[0-9a-f]{32}$"),
    "idempotencyKey": re.compile(r"^idem2_[0-9a-f]{32}$"),
    "bindingId": re.compile(r"^tb2_[0-9a-f]{32}$"),
    "routeId": re.compile(r"^route2_[0-9a-f]{32}$"),
    "nodeId": re.compile(r"^node2_[0-9a-f]{32}$"),
    "startRequestId": re.compile(r"^sr2_[0-9a-f]{32}$"),
    "evidenceJobId": re.compile(r"^aej2_[0-9a-f]{32}$"),
    "admissionId": re.compile(r"^adm2_[0-9a-f]{32}$"),
    "attemptId": re.compile(r"^att2_[0-9a-f]{32}$"),
    "cursor": re.compile(r"^cur2_[0-9a-f]{32}$"),
}
_REASON_CODES = {"USER_REQUESTED", "TURN_ENDED", "ROUTE_SUPERSEDED"}


@dataclass
class SmartTurnRuntimeV2Error(ValueError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class SmartTurnRuntimeV2:
    """Проецирует службу и хранилище в строгий публичный протокол."""

    def __init__(
        self,
        *,
        service: Any,
        store: SmartStoreV2 | Any,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        for owner, name, methods in (
            (service, "service", ("issue_turn_binding", "smart_plan", "route_start")),
            (store, "store", ("read_start_status", "cancel_start_request")),
        ):
            for method in methods:
                if not callable(getattr(owner, method, None)):
                    raise TypeError(f"{name} must provide {method}()")
        self.service = service
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.monotonic = monotonic or time.monotonic
        self.sleeper = sleeper or time.sleep

    def issue_turn_binding(
        self,
        request: Mapping[str, Any],
        *,
        request_context: RequestContextV2,
    ) -> dict[str, Any]:
        value = self._request(
            request,
            "issue_turn_binding",
            request_context=request_context,
        )
        params = value["params"]
        try:
            binding = self.service.issue_turn_binding(
                request_context,
                ttl_seconds=params["ttlSeconds"],
                request_key=value["idempotencyKey"],
            )
        except Exception as exc:
            return self._problem_response(value, exc)
        projection = _turn_binding_value(binding, value["owner"])
        payload_base = {"status": "ISSUED", "turnBinding": projection}
        payload = {
            **payload_base,
            "effect": self._effect(
                operation="READ" if binding.replayed else "TRANSITION",
                transitions=(
                    []
                    if binding.replayed
                    else [
                        {
                            "table": "turn_bindings",
                            "entityId": binding.binding_id,
                            "beforeState": None,
                            "afterState": binding.state,
                        }
                    ]
                ),
                result_kind="TURN_BINDING",
                result_id=binding.binding_id,
                result_value=payload_base,
            ),
        }
        return _response(value, "SUCCESS", payload)

    def smart_plan(
        self,
        request: Mapping[str, Any],
        *,
        request_context: RequestContextV2,
    ) -> dict[str, Any]:
        value = self._request(request, "smart_plan", request_context=request_context)
        binding = value["turnBinding"]
        try:
            result = self.service.smart_plan(
                binding_id=binding["bindingId"],
                request_context=request_context,
                request_key=value["idempotencyKey"],
                nodes=value["params"]["nodes"],
            )
        except Exception as exc:
            return self._problem_response(value, exc)

        payload_base = {
            "status": "PLANNED",
            "routeId": result.route_id,
            "disposition": result.disposition,
            "nodeDecisions": [
                {
                    "clientNodeId": decision.client_node_id,
                    "nodeId": decision.node_id,
                    "dependencyNodeIds": list(decision.dependency_node_ids),
                    "disposition": decision.disposition,
                    "selectedPair": copy.deepcopy(decision.selected_pair),
                    "score": decision.score,
                    "factors": copy.deepcopy(decision.factors),
                }
                for decision in result.node_decisions
            ],
            "clarification": (
                " ".join(result.clarification)
                if result.disposition == "CLARIFY"
                else None
            ),
            "planFingerprint": result.plan_fingerprint,
        }
        payload = {
            **payload_base,
            "effect": self._effect(
                operation="READ" if result.replayed else "TRANSITION",
                transitions=(
                    []
                    if result.replayed
                    else [
                        {
                            "table": "turn_bindings",
                            "entityId": binding["bindingId"],
                            "beforeState": "ACTIVE",
                            "afterState": "CONSUMED",
                        },
                        {
                            "table": "routes",
                            "entityId": result.route_id,
                            "beforeState": None,
                            "afterState": (
                                "PLANNED"
                                if result.disposition == "DELEGATE"
                                else result.disposition
                            ),
                        },
                    ]
                ),
                result_kind="ROUTE_PLAN",
                result_id=result.route_id,
                result_value=payload_base,
                forced_result_fingerprint=result.plan_fingerprint,
            ),
        }
        return _response(value, "SUCCESS", payload)

    def route_start(
        self,
        request: Mapping[str, Any],
        *,
        request_context: RequestContextV2,
        activation_gate: Mapping[str, Any],
    ) -> dict[str, Any]:
        value = self._request(
            request,
            "route_start",
            request_context=request_context,
            activation_gate=activation_gate,
        )
        params = value["params"]
        try:
            result = self.service.route_start(
                route_id=params["routeId"],
                node_id=params["nodeId"],
                request_context=request_context,
                activation_gate=copy.deepcopy(dict(activation_gate)),
                request_key=value["idempotencyKey"],
            )
        except Exception as exc:
            return self._problem_response(value, exc)
        evidence = {
            "evidenceJobId": result.evidence_job_id,
            "state": "QUEUED",
            "owner": copy.deepcopy(value["owner"]),
            "queuePosition": result.queue_position,
            "deadlineAt": _iso(result.deadline_at),
            "stage": None,
        }
        payload_base = {
            "status": "ATTESTING",
            "routeId": result.route_id,
            "nodeId": result.node_id,
            "startRequestId": result.start_request_id,
            "evidenceJob": evidence,
            "admissionId": None,
        }
        payload = {
            **payload_base,
            "effect": self._effect(
                operation="READ" if result.replayed else "TRANSITION",
                transitions=(
                    []
                    if result.replayed
                    else [
                        {
                            "table": "start_requests",
                            "entityId": result.start_request_id,
                            "beforeState": None,
                            "afterState": "ATTESTING",
                        },
                        {
                            "table": "account_evidence_jobs",
                            "entityId": result.evidence_job_id,
                            "beforeState": None,
                            "afterState": "QUEUED",
                        },
                    ]
                ),
                result_kind="START_REQUEST",
                result_id=result.start_request_id,
                result_value=payload_base,
            ),
        }
        return _response(value, "SUCCESS", payload)

    def smart_wait(
        self,
        request: Mapping[str, Any],
        *,
        request_context: RequestContextV2,
    ) -> dict[str, Any]:
        value = self._request(request, "smart_wait", request_context=request_context)
        params = value["params"]
        wait_deadline = _datetime(params["waitDeadlineAt"], "waitDeadlineAt")
        wait_budget = min(
            60.0,
            max(0.0, (wait_deadline - self._now()).total_seconds()),
        )
        monotonic_deadline = self.monotonic() + wait_budget
        try:
            while True:
                result = self.store.read_start_status(
                    params["startRequestId"],
                    request_context,
                    cursor=params["cursor"],
                    page_size=params["pageSize"],
                )
                if result.terminal or result.page.items:
                    break
                remaining = monotonic_deadline - self.monotonic()
                if remaining <= 0:
                    break
                self.sleeper(min(0.05, remaining))
        except Exception as exc:
            return self._problem_response(value, exc)
        payload_base = _start_status_value(result)
        payload = {
            **payload_base,
            "effect": self._effect(
                operation="READ",
                transitions=[],
                result_kind="WAIT_PAGE",
                result_id=result.start_request_id,
                result_value=payload_base,
            ),
        }
        return _response(value, "SUCCESS", payload)

    def smart_cancel(
        self,
        request: Mapping[str, Any],
        *,
        request_context: RequestContextV2,
    ) -> dict[str, Any]:
        value = self._request(request, "smart_cancel", request_context=request_context)
        params = value["params"]
        try:
            result = self.store.cancel_start_request(
                params["startRequestId"],
                request_context,
                idempotency_key=value["idempotencyKey"],
                reason_code=params["reasonCode"],
                now=self._now(),
            )
        except Exception as exc:
            return self._problem_response(value, exc)
        payload_base = _cancellation_value(result)
        if (
            result.idempotency_status == "REPLAYED"
            or result.status == "ALREADY_TERMINAL"
        ):
            operation = "READ"
            transitions: list[dict[str, Any]] = []
        elif result.status == "CANCEL_REQUESTED":
            operation = "TRANSITION"
            transitions = [
                {
                    "table": "account_evidence_jobs",
                    "entityId": result.start_request_id,
                    "beforeState": "RUNNING",
                    "afterState": "CANCEL_REQUESTED",
                }
            ]
        else:
            operation = "TRANSITION"
            transitions = [
                {
                    "table": "start_requests",
                    "entityId": result.start_request_id,
                    "beforeState": "ATTESTING",
                    "afterState": result.state,
                }
            ]
        payload = {
            **payload_base,
            "effect": self._effect(
                operation=operation,
                transitions=transitions,
                result_kind="CANCELLATION",
                result_id=result.start_request_id,
                result_value=payload_base,
            ),
        }
        return _response(value, "SUCCESS", payload)

    def dispatch(
        self,
        request: Mapping[str, Any],
        *,
        request_context: RequestContextV2,
        activation_gate: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if type(request) is not dict or request.get("method") not in PUBLIC_METHODS:
            _fail("INVALID_REQUEST", "неизвестный публичный метод")
        method = str(request["method"])
        if method == "route_start":
            if activation_gate is None:
                _fail(
                    "AUTHORITATIVE_ACTIVATION_GATE_MISSING",
                    "шлюз активации не передан доверенной зависимостью",
                )
            return self.route_start(
                request,
                request_context=request_context,
                activation_gate=activation_gate,
            )
        return getattr(self, method)(request, request_context=request_context)

    def _request(
        self,
        request: Mapping[str, Any],
        method: str,
        *,
        request_context: RequestContextV2,
        activation_gate: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        value = verify_public_request_v2(request, expected_method=method)
        expected_owner = owner_for_context_v2(request_context)
        if value["owner"] != expected_owner:
            _fail(
                "AUTHORITATIVE_CONTEXT_MISMATCH",
                "владелец запроса не совпал с доверенным контекстом",
            )
        if method == "issue_turn_binding":
            if value["params"]["requestContext"] != request_context.contract_value():
                _fail(
                    "AUTHORITATIVE_CONTEXT_MISMATCH",
                    "requestContext не совпал с доверенным контекстом",
                )
        if method == "route_start":
            if type(activation_gate) is not dict:
                _fail(
                    "AUTHORITATIVE_ACTIVATION_GATE_MISSING",
                    "шлюз активации не передан доверенной зависимостью",
                )
            if value["params"]["activationGate"] != dict(activation_gate):
                _fail(
                    "AUTHORITATIVE_ACTIVATION_GATE_MISMATCH",
                    "параметры запроса расходятся с доверенным шлюзом",
                )
        return value

    def _ordinary_response(
        self,
        request: Mapping[str, Any],
        *,
        reason_code: str,
        message: str,
        route_id: str,
        route_state: str | None,
    ) -> dict[str, Any]:
        payload_base = {
            "status": "ORDINARY",
            "reasonCode": reason_code,
            "ordinaryCommand": "codex",
            "preserveUserRequest": True,
            "message": message[:1024],
        }
        transitions = (
            [
                {
                    "table": "routes",
                    "entityId": route_id,
                    "beforeState": None,
                    "afterState": route_state,
                }
            ]
            if route_state is not None
            else []
        )
        payload = {
            **payload_base,
            "effect": self._effect(
                operation="TRANSITION" if transitions else "READ",
                transitions=transitions,
                result_kind="ORDINARY_DECISION",
                result_id=route_id,
                result_value=payload_base,
            ),
        }
        return _response(request, "ORDINARY", payload)

    def ordinary_unavailable(
        self,
        request: Mapping[str, Any],
        *,
        message: str = "Умный режим недоступен; выполнить исходный запрос в обычном Codex.",
    ) -> dict[str, Any]:
        """Возвращает безопасный обычный путь для плана или начала маршрута."""

        value = verify_public_request_v2(request)
        if value["method"] not in {"smart_plan", "route_start"}:
            _fail("INVALID_ORDINARY_METHOD", "обычный ответ не разрешён этому методу")
        params = value["params"]
        result_id = str(params.get("routeId", value["requestId"]))
        return self._ordinary_response(
            value,
            reason_code="SMART_DISABLED",
            message=message,
            route_id=result_id,
            route_state=None,
        )

    def ordinary_unavailable_call(
        self,
        *,
        method: str,
        request_id: str,
        owner: Mapping[str, Any],
        call_arguments: Mapping[str, Any],
        result_id: str,
        message: str = "Умный режим недоступен; выполнить исходный запрос в обычном Codex.",
    ) -> dict[str, Any]:
        """Закрывает пользовательский вызов до создания публичной мутации."""

        if method not in {"smart_plan", "route_start"}:
            _fail("INVALID_ORDINARY_METHOD", "обычный ответ не разрешён этому методу")
        _identifier(request_id, "requestId")
        trusted_owner = copy.deepcopy(dict(owner))
        _owner(trusted_owner)
        canonical_json_v1(dict(call_arguments))
        request_stub = {
            "requestId": request_id,
            "owner": trusted_owner,
            "method": method,
            "requestFingerprint": domain_fingerprint(
                "codex-smart/mcp-tool-call/v2",
                {
                    "requestId": request_id,
                    "owner": trusted_owner,
                    "method": method,
                    "arguments": copy.deepcopy(dict(call_arguments)),
                },
            ),
        }
        return self._ordinary_response(
            request_stub,
            reason_code="SMART_DISABLED",
            message=message,
            route_id=result_id,
            route_state=None,
        )

    def _problem_response(
        self,
        request: Mapping[str, Any],
        exc: Exception,
    ) -> dict[str, Any]:
        problem = _public_problem(exc)
        response_kind = {
            "STALE": "STALE",
            "UNAVAILABLE": "UNAVAILABLE",
        }.get(problem["category"], "ERROR")
        params = request["params"]
        result_id = str(
            params.get(
                "startRequestId",
                params.get("routeId", request["requestId"]),
            )
        )
        payload_base = {
            "status": response_kind,
            "problem": problem,
        }
        raw_transitions = getattr(exc, "committed_transitions", ())
        transitions = [copy.deepcopy(dict(item)) for item in raw_transitions]
        payload = {
            **payload_base,
            "effect": self._effect(
                operation="TRANSITION" if transitions else "READ",
                transitions=transitions,
                result_kind="PROBLEM",
                result_id=result_id,
                result_value=payload_base,
            ),
        }
        return _response(request, response_kind, payload)

    def _effect(
        self,
        *,
        operation: str,
        transitions: list[dict[str, Any]],
        result_kind: str,
        result_id: str,
        result_value: Mapping[str, Any],
        forced_result_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        if operation not in {"TRANSITION", "READ"}:
            raise AssertionError("неизвестный вид эффекта")
        result_fingerprint = forced_result_fingerprint or domain_fingerprint(
            "codex-smart/smart-turn-result/v2",
            {
                "resultKind": result_kind,
                "resultId": result_id,
                "value": copy.deepcopy(dict(result_value)),
            },
        )
        return {
            "operation": operation,
            "transactionMode": (
                "BEGIN_IMMEDIATE" if operation == "TRANSITION" else "READ_ONLY"
            ),
            "transitions": copy.deepcopy(transitions),
            "completedAt": _iso(self._now()),
            "result": {
                "resultKind": result_kind,
                "resultId": result_id,
                "resultFingerprint": result_fingerprint,
            },
        }

    def _now(self) -> datetime:
        value = self.clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            _fail("CLOCK_INVALID", "часы должны возвращать время с часовым поясом")
        return value.astimezone(timezone.utc)


def owner_for_context_v2(request_context: RequestContextV2) -> dict[str, Any]:
    projection = {
        "shellSessionId": request_context.shell_session_id,
        "sessionId": request_context.session_id,
        "turnId": request_context.turn_id,
    }
    return {
        **projection,
        "ownerFingerprint": domain_fingerprint(
            "codex-smart/smart-turn-owner/v2",
            projection,
        ),
    }


def build_public_request_v2(
    method: str,
    *,
    request_id: str,
    owner: Mapping[str, Any],
    turn_binding: Mapping[str, Any] | None,
    idempotency_key: str | None,
    request_deadline_at: datetime,
    params: Mapping[str, Any],
    extensions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    base = {
        "messageType": "request",
        "protocolVersion": PROTOCOL_VERSION,
        "release": RELEASE,
        "requestId": request_id,
        "owner": copy.deepcopy(dict(owner)),
        "turnBinding": (
            copy.deepcopy(dict(turn_binding)) if turn_binding is not None else None
        ),
        "idempotencyKey": idempotency_key,
        "requestDeadlineAt": _iso(request_deadline_at),
        "method": method,
        "params": copy.deepcopy(dict(params)),
        "extensions": copy.deepcopy(dict(extensions or {})),
    }
    request = {
        **base,
        "requestFingerprint": _request_fingerprint(base),
    }
    return verify_public_request_v2(request, expected_method=method)


def verify_public_request_v2(
    request: Mapping[str, Any],
    *,
    expected_method: str | None = None,
) -> dict[str, Any]:
    value = _closed_copy(request, _REQUEST_FIELDS, "request")
    if (
        value["messageType"] != "request"
        or value["protocolVersion"] != PROTOCOL_VERSION
        or value["release"] != RELEASE
    ):
        _fail("INVALID_REQUEST", "неверная версия или вид публичного запроса")
    method = value["method"]
    if method not in PUBLIC_METHODS or (
        expected_method is not None and method != expected_method
    ):
        _fail("INVALID_REQUEST", "метод публичного запроса не совпал")
    _identifier(value["requestId"], "requestId")
    _owner(value["owner"])
    _datetime(value["requestDeadlineAt"], "requestDeadlineAt")
    if type(value["extensions"]) is not dict or len(value["extensions"]) > 32:
        _fail("INVALID_REQUEST", "extensions должен быть ограниченным объектом")
    canonical_json_v1(value["extensions"])
    if not _sha256(value["requestFingerprint"]):
        _fail("INVALID_REQUEST", "неверная форма requestFingerprint")
    expected_fingerprint = _request_fingerprint(
        {name: value[name] for name in value if name != "requestFingerprint"}
    )
    if value["requestFingerprint"] != expected_fingerprint:
        _fail("REQUEST_FINGERPRINT_MISMATCH", "requestFingerprint не совпал")
    _validate_request_fences(value)
    _validate_params(value)
    return value


def verify_public_response_v2(response: Mapping[str, Any]) -> dict[str, Any]:
    value = _closed_copy(response, _RESPONSE_FIELDS, "response")
    if (
        value["messageType"] != "response"
        or value["protocolVersion"] != PROTOCOL_VERSION
        or value["release"] != RELEASE
        or value["method"] not in PUBLIC_METHODS
        or value["responseKind"]
        not in {"SUCCESS", "ORDINARY", "STALE", "UNAVAILABLE", "ERROR"}
    ):
        _fail("INVALID_RESPONSE", "неверная версия или вид публичного ответа")
    _identifier(value["requestId"], "requestId")
    _owner(value["owner"])
    if not _sha256(value["requestFingerprint"]) or not _sha256(
        value["responseFingerprint"]
    ):
        _fail("INVALID_RESPONSE", "неверная форма отпечатка ответа")
    if type(value["extensions"]) is not dict or len(value["extensions"]) > 32:
        _fail("INVALID_RESPONSE", "extensions ответа имеет неверную форму")
    expected = _response_fingerprint(
        {name: value[name] for name in value if name != "responseFingerprint"}
    )
    if value["responseFingerprint"] != expected:
        _fail("RESPONSE_FINGERPRINT_MISMATCH", "responseFingerprint не совпал")
    _validate_response_payload(value)
    return value


def _response(
    request: Mapping[str, Any],
    response_kind: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    base = {
        "messageType": "response",
        "protocolVersion": PROTOCOL_VERSION,
        "release": RELEASE,
        "requestId": request["requestId"],
        "owner": copy.deepcopy(request["owner"]),
        "method": request["method"],
        "responseKind": response_kind,
        "requestFingerprint": request["requestFingerprint"],
        "payload": copy.deepcopy(dict(payload)),
        "extensions": {},
    }
    response = {**base, "responseFingerprint": _response_fingerprint(base)}
    return verify_public_response_v2(response)


def _request_fingerprint(value: Mapping[str, Any]) -> str:
    projection = {
        name: copy.deepcopy(value[name])
        for name in (
            "messageType",
            "protocolVersion",
            "release",
            "requestId",
            "owner",
            "turnBinding",
            "idempotencyKey",
            "requestDeadlineAt",
            "method",
            "params",
        )
    }
    return domain_fingerprint("codex-smart/smart-turn-request/v2", projection)


def _response_fingerprint(value: Mapping[str, Any]) -> str:
    projection = {
        name: copy.deepcopy(value[name])
        for name in (
            "messageType",
            "protocolVersion",
            "release",
            "requestId",
            "owner",
            "method",
            "responseKind",
            "requestFingerprint",
            "payload",
        )
    }
    return domain_fingerprint("codex-smart/smart-turn-response/v2", projection)


def _validate_request_fences(value: Mapping[str, Any]) -> None:
    method = value["method"]
    binding = value["turnBinding"]
    idempotency = value["idempotencyKey"]
    if method == "smart_plan":
        if type(binding) is not dict:
            _fail("INVALID_REQUEST", "smart_plan требует активную привязку хода")
        _binding(binding, expected_owner=value["owner"])
    elif binding is not None:
        _fail("INVALID_REQUEST", "этому методу не разрешена привязка хода")
    if method == "smart_wait":
        if idempotency is not None:
            _fail("INVALID_REQUEST", "smart_wait не принимает ключ повторяемости")
    else:
        _identifier(idempotency, "idempotencyKey")


def _validate_params(value: Mapping[str, Any]) -> None:
    params = value["params"]
    if type(params) is not dict:
        _fail("INVALID_REQUEST", "params должен быть объектом")
    method = value["method"]
    fields = {
        "issue_turn_binding": {"requestContext", "ttlSeconds"},
        "smart_plan": {"nodes"},
        "route_start": {"routeId", "nodeId", "activationGate"},
        "smart_wait": {"startRequestId", "cursor", "pageSize", "waitDeadlineAt"},
        "smart_cancel": {"startRequestId", "reasonCode"},
    }[method]
    if set(params) != fields:
        _fail("INVALID_REQUEST", "params имеет незакрытый набор полей")
    if method == "issue_turn_binding":
        if type(params["requestContext"]) is not dict:
            _fail("INVALID_REQUEST", "requestContext должен быть объектом")
        if (
            type(params["ttlSeconds"]) is not int
            or not 30 <= params["ttlSeconds"] <= 300
        ):
            _fail("INVALID_REQUEST", "ttlSeconds вне диапазона 30..300")
    elif method == "smart_plan":
        _plan_nodes(params["nodes"], code="INVALID_REQUEST")
    elif method == "route_start":
        _identifier(params["routeId"], "routeId")
        _identifier(params["nodeId"], "nodeId")
        if type(params["activationGate"]) is not dict:
            _fail("INVALID_REQUEST", "activationGate должен быть объектом")
        canonical_json_v1(params["activationGate"])
    elif method == "smart_wait":
        _identifier(params["startRequestId"], "startRequestId")
        if params["cursor"] is not None:
            _identifier(params["cursor"], "cursor")
        if type(params["pageSize"]) is not int or not 1 <= params["pageSize"] <= 100:
            _fail("INVALID_REQUEST", "pageSize вне диапазона 1..100")
        wait_deadline = _datetime(params["waitDeadlineAt"], "waitDeadlineAt")
        request_deadline = _datetime(value["requestDeadlineAt"], "requestDeadlineAt")
        if wait_deadline > request_deadline:
            _fail("INVALID_REQUEST", "срок ожидания вышел за срок запроса")
    else:
        _identifier(params["startRequestId"], "startRequestId")
        if params["reasonCode"] not in _REASON_CODES:
            _fail("INVALID_REQUEST", "неизвестная причина отмены")


def _plan_nodes(value: Any, *, code: str) -> None:
    if type(value) is not list or not 1 <= len(value) <= 20:
        _fail(code, "nodes должен содержать от 1 до 20 узлов")
    known: set[str] = set()
    edge_count = 0
    for index, node in enumerate(value):
        if type(node) is not dict or set(node) != {
            "clientNodeId",
            "dependencyIds",
            "routingInput",
        }:
            _fail(code, f"узел {index} имеет незакрытый набор полей")
        client_node_id = node["clientNodeId"]
        if (
            type(client_node_id) is not str
            or _CLIENT_NODE_ID.fullmatch(client_node_id) is None
            or client_node_id in known
        ):
            _fail(code, f"узел {index} имеет неверный или повторный clientNodeId")
        known.add(client_node_id)
        dependencies = node["dependencyIds"]
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
            _fail(code, f"узел {client_node_id} имеет неверные dependencyIds")
        edge_count += len(dependencies)
        if type(node["routingInput"]) is not dict:
            _fail(code, f"узел {client_node_id} не имеет routingInput")
    if edge_count > 60:
        _fail(code, "граф содержит более 60 рёбер")
    for node in value:
        if node["clientNodeId"] in node["dependencyIds"] or not set(
            node["dependencyIds"]
        ).issubset(known):
            _fail(code, f"узел {node['clientNodeId']} имеет неизвестную зависимость")
    canonical_json_v1(value)


def _validate_response_payload(value: Mapping[str, Any]) -> None:
    payload = value["payload"]
    if type(payload) is not dict:
        _fail("INVALID_RESPONSE", "payload ответа должен быть объектом")
    kind = value["responseKind"]
    method = value["method"]
    if kind == "SUCCESS":
        expected = {
            "issue_turn_binding": {"status", "turnBinding", "effect"},
            "smart_plan": {
                "status",
                "routeId",
                "disposition",
                "nodeDecisions",
                "clarification",
                "planFingerprint",
                "effect",
            },
            "route_start": {
                "status",
                "routeId",
                "nodeId",
                "startRequestId",
                "evidenceJob",
                "admissionId",
                "effect",
            },
            "smart_wait": {
                "startRequestId",
                "state",
                "evidenceJobState",
                "admissionId",
                "terminal",
                "terminalResult",
                "page",
                "effect",
            },
            "smart_cancel": {
                "status",
                "startRequestId",
                "state",
                "terminal",
                "idempotencyKey",
                "idempotencyStatus",
                "effect",
            },
        }[method]
    elif kind == "ORDINARY":
        if method not in {"smart_plan", "route_start"}:
            _fail("INVALID_RESPONSE", "обычный ответ запрещён этому методу")
        expected = {
            "status",
            "reasonCode",
            "ordinaryCommand",
            "preserveUserRequest",
            "message",
            "effect",
        }
    else:
        expected = {"status", "problem", "effect"}
    if set(payload) != expected:
        _fail("INVALID_RESPONSE", "payload ответа имеет незакрытый набор полей")
    _validate_effect(payload["effect"])
    if kind == "SUCCESS":
        _validate_success_payload(method, payload)
    elif kind == "ORDINARY":
        if (
            payload["status"] != "ORDINARY"
            or payload["reasonCode"]
            not in {"SMART_DISABLED", "DIRECT_SELECTED", "CLARIFICATION_REQUIRED"}
            or payload["ordinaryCommand"] != "codex"
            or payload["preserveUserRequest"] is not True
            or type(payload["message"]) is not str
            or not 1 <= len(payload["message"]) <= 1024
        ):
            _fail("INVALID_RESPONSE", "неверный обычный ответ")
    else:
        if payload["status"] != kind:
            _fail("INVALID_RESPONSE", "статус проблемы не совпал с видом ответа")
        _validate_problem(payload["problem"], kind)


def _validate_success_payload(method: str, payload: Mapping[str, Any]) -> None:
    if method == "issue_turn_binding":
        if payload["status"] != "ISSUED":
            _fail("INVALID_RESPONSE", "неверный статус привязки")
        _binding(payload["turnBinding"], expected_owner=payload["turnBinding"]["owner"])
    elif method == "smart_plan":
        if payload["status"] != "PLANNED" or payload["disposition"] not in {
            "DIRECT",
            "DELEGATE",
            "CLARIFY",
        }:
            _fail("INVALID_RESPONSE", "успешный план имеет неверный общий исход")
        _identifier(payload["routeId"], "routeId")
        _node_decisions(payload["nodeDecisions"], payload["disposition"])
        clarification = payload["clarification"]
        if payload["disposition"] == "CLARIFY":
            if type(clarification) is not str or not 1 <= len(clarification) <= 2048:
                _fail("INVALID_RESPONSE", "уточняющий план не содержит вопроса")
        elif clarification is not None:
            _fail("INVALID_RESPONSE", "план без уточнения содержит лишний вопрос")
        if not _sha256(payload["planFingerprint"]):
            _fail("INVALID_RESPONSE", "неверный отпечаток плана")
    elif method == "route_start":
        if payload["status"] != "ATTESTING" or payload["admissionId"] is not None:
            _fail("INVALID_RESPONSE", "route_start преждевременно выдал допуск")
        for field in ("routeId", "nodeId", "startRequestId"):
            _identifier(payload[field], field)
        _evidence_job(payload["evidenceJob"])
    elif method == "smart_wait":
        _identifier(payload["startRequestId"], "startRequestId")
        if (
            payload["state"]
            not in {
                "ATTESTING",
                "READY",
                "STARTED",
                "SUCCEEDED",
                "QUARANTINED",
                "STALE",
                "FAILED",
                "CANCELLED",
            }
            or payload["evidenceJobState"]
            not in {
                "QUEUED",
                "RUNNING",
                "SUCCEEDED",
                "FAILED",
                "CANCEL_REQUESTED",
                "CANCELLED",
            }
            or type(payload["terminal"]) is not bool
        ):
            _fail("INVALID_RESPONSE", "terminal должен быть логическим")
        if payload["admissionId"] is not None:
            _identifier(payload["admissionId"], "admissionId", response=True)
        if (
            payload["state"] in {"ATTESTING", "READY"}
            and payload["admissionId"] is not None
        ):
            _fail("INVALID_RESPONSE", "раннее состояние не раскрывает admissionId")
        if payload["state"] == "STARTED" and payload["admissionId"] is None:
            _fail("INVALID_RESPONSE", "STARTED требует admissionId")
        expected_terminal = payload["state"] in {
            "SUCCEEDED",
            "QUARANTINED",
            "STALE",
            "FAILED",
            "CANCELLED",
        }
        if payload["terminal"] != expected_terminal:
            _fail("INVALID_RESPONSE", "terminal расходится с состоянием")
        terminal_result = payload["terminalResult"]
        if terminal_result is not None:
            _terminal_result(terminal_result, expected_state=payload["state"])
        if payload["state"] in {"SUCCEEDED", "QUARANTINED"} and terminal_result is None:
            _fail("INVALID_RESPONSE", "конечный результат попытки отсутствует")
        if not payload["terminal"] and terminal_result is not None:
            _fail("INVALID_RESPONSE", "промежуточное состояние раскрыло результат")
        _wait_page(payload["page"])
    else:
        if payload["status"] not in {
            "CANCEL_REQUESTED",
            "CANCELLED",
            "ALREADY_TERMINAL",
        }:
            _fail("INVALID_RESPONSE", "неверный статус отмены")
        _identifier(payload["startRequestId"], "startRequestId")
        _identifier(payload["idempotencyKey"], "idempotencyKey")
        if (
            payload["state"]
            not in {"ATTESTING", "READY", "STALE", "FAILED", "CANCELLED"}
            or type(payload["terminal"]) is not bool
            or payload["idempotencyStatus"] not in {"COMMITTED", "REPLAYED"}
        ):
            _fail("INVALID_RESPONSE", "неверная проекция отмены")


def _node_decisions(value: Any, overall_disposition: str) -> None:
    if type(value) is not list or not 1 <= len(value) <= 20:
        _fail("INVALID_RESPONSE", "план должен содержать от 1 до 20 решений узлов")
    client_ids: set[str] = set()
    node_ids: set[str] = set()
    dispositions: list[str] = []
    for index, raw in enumerate(value):
        item = _closed_copy(
            raw,
            {
                "clientNodeId",
                "nodeId",
                "dependencyNodeIds",
                "disposition",
                "selectedPair",
                "score",
                "factors",
            },
            f"nodeDecisions[{index}]",
            response=True,
        )
        client_node_id = item["clientNodeId"]
        if (
            type(client_node_id) is not str
            or _CLIENT_NODE_ID.fullmatch(client_node_id) is None
            or client_node_id in client_ids
        ):
            _fail("INVALID_RESPONSE", "решение имеет неверный clientNodeId")
        client_ids.add(client_node_id)
        _identifier(item["nodeId"], "nodeId", response=True)
        if item["nodeId"] in node_ids:
            _fail("INVALID_RESPONSE", "решения повторяют nodeId")
        node_ids.add(item["nodeId"])
        dependencies = item["dependencyNodeIds"]
        if (
            type(dependencies) is not list
            or len(dependencies) > 20
            or len(dependencies) != len(set(dependencies))
        ):
            _fail("INVALID_RESPONSE", "решение имеет неверные зависимости")
        for dependency in dependencies:
            _identifier(dependency, "nodeId", response=True)
        disposition = item["disposition"]
        if disposition not in {"DIRECT", "DELEGATE", "CLARIFY"}:
            _fail("INVALID_RESPONSE", "решение узла имеет неизвестный исход")
        dispositions.append(disposition)
        pair = item["selectedPair"]
        score = item["score"]
        factors = item["factors"]
        if disposition == "DELEGATE":
            if type(pair) is not dict or set(pair) != {"model", "reasoningEffort"}:
                _fail("INVALID_RESPONSE", "делегируемый узел не имеет точной пары")
            if any(
                type(pair[field]) is not str or not 1 <= len(pair[field]) <= limit
                for field, limit in (("model", 256), ("reasoningEffort", 64))
            ):
                _fail("INVALID_RESPONSE", "точная пара узла содержит неверные значения")
            if type(score) is not int or not 0 <= score <= 8:
                _fail("INVALID_RESPONSE", "делегируемый узел имеет неверную оценку")
            if (
                type(factors) is not dict
                or set(factors) != {"q", "p", "v", "o"}
                or any(type(factor) is not int or not 0 <= factor <= 2 for factor in factors.values())
            ):
                _fail("INVALID_RESPONSE", "делегируемый узел имеет неверные факторы")
            if score != sum(factors.values()):
                _fail(
                    "INVALID_RESPONSE",
                    "оценка делегируемого узла расходится с суммой факторов",
                )
        elif pair is not None or score is not None or factors is not None:
            _fail("INVALID_RESPONSE", "неделегируемый узел раскрыл точную пару")
    for item in value:
        if item["nodeId"] in item["dependencyNodeIds"] or not set(
            item["dependencyNodeIds"]
        ).issubset(node_ids):
            _fail("INVALID_RESPONSE", "решение ссылается на неизвестную зависимость")
    if overall_disposition == "DELEGATE" and set(dispositions) != {"DELEGATE"}:
        _fail("INVALID_RESPONSE", "общий DELEGATE допускает только DELEGATE-узлы")
    if overall_disposition == "CLARIFY" and "CLARIFY" not in dispositions:
        _fail("INVALID_RESPONSE", "общий CLARIFY не подтверждён узлом")
    if overall_disposition == "DIRECT" and (
        "CLARIFY" in dispositions or set(dispositions) == {"DELEGATE"}
    ):
        _fail("INVALID_RESPONSE", "общий DIRECT расходится с решениями узлов")


def _validate_effect(effect: Any) -> None:
    value = _closed_copy(
        effect,
        {"operation", "transactionMode", "transitions", "completedAt", "result"},
        "effect",
        response=True,
    )
    operation = value["operation"]
    if operation not in {"TRANSITION", "READ"}:
        _fail("INVALID_RESPONSE", "неизвестный вид эффекта")
    expected_mode = "BEGIN_IMMEDIATE" if operation == "TRANSITION" else "READ_ONLY"
    if (
        value["transactionMode"] != expected_mode
        or type(value["transitions"]) is not list
    ):
        _fail("INVALID_RESPONSE", "эффект расходится с режимом транзакции")
    if operation == "TRANSITION" and not value["transitions"]:
        _fail("INVALID_RESPONSE", "переход не может быть пустым")
    if operation == "READ" and value["transitions"]:
        _fail("INVALID_RESPONSE", "чтение не может содержать переходы")
    for transition in value["transitions"]:
        item = _closed_copy(
            transition,
            {"table", "entityId", "beforeState", "afterState"},
            "transition",
            response=True,
        )
        if item["table"] not in {
            "turn_bindings",
            "routes",
            "start_requests",
            "account_evidence_jobs",
        }:
            _fail("INVALID_RESPONSE", "неизвестная таблица перехода")
        if type(item["entityId"]) is not str or not 1 <= len(item["entityId"]) <= 128:
            _fail("INVALID_RESPONSE", "неверный идентификатор перехода")
        for state_name in ("beforeState", "afterState"):
            state = item[state_name]
            if state is not None and (type(state) is not str or len(state) > 64):
                _fail("INVALID_RESPONSE", "неверное состояние перехода")
    _datetime(value["completedAt"], "completedAt", response=True)
    result = _closed_copy(
        value["result"],
        {"resultKind", "resultId", "resultFingerprint"},
        "result",
        response=True,
    )
    if not _sha256(result["resultFingerprint"]):
        _fail("INVALID_RESPONSE", "неверный отпечаток результата")
    if type(result["resultId"]) is not str or not 1 <= len(result["resultId"]) <= 128:
        _fail("INVALID_RESPONSE", "неверный resultId")


def _evidence_job(value: Any) -> None:
    job = _closed_copy(
        value,
        {"evidenceJobId", "state", "owner", "queuePosition", "deadlineAt", "stage"},
        "evidenceJob",
        response=True,
    )
    _identifier(job["evidenceJobId"], "evidenceJobId", response=True)
    _owner(job["owner"], response=True)
    if job["state"] != "QUEUED" or job["stage"] is not None:
        _fail("INVALID_RESPONSE", "начальное задание должно быть в очереди")
    if type(job["queuePosition"]) is not int or not 1 <= job["queuePosition"] <= 32:
        _fail("INVALID_RESPONSE", "неверная позиция задания")
    _datetime(job["deadlineAt"], "deadlineAt", response=True)


def _wait_page(value: Any) -> None:
    page = _closed_copy(
        value,
        {"cursor", "nextCursor", "items"},
        "page",
        response=True,
    )
    for field in ("cursor", "nextCursor"):
        if page[field] is not None:
            _identifier(page[field], "cursor", response=True)
    if type(page["items"]) is not list or len(page["items"]) > 100:
        _fail("INVALID_RESPONSE", "неверная страница событий")
    for event in page["items"]:
        item = _closed_copy(
            event,
            {
                "sequence",
                "eventAt",
                "kind",
                "startState",
                "evidenceJobId",
                "admissionId",
                "attestation",
                "problem",
            },
            "event",
            response=True,
        )
        if type(item["sequence"]) is not int or item["sequence"] < 1:
            _fail("INVALID_RESPONSE", "неверный номер события")
        if item["kind"] not in {
            "EVIDENCE_QUEUED",
            "EVIDENCE_RUNNING",
            "EVIDENCE_PROGRESS",
            "EVIDENCE_SUCCEEDED",
            "EVIDENCE_FAILED",
            "CANCEL_REQUESTED",
            "CANCELLED",
            "ADMITTED",
            "CHILD_STARTED",
            "CHILD_ATTESTED",
            "CHILD_SUCCEEDED",
            "CHILD_FAILED",
            "CHILD_CANCELLED",
            "CHILD_QUARANTINED",
            "CHILD_FAILED_BEFORE_START",
            "ROUTE_COMPLETED",
            "ROUTE_STALE",
        } or item["startState"] not in {
            "ATTESTING",
            "READY",
            "STARTED",
            "SUCCEEDED",
            "QUARANTINED",
            "STALE",
            "FAILED",
            "CANCELLED",
        }:
            _fail("INVALID_RESPONSE", "событие содержит неизвестное состояние")
        _datetime(item["eventAt"], "eventAt", response=True)
        if item["evidenceJobId"] is not None:
            _identifier(item["evidenceJobId"], "evidenceJobId", response=True)
        if item["admissionId"] is not None:
            _identifier(item["admissionId"], "admissionId", response=True)
        if item["problem"] is not None:
            _validate_problem(item["problem"], None)
        if item["kind"] == "ROUTE_COMPLETED" and (
            item["startState"]
            not in {"SUCCEEDED", "FAILED", "CANCELLED", "QUARANTINED", "STALE"}
            or item["attestation"] is not None
        ):
            _fail("INVALID_RESPONSE", "итоговое событие маршрута имеет неверную форму")
        canonical_json_v1(item["attestation"])


def _terminal_result(value: Any, *, expected_state: str) -> None:
    result = _closed_copy(
        value,
        {
            "attemptId",
            "state",
            "resultFingerprint",
            "resultBytes",
            "inlineResult",
            "resultTruncated",
            "errorCode",
        },
        "terminalResult",
        response=True,
    )
    _identifier(result["attemptId"], "attemptId", response=True)
    if result["state"] != expected_state or result["state"] not in {
        "SUCCEEDED",
        "FAILED",
        "CANCELLED",
        "QUARANTINED",
    }:
        _fail("INVALID_RESPONSE", "состояние конечного результата расходится")
    if (
        type(result["resultBytes"]) is not int
        or not 0 <= result["resultBytes"] <= 64 * 1024 * 1024
    ):
        _fail("INVALID_RESPONSE", "размер конечного результата неверен")
    fingerprint = result["resultFingerprint"]
    if fingerprint is not None and not _sha256(fingerprint):
        _fail("INVALID_RESPONSE", "отпечаток конечного результата неверен")
    if (fingerprint is None) != (result["resultBytes"] == 0):
        _fail("INVALID_RESPONSE", "размер и отпечаток конечного результата расходятся")
    inline = result["inlineResult"]
    if type(inline) is not dict:
        _fail("INVALID_RESPONSE", "встроенный результат должен быть объектом")
    if len(canonical_json_v1(inline).encode("utf-8")) > 8 * 1024:
        _fail("INVALID_RESPONSE", "встроенный результат превышает предел")
    if type(result["resultTruncated"]) is not bool:
        _fail("INVALID_RESPONSE", "признак усечения должен быть логическим")
    error_code = result["errorCode"]
    if result["state"] == "SUCCEEDED":
        if error_code is not None:
            _fail("INVALID_RESPONSE", "успешный результат содержит ошибку")
    elif type(error_code) is not str or not 1 <= len(error_code) <= 256:
        _fail("INVALID_RESPONSE", "ошибочный результат не содержит кода")


def _validate_problem(value: Any, response_kind: str | None) -> None:
    problem = _closed_copy(
        value,
        {"category", "code", "message", "retryable"},
        "problem",
        response=True,
    )
    if (
        response_kind in {"STALE", "UNAVAILABLE"}
        and problem["category"] != response_kind
    ):
        _fail("INVALID_RESPONSE", "категория проблемы не совпала с ответом")
    if type(problem["message"]) is not str or not 1 <= len(problem["message"]) <= 1024:
        _fail("INVALID_RESPONSE", "сообщение проблемы имеет неверную длину")
    if type(problem["retryable"]) is not bool:
        _fail("INVALID_RESPONSE", "retryable должен быть логическим")


def _turn_binding_value(
    binding: TurnBindingV2, owner: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "bindingId": binding.binding_id,
        "owner": copy.deepcopy(dict(owner)),
        "contextFingerprint": binding.context_fingerprint,
        "issuedControlEpoch": binding.issued_control_epoch,
        "issuedAt": _iso(binding.issued_at),
        "expiresAt": _iso(binding.expires_at),
        "state": binding.state,
    }


def _start_status_value(result: StartStatusV2) -> dict[str, Any]:
    return {
        "startRequestId": result.start_request_id,
        "state": result.state,
        "evidenceJobState": result.evidence_job_state,
        "admissionId": result.admission_id,
        "terminal": result.terminal,
        "terminalResult": _start_terminal_result_value(result.terminal_result),
        "page": {
            "cursor": result.page.cursor,
            "nextCursor": result.page.next_cursor,
            "items": [_start_event_value(item) for item in result.page.items],
        },
    }


def _start_terminal_result_value(
    result: StartTerminalResultV2 | None,
) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "attemptId": result.attempt_id,
        "state": result.state,
        "resultFingerprint": result.result_fingerprint,
        "resultBytes": result.result_bytes,
        "inlineResult": copy.deepcopy(result.inline_result),
        "resultTruncated": result.result_truncated,
        "errorCode": result.error_code,
    }


def _start_event_value(event: StartEventV2) -> dict[str, Any]:
    return {
        "sequence": event.sequence,
        "eventAt": _iso(event.event_at),
        "kind": event.kind,
        "startState": event.start_state,
        "evidenceJobId": event.evidence_job_id,
        "admissionId": event.admission_id,
        "attestation": copy.deepcopy(event.attestation),
        "problem": copy.deepcopy(event.problem),
    }


def _cancellation_value(result: CancellationV2) -> dict[str, Any]:
    return {
        "status": result.status,
        "startRequestId": result.start_request_id,
        "state": result.state,
        "terminal": result.terminal,
        "idempotencyKey": result.idempotency_key,
        "idempotencyStatus": result.idempotency_status,
    }


def _public_problem(exc: Exception) -> dict[str, Any]:
    internal = str(getattr(exc, "code", "INTERNAL_ERROR"))
    table = {
        "TURN_BINDING_EXPIRED": ("STALE", "TURN_BINDING_EXPIRED", False),
        "ROUTE_STALE": ("STALE", "ROUTE_STALE", False),
        "ROUTE_EXPIRED": ("STALE", "ROUTE_STALE", False),
        "ROUTE_POLICY_STALE": ("STALE", "ROUTE_STALE", False),
        "ACTIVATION_GATE_CHANGED": ("STALE", "ROUTE_STALE", False),
        "ACCOUNT_CONTEXT_CHANGED": ("STALE", "ACCOUNT_CONTEXT_CHANGED", False),
        "CHILD_ATTESTATION_STALE": ("STALE", "CHILD_ATTESTATION_STALE", False),
        "ACTIVATION_GATE_UNAVAILABLE": (
            "UNAVAILABLE",
            "ADAPTIVE_ACTIVATION_UNCOMMITTED",
            True,
        ),
        "ACTIVATION_GATE_INVALID": (
            "UNAVAILABLE",
            "ADAPTIVE_ACTIVATION_UNCOMMITTED",
            True,
        ),
        "CONTROL_EPOCH_MISMATCH": ("UNAVAILABLE", "CONTROLLER_UNAVAILABLE", True),
        "CONTROLLER_NOT_ACCEPTING": ("UNAVAILABLE", "CONTROLLER_UNAVAILABLE", True),
        "CONTROLLER_STATE_MISMATCH": ("UNAVAILABLE", "CONTROLLER_UNAVAILABLE", True),
        "ACCOUNT_EVIDENCE_UNAVAILABLE": (
            "UNAVAILABLE",
            "ACCOUNT_EVIDENCE_UNAVAILABLE",
            True,
        ),
        "ACCOUNT_EVIDENCE_QUEUE_FULL": (
            "UNAVAILABLE",
            "ACCOUNT_EVIDENCE_QUEUE_FULL",
            True,
        ),
        "ACCOUNT_EVIDENCE_CAPACITY": (
            "UNAVAILABLE",
            "ACCOUNT_EVIDENCE_QUEUE_FULL",
            True,
        ),
        "ROUTING_PAIR_UNAVAILABLE": (
            "UNAVAILABLE",
            "ROUTING_PAIR_UNAVAILABLE",
            False,
        ),
        "EXACT_PAIR_UNAVAILABLE": (
            "UNAVAILABLE",
            "ROUTING_PAIR_UNAVAILABLE",
            False,
        ),
        "REQUEST_DEADLINE_EXCEEDED": (
            "UNAVAILABLE",
            "REQUEST_DEADLINE_EXCEEDED",
            True,
        ),
        "ACCOUNT_DEADLINE_EXCEEDED": (
            "UNAVAILABLE",
            "REQUEST_DEADLINE_EXCEEDED",
            True,
        ),
        "ACCOUNT_EVIDENCE_DEADLINE": (
            "UNAVAILABLE",
            "REQUEST_DEADLINE_EXCEEDED",
            True,
        ),
        "TURN_BINDING_OWNERSHIP_MISMATCH": (
            "INVALID",
            "TURN_BINDING_OWNERSHIP_MISMATCH",
            False,
        ),
        "TURN_BINDING_CONTEXT_MISMATCH": (
            "INVALID",
            "TURN_BINDING_OWNERSHIP_MISMATCH",
            False,
        ),
        "START_OWNER_MISMATCH": ("INVALID", "ROUTE_OWNERSHIP_MISMATCH", False),
        "ROUTE_OWNER_MISMATCH": ("INVALID", "ROUTE_OWNERSHIP_MISMATCH", False),
        "CURSOR_REJECT": ("INVALID", "CURSOR_INVALID", False),
        "ROUTE_REPLAY_CONFLICT": ("CONFLICT", "IDEMPOTENCY_CONFLICT", False),
        "START_REQUEST_REPLAY_CONFLICT": (
            "CONFLICT",
            "IDEMPOTENCY_CONFLICT",
            False,
        ),
        "CANCELLATION_REPLAY_CONFLICT": (
            "CONFLICT",
            "IDEMPOTENCY_CONFLICT",
            False,
        ),
    }
    invalid_request_codes = {
        "ROUTING_INPUT_INVALID",
        "SMART_PLAN_PHASE_INVALID",
        "ROLE_TEMPLATE_UNKNOWN",
        "ROUTING_PAIR_MISSING",
        "INVALID_IDENTIFIER",
        "INVALID_VALUE",
        "INVALID_REQUEST_CONTEXT",
        "INVALID_TURN_BINDING_TTL",
        "INVALID_ROUTE_PLAN",
        "INVALID_START_REQUEST_IDEMPOTENCY",
        "INVALID_EVIDENCE_DEADLINE",
        "PLAN_GRAPH_INVALID",
        "SPLIT_GENERATION_EXCEEDED",
        "EMPTY_GRAPH",
        "TOO_MANY_NODES",
        "DUPLICATE_NODE",
        "UNKNOWN_ROLE",
        "DUPLICATE_DEPENDENCY",
        "TOO_MANY_EDGES",
        "SELF_DEPENDENCY",
        "UNKNOWN_DEPENDENCY",
        "GRAPH_CYCLE",
        "GRAPH_TOO_DEEP",
        "MULTIPLE_WRITERS",
        "WRITER_NOT_SINK",
        "WRITER_MISSING_READER_DEPENDENCY",
        "ROUTE_NODE_NOT_FOUND",
        "ROUTE_NOT_STARTABLE",
        "NODE_NOT_STARTABLE",
        "NODE_DEPENDENCIES_INCOMPLETE",
        "DEPENDENCY_RESULT_MISSING",
        "START_REQUEST_NOT_FOUND",
        "START_NOT_CANCELLABLE",
        "TURN_BINDING_NOT_FOUND",
    }
    conflict_codes = {
        "TURN_BINDING_USED",
        "TURN_BINDING_REPLAY_CONFLICT",
        "START_REQUEST_INFLIGHT",
        "EVIDENCE_TERMINAL_REPLAY_CONFLICT",
        "START_STALE_REPLAY_CONFLICT",
    }
    if internal in invalid_request_codes:
        table[internal] = ("INVALID", "INVALID_REQUEST", False)
    elif internal in conflict_codes:
        table[internal] = ("CONFLICT", "IDEMPOTENCY_CONFLICT", False)
    category, code, retryable = table.get(
        internal,
        ("INTERNAL", "INTERNAL_ERROR", False),
    )
    messages = {
        "TURN_BINDING_EXPIRED": "Привязка хода истекла.",
        "ROUTE_STALE": "Маршрут больше не соответствует текущему состоянию.",
        "ACCOUNT_CONTEXT_CHANGED": "Учётная среда изменилась после планирования.",
        "CHILD_ATTESTATION_STALE": "Аттестация дочернего процесса устарела.",
        "ADAPTIVE_ACTIVATION_UNCOMMITTED": "Умный режим не имеет подтверждённой активации.",
        "ACCOUNT_EVIDENCE_UNAVAILABLE": "Не удалось получить свежее свидетельство учётной среды.",
        "ACCOUNT_EVIDENCE_QUEUE_FULL": "Очередь заданий свидетельства заполнена.",
        "ROUTING_PAIR_UNAVAILABLE": "Точная выбранная пара модели и рассуждения недоступна.",
        "CONTROLLER_UNAVAILABLE": "Контроллер умного режима недоступен.",
        "REQUEST_DEADLINE_EXCEEDED": "Истёк общий срок запроса.",
        "TURN_BINDING_OWNERSHIP_MISMATCH": "Привязка хода принадлежит другому владельцу.",
        "INVALID_REQUEST": "Публичный запрос имеет неверную форму.",
        "CURSOR_INVALID": "Курсор ожидания недействителен.",
        "ROUTE_OWNERSHIP_MISMATCH": "Маршрут принадлежит другому ходу.",
        "IDEMPOTENCY_CONFLICT": "Повторяемый ключ использован с другими данными.",
        "INTERNAL_ERROR": "Внутренняя ошибка умного режима.",
    }
    return {
        "category": category,
        "code": code,
        "message": messages[code],
        "retryable": retryable,
    }


def _owner(value: Any, *, response: bool = False) -> None:
    owner = _closed_copy(value, _OWNER_FIELDS, "owner", response=response)
    for field in ("shellSessionId", "sessionId", "turnId"):
        if type(owner[field]) is not str or not 1 <= len(owner[field]) <= 256:
            _fail(
                "INVALID_RESPONSE" if response else "INVALID_REQUEST",
                f"неверный {field}",
            )
    if not _sha256(owner["ownerFingerprint"]):
        _fail(
            "INVALID_RESPONSE" if response else "INVALID_REQUEST",
            "неверный ownerFingerprint",
        )
    projection = {
        name: owner[name] for name in ("shellSessionId", "sessionId", "turnId")
    }
    expected = domain_fingerprint("codex-smart/smart-turn-owner/v2", projection)
    if owner["ownerFingerprint"] != expected:
        _fail(
            "INVALID_RESPONSE" if response else "INVALID_REQUEST",
            "ownerFingerprint не совпал",
        )


def _binding(value: Any, *, expected_owner: Mapping[str, Any]) -> None:
    binding = _closed_copy(value, _BINDING_FIELDS, "turnBinding")
    _identifier(binding["bindingId"], "bindingId")
    _owner(binding["owner"])
    if binding["owner"] != expected_owner or binding["state"] not in {
        "ACTIVE",
        "CONSUMED",
    }:
        _fail(
            "INVALID_REQUEST",
            "привязка не допускает новый вызов или точный повтор",
        )
    if not _sha256(binding["contextFingerprint"]):
        _fail("INVALID_REQUEST", "неверный contextFingerprint")
    if (
        type(binding["issuedControlEpoch"]) is not int
        or binding["issuedControlEpoch"] < 1
    ):
        _fail("INVALID_REQUEST", "неверная эпоха привязки")
    _datetime(binding["issuedAt"], "issuedAt")
    _datetime(binding["expiresAt"], "expiresAt")


def _closed_copy(
    value: Any,
    fields: set[str],
    name: str,
    *,
    response: bool = False,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        _fail(
            "INVALID_RESPONSE" if response else "INVALID_REQUEST",
            f"{name} имеет незакрытый набор полей",
        )
    try:
        canonical_json_v1(value)
    except Exception as exc:
        _fail(
            "INVALID_RESPONSE" if response else "INVALID_REQUEST",
            f"{name} не канонизируется: {exc}",
        )
    return copy.deepcopy(value)


def _identifier(value: Any, name: str, *, response: bool = False) -> None:
    pattern = _IDENTIFIERS[name]
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(
            "INVALID_RESPONSE" if response else "INVALID_REQUEST",
            f"неверный {name}",
        )


def _datetime(value: Any, name: str, *, response: bool = False) -> datetime:
    if type(value) is not str:
        _fail("INVALID_RESPONSE" if response else "INVALID_REQUEST", f"неверный {name}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("INVALID_RESPONSE" if response else "INVALID_REQUEST", f"неверный {name}")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("INVALID_RESPONSE" if response else "INVALID_REQUEST", f"неверный {name}")
    return parsed.astimezone(timezone.utc)


def _sha256(value: Any) -> bool:
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _iso(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        _fail("INVALID_TIME", "время должно содержать часовой пояс")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _fail(code: str, message: str) -> None:
    raise SmartTurnRuntimeV2Error(code, message)


__all__ = [
    "PROTOCOL_VERSION",
    "PUBLIC_METHODS",
    "RELEASE",
    "SmartTurnRuntimeV2",
    "SmartTurnRuntimeV2Error",
    "build_public_request_v2",
    "owner_for_context_v2",
    "verify_public_request_v2",
    "verify_public_response_v2",
]

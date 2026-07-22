"""Один вертикальный проход: доказательства, допуск и дочерний запуск."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

from .canonical_json import canonical_json_v1, domain_fingerprint
from .child_launch_v2 import (
    PreparedChildLaunchV2,
    cleanup_prepared_child_launch_v2,
)
from .plan_projection_v2 import PlanProjectionV2Error, node_routing_input_v2
from .state_store_v2 import RequestContextV2, StartRequestV2


_ROLE_FIELDS = {
    "schemaVersion",
    "contractVersion",
    "templateId",
    "semanticRole",
    "executionProfile",
    "objective",
    "requiredContextKinds",
    "requiredEvidenceKinds",
    "requiredOutputFields",
    "completionConditions",
}
_BUNDLE_FIELDS = {
    "schemaVersion",
    "contractVersion",
    "bundleId",
    "maxBytes",
    "totalBytes",
    "entries",
}
_ENTRY_FIELDS = {
    "contextRefId",
    "kind",
    "required",
    "sourceEvidenceRefs",
    "sha256",
    "byteLength",
    "content",
}
_MAX_CHILD_CONTEXT_CONTENT_BYTES = 24 * 1024
_MAX_DEPENDENCY_PROJECTION_BYTES = 512


@dataclass
class ChildExecutionV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class ChildExecutionV2:
    """Связывает уже созданный StartRequest с ровно одной попыткой узла."""

    def __init__(
        self,
        *,
        service: Any,
        store: Any,
        launch_coordinator: Any,
        launch_preparer: Callable[
            [Any, str, RequestContextV2, StartRequestV2],
            Any,
        ],
        activation_gate_provider: Callable[[], Mapping[str, Any]],
        launch_barrier: Callable[[], Any],
        role_templates: Sequence[Mapping[str, Any]],
        owner_id: str,
        pid: int,
        process_start_marker: str,
        child_timeout_seconds: float = 300,
        max_output_bytes: int = 1024 * 1024,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        for owner, name, methods in (
            (service, "service", ("process_account_evidence",)),
            (
                store,
                "store",
                ("read_node_plan", "abort_admission_before_permit"),
            ),
            (launch_coordinator, "launch_coordinator", ("run",)),
        ):
            for method in methods:
                if not callable(getattr(owner, method, None)):
                    raise TypeError(f"{name} must provide {method}()")
        for callback, name in (
            (launch_preparer, "launch_preparer"),
            (activation_gate_provider, "activation_gate_provider"),
            (launch_barrier, "launch_barrier"),
        ):
            if not callable(callback):
                raise TypeError(f"{name} must be callable")
        if (
            not isinstance(owner_id, str)
            or not owner_id
            or len(owner_id.encode("utf-8")) > 256
            or any(character in owner_id for character in "\0\r\n")
            or type(pid) is not int
            or pid <= 0
            or not isinstance(process_start_marker, str)
            or not process_start_marker
        ):
            raise ValueError("worker identity is invalid")
        if not 0 < float(child_timeout_seconds) <= 1800:
            raise ValueError("child timeout is invalid")
        if (
            type(max_output_bytes) is not int
            or not 1024 <= max_output_bytes <= 16 * 1024 * 1024
        ):
            raise ValueError("child output limit is invalid")
        templates: dict[str, dict[str, Any]] = {}
        for raw in role_templates:
            template = _role_template(raw)
            if template["templateId"] in templates:
                raise ValueError("role template is duplicated")
            templates[template["templateId"]] = template
        if not templates:
            raise ValueError("role templates are empty")
        self.service = service
        self.store = store
        self.launch_coordinator = launch_coordinator
        self.launch_preparer = launch_preparer
        self.activation_gate_provider = activation_gate_provider
        self.launch_barrier = launch_barrier
        self.role_templates = templates
        self.owner_id = owner_id
        self.pid = pid
        self.process_start_marker = process_start_marker
        self.child_timeout_seconds = float(child_timeout_seconds)
        self.max_output_bytes = max_output_bytes
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run(
        self, start_request: StartRequestV2, request_context: RequestContextV2
    ) -> Any:
        self._require_live_pre_admission_deadline(
            start_request,
            request_context,
            "срок запуска истёк до чтения активационного шлюза",
        )
        try:
            gate = copy.deepcopy(dict(self.activation_gate_provider()))
        except Exception as exc:
            effective_error = self._pre_admission_deadline_error(
                start_request,
                "срок запуска истёк во время чтения активационного шлюза",
            ) or ChildExecutionV2Error("ACTIVATION_GATE_UNAVAILABLE", str(exc))
            self._terminalize_before_admission(
                start_request,
                request_context,
                effective_error,
            )
        self._require_live_pre_admission_deadline(
            start_request,
            request_context,
            "срок запуска истёк после чтения активационного шлюза",
        )
        try:
            admission = self.service.process_account_evidence(
                start_request=start_request,
                request_context=request_context,
                activation_gate=gate,
                owner_id=self.owner_id,
                pid=self.pid,
                process_start_marker=self.process_start_marker,
                admission_barrier=self.launch_barrier,
            )
        except Exception as error:
            if getattr(error, "code", None) != "ACCOUNT_EVIDENCE_DEADLINE":
                raise
            self._terminalize_before_admission(
                start_request,
                request_context,
                ChildExecutionV2Error(
                    "REQUEST_DEADLINE_EXCEEDED",
                    "срок запуска истёк до захвата задания доказательств",
                ),
            )
        prepared: Any | None = None
        try:
            plan = self.store.read_node_plan(
                start_request.route_id,
                start_request.node_id,
                request_context,
            )
            try:
                routing_input = node_routing_input_v2(
                    plan.plan_output,
                    plan.node_id,
                )
                template_id = routing_input["roleTemplateId"]
            except (KeyError, TypeError, PlanProjectionV2Error) as exc:
                self._fail("ROLE_TEMPLATE_MISSING", str(exc))
            if template_id not in self.role_templates:
                self._fail("ROLE_TEMPLATE_MISSING", str(template_id))
            prompt = materialize_child_prompt_v2(
                plan,
                self.role_templates[template_id],
            )
            remaining = (start_request.deadline_at - self._now()).total_seconds()
            if remaining <= 0:
                self._fail(
                    "REQUEST_DEADLINE_EXCEEDED",
                    "срок запуска истёк до подготовки",
                )
            prepared = self.launch_preparer(
                plan,
                prompt,
                request_context,
                start_request,
            )
            remaining = (start_request.deadline_at - self._now()).total_seconds()
            if remaining <= 0:
                self._fail(
                    "REQUEST_DEADLINE_EXCEEDED",
                    "срок запуска истёк до сторожа",
                )
        except Exception as exc:
            effective_error = exc
            if isinstance(prepared, PreparedChildLaunchV2):
                try:
                    cleanup_prepared_child_launch_v2(prepared)
                except Exception as cleanup_error:
                    effective_error = ChildExecutionV2Error(
                        "LAUNCH_CLEANUP_FAILED",
                        f"{cleanup_error}; preceding error: {exc}",
                    )
            code = self._error_code(effective_error)
            try:
                self.store.abort_admission_before_permit(
                    admission_id=admission.admission_id,
                    request_context=request_context,
                    failure_code=code,
                    message=str(effective_error)[:1024]
                    or type(effective_error).__name__,
                    now=self._terminalization_now(),
                )
            except Exception as terminalization_error:
                raise ChildExecutionV2Error(
                    "PRESTART_TERMINALIZATION_FAILED",
                    str(terminalization_error),
                ) from terminalization_error
            if isinstance(effective_error, ChildExecutionV2Error):
                raise effective_error
            raise ChildExecutionV2Error(code, str(effective_error)) from effective_error
        return self.launch_coordinator.run(
            admission_id=admission.admission_id,
            request_context=request_context,
            prepared=prepared,
            timeout_seconds=self.child_timeout_seconds,
            max_output_bytes=self.max_output_bytes,
        )

    @staticmethod
    def _error_code(error: BaseException) -> str:
        code = getattr(error, "code", None)
        if isinstance(code, str) and code:
            return code[:256]
        return "CHILD_PREPARATION_FAILED"

    def _now(self) -> datetime:
        try:
            value = self.clock()
        except Exception as error:
            self._fail("CLOCK_INVALID", str(error) or type(error).__name__)
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            self._fail("CLOCK_INVALID", "часы вернули время без часового пояса")
        return value.astimezone(timezone.utc)

    def _terminalization_now(self) -> datetime:
        """Даёт время для аварийной записи, даже если внедрённые часы сломаны."""

        try:
            return self._now()
        except Exception:
            return datetime.now(timezone.utc)

    def _pre_admission_deadline_error(
        self,
        start_request: StartRequestV2,
        message: str,
    ) -> ChildExecutionV2Error | None:
        try:
            now = self._now()
        except ChildExecutionV2Error as error:
            return error
        deadline_at = getattr(start_request, "deadline_at", None)
        if (
            not isinstance(deadline_at, datetime)
            or deadline_at.tzinfo is None
            or deadline_at.utcoffset() is None
        ):
            return ChildExecutionV2Error(
                "REQUEST_DEADLINE_INVALID",
                "долговечная заявка не содержит корректный срок",
            )
        if deadline_at.astimezone(timezone.utc) <= now:
            return ChildExecutionV2Error(
                "REQUEST_DEADLINE_EXCEEDED",
                message,
            )
        return None

    def _require_live_pre_admission_deadline(
        self,
        start_request: StartRequestV2,
        request_context: RequestContextV2,
        message: str,
    ) -> None:
        error = self._pre_admission_deadline_error(start_request, message)
        if error is not None:
            self._terminalize_before_admission(
                start_request,
                request_context,
                error,
            )

    def _terminalize_before_admission(
        self,
        start_request: StartRequestV2,
        request_context: RequestContextV2,
        error: BaseException,
    ) -> None:
        code = self._error_code(error)
        public_problem = self._pre_admission_public_problem(code)
        try:
            terminal = self.store.record_account_evidence_terminal(
                start_request.evidence_job_id,
                request_context,
                state="FAILED",
                failure_code=code,
                problem=public_problem,
                now=self._terminalization_now(),
            )
        except Exception as terminalization_error:
            raise ChildExecutionV2Error(
                "PRESTART_TERMINALIZATION_FAILED",
                str(terminalization_error),
            ) from terminalization_error
        if (
            getattr(terminal, "state", None) != "FAILED"
            or getattr(terminal, "terminal", None) is not True
        ):
            raise ChildExecutionV2Error(
                "PRESTART_TERMINALIZATION_FAILED",
                "хранилище не подтвердило терминализацию заявки",
            )
        if isinstance(error, ChildExecutionV2Error):
            raise error
        raise ChildExecutionV2Error(code, str(error)) from error

    @staticmethod
    def _pre_admission_public_problem(code: str) -> dict[str, Any]:
        if code == "REQUEST_DEADLINE_EXCEEDED":
            return {
                "category": "UNAVAILABLE",
                "code": "REQUEST_DEADLINE_EXCEEDED",
                "message": "Истёк общий срок запуска дочерней задачи.",
                "retryable": True,
            }
        if code == "ACTIVATION_GATE_UNAVAILABLE":
            return {
                "category": "UNAVAILABLE",
                "code": "ADAPTIVE_ACTIVATION_UNCOMMITTED",
                "message": "Не удалось подтвердить действующую активацию умного режима.",
                "retryable": True,
            }
        return {
            "category": "INTERNAL",
            "code": "INTERNAL_ERROR",
            "message": "Внутренняя ошибка остановила дочернюю задачу до допуска.",
            "retryable": False,
        }

    @staticmethod
    def _fail(code: str, message: str) -> None:
        raise ChildExecutionV2Error(code, message)


def materialize_child_prompt_v2(plan: Any, role_template: Mapping[str, Any]) -> str:
    """Материализует только отпечатанный контекст и смысловую роль узла."""

    role = _role_template(role_template)
    try:
        routing = node_routing_input_v2(plan.plan_output, plan.node_id)
        bundle = copy.deepcopy(routing["contextBundle"])
        template_id = routing["roleTemplateId"]
        node = plan.node
    except (AttributeError, KeyError, TypeError, PlanProjectionV2Error) as exc:
        _fail("CHILD_CONTEXT_INVALID", str(exc))
    if (
        type(bundle) is not dict
        or set(bundle) != _BUNDLE_FIELDS
        or bundle["schemaVersion"] != 1
        or bundle["contractVersion"] != "codex-context-bundle-v1"
        or template_id != role["templateId"]
        or node.role != role["semanticRole"]
    ):
        _fail("CHILD_CONTEXT_INVALID", "роль или пакет контекста расходятся")
    maximum = bundle["maxBytes"]
    claimed_total = bundle["totalBytes"]
    entries = bundle["entries"]
    if (
        type(maximum) is not int
        or type(claimed_total) is not int
        or not 0
        <= claimed_total
        <= maximum
        <= _MAX_CHILD_CONTEXT_CONTENT_BYTES
        or type(entries) is not list
        or not entries
        or len(entries) > 64
    ):
        _fail("CHILD_CONTEXT_INVALID", "размер пакета контекста вне договора")
    materialized: list[dict[str, Any]] = []
    total = 0
    identifiers: list[str] = []
    kinds: set[str] = set()
    for entry in entries:
        if type(entry) is not dict or set(entry) != _ENTRY_FIELDS:
            _fail("CHILD_CONTEXT_INVALID", "запись контекста имеет неверную форму")
        content = entry["content"]
        if not isinstance(content, str):
            _fail("CHILD_CONTEXT_INVALID", "содержимое контекста не является строкой")
        encoded = content.encode("utf-8")
        if (
            entry["byteLength"] != len(encoded)
            or entry["sha256"] != hashlib.sha256(encoded).hexdigest()
        ):
            _fail("CONTEXT_CONTENT_MISMATCH", str(entry.get("contextRefId")))
        identifier = entry["contextRefId"]
        kind = entry["kind"]
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in identifiers
            or not isinstance(kind, str)
            or not kind
            or type(entry["required"]) is not bool
            or type(entry["sourceEvidenceRefs"]) is not list
        ):
            _fail("CHILD_CONTEXT_INVALID", "идентичность контекста неверна")
        identifiers.append(identifier)
        kinds.add(kind)
        total += len(encoded)
        materialized.append(
            {
                "contextRefId": identifier,
                "kind": kind,
                "required": entry["required"],
                "sha256": entry["sha256"],
                "content": content,
            }
        )
    if (
        total != claimed_total
        or tuple(identifiers) != tuple(node.context_refs)
        or not set(role["requiredContextKinds"]).issubset(kinds)
    ):
        _fail("CHILD_CONTEXT_INVALID", "состав пакета контекста расходится")
    dependency_results = getattr(plan, "dependency_results", ())
    if not isinstance(dependency_results, tuple) or len(dependency_results) != len(
        node.dependencies
    ):
        _fail(
            "DEPENDENCY_RESULT_MISMATCH",
            "результаты зависимостей не соответствуют плану узла",
        )
    materialized_dependency_results: list[dict[str, Any]] = []
    for dependency_node_id, dependency in zip(
        node.dependencies,
        dependency_results,
        strict=True,
    ):
        try:
            stored_node_id = dependency.node_id
            result = copy.deepcopy(dependency.result)
            raw_result_fingerprint = dependency.raw_result_fingerprint
            raw_result_bytes = dependency.raw_result_bytes
            result_truncated = dependency.result_truncated
            projection_fingerprint = dependency.projection_fingerprint
        except AttributeError as exc:
            _fail("DEPENDENCY_RESULT_MISMATCH", str(exc))
        if (
            stored_node_id != dependency_node_id
            or type(result) is not dict
            or not isinstance(raw_result_fingerprint, str)
            or len(raw_result_fingerprint) != 64
            or any(
                character not in "0123456789abcdef"
                for character in raw_result_fingerprint
            )
            or type(raw_result_bytes) is not int
            or not 1 <= raw_result_bytes <= 64 * 1024 * 1024
            or type(result_truncated) is not bool
            or not isinstance(projection_fingerprint, str)
        ):
            _fail(
                "DEPENDENCY_RESULT_MISMATCH",
                "результат относится к другой зависимости",
            )
        encoded_result = canonical_json_v1(result).encode("utf-8")
        if len(encoded_result) > _MAX_DEPENDENCY_PROJECTION_BYTES:
            _fail(
                "DEPENDENCY_RESULT_MISMATCH",
                "проекция результата зависимости превышает 512 байт",
            )
        if not result_truncated and (
            len(encoded_result) != raw_result_bytes
            or hashlib.sha256(encoded_result).hexdigest() != raw_result_fingerprint
        ):
            _fail(
                "DEPENDENCY_RESULT_MISMATCH",
                "полный результат не соответствует своему отпечатку",
            )
        projection = {
            "nodeId": stored_node_id,
            "result": result,
            "rawResultFingerprint": raw_result_fingerprint,
            "rawResultBytes": raw_result_bytes,
            "resultTruncated": result_truncated,
        }
        expected_projection_fingerprint = domain_fingerprint(
            "codex-smart/dependency-result-projection/v2",
            projection,
        )
        if projection_fingerprint != expected_projection_fingerprint:
            _fail(
                "DEPENDENCY_RESULT_MISMATCH",
                "отпечаток проекции результата зависимости не подтверждён",
            )
        materialized_dependency_results.append(
            {
                **projection,
                "projectionFingerprint": projection_fingerprint,
            }
        )
    prompt_value = {
        "schemaVersion": 2,
        "mission": node.mission,
        "role": {
            "templateId": role["templateId"],
            "semanticRole": role["semanticRole"],
            "objective": role["objective"],
            "requiredEvidenceKinds": role["requiredEvidenceKinds"],
            "requiredOutputFields": role["requiredOutputFields"],
            "completionConditions": role["completionConditions"],
        },
        "context": materialized,
        "dependencyResults": materialized_dependency_results,
    }
    prompt = canonical_json_v1(prompt_value)
    if len(prompt.encode("utf-8")) > 64 * 1024:
        _fail("CHILD_PROMPT_TOO_LARGE", "материализованная миссия превышает 64 КиБ")
    return prompt


def _role_template(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        result = copy.deepcopy(dict(value))
    except (TypeError, ValueError, RecursionError) as exc:
        _fail("ROLE_TEMPLATE_INVALID", str(exc))
    if (
        set(result) != _ROLE_FIELDS
        or result.get("schemaVersion") != 1
        or result.get("contractVersion") != "codex-role-template-v1"
    ):
        _fail("ROLE_TEMPLATE_INVALID", "форма шаблона роли неверна")
    for name in ("templateId", "semanticRole", "executionProfile", "objective"):
        if not isinstance(result[name], str) or not result[name]:
            _fail("ROLE_TEMPLATE_INVALID", name)
    for name in (
        "requiredContextKinds",
        "requiredEvidenceKinds",
        "requiredOutputFields",
        "completionConditions",
    ):
        values = result[name]
        if (
            type(values) is not list
            or not values
            or len(values) != len(set(values))
            or any(not isinstance(item, str) or not item for item in values)
        ):
            _fail("ROLE_TEMPLATE_INVALID", name)
    return result


def _fail(code: str, message: str) -> None:
    raise ChildExecutionV2Error(code, message)

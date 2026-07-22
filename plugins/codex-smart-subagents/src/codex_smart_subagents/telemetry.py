"""One-shot local OTLP receiver and independent child-run attestation."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .identity import canonical_sha256


DEFAULT_MAX_REQUEST_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_REQUESTS = 32
_SAFE_FIELDS = frozenset(
    {
        "event.name",
        "name",
        "app.version",
        "service.version",
        "model",
        "reasoning_effort",
        "conversation.id",
        "sandbox_policy",
        "approval_policy",
    }
)


@dataclass
class AttestationError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class RunAttestation:
    cli_version: str
    requested_model: str
    observed_model: str
    requested_effort: str
    observed_effort: str
    conversation_hash: str
    argv_fingerprint: str
    permission_probe_id: str
    run_fingerprint: str


class OTelReceiver:
    """Receive bounded OTLP/HTTP JSON without retaining raw request bodies."""

    header_name = "X-Codex-Attestation-Token"

    def __init__(
        self,
        *,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        max_requests: int = DEFAULT_MAX_REQUESTS,
    ) -> None:
        if max_request_bytes <= 0 or max_requests <= 0:
            raise ValueError("receiver limits must be positive")
        self.max_request_bytes = max_request_bytes
        self.max_requests = max_requests
        self.token = secrets.token_urlsafe(32)
        self.base_path = f"/{secrets.token_urlsafe(24)}"
        self.path = self.base_path + "/v1/logs"
        self.events: list[dict[str, str]] = []
        self._request_count = 0
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return "127.0.0.1"

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("receiver has not been started")
        return int(self._server.server_address[1])

    @property
    def endpoint(self) -> str:
        return f"http://{self.host}:{self.port}{self.path}"

    @property
    def otlp_endpoint(self) -> str:
        """Базовый OTLP endpoint для ``OTEL_EXPORTER_OTLP_ENDPOINT``."""

        return f"http://{self.host}:{self.port}{self.base_path}"

    def __enter__(self) -> "OTelReceiver":
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802
                receiver._handle(self)

            def log_message(self, _format: str, *args: object) -> None:
                del args

        server = ThreadingHTTPServer((self.host, 0), Handler)
        server.daemon_threads = True
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever,
            name="codex-smart-subagents-otel",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        del exc_type, exc, traceback
        server = self._server
        if server is not None:
            server.shutdown()
            server.server_close()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2)
        self._server = None
        self._thread = None

    def snapshot_events(self) -> list[dict[str, str]]:
        """Возвращает согласованный снимок уже принятых безопасных полей."""

        with self._lock:
            return [dict(event) for event in self.events]

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        if handler.path != self.path:
            _reply(handler, 404)
            return
        if handler.headers.get(self.header_name) != self.token:
            _reply(handler, 403)
            return
        content_type = handler.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            _reply(handler, 415)
            return
        try:
            length = int(handler.headers.get("Content-Length", ""))
        except ValueError:
            _reply(handler, 400)
            return
        if length < 0 or length > self.max_request_bytes:
            _reply(handler, 413)
            return

        with self._lock:
            if self._request_count >= self.max_requests:
                _reply(handler, 429)
                return
            self._request_count += 1

        body = handler.rfile.read(length)
        if len(body) != length:
            _reply(handler, 400)
            return
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            _reply(handler, 400)
            return
        extracted = _extract_safe_events(payload)
        with self._lock:
            self.events.extend(extracted)
        _reply(handler, 200)


def attest_run(
    *,
    events: list[dict[str, Any]],
    jsonl_events: list[dict[str, Any]],
    requested_model: str,
    requested_effort: str,
    expected_cli_version: str,
    permission_probe_id: str,
    argv_fingerprint: str,
) -> RunAttestation:
    """Validate observed launch facts against request and JSONL evidence."""

    starts = [
        event
        for event in events
        if event.get("event.name", event.get("name"))
        == "codex.conversation_starts"
    ]
    if not starts:
        raise AttestationError(
            "FIELD_MISSING",
            "codex.conversation_starts telemetry is missing",
        )

    cli_version = _one_required_alias(
        starts,
        ("app.version", "service.version"),
    )
    observed_model = _one_required(starts, "model")
    observed_effort = _one_required(starts, "reasoning_effort")
    conversation_id = _one_required(starts, "conversation.id")
    jsonl_thread = _jsonl_thread_id(jsonl_events)

    if cli_version != expected_cli_version:
        raise AttestationError(
            "CLI_VERSION_MISMATCH",
            f"observed Codex {cli_version}, expected {expected_cli_version}",
        )
    if observed_model != requested_model:
        raise AttestationError(
            "MODEL_MISMATCH",
            f"observed model {observed_model}, requested {requested_model}",
        )
    if observed_effort != requested_effort:
        raise AttestationError(
            "EFFORT_MISMATCH",
            f"observed effort {observed_effort}, requested {requested_effort}",
        )
    if conversation_id != jsonl_thread:
        raise AttestationError(
            "CONVERSATION_MISMATCH",
            "telemetry and JSONL conversation identifiers differ",
        )
    if (
        len(argv_fingerprint) != 64
        or any(character not in "0123456789abcdef" for character in argv_fingerprint)
    ):
        raise AttestationError(
            "ARGV_FINGERPRINT_INVALID",
            "argv fingerprint must be lowercase SHA-256",
        )
    if not permission_probe_id:
        raise AttestationError(
            "PERMISSION_PROBE_MISSING",
            "permission probe identifier is required",
        )

    conversation_hash = hashlib.sha256(
        conversation_id.encode("utf-8")
    ).hexdigest()
    run_fingerprint = canonical_sha256(
        {
            "cliVersion": cli_version,
            "requestedModel": requested_model,
            "observedModel": observed_model,
            "requestedEffort": requested_effort,
            "observedEffort": observed_effort,
            "conversationHash": conversation_hash,
            "argvFingerprint": argv_fingerprint,
            "permissionProbeId": permission_probe_id,
        }
    )
    return RunAttestation(
        cli_version=cli_version,
        requested_model=requested_model,
        observed_model=observed_model,
        requested_effort=requested_effort,
        observed_effort=observed_effort,
        conversation_hash=conversation_hash,
        argv_fingerprint=argv_fingerprint,
        permission_probe_id=permission_probe_id,
        run_fingerprint=run_fingerprint,
    )


def _extract_safe_events(payload: Any) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    events: list[dict[str, str]] = []
    resources = payload.get("resourceLogs", [])
    if not isinstance(resources, list):
        return events
    for resource_log in resources:
        if not isinstance(resource_log, dict):
            continue
        resource = resource_log.get("resource", {})
        resource_values = _attributes(
            resource.get("attributes", []) if isinstance(resource, dict) else []
        )
        scopes = resource_log.get("scopeLogs", [])
        if not isinstance(scopes, list):
            continue
        for scope in scopes:
            if not isinstance(scope, dict):
                continue
            records = scope.get("logRecords", [])
            if not isinstance(records, list):
                continue
            for record in records:
                if not isinstance(record, dict):
                    continue
                combined: dict[str, Any] = dict(resource_values)
                combined.update(_attributes(record.get("attributes", [])))
                body = _decode_value(record.get("body"))
                if isinstance(body, str):
                    try:
                        parsed = json.loads(body)
                    except json.JSONDecodeError:
                        parsed = None
                    if isinstance(parsed, dict):
                        combined.update(parsed)
                elif isinstance(body, dict):
                    combined.update(body)
                safe = {
                    key: str(value)
                    for key, value in combined.items()
                    if key in _SAFE_FIELDS
                    and isinstance(value, (str, int, float, bool))
                }
                if safe:
                    events.append(safe)
    return events


def _attributes(value: Any) -> dict[str, Any]:
    if not isinstance(value, list):
        return {}
    result: dict[str, Any] = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if isinstance(key, str):
            result[key] = _decode_value(item.get("value"))
    return result


def _decode_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    scalar_keys = (
        "stringValue",
        "boolValue",
        "intValue",
        "doubleValue",
        "bytesValue",
    )
    for key in scalar_keys:
        if key in value:
            return value[key]
    array = value.get("arrayValue")
    if isinstance(array, dict):
        values = array.get("values", [])
        return [_decode_value(item) for item in values] if isinstance(values, list) else []
    mapping = value.get("kvlistValue")
    if isinstance(mapping, dict):
        return _attributes(mapping.get("values", []))
    return None


def _one_required(events: list[dict[str, Any]], key: str) -> str:
    values = {
        value
        for event in events
        if isinstance((value := event.get(key)), str) and value
    }
    if not values:
        raise AttestationError("FIELD_MISSING", f"telemetry field {key} is missing")
    if len(values) != 1:
        raise AttestationError(
            "AMBIGUOUS_ATTESTATION",
            f"telemetry field {key} has conflicting values",
        )
    return values.pop()


def _one_required_alias(
    events: list[dict[str, Any]],
    keys: tuple[str, ...],
) -> str:
    values: set[str] = set()
    for event in events:
        for key in keys:
            value = event.get(key)
            if isinstance(value, str) and value:
                values.add(value)
    if not values:
        raise AttestationError(
            "FIELD_MISSING",
            f"telemetry field {'/'.join(keys)} is missing",
        )
    if len(values) != 1:
        raise AttestationError(
            "AMBIGUOUS_ATTESTATION",
            f"telemetry field {'/'.join(keys)} has conflicting values",
        )
    return values.pop()


def _jsonl_thread_id(events: list[dict[str, Any]]) -> str:
    values = {
        value
        for event in events
        if event.get("type") == "thread.started"
        and isinstance((value := event.get("thread_id")), str)
        and value
    }
    if not values:
        raise AttestationError(
            "FIELD_MISSING",
            "thread.started JSONL event is missing",
        )
    if len(values) != 1:
        raise AttestationError(
            "AMBIGUOUS_ATTESTATION",
            "JSONL contains conflicting thread identifiers",
        )
    return values.pop()


def _reply(handler: BaseHTTPRequestHandler, status: int) -> None:
    payload = b"{}"
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.wfile.write(payload)

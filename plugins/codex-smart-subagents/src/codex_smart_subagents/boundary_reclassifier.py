"""One-shot, isolated reclassification of boundary delegation decisions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any, Callable, ContextManager, Protocol

from . import child_runner as _child
from .permissions import CanaryRequest, PermissionGate
from .routing import (
    TERRA,
    DelegationAssessment,
    Disposition,
    Interval,
)
from .telemetry import OTelReceiver, RunAttestation, attest_run


BOUNDARY_MODEL = TERRA
BOUNDARY_REASONING_EFFORT = "high"
BOUNDARY_PERMISSION_PROFILE = "adaptive_boundary_classifier"
BOUNDARY_CONTRACT_VERSION = "boundary-reclassification-v1"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_ROLES = frozenset(
    {
        "researcher",
        "diagnostician",
        "implementer",
        "validator",
        "risk_auditor",
    }
)
_RISK_FLAGS = frozenset(
    {
        "security",
        "architecture",
        "public_contract",
        "risky_migration",
        "irreversible",
        "critical_incident",
        "writer_final_validation",
    }
)
_BOUNDARY_DISABLED_FEATURES = (
    "auth_elicitation",
    "code_mode_host",
    "enable_fanout",
    "goals",
    "image_generation",
    "multi_agent",
    "multi_agent_v2",
    "request_permissions_tool",
    "shell_tool",
    "tool_call_mcp_elicitation",
    "tool_suggest",
    "unified_exec",
)
_ALLOWED_EVENT_TYPES = frozenset(
    {
        "thread.started",
        "turn.started",
        "item.started",
        "item.updated",
        "item.completed",
        "turn.completed",
    }
)
_ALLOWED_ITEM_TYPES = frozenset({"reasoning", "agent_message"})

_INTERVAL_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "min": {"type": "integer", "minimum": 0, "maximum": 2},
        "max": {"type": "integer", "minimum": 0, "maximum": 2},
    },
    "required": ["min", "max"],
    "additionalProperties": False,
}
BOUNDARY_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "q": _INTERVAL_OUTPUT_SCHEMA,
        "p": _INTERVAL_OUTPUT_SCHEMA,
        "v": _INTERVAL_OUTPUT_SCHEMA,
        "o": _INTERVAL_OUTPUT_SCHEMA,
        "hardBan": {
            "type": "string",
            "enum": ["none", "direct", "clarify"],
        },
    },
    "required": ["q", "p", "v", "o", "hardBan"],
    "additionalProperties": False,
}


@dataclass
class BoundaryReclassificationError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class BoundaryReclassifierConfig:
    codex_executable: Path
    codex_version: str
    managed_config_sha256: str
    runtime_parent: Path
    permission_snapshot_root: Path
    auth_file: Path | None = field(default=None, repr=False)
    api_key: str | None = field(default=None, repr=False)
    timeout_seconds: float = 60.0
    max_output_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        executable = Path(self.codex_executable).expanduser()
        runtime_parent = _private_directory(Path(self.runtime_parent))
        permission_snapshot_root = _read_only_directory(
            Path(self.permission_snapshot_root)
        )
        if self.codex_version != _child.SUPPORTED_CODEX_VERSION:
            raise ValueError("unsupported Codex CLI version")
        if _SHA256.fullmatch(self.managed_config_sha256) is None:
            raise ValueError(
                "managed_config_sha256 must be a lowercase SHA-256"
            )
        if (self.auth_file is None) == (self.api_key is None):
            raise ValueError("exactly one authentication source is required")
        auth_file = self.auth_file
        if auth_file is not None:
            auth_file = Path(auth_file).expanduser()
            if not auth_file.is_absolute():
                raise ValueError("auth_file must be absolute")
        api_key = self.api_key
        if api_key is not None and (
            not isinstance(api_key, str)
            or not api_key
            or len(api_key.encode("utf-8")) > 16 * 1024
            or "\0" in api_key
            or "\n" in api_key
            or "\r" in api_key
        ):
            raise ValueError("api_key must be a bounded single-line string")
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not 0 < float(self.timeout_seconds) <= 3600
        ):
            raise ValueError("timeout_seconds must be in (0, 3600]")
        if (
            type(self.max_output_bytes) is not int
            or not 1024 <= self.max_output_bytes <= 64 * 1024 * 1024
        ):
            raise ValueError("max_output_bytes is outside the supported range")
        object.__setattr__(self, "codex_executable", executable)
        object.__setattr__(self, "runtime_parent", runtime_parent)
        object.__setattr__(
            self,
            "permission_snapshot_root",
            permission_snapshot_root,
        )
        object.__setattr__(self, "auth_file", auth_file)


@dataclass(frozen=True)
class BoundaryPermissionProfile:
    snapshot_root: Path
    name: str = BOUNDARY_PERMISSION_PROFILE
    description: str = "Adaptive boundary classifier"
    writable_root: None = field(default=None, init=False)
    workspace_access: str = field(default="read", init=False)

    def __post_init__(self) -> None:
        root = _read_only_directory(self.snapshot_root)
        object.__setattr__(self, "snapshot_root", root)

    @property
    def config_overrides(self) -> tuple[str, ...]:
        quoted_path = json.dumps(os.fspath(self.snapshot_root))
        filesystem = (
            f"permissions.{self.name}.filesystem="
            '{":root"="deny",":minimal"="read",":tmpdir"="write",'
            '":workspace_roots"={"."="read"},'
            f"{quoted_path}=\"read\"}}"
        )
        return (
            f"permissions.{self.name}.description="
            f"{json.dumps(self.description)}",
            filesystem,
            f"permissions.{self.name}.network.enabled=false",
        )

    @property
    def sha256(self) -> str:
        encoded = json.dumps(
            {
                "name": self.name,
                "overrides": self.config_overrides,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class BoundaryReclassification:
    assessment: DelegationAssessment
    model: str
    reasoning_effort: str
    permission_profile: str
    permission_profile_sha256: str
    permission_probe_id: str
    argv_fingerprint: str
    stdout_sha256: str
    run_fingerprint: str


class BoundaryLauncher(Protocol):
    def run(
        self,
        request: _child.ChildRunRequest,
        *,
        api_key: str | None = None,
    ) -> _child.ChildRunResult:
        """Run exactly one isolated boundary-classification turn."""


class CapacityGate(Protocol):
    def require_capacity(self) -> object:
        """Fail closed unless local capacity is sufficient for a child."""


class ProcessSlotGate(Protocol):
    def hold(
        self,
        *,
        timeout_seconds: float,
    ) -> ContextManager[None]:
        """Reserve one global external-process workflow slot."""


class AttestationReceiver(Protocol):
    endpoint: str
    header_name: str
    token: str
    events: list[dict[str, Any]]

    def __enter__(self) -> "AttestationReceiver":
        """Start receiving local attestation events."""

    def __exit__(self, *_: object) -> None:
        """Stop receiving local attestation events."""


class BoundaryProcessRunner:
    """Run the classifier with the shared admission and launch primitives."""

    def __init__(
        self,
        permission_gate: PermissionGate,
        resource_gate: CapacityGate | None = None,
        process_limiter: ProcessSlotGate | None = None,
    ) -> None:
        self._permission_gate = permission_gate
        self._resource_gate = resource_gate
        self._process_limiter = process_limiter

    def run(
        self,
        request: _child.ChildRunRequest,
        *,
        api_key: str | None = None,
    ) -> _child.ChildRunResult:
        reservation = (
            nullcontext()
            if self._process_limiter is None
            else self._process_limiter.hold(timeout_seconds=1.0)
        )
        with reservation:
            return self._run_admitted(request, api_key=api_key)

    def _run_admitted(
        self,
        request: _child.ChildRunRequest,
        *,
        api_key: str | None = None,
    ) -> _child.ChildRunResult:
        if request.auth_file is not None and api_key is not None:
            raise BoundaryReclassificationError(
                "AUTH_SOURCE_CONFLICT",
                "boundary child received two authentication sources",
            )
        if request.auth_file is None and api_key is None:
            raise BoundaryReclassificationError(
                "AUTH_SOURCE_MISSING",
                "boundary child received no authentication source",
            )

        argv = build_boundary_exec_argv(request)
        if self._resource_gate is not None:
            self._resource_gate.require_capacity()
        evidence = self._permission_gate.require_verified(
            CanaryRequest(
                codex_version=request.codex_version,
                permission_profile=request.permission_profile.name,
                profile_sha256=request.permission_profile.sha256,
                managed_config_sha256=request.managed_config_sha256,
            )
        )
        if self._resource_gate is not None:
            self._resource_gate.require_capacity()
        _child._validate_workdir(  # noqa: SLF001
            request.runtime.work_dir,
            allow_populated=False,
        )
        staged_auth = (
            _child._stage_auth_file(  # noqa: SLF001
                request.auth_file,
                request.runtime.codex_home,
            )
            if request.auth_file is not None
            else None
        )
        try:
            _assert_codex_home(
                request.runtime.codex_home,
                auth_expected=staged_auth is not None,
                allow_model_cache=False,
            )
            environment = _child._child_environment(  # noqa: SLF001
                request.runtime,
                request.permission_profile.snapshot_root,
                request.telemetry,
                request.permission_profile.writable_root,
            )
            if api_key is not None:
                environment["OPENAI_API_KEY"] = api_key
            codex_target = Path(argv[0])
            baseline_bytes = _child._runtime_tree_usage(  # noqa: SLF001
                request.runtime.root,
                allowed_arg0_target=codex_target,
            )
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=request.runtime.work_dir,
                    env=environment,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    close_fds=True,
                    start_new_session=True,
                    restore_signals=True,
                    umask=0o077,
                )
            except OSError as exc:
                raise _child.ChildLaunchError(
                    "CHILD_SPAWN_FAILED",
                    str(exc),
                ) from exc

            try:
                stdout, stderr, terminal_reason = (
                    _child._collect_bounded_output(  # noqa: SLF001
                        process,
                        prompt=request.prompt.encode("utf-8"),
                        timeout_seconds=float(request.timeout_seconds),
                        max_output_bytes=request.max_output_bytes,
                        max_memory_bytes=(
                            request.resource_limits.max_memory_bytes
                        ),
                        max_processes=request.resource_limits.max_processes,
                        max_growth_bytes=(
                            request.resource_limits.max_growth_bytes
                        ),
                        growth_root=request.runtime.root,
                        baseline_bytes=baseline_bytes,
                        allowed_arg0_target=codex_target,
                        cancellation=Event(),
                    )
                )
            except BaseException:
                _close_failed_process(process)
                raise
            if terminal_reason is not None:
                raise _child.ChildLaunchError(
                    terminal_reason,
                    _child._reason_message(terminal_reason),  # noqa: SLF001
                )
            _child._validate_workdir(  # noqa: SLF001
                request.runtime.work_dir,
                allow_populated=False,
            )
            _child._validate_workdir(  # noqa: SLF001
                request.runtime.sqlite_home,
                allow_populated=True,
            )
            _assert_codex_home(
                request.runtime.codex_home,
                auth_expected=staged_auth is not None,
                allow_model_cache=True,
            )
            events = _child._parse_jsonl(stdout)  # noqa: SLF001
            return _child.ChildRunResult(
                exit_code=int(process.returncode),
                events=events,
                stderr=stderr.decode("utf-8", errors="replace"),
                stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                probe_id=evidence.probe_id,
                argv_fingerprint=hashlib.sha256(
                    "\0".join(argv).encode("utf-8")
                ).hexdigest(),
            )
        finally:
            _remove_generated_model_cache(request.runtime.codex_home)
            if staged_auth is not None:
                _child._remove_staged_auth(staged_auth)  # noqa: SLF001


class BoundaryReclassifier:
    """Callable injected into ``SmartService`` for one boundary only."""

    def __init__(
        self,
        config: BoundaryReclassifierConfig,
        *,
        permission_gate: PermissionGate | None = None,
        resource_gate: CapacityGate | None = None,
        process_limiter: ProcessSlotGate | None = None,
        launcher: BoundaryLauncher | None = None,
        receiver_factory: Callable[[], AttestationReceiver] = OTelReceiver,
        attestation: Callable[..., RunAttestation] = attest_run,
    ) -> None:
        if launcher is None:
            if permission_gate is None:
                raise ValueError(
                    "permission_gate is required for the production launcher"
                )
            launcher = BoundaryProcessRunner(
                permission_gate,
                resource_gate,
                process_limiter,
            )
        self.config = config
        self.launcher = launcher
        self.receiver_factory = receiver_factory
        self.attestation = attestation

    def __call__(
        self,
        node: dict[str, Any],
    ) -> DelegationAssessment | None:
        try:
            return self.classify_or_raise(node).assessment
        except Exception:
            return None

    def classify_or_raise(
        self,
        node: dict[str, Any],
    ) -> BoundaryReclassification:
        prompt, writer = _boundary_prompt(node)
        with tempfile.TemporaryDirectory(
            prefix="boundary-reclassifier-",
            dir=self.config.runtime_parent,
        ) as raw_root:
            root = Path(raw_root)
            schema = root / "boundary-output.schema.json"
            schema.write_text(
                json.dumps(
                    BOUNDARY_OUTPUT_SCHEMA,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            schema.chmod(0o400)
            runtime = _child.ChildRuntimeLayout.create(root / "runtime")
            profile = BoundaryPermissionProfile(
                self.config.permission_snapshot_root
            )

            with self.receiver_factory() as receiver:
                telemetry = _telemetry_config(receiver)
                request = _child.ChildRunRequest(
                    codex_executable=self.config.codex_executable,
                    codex_version=self.config.codex_version,
                    model=BOUNDARY_MODEL,
                    reasoning_effort=BOUNDARY_REASONING_EFFORT,
                    permission_profile=profile,
                    managed_config_sha256=(
                        self.config.managed_config_sha256
                    ),
                    runtime=runtime,
                    output_schema=schema,
                    prompt=prompt,
                    timeout_seconds=self.config.timeout_seconds,
                    max_output_bytes=self.config.max_output_bytes,
                    auth_file=self.config.auth_file,
                    telemetry=telemetry,
                )
                child = self.launcher.run(
                    request,
                    api_key=self.config.api_key,
                )
                return self._collect(
                    child=child,
                    receiver=receiver,
                    profile=profile,
                    writer=writer,
                )

    def _collect(
        self,
        *,
        child: _child.ChildRunResult,
        receiver: AttestationReceiver,
        profile: BoundaryPermissionProfile,
        writer: bool,
    ) -> BoundaryReclassification:
        if not isinstance(child, _child.ChildRunResult) or not child.succeeded:
            raise BoundaryReclassificationError(
                "CHILD_RESULT_INVALID",
                "boundary child did not complete successfully",
            )
        events = _validated_events(child.events)
        assessment = _assessment_from_events(events, writer=writer)
        if _SHA256.fullmatch(child.stdout_sha256) is None:
            raise BoundaryReclassificationError(
                "CHILD_RESULT_INVALID",
                "boundary child JSONL fingerprint is missing",
            )
        if _SHA256.fullmatch(child.argv_fingerprint) is None:
            raise BoundaryReclassificationError(
                "CHILD_RESULT_INVALID",
                "boundary child argv fingerprint is missing",
            )
        if not isinstance(child.probe_id, str) or not child.probe_id:
            raise BoundaryReclassificationError(
                "CHILD_RESULT_INVALID",
                "boundary child permission evidence is missing",
            )
        otel_events = getattr(receiver, "events", None)
        if (
            not isinstance(otel_events, list)
            or not otel_events
            or not all(isinstance(event, dict) for event in otel_events)
        ):
            raise BoundaryReclassificationError(
                "ATTESTATION_FAILED",
                "boundary child OTel evidence is missing",
            )
        attestation = self.attestation(
            events=list(otel_events),
            jsonl_events=list(events),
            requested_model=BOUNDARY_MODEL,
            requested_effort=BOUNDARY_REASONING_EFFORT,
            expected_cli_version=self.config.codex_version,
            permission_probe_id=child.probe_id,
            argv_fingerprint=child.argv_fingerprint,
        )
        _validate_attestation(
            attestation,
            cli_version=self.config.codex_version,
            permission_probe_id=child.probe_id,
            argv_fingerprint=child.argv_fingerprint,
        )
        return BoundaryReclassification(
            assessment=assessment,
            model=BOUNDARY_MODEL,
            reasoning_effort=BOUNDARY_REASONING_EFFORT,
            permission_profile=profile.name,
            permission_profile_sha256=profile.sha256,
            permission_probe_id=child.probe_id,
            argv_fingerprint=child.argv_fingerprint,
            stdout_sha256=child.stdout_sha256,
            run_fingerprint=attestation.run_fingerprint,
        )


def build_boundary_exec_argv(
    request: _child.ChildRunRequest,
) -> tuple[str, ...]:
    """Build the shared argv and remove every classifier tool surface."""

    arguments = list(_child.build_codex_exec_argv(request))
    disabled = {
        arguments[index + 1]
        for index, value in enumerate(arguments[:-1])
        if value == "--disable"
    }
    for feature in _BOUNDARY_DISABLED_FEATURES:
        if feature not in disabled:
            arguments.extend(("--disable", feature))
    return tuple(arguments)


def _boundary_prompt(node: dict[str, Any]) -> tuple[str, bool]:
    if not isinstance(node, dict):
        raise BoundaryReclassificationError(
            "NODE_INVALID",
            "boundary task must be an object",
        )
    mission = node.get("mission")
    role = node.get("role")
    risk_flags = node.get("riskFlags")
    if (
        not isinstance(mission, str)
        or not mission.strip()
        or len(mission) > 2000
        or "\0" in mission
    ):
        raise BoundaryReclassificationError(
            "NODE_INVALID",
            "boundary task mission is invalid",
        )
    if role not in _ROLES:
        raise BoundaryReclassificationError(
            "NODE_INVALID",
            "boundary task role is invalid",
        )
    if (
        not isinstance(risk_flags, list)
        or len(risk_flags) > len(_RISK_FLAGS)
        or len(risk_flags) != len(set(risk_flags))
        or any(flag not in _RISK_FLAGS for flag in risk_flags)
    ):
        raise BoundaryReclassificationError(
            "NODE_INVALID",
            "boundary task risk flags are invalid",
        )
    payload = {
        "contractVersion": BOUNDARY_CONTRACT_VERSION,
        "task": {
            "mission": mission,
            "role": role,
            "riskFlags": risk_flags,
        },
        "factorDefinitions": {
            "q": (
                "Ожидаемый прирост качества от передачи задачи дочернему "
                "агенту."
            ),
            "p": "Польза параллельного выполнения.",
            "v": "Проверяемость результата объективными средствами.",
            "o": "Накладные расходы и задержка от передачи задачи.",
        },
        "instructions": [
            (
                "Независимо оцени каждый фактор одним интервалом: "
                "[0,0], [0,1], [0,2], [1,1], [1,2] или [2,2]."
            ),
            (
                "Не предполагай и не восстанавливай предыдущую оценку; "
                "она намеренно не передана."
            ),
            (
                "hardBan равен direct или clarify только при внутреннем "
                "жёстком запрете; иначе верни none."
            ),
            (
                "Не вызывай средства, не обращайся к сети и не создавай "
                "файлы. Верни только JSON по заданной схеме."
            ),
        ],
    }
    prompt = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(prompt.encode("utf-8")) > _child.MAX_PROMPT_BYTES:
        raise BoundaryReclassificationError(
            "PROMPT_LIMIT_EXCEEDED",
            "boundary classifier prompt exceeds the byte limit",
        )
    return prompt, role == "implementer"


def _validated_events(
    events: object,
) -> tuple[dict[str, Any], ...]:
    if (
        not isinstance(events, (list, tuple))
        or not events
        or not all(isinstance(event, dict) for event in events)
    ):
        raise BoundaryReclassificationError(
            "CHILD_PROTOCOL_INVALID",
            "boundary child JSONL events are malformed",
        )
    copied = tuple(events)
    types = [event.get("type") for event in copied]
    if (
        types[0] != "thread.started"
        or types[-1] != "turn.completed"
        or types.count("thread.started") != 1
        or types.count("turn.completed") != 1
        or types.count("turn.started") > 1
        or any(event_type not in _ALLOWED_EVENT_TYPES for event_type in types)
    ):
        raise BoundaryReclassificationError(
            "CHILD_PROTOCOL_INVALID",
            "boundary child did not emit one clean completed turn",
        )
    for event in copied:
        if not str(event["type"]).startswith("item."):
            continue
        item = event.get("item")
        if (
            not isinstance(item, dict)
            or item.get("type") not in _ALLOWED_ITEM_TYPES
        ):
            raise BoundaryReclassificationError(
                "TOOL_USE_DETECTED",
                "boundary child emitted a tool or action item",
            )
    return copied


def _assessment_from_events(
    events: tuple[dict[str, Any], ...],
    *,
    writer: bool,
) -> DelegationAssessment:
    messages = []
    for event in events:
        if event.get("type") != "item.completed":
            continue
        item = event.get("item")
        if (
            isinstance(item, dict)
            and item.get("type") == "agent_message"
            and isinstance(item.get("text"), str)
        ):
            messages.append(item["text"])
    if len(messages) != 1:
        raise BoundaryReclassificationError(
            "CHILD_RESULT_INVALID",
            "boundary child must emit exactly one completed agent message",
        )
    try:
        payload = json.loads(
            messages[0],
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BoundaryReclassificationError(
            "CHILD_RESULT_INVALID",
            "boundary child result is not strict JSON",
        ) from exc
    if not isinstance(payload, dict) or set(payload) != {
        "q",
        "p",
        "v",
        "o",
        "hardBan",
    }:
        raise BoundaryReclassificationError(
            "CHILD_RESULT_INVALID",
            "boundary child result does not match the object contract",
        )
    hard_ban = payload["hardBan"]
    if hard_ban not in {"none", "direct", "clarify"}:
        raise BoundaryReclassificationError(
            "CHILD_RESULT_INVALID",
            "boundary child hardBan is invalid",
        )
    return DelegationAssessment(
        q=_interval(payload["q"], "q"),
        p=_interval(payload["p"], "p"),
        v=_interval(payload["v"], "v"),
        o=_interval(payload["o"], "o"),
        hard_ban=(
            None if hard_ban == "none" else Disposition(hard_ban)
        ),
        writer=writer,
    )


def _interval(value: object, name: str) -> Interval:
    if (
        not isinstance(value, dict)
        or set(value) != {"min", "max"}
        or type(value["min"]) is not int
        or type(value["max"]) is not int
    ):
        raise BoundaryReclassificationError(
            "CHILD_RESULT_INVALID",
            f"boundary child interval {name} is malformed",
        )
    try:
        return Interval(value["min"], value["max"])
    except ValueError as exc:
        raise BoundaryReclassificationError(
            "CHILD_RESULT_INVALID",
            f"boundary child interval {name} is invalid",
        ) from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def _telemetry_config(
    receiver: AttestationReceiver,
) -> _child.ChildTelemetryConfig:
    try:
        return _child.ChildTelemetryConfig(
            endpoint=receiver.endpoint,
            header_name=receiver.header_name,
            token=receiver.token,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise BoundaryReclassificationError(
            "ATTESTATION_UNAVAILABLE",
            "boundary attestation receiver configuration is invalid",
        ) from exc


def _validate_attestation(
    value: object,
    *,
    cli_version: str,
    permission_probe_id: str,
    argv_fingerprint: str,
) -> None:
    if (
        not isinstance(value, RunAttestation)
        or value.cli_version != cli_version
        or value.requested_model != BOUNDARY_MODEL
        or value.observed_model != BOUNDARY_MODEL
        or value.requested_effort != BOUNDARY_REASONING_EFFORT
        or value.observed_effort != BOUNDARY_REASONING_EFFORT
        or value.permission_probe_id != permission_probe_id
        or value.argv_fingerprint != argv_fingerprint
        or _SHA256.fullmatch(value.conversation_hash) is None
        or _SHA256.fullmatch(value.run_fingerprint) is None
    ):
        raise BoundaryReclassificationError(
            "ATTESTATION_FAILED",
            "boundary launch facts do not match the requested run",
        )


def _private_directory(path: Path) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute() or expanded.is_symlink():
        raise ValueError(
            "runtime_parent must be an absolute non-symlink directory"
        )
    try:
        resolved = expanded.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ValueError("runtime_parent must exist") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError("runtime_parent must be a private owned directory")
    return resolved


def _read_only_directory(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("snapshot root must be absolute and non-symlink")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ValueError("snapshot root is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o222
    ):
        raise ValueError("snapshot root must be owned and read-only")
    try:
        _child._validate_read_only_tree(resolved)  # noqa: SLF001
    except _child.ChildLaunchError as exc:
        raise ValueError("snapshot tree must be read-only and bounded") from exc
    return resolved


def _assert_codex_home(
    path: Path,
    *,
    auth_expected: bool,
    allow_model_cache: bool,
) -> None:
    expected = {"auth.json"} if auth_expected else set()
    allowed = set(expected)
    if allow_model_cache:
        allowed.add("models_cache.json")
    try:
        metadata = path.lstat()
        entries = {entry.name for entry in path.iterdir()}
    except OSError as exc:
        raise BoundaryReclassificationError(
            "CODEX_HOME_INVALID",
            "isolated CODEX_HOME is unavailable",
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or not expected <= entries <= allowed
    ):
        raise BoundaryReclassificationError(
            "CODEX_HOME_CHANGED",
            "isolated CODEX_HOME contains unexpected state",
        )
    if "models_cache.json" in entries:
        _validate_generated_model_cache(path / "models_cache.json")


def _validate_generated_model_cache(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BoundaryReclassificationError(
            "CODEX_HOME_CHANGED",
            "isolated model cache is unavailable",
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or not 0 < metadata.st_size <= 16 * 1024 * 1024
    ):
        raise BoundaryReclassificationError(
            "CODEX_HOME_CHANGED",
            "isolated model cache metadata is unsafe",
        )


def _remove_generated_model_cache(codex_home: Path) -> None:
    cache = codex_home / "models_cache.json"
    try:
        cache.lstat()
    except FileNotFoundError:
        return
    _validate_generated_model_cache(cache)
    cache.unlink()


def _close_failed_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        _child._terminate_process_group(process)  # noqa: SLF001
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            stream.close()

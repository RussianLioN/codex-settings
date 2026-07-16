from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import threading
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.execution import (  # noqa: E402
    NodeExecutionError,
    NodeExecutionOutcome,
    NodeExecutionRequest,
)
from codex_smart_subagents.identity import RequestContext  # noqa: E402
from codex_smart_subagents.runtime_executor import (  # noqa: E402
    READER_RESULT_SCHEMA,
    RuntimeExecutorConfig,
    RuntimeNodeExecutor,
)
from codex_smart_subagents.state import RouteState  # noqa: E402
from codex_smart_subagents.store import NodeRecord  # noqa: E402


def context(repository: Path) -> RequestContext:
    return RequestContext(
        shell_session_id="shell-1",
        session_id="session-1",
        turn_id="turn-1",
        codex_home="/Users/test/.codex",
        repo_root=str(repository),
        base_sha="a" * 40,
        worktree_fingerprint="b" * 64,
    )


def node(**overrides: object) -> NodeRecord:
    values: dict[str, object] = {
        "route_id": "rt1_" + "A" * 43,
        "node_id": "reader_a",
        "ordinal": 0,
        "role": "researcher",
        "mission": "Проверь архитектурные границы.",
        "dependencies": (),
        "context_refs": ("context_architecture",),
        "scope_id": "scope_default",
        "artifact_profile_id": "artifact_report",
        "validation_profile_id": "validation_none",
        "assessment": {},
        "risk_flags": (),
        "selected_model": "gpt-5.6-terra",
        "reasoning_effort": "high",
        "permission_profile_id": "permission_reader",
        "disposition": "delegate",
        "state": RouteState.RUNNING,
        "result": None,
    }
    values.update(overrides)
    return NodeRecord(**values)


def request(
    repository: Path,
    *,
    current_node: NodeRecord | None = None,
    dependencies: dict[str, NodeExecutionOutcome] | None = None,
) -> NodeExecutionRequest:
    selected = current_node or node()
    return NodeExecutionRequest(
        route_id=selected.route_id,
        context=context(repository),
        node=selected,
        dependency_results=dependencies or {},
    )


def child_events(
    payload: object | None = None,
    *,
    model: str = "gpt-5.6-terra",
    effort: str = "high",
) -> tuple[dict[str, object], ...]:
    result = payload
    if result is None:
        result = {
            "summary": "Границы проверены.",
            "validationState": "passed",
            "artifactId": "",
        }
    return (
        {"type": "thread.started", "thread_id": "thread-123"},
        {
            "type": "item.completed",
            "item": {
                "id": "item-1",
                "type": "agent_message",
                "text": json.dumps(result, ensure_ascii=False),
            },
        },
        {
            "type": "turn.completed",
            "model": model,
            "reasoning_effort": effort,
            "usage": {
                "input_tokens": 10,
                "cached_input_tokens": 0,
                "output_tokens": 5,
                "reasoning_output_tokens": 1,
            },
        },
    )


class FakeWorker:
    def __init__(
        self,
        *,
        events: tuple[dict[str, object], ...] | None = None,
        exit_code: int = 0,
        error: Exception | None = None,
    ) -> None:
        self.events = events if events is not None else child_events()
        self.exit_code = exit_code
        self.error = error
        self.requests = []
        self.cancellations = []

    def run(self, work_request, *, cancellation=None):
        self.requests.append(work_request)
        self.cancellations.append(cancellation)
        if self.error is not None:
            raise self.error
        child = SimpleNamespace(
            exit_code=self.exit_code,
            events=self.events,
            stderr="",
            stdout_sha256=hashlib.sha256(b"jsonl").hexdigest(),
            probe_id="pc1_" + "A" * 43,
            argv_fingerprint="f" * 64,
            succeeded=(
                self.exit_code == 0
                and bool(self.events)
                and self.events[-1].get("type") == "turn.completed"
            ),
        )
        return SimpleNamespace(child=child)


class FakeReceiver:
    def __init__(self, events: list[dict[str, str]] | None = None) -> None:
        self.events = list(
            events
            if events is not None
            else [
                {
                    "event.name": "codex.conversation_starts",
                    "app.version": "0.144.4",
                    "service.version": "0.144.4",
                    "model": "gpt-5.6-terra",
                    "reasoning_effort": "high",
                    "conversation.id": "thread-123",
                }
            ]
        )
        self.entered = False
        self.exited = False
        self.endpoint = "http://127.0.0.1:4318/private/v1/logs"
        self.header_name = "X-Codex-Attestation-Token"
        self.token = "private-test-token"

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exc_type, exc, traceback):
        del exc_type, exc, traceback
        self.exited = True


@dataclass(frozen=True)
class FakeAttestation:
    cli_version: str
    requested_model: str
    observed_model: str
    requested_effort: str
    observed_effort: str
    conversation_hash: str
    argv_fingerprint: str
    permission_probe_id: str
    run_fingerprint: str


class RecordingAttestor:
    def __init__(
        self,
        *,
        observed_model: str = "gpt-5.6-terra",
        observed_effort: str = "high",
        error: Exception | None = None,
    ) -> None:
        self.observed_model = observed_model
        self.observed_effort = observed_effort
        self.error = error
        self.calls = []

    def __call__(self, **arguments):
        self.calls.append(arguments)
        if self.error is not None:
            raise self.error
        return FakeAttestation(
            cli_version=arguments["expected_cli_version"],
            requested_model=arguments["requested_model"],
            observed_model=self.observed_model,
            requested_effort=arguments["requested_effort"],
            observed_effort=self.observed_effort,
            conversation_hash="d" * 64,
            argv_fingerprint=arguments["argv_fingerprint"],
            permission_probe_id=arguments["permission_probe_id"],
            run_fingerprint="e" * 64,
        )


class CodedError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
        self.message = "внутренняя подробность"


class FakeResourceGate:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls = 0

    def require_capacity(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return SimpleNamespace(
            free_disk_bytes=10_000,
            available_memory_bytes=20_000,
            available_fds=300,
        )


class FakeArtifactRegistry:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.reservations = []
        self.seals = []

    def reserve_runtime_artifact(self, **arguments):
        if self.error is not None:
            raise self.error
        self.reservations.append(arguments)
        return "ra1_" + "A" * 43

    def seal_runtime_artifact(self, artifact_id, *, terminal):
        self.seals.append((artifact_id, terminal))
        return {"state": "TERMINAL"}


class RuntimeNodeExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.repository = self.base / "repository"
        self.repository.mkdir()
        self.runtime_parent = self.base / "runtime"
        self.runtime_parent.mkdir(mode=0o700)
        self.schema = self.base / "reader-output.schema.json"
        self.schema.write_text(
            json.dumps(READER_RESULT_SCHEMA, sort_keys=True),
            encoding="utf-8",
        )
        self.codex = self.base / "codex"
        self.codex.write_text("#!/bin/sh\n", encoding="utf-8")
        self.codex.chmod(0o700)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def config(self, **overrides: object) -> RuntimeExecutorConfig:
        values: dict[str, object] = {
            "runtime_parent": self.runtime_parent,
            "codex_executable": self.codex,
            "codex_version": "0.144.4",
            "reader_permission_profile_id": "permission_reader",
            "reader_permission_profile_name": "adaptive_reader",
            "managed_config_sha256": "c" * 64,
            "output_schema": self.schema,
            "timeout_seconds": 15.0,
            "max_output_bytes": 1024 * 1024,
        }
        values.update(overrides)
        return RuntimeExecutorConfig(**values)

    def executor(
        self,
        worker: FakeWorker,
        *,
        receiver: FakeReceiver | None = None,
        attestor: RecordingAttestor | None = None,
        resource_gate: FakeResourceGate | None = None,
        artifact_registry: FakeArtifactRegistry | None = None,
    ) -> tuple[RuntimeNodeExecutor, FakeReceiver, RecordingAttestor]:
        selected_receiver = receiver or FakeReceiver()
        selected_attestor = attestor or RecordingAttestor()
        return (
            RuntimeNodeExecutor(
                worker=worker,
                config=self.config(),
                receiver_factory=lambda: selected_receiver,
                attestation=selected_attestor,
                resource_gate=resource_gate,
                artifact_registry=artifact_registry,
            ),
            selected_receiver,
            selected_attestor,
        )

    def test_executes_reader_and_returns_attested_structured_outcome(self) -> None:
        dependency = NodeExecutionOutcome(
            summary="Предыдущая проверка завершена.",
            fingerprint="1" * 64,
            validation_state="passed",
            artifact_id="",
            attestation={},
            permission_probe_id="pc1_" + "B" * 43,
            argv_fingerprint="2" * 64,
        )
        current = node(dependencies=("reader_before",))
        worker = FakeWorker()
        executor, receiver, attestor = self.executor(worker)
        cancellation = threading.Event()

        outcome = executor.execute(
            request(
                self.repository,
                current_node=current,
                dependencies={"reader_before": dependency},
            ),
            cancellation,
        )

        self.assertEqual("Границы проверены.", outcome.summary)
        self.assertEqual("passed", outcome.validation_state)
        self.assertEqual("", outcome.artifact_id)
        self.assertEqual(64, len(outcome.fingerprint))
        self.assertEqual("pc1_" + "A" * 43, outcome.permission_probe_id)
        self.assertEqual(64, len(outcome.argv_fingerprint))
        self.assertEqual("gpt-5.6-terra", outcome.attestation["observedModel"])
        self.assertEqual("high", outcome.attestation["observedEffort"])
        self.assertEqual(
            {
                "inputTokens": 10,
                "cachedInputTokens": 0,
                "outputTokens": 5,
                "reasoningOutputTokens": 1,
            },
            outcome.usage,
        )
        self.assertTrue(receiver.entered)
        self.assertTrue(receiver.exited)
        self.assertEqual(1, len(worker.requests))
        work_request = worker.requests[0]
        self.assertEqual(self.repository.resolve(), work_request.repository)
        self.assertEqual("a" * 40, work_request.base_sha)
        self.assertEqual("gpt-5.6-terra", work_request.model)
        self.assertEqual("high", work_request.reasoning_effort)
        self.assertEqual("adaptive_reader", work_request.permission_profile_name)
        self.assertEqual(receiver.endpoint, work_request.telemetry.endpoint)
        self.assertEqual(receiver.header_name, work_request.telemetry.header_name)
        self.assertEqual(receiver.token, work_request.telemetry.token)
        self.assertIs(cancellation, worker.cancellations[0])
        self.assertNotIn(str(self.repository.resolve()), work_request.prompt)
        prompt = json.loads(work_request.prompt)
        self.assertEqual(
            "Проверь архитектурные границы.",
            prompt["mission"],
        )
        self.assertEqual(
            ["reader_before"],
            [item["nodeId"] for item in prompt["dependencyResults"]],
        )
        self.assertEqual(1, len(attestor.calls))
        attestation_call = attestor.calls[0]
        self.assertEqual(
            list(receiver.events),
            attestation_call["events"],
        )
        self.assertEqual(
            list(child_events()),
            attestation_call["jsonl_events"],
        )
        self.assertEqual(
            outcome.argv_fingerprint,
            attestation_call["argv_fingerprint"],
        )

    def test_runtime_is_registered_before_worker_and_sealed_afterward(self) -> None:
        registry = FakeArtifactRegistry()
        worker = FakeWorker()
        executor, _receiver, _attestor = self.executor(
            worker,
            artifact_registry=registry,
        )

        executor.execute(request(self.repository), threading.Event())

        self.assertEqual(1, len(registry.reservations))
        reservation = registry.reservations[0]
        self.assertEqual(node().route_id, reservation["route_id"])
        self.assertEqual("reader_a", reservation["node_id"])
        self.assertEqual("reader_runtime", reservation["kind"])
        self.assertEqual(
            self.runtime_parent.resolve(),
            reservation["allowed_root"],
        )
        self.assertEqual(
            self.runtime_parent.resolve(),
            reservation["path"].parent,
        )
        self.assertEqual(
            [("ra1_" + "A" * 43, True)],
            registry.seals,
        )

    def test_rejects_non_reader_or_unexpected_routing_before_launch(self) -> None:
        cases = (
            ("ROLE_NOT_SUPPORTED", node(role="implementer")),
            (
                "NODE_NOT_DELEGATED",
                node(disposition="direct"),
            ),
            (
                "PERMISSION_PROFILE_MISMATCH",
                node(permission_profile_id="permission_writer"),
            ),
            (
                "MODEL_NOT_SUPPORTED",
                node(selected_model="gpt-5.7-unknown"),
            ),
            (
                "REASONING_EFFORT_MISMATCH",
                node(reasoning_effort="low"),
            ),
        )
        for expected_code, current in cases:
            with self.subTest(expected_code=expected_code):
                worker = FakeWorker()
                executor, receiver, attestor = self.executor(worker)
                with self.assertRaises(NodeExecutionError) as caught:
                    executor.execute(
                        request(self.repository, current_node=current),
                        threading.Event(),
                    )
                self.assertEqual(expected_code, caught.exception.code)
                self.assertEqual([], worker.requests)
                self.assertFalse(receiver.entered)
                self.assertEqual([], attestor.calls)

    def test_rejects_source_path_in_prompt_inputs_or_result(self) -> None:
        source = str(self.repository.resolve())
        cases = (
            node(mission=f"Прочитай {source}."),
            node(dependencies=("reader_before",)),
        )
        dependencies = (
            {},
            {
                "reader_before": NodeExecutionOutcome(
                    summary=f"Источник: {source}",
                    fingerprint="1" * 64,
                    validation_state="passed",
                    artifact_id="",
                    attestation={},
                    permission_probe_id="pc1_" + "B" * 43,
                    argv_fingerprint="2" * 64,
                )
            },
        )
        for current, dependency_results in zip(cases, dependencies):
            with self.subTest(current=current):
                worker = FakeWorker()
                executor, receiver, _attestor = self.executor(worker)
                with self.assertRaises(NodeExecutionError) as caught:
                    executor.execute(
                        request(
                            self.repository,
                            current_node=current,
                            dependencies=dependency_results,
                        ),
                        threading.Event(),
                    )
                self.assertEqual("SOURCE_PATH_IN_PROMPT", caught.exception.code)
                self.assertEqual([], worker.requests)
                self.assertFalse(receiver.entered)

        worker = FakeWorker(
            events=child_events(
                {
                    "summary": f"Проверен {source}",
                    "validationState": "passed",
                    "artifactId": "",
                }
            )
        )
        executor, _receiver, _attestor = self.executor(worker)
        with self.assertRaises(NodeExecutionError) as caught:
            executor.execute(request(self.repository), threading.Event())
        self.assertEqual("SOURCE_PATH_IN_RESULT", caught.exception.code)

    def test_structured_result_protocol_fails_closed(self) -> None:
        cases = (
            (
                "missing message",
                (
                    {"type": "thread.started", "thread_id": "thread-123"},
                    {"type": "turn.completed"},
                ),
                0,
            ),
            (
                "invalid json",
                child_events("not an object"),
                0,
            ),
            (
                "extra field",
                child_events(
                    {
                        "summary": "Готово.",
                        "validationState": "passed",
                        "artifactId": "",
                        "extra": True,
                    }
                ),
                0,
            ),
            (
                "reader artifact",
                child_events(
                    {
                        "summary": "Готово.",
                        "validationState": "passed",
                        "artifactId": "art1_" + "A" * 43,
                    }
                ),
                0,
            ),
            (
                "nonzero exit",
                child_events(),
                7,
            ),
        )
        for label, events, exit_code in cases:
            with self.subTest(label=label):
                worker = FakeWorker(events=events, exit_code=exit_code)
                executor, _receiver, _attestor = self.executor(worker)
                with self.assertRaises(NodeExecutionError) as caught:
                    executor.execute(
                        request(self.repository),
                        threading.Event(),
                    )
                self.assertEqual("CHILD_RESULT_INVALID", caught.exception.code)

    def test_attestation_mismatch_or_error_fails_closed(self) -> None:
        cases = (
            RecordingAttestor(observed_model="gpt-5.6-luna"),
            RecordingAttestor(observed_effort="medium"),
            RecordingAttestor(error=CodedError("MODEL_MISMATCH")),
        )
        for attestor in cases:
            with self.subTest(attestor=attestor):
                worker = FakeWorker()
                executor, _receiver, _attestor = self.executor(
                    worker,
                    attestor=attestor,
                )
                with self.assertRaises(NodeExecutionError) as caught:
                    executor.execute(
                        request(self.repository),
                        threading.Event(),
                    )
                self.assertEqual("ATTESTATION_FAILED", caught.exception.code)

    def test_cancellation_and_timeout_are_mapped_for_execution_engine(self) -> None:
        cancelled = threading.Event()
        cancelled.set()
        worker = FakeWorker()
        executor, receiver, _attestor = self.executor(worker)
        with self.assertRaises(NodeExecutionError) as caught:
            executor.execute(request(self.repository), cancelled)
        self.assertEqual("CANCELLED", caught.exception.code)
        self.assertEqual([], worker.requests)
        self.assertFalse(receiver.entered)

        worker = FakeWorker(error=CodedError("CHILD_CANCELLED"))
        executor, _receiver, _attestor = self.executor(worker)
        with self.assertRaises(NodeExecutionError) as caught:
            executor.execute(request(self.repository), threading.Event())
        self.assertEqual("CANCELLED", caught.exception.code)

        worker = FakeWorker(error=CodedError("CHILD_TIMEOUT"))
        executor, _receiver, _attestor = self.executor(worker)
        with self.assertRaises(NodeExecutionError) as caught:
            executor.execute(request(self.repository), threading.Event())
        self.assertEqual("NODE_TIMEOUT", caught.exception.code)

    def test_resource_gate_runs_immediately_before_worker_and_fails_closed(
        self,
    ) -> None:
        gate = FakeResourceGate()
        worker = FakeWorker()
        executor, _receiver, _attestor = self.executor(
            worker,
            resource_gate=gate,
        )

        executor.execute(request(self.repository), threading.Event())

        self.assertEqual(1, gate.calls)
        self.assertEqual(1, len(worker.requests))

        gate = FakeResourceGate(CodedError("MEMORY_CAPACITY_EXHAUSTED"))
        worker = FakeWorker()
        executor, _receiver, attestor = self.executor(
            worker,
            resource_gate=gate,
        )
        with self.assertRaises(NodeExecutionError) as caught:
            executor.execute(request(self.repository), threading.Event())
        self.assertEqual(
            "MEMORY_CAPACITY_EXHAUSTED",
            caught.exception.code,
        )
        self.assertEqual(1, gate.calls)
        self.assertEqual([], worker.requests)
        self.assertEqual([], attestor.calls)

    def test_config_rejects_schema_drift(self) -> None:
        self.schema.write_text(
            '{"type":"object","additionalProperties":true}',
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            self.config()

    def test_executor_rechecks_schema_immediately_before_the_attempt(self) -> None:
        config = self.config()
        self.schema.write_text(
            '{"type":"object","additionalProperties":true}',
            encoding="utf-8",
        )
        worker = FakeWorker()
        receiver = FakeReceiver()
        executor = RuntimeNodeExecutor(
            worker=worker,
            config=config,
            receiver_factory=lambda: receiver,
            attestation=RecordingAttestor(),
        )

        with self.assertRaises(NodeExecutionError) as caught:
            executor.execute(request(self.repository), threading.Event())

        self.assertEqual("OUTPUT_SCHEMA_CHANGED", caught.exception.code)
        self.assertEqual([], worker.requests)
        self.assertFalse(receiver.entered)


if __name__ == "__main__":
    unittest.main()

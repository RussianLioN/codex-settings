from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
FAKE_CODEX = Path(__file__).with_name("test_boundary_fake_codex.py")
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.boundary_reclassifier import (  # noqa: E402
    BOUNDARY_MODEL,
    BOUNDARY_REASONING_EFFORT,
    BoundaryReclassifier,
    BoundaryReclassifierConfig,
    build_boundary_exec_argv,
)
from codex_smart_subagents.child_runner import ChildRunResult  # noqa: E402
from codex_smart_subagents.permissions import (  # noqa: E402
    REQUIRED_CANARY_CHECKS,
    CanaryEvidence,
    PermissionGate,
)
from codex_smart_subagents.routing import Disposition, Interval  # noqa: E402

from tests.smart_subagents.fixtures import valid_plan  # noqa: E402


def _result_events(
    payload: object | None = None,
    *,
    extra_event: dict[str, object] | None = None,
    final: bool = True,
    raw_text: str | None = None,
) -> tuple[dict[str, object], ...]:
    result = payload
    if result is None:
        result = {
            "q": {"min": 1, "max": 2},
            "p": {"min": 0, "max": 1},
            "v": {"min": 2, "max": 2},
            "o": {"min": 0, "max": 1},
            "hardBan": "none",
        }
    events: list[dict[str, object]] = [
        {"type": "thread.started", "thread_id": "boundary-thread-123"},
    ]
    if extra_event is not None:
        events.append(extra_event)
    events.append(
        {
            "type": "item.completed",
            "item": {
                "id": "message-1",
                "type": "agent_message",
                "text": (
                    raw_text
                    if raw_text is not None
                    else json.dumps(result, ensure_ascii=False)
                ),
            },
        }
    )
    events.append(
        {
            "type": "turn.completed" if final else "turn.failed",
            "usage": {
                "input_tokens": 10,
                "cached_input_tokens": 0,
                "output_tokens": 5,
                "reasoning_output_tokens": 1,
            },
        }
    )
    return tuple(events)


class FakeReceiver:
    header_name = "X-Codex-Attestation-Token"
    endpoint = "http://127.0.0.1:4318/boundary/v1/logs"
    token = "boundary-test-token"

    def __init__(
        self,
        *,
        model: str = BOUNDARY_MODEL,
        effort: str = BOUNDARY_REASONING_EFFORT,
    ) -> None:
        self.events = [
            {
                "event.name": "codex.conversation_starts",
                "app.version": "0.144.4",
                "service.version": "0.144.4",
                "model": model,
                "reasoning_effort": effort,
                "conversation.id": "boundary-thread-123",
            }
        ]

    def __enter__(self) -> "FakeReceiver":
        return self

    def __exit__(self, *_: object) -> None:
        return None


class RecordingLauncher:
    def __init__(
        self,
        *,
        events: tuple[dict[str, object], ...] | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.events = events or _result_events()
        self.failure = failure
        self.calls = 0
        self.requests = []
        self.request = None
        self.api_key = None
        self.argv: tuple[str, ...] = ()
        self.prompt: dict[str, object] = {}
        self.schema: dict[str, object] = {}
        self.runtime_root: Path | None = None

    def run(self, request, *, api_key=None):
        self.calls += 1
        self.requests.append(request)
        self.request = request
        self.api_key = api_key
        self.runtime_root = request.runtime.root
        self.argv = build_boundary_exec_argv(request)
        self.prompt = json.loads(request.prompt)
        self.schema = json.loads(
            request.output_schema.read_text(encoding="utf-8")
        )
        if self.failure is not None:
            raise self.failure
        return ChildRunResult(
            exit_code=(
                0
                if self.events
                and self.events[-1].get("type") == "turn.completed"
                else 1
            ),
            events=self.events,
            stderr="",
            stdout_sha256="a" * 64,
            probe_id="pc1_" + "A" * 43,
            argv_fingerprint="b" * 64,
        )


class PassingCanary:
    def __init__(self) -> None:
        self.calls = []

    def verify(self, request):
        self.calls.append(request)
        return CanaryEvidence(
            probe_id="pc1_" + "A" * 43,
            codex_version=request.codex_version,
            permission_profile=request.permission_profile,
            profile_sha256=request.profile_sha256,
            managed_config_sha256=request.managed_config_sha256,
            verified_at=datetime.now(timezone.utc),
            legacy_sandbox_mode=False,
            checks={name: True for name in REQUIRED_CANARY_CHECKS},
        )


class RejectingCapacityGate:
    def __init__(self) -> None:
        self.calls = 0

    def require_capacity(self) -> object:
        self.calls += 1
        raise RuntimeError("synthetic capacity failure")


class BoundaryReclassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.runtime_parent = self.base / "runtime-parent"
        self.runtime_parent.mkdir(mode=0o700)
        self.permission_snapshot = self.base / "permission-snapshot"
        self.permission_snapshot.mkdir(mode=0o700)
        (self.permission_snapshot / "read-probe.txt").write_text(
            "synthetic boundary canary\n",
            encoding="utf-8",
        )
        (self.permission_snapshot / "read-probe.txt").chmod(0o444)
        self.permission_snapshot.chmod(0o555)
        self.auth_file = self.base / "auth.json"
        self.auth_file.write_text('{"token":"test-only"}\n', encoding="utf-8")
        self.auth_file.chmod(0o600)
        self.node = valid_plan()["nodes"][0]

    def tearDown(self) -> None:
        self.directory.cleanup()

    def config(self, **overrides: object) -> BoundaryReclassifierConfig:
        values: dict[str, object] = {
            "codex_executable": FAKE_CODEX,
            "codex_version": "0.144.4",
            "managed_config_sha256": "c" * 64,
            "runtime_parent": self.runtime_parent,
            "permission_snapshot_root": self.permission_snapshot,
            "auth_file": self.auth_file,
            "timeout_seconds": 5.0,
            "max_output_bytes": 1024 * 1024,
        }
        values.update(overrides)
        return BoundaryReclassifierConfig(**values)

    def test_one_independent_terra_high_pass_is_read_only_and_toolless(
        self,
    ) -> None:
        launcher = RecordingLauncher()
        reclassifier = BoundaryReclassifier(
            self.config(),
            launcher=launcher,
            receiver_factory=FakeReceiver,
        )

        assessment = reclassifier(self.node)

        self.assertEqual(1, launcher.calls)
        self.assertEqual(BOUNDARY_MODEL, launcher.request.model)
        self.assertEqual(
            BOUNDARY_REASONING_EFFORT,
            launcher.request.reasoning_effort,
        )
        self.assertEqual(Interval(1, 2), assessment.q)
        self.assertEqual(Interval(0, 1), assessment.p)
        self.assertEqual(Interval(2, 2), assessment.v)
        self.assertEqual(Interval(0, 1), assessment.o)
        self.assertIsNone(assessment.hard_ban)
        self.assertFalse(assessment.writer)

        self.assertEqual(
            {"mission", "riskFlags", "role"},
            set(launcher.prompt["task"]),
        )
        prompt_text = json.dumps(launcher.prompt, ensure_ascii=False)
        self.assertNotIn('"assessment"', prompt_text)
        self.assertNotIn('"delegation"', prompt_text)
        self.assertEqual(
            "boundary-reclassification-v1",
            launcher.prompt["contractVersion"],
        )

        filesystem_override = next(
            value
            for value in launcher.request.permission_profile.config_overrides
            if ".filesystem=" in value
        )
        self.assertIn('":workspace_roots"={"."="read"}', filesystem_override)
        self.assertNotIn('":workspace_roots"={"."="write"}', filesystem_override)
        self.assertIn(
            "permissions.adaptive_boundary_classifier.network.enabled=false",
            launcher.request.permission_profile.config_overrides,
        )
        self.assertEqual(
            self.permission_snapshot.resolve(),
            launcher.request.permission_profile.snapshot_root,
        )
        for feature in (
            "enable_fanout",
            "multi_agent",
            "multi_agent_v2",
            "shell_tool",
            "unified_exec",
        ):
            self.assertIn(("--disable", feature), tuple(zip(
                launcher.argv,
                launcher.argv[1:],
            )))
        self.assertIn("agents.max_depth=1", launcher.argv)
        self.assertIn('approval_policy="never"', launcher.argv)
        self.assertEqual(False, launcher.schema["additionalProperties"])
        self.assertEqual(
            {"q", "p", "v", "o", "hardBan"},
            set(launcher.schema["required"]),
        )
        self.assertIsNotNone(launcher.runtime_root)
        self.assertFalse(launcher.runtime_root.exists())

    def test_permission_profile_identity_is_stable_across_invocations(
        self,
    ) -> None:
        launcher = RecordingLauncher()
        reclassifier = BoundaryReclassifier(
            self.config(),
            launcher=launcher,
            receiver_factory=FakeReceiver,
        )

        first = reclassifier.classify_or_raise(self.node)
        second = reclassifier.classify_or_raise(self.node)

        self.assertEqual(2, launcher.calls)
        self.assertEqual(
            first.permission_profile_sha256,
            second.permission_profile_sha256,
        )
        self.assertEqual(
            {self.permission_snapshot.resolve()},
            {
                request.permission_profile.snapshot_root
                for request in launcher.requests
            },
        )
        self.assertEqual(
            2,
            len({request.runtime.root for request in launcher.requests}),
        )
        self.assertTrue(
            all(
                not request.runtime.root.exists()
                for request in launcher.requests
            )
        )

    def test_hard_ban_and_writer_role_are_preserved(self) -> None:
        node = dict(self.node)
        node["role"] = "implementer"
        launcher = RecordingLauncher(
            events=_result_events(
                {
                    "q": {"min": 0, "max": 0},
                    "p": {"min": 0, "max": 0},
                    "v": {"min": 0, "max": 1},
                    "o": {"min": 2, "max": 2},
                    "hardBan": "clarify",
                }
            )
        )
        reclassifier = BoundaryReclassifier(
            self.config(),
            launcher=launcher,
            receiver_factory=FakeReceiver,
        )

        assessment = reclassifier(node)

        self.assertEqual(Disposition.CLARIFY, assessment.hard_ban)
        self.assertTrue(assessment.writer)

    def test_every_failure_closes_to_none_without_retry(self) -> None:
        tool_event = {
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "command": "pwd",
                "status": "completed",
                "exit_code": 0,
            },
        }
        invalid_interval = {
            "q": {"min": 2, "max": 1},
            "p": {"min": 0, "max": 0},
            "v": {"min": 1, "max": 1},
            "o": {"min": 0, "max": 0},
            "hardBan": "none",
        }
        duplicate_key = (
            '{"q":{"min":1,"max":2},"p":{"min":0,"max":1},'
            '"v":{"min":2,"max":2},"o":{"min":0,"max":1},'
            '"hardBan":"none","hardBan":"direct"}'
        )
        second_message = {
            "type": "item.completed",
            "item": {
                "type": "agent_message",
                "text": json.dumps(invalid_interval),
            },
        }
        cases = (
            (
                RecordingLauncher(failure=RuntimeError("launch failed")),
                FakeReceiver,
            ),
            (
                RecordingLauncher(events=_result_events(final=False)),
                FakeReceiver,
            ),
            (
                RecordingLauncher(
                    events=_result_events(extra_event=tool_event)
                ),
                FakeReceiver,
            ),
            (
                RecordingLauncher(events=_result_events(invalid_interval)),
                FakeReceiver,
            ),
            (
                RecordingLauncher(
                    events=_result_events(raw_text=duplicate_key)
                ),
                FakeReceiver,
            ),
            (
                RecordingLauncher(
                    events=_result_events(extra_event=second_message)
                ),
                FakeReceiver,
            ),
            (
                RecordingLauncher(),
                lambda: FakeReceiver(model="gpt-5.6-luna"),
            ),
        )
        for launcher, receiver_factory in cases:
            with self.subTest(launcher=launcher, receiver=receiver_factory):
                reclassifier = BoundaryReclassifier(
                    self.config(),
                    launcher=launcher,
                    receiver_factory=receiver_factory,
                )
                self.assertIsNone(reclassifier(self.node))
                self.assertEqual(1, launcher.calls)

    def test_production_launcher_uses_only_selected_auth_source(self) -> None:
        FAKE_CODEX.chmod(0o755)
        cases = (
            {"auth_file": self.auth_file},
            {
                "auth_file": None,
                "api_key": "synthetic-openai-key",
            },
        )
        for index, auth in enumerate(cases):
            with self.subTest(auth=auth):
                runtime_parent = self.base / f"runtime-parent-{index}"
                runtime_parent.mkdir(mode=0o700)
                canary = PassingCanary()
                config = self.config(runtime_parent=runtime_parent, **auth)
                reclassifier = BoundaryReclassifier(
                    config,
                    permission_gate=PermissionGate(canary),
                )

                assessment = reclassifier(self.node)

                self.assertIsNotNone(assessment)
                self.assertEqual(1, len(canary.calls))
                self.assertEqual(
                    "adaptive_boundary_classifier",
                    canary.calls[0].permission_profile,
                )
                self.assertEqual(
                    0o600,
                    stat.S_IMODE(self.auth_file.stat().st_mode),
                )
                self.assertEqual(
                    '{"token":"test-only"}\n',
                    self.auth_file.read_text(encoding="utf-8"),
                )
                self.assertEqual([], list(runtime_parent.iterdir()))

    def test_capacity_failure_prevents_boundary_process_launch(self) -> None:
        FAKE_CODEX.chmod(0o755)
        canary = PassingCanary()
        capacity = RejectingCapacityGate()
        reclassifier = BoundaryReclassifier(
            self.config(),
            permission_gate=PermissionGate(canary),
            resource_gate=capacity,
        )

        self.assertIsNone(reclassifier(self.node))
        self.assertEqual(0, len(canary.calls))
        self.assertEqual(1, capacity.calls)
        self.assertEqual([], list(self.runtime_parent.iterdir()))

    def test_configuration_requires_exactly_one_auth_source(self) -> None:
        with self.assertRaises(ValueError):
            self.config(auth_file=None, api_key=None)
        with self.assertRaises(ValueError):
            self.config(api_key="also-set")
        with self.assertRaises(ValueError):
            self.config(
                auth_file=None,
                api_key="key\x00with-null",
            )
        self.runtime_parent.chmod(0o755)
        with self.assertRaises(ValueError):
            self.config()


if __name__ == "__main__":
    unittest.main()

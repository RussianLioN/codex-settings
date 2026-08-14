from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.execution import (  # noqa: E402
    NodeExecutionError,
    NodeExecutionRequest,
)
from codex_smart_subagents.identity import RequestContext  # noqa: E402
from codex_smart_subagents.quarantine import QuarantineRepository  # noqa: E402
from codex_smart_subagents.state import RouteState  # noqa: E402
from codex_smart_subagents.store import NodeRecord  # noqa: E402
from codex_smart_subagents.validation import (  # noqa: E402
    ValidationCommandResult,
    ValidationError,
    ValidationResult,
)
from codex_smart_subagents.writer_executor import (  # noqa: E402
    WRITER_RESULT_SCHEMA,
    WriterExecutorConfig,
    WriterNodeExecutor,
)


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(root), *arguments],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout.strip()


class FakeWriterWorker:
    def __init__(self, *, mutate_source: bool = False) -> None:
        self.mutate_source = mutate_source
        self.requests = []

    def run(self, request, *, cancellation=None):
        self.requests.append(request)
        request.runtime_root.mkdir(mode=0o700)
        workspace = request.runtime_root / "work"
        workspace.mkdir(mode=0o700)
        shutil.copy2(request.repository / "tracked.txt", workspace / "tracked.txt")
        (workspace / "tracked.txt").chmod(0o600)
        (workspace / "tracked.txt").write_text(
            "candidate\n",
            encoding="utf-8",
        )
        if self.mutate_source:
            (request.repository / "tracked.txt").write_text(
                "source changed\n",
                encoding="utf-8",
            )
        child = SimpleNamespace(
            exit_code=0,
            events=(
                {"type": "thread.started", "thread_id": "writer-thread"},
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": json.dumps(
                            {
                                "summary": "Кандидат подготовлен.",
                                "validationState": "not_applicable",
                                "artifactId": "",
                            },
                            ensure_ascii=False,
                        ),
                    },
                },
                {
                    "type": "turn.completed",
                    "model": request.model,
                    "reasoning_effort": request.reasoning_effort,
                    "usage": {
                        "input_tokens": 20,
                        "cached_input_tokens": 3,
                        "output_tokens": 8,
                        "reasoning_output_tokens": 2,
                    },
                },
            ),
            stderr="",
            stdout_sha256=hashlib.sha256(b"writer-jsonl").hexdigest(),
            probe_id="pc1_" + "A" * 43,
            argv_fingerprint="f" * 64,
            succeeded=True,
        )
        return SimpleNamespace(
            workspace=SimpleNamespace(root=workspace),
            child=child,
        )


class FakeReceiver:
    endpoint = "http://127.0.0.1:4318/private/v1/logs"
    header_name = "X-Codex-Attestation-Token"
    token = "private-test-token"

    def __init__(self) -> None:
        self.events = [
            {
                "event.name": "codex.conversation_starts",
                "app.version": "0.144.4",
                "service.version": "0.144.4",
                "model": "gpt-5.6-sol",
                "reasoning_effort": "max",
                "conversation.id": "writer-thread",
            }
        ]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        del exc_type, exc, traceback


class FakeAttestor:
    def __call__(self, **arguments):
        return SimpleNamespace(
            cli_version=arguments["expected_cli_version"],
            requested_model=arguments["requested_model"],
            observed_model=arguments["requested_model"],
            requested_effort=arguments["requested_effort"],
            observed_effort=arguments["requested_effort"],
            conversation_hash="d" * 64,
            argv_fingerprint=arguments["argv_fingerprint"],
            permission_probe_id=arguments["permission_probe_id"],
            run_fingerprint="e" * 64,
        )


class MutatingValidation:
    def __init__(self) -> None:
        self.calls = []

    def run(self, *, workspace, commands, cancellation):
        self.calls.append((workspace, commands, cancellation))
        self.before = (workspace / "tracked.txt").read_text(encoding="utf-8")
        (workspace / "tracked.txt").write_text(
            "validation mutation\n",
            encoding="utf-8",
        )
        return ValidationResult(
            "passed",
            (
                ValidationCommandResult(
                    catalog_argv=commands[0],
                    exit_code=0,
                    stdout_sha256="1" * 64,
                    stderr_sha256="2" * 64,
                ),
            ),
        )


class BrokenValidation:
    def run(self, *, workspace, commands, cancellation):
        del workspace, commands, cancellation
        raise ValidationError(
            "VALIDATION_TIMEOUT",
            "synthetic timeout",
        )


class FakeRegistry:
    def __init__(self) -> None:
        self.reservations = []
        self.seals = []
        self.candidate_events = []

    def reserve_runtime_artifact(self, **arguments):
        self.reservations.append(arguments)
        return "ra1_" + chr(65 + len(self.reservations)) * 43

    def seal_runtime_artifact(self, artifact_id, *, terminal):
        self.seals.append((artifact_id, terminal))
        return {"state": "TERMINAL"}

    def register_quarantine_repository(self, **arguments):
        self.candidate_events.append(("repository", arguments))
        return "qr1_" + "A" * 43

    def begin_candidate_publication(self, **arguments):
        self.candidate_events.append(("intent", arguments))
        return "cpi1_" + "B" * 43

    def complete_candidate_publication(self, intent_id, **arguments):
        self.candidate_events.append(
            ("complete", {"intentId": intent_id, **arguments})
        )
        return True


class TrackingQuarantine:
    def __init__(self, delegate, events, *, mutate_ref=False) -> None:
        self.delegate = delegate
        self.events = events
        self.mutate_ref = mutate_ref
        self.candidate = None
        self.materializations = 0

    def __getattr__(self, name):
        return getattr(self.delegate, name)

    def publish_candidate(self, candidate):
        self.candidate = candidate
        self.events.append(("publish", {"ref": candidate.ref}))
        return self.delegate.publish_candidate(candidate)

    def materialize(self, revision, destination):
        result = self.delegate.materialize(revision, destination)
        self.materializations += 1
        if self.mutate_ref and self.materializations == 2:
            evidence = self.delegate.candidate_evidence(self.candidate.ref)
            subprocess.run(
                [
                    "/usr/bin/git",
                    f"--git-dir={self.delegate.git_dir}",
                    "update-ref",
                    self.candidate.ref,
                    evidence.parent_sha,
                    self.candidate.commit_sha,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        return result


class TrackingQuarantineFactory:
    def __init__(self, events, *, mutate_ref=False) -> None:
        self.events = events
        self.mutate_ref = mutate_ref

    def __call__(self, state_root, repository):
        return TrackingQuarantine(
            QuarantineRepository.for_source(state_root, repository),
            self.events,
            mutate_ref=self.mutate_ref,
        )


class WriterExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        git(self.repository, "init", "-q")
        git(self.repository, "config", "user.name", "Writer Test")
        git(self.repository, "config", "user.email", "writer@example.invalid")
        (self.repository / "tracked.txt").write_text("base\n", encoding="utf-8")
        git(self.repository, "add", "tracked.txt")
        git(self.repository, "commit", "-qm", "base")
        self.base_sha = git(self.repository, "rev-parse", "HEAD")
        for name in ("runtime", "validation", "quarantine"):
            (self.root / name).mkdir(mode=0o700)
        self.schema = self.root / "writer.schema.json"
        self.schema.write_text(
            json.dumps(WRITER_RESULT_SCHEMA, sort_keys=True),
            encoding="utf-8",
        )
        self.schema.chmod(0o400)
        self.codex = self.root / "codex"
        self.codex.write_text("#!/bin/sh\n", encoding="utf-8")
        self.codex.chmod(0o700)
        self.worker = FakeWriterWorker()
        self.validation = MutatingValidation()
        self.registry = FakeRegistry()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def node(self, **overrides) -> NodeRecord:
        values = {
            "route_id": "rt1_" + "A" * 43,
            "node_id": "writer_a",
            "ordinal": 1,
            "role": "implementer",
            "mission": "Измени tracked.txt.",
            "dependencies": (),
            "context_refs": (),
            "scope_id": "scope_default",
            "artifact_profile_id": "artifact_patch",
            "validation_profile_id": "validation_python",
            "assessment": {},
            "risk_flags": ("writer_final_validation",),
            "selected_model": "gpt-5.6-sol",
            "reasoning_effort": "max",
            "permission_profile_id": "permission_writer",
            "disposition": "delegate",
            "state": RouteState.RUNNING,
            "result": None,
        }
        values.update(overrides)
        return NodeRecord(**values)

    def request(self, current: NodeRecord | None = None) -> NodeExecutionRequest:
        selected = current or self.node()
        return NodeExecutionRequest(
            route_id=selected.route_id,
            context=RequestContext(
                shell_session_id="shell-1",
                session_id="session-1",
                turn_id="turn-1",
                codex_home="/Users/test/.codex",
                repo_root=str(self.repository),
                base_sha=self.base_sha,
                worktree_fingerprint="b" * 64,
            ),
            node=selected,
            dependency_results={},
        )

    def executor(
        self,
        worker=None,
        validation=None,
        quarantine_factory=None,
    ) -> WriterNodeExecutor:
        return WriterNodeExecutor(
            worker=worker or self.worker,
            config=WriterExecutorConfig(
                runtime_parent=self.root / "runtime",
                validation_parent=self.root / "validation",
                quarantine_state_root=self.root / "quarantine",
                codex_executable=self.codex,
                codex_version="0.144.4",
                writer_permission_profile_id="permission_writer",
                writer_permission_profile_name="adaptive_writer",
                managed_config_sha256="c" * 64,
                output_schema=self.schema,
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
                max_files=100,
                max_file_bytes=1024 * 1024,
                max_total_bytes=8 * 1024 * 1024,
                validation_commands={
                    "validation_python": (("/usr/bin/true",),),
                },
            ),
            validation_runner=validation or self.validation,
            receiver_factory=FakeReceiver,
            attestation=FakeAttestor(),
            artifact_registry=self.registry,
            quarantine_factory=(
                quarantine_factory
                if quarantine_factory is not None
                else QuarantineRepository.for_source
            ),
        )

    def test_builds_independent_candidate_and_rechecks_after_validation_mutation(
        self,
    ) -> None:
        outcome = self.executor().execute(
            self.request(),
            threading.Event(),
        )

        self.assertEqual("candidate\n", self.validation.before)
        self.assertEqual("base\n", (self.repository / "tracked.txt").read_text())
        self.assertTrue(outcome.artifact_id.startswith("art1_"))
        self.assertEqual("passed", outcome.validation_state)
        self.assertEqual(
            {
                "inputTokens": 20,
                "cachedInputTokens": 3,
                "outputTokens": 8,
                "reasoningOutputTokens": 2,
            },
            outcome.usage,
        )
        self.assertEqual("Кандидат подготовлен.", outcome.summary)
        self.assertEqual(3, len(self.registry.reservations))
        self.assertEqual(
            ["writer_runtime", "validation_runtime", "validation_proof"],
            [item["kind"] for item in self.registry.reservations],
        )
        self.assertEqual(3, len(self.registry.seals))
        quarantine_dirs = list((self.root / "quarantine" / "quarantine").glob("*.git"))
        self.assertEqual(1, len(quarantine_dirs))
        fsck = subprocess.run(
            [
                "/usr/bin/git",
                f"--git-dir={quarantine_dirs[0]}",
                "fsck",
                "--strict",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(0, fsck.returncode, fsck.stderr)

    def test_records_publication_intent_before_ref_and_finalizes_proof(
        self,
    ) -> None:
        events = self.registry.candidate_events
        outcome = self.executor(
            quarantine_factory=TrackingQuarantineFactory(events),
        ).execute(
            self.request(),
            threading.Event(),
        )

        names = [name for name, _payload in events]
        self.assertEqual(
            ["repository", "intent", "publish", "complete"],
            names,
        )
        completion = events[-1][1]
        self.assertEqual("passed", completion["validation_state"])
        self.assertRegex(completion["proof_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(outcome.fingerprint, completion["proof_hash"])

    def test_ref_change_after_validation_is_not_finalized_as_trusted(
        self,
    ) -> None:
        events = self.registry.candidate_events

        with self.assertRaisesRegex(
            NodeExecutionError,
            "CANDIDATE_IDENTITY_CHANGED",
        ):
            self.executor(
                quarantine_factory=TrackingQuarantineFactory(
                    events,
                    mutate_ref=True,
                ),
            ).execute(
                self.request(),
                threading.Event(),
            )

        self.assertEqual(
            ["repository", "intent", "publish"],
            [name for name, _payload in events],
        )

    def test_source_change_and_unknown_validation_fail_before_acceptance(self) -> None:
        with self.assertRaisesRegex(
            NodeExecutionError,
            "SOURCE_CHANGED_DURING_WRITER",
        ):
            self.executor(FakeWriterWorker(mutate_source=True)).execute(
                self.request(),
                threading.Event(),
            )

        git(self.repository, "checkout", "-q", "--", "tracked.txt")
        unknown = self.node(validation_profile_id="validation_unknown")
        worker = FakeWriterWorker()
        with self.assertRaisesRegex(
            NodeExecutionError,
            "VALIDATION_PROFILE_UNKNOWN",
        ):
            self.executor(worker).execute(
                self.request(unknown),
                threading.Event(),
            )
        self.assertEqual([], worker.requests)

    def test_validation_infrastructure_failure_preserves_quarantined_artifact(
        self,
    ) -> None:
        outcome = self.executor(
            validation=BrokenValidation(),
        ).execute(
            self.request(),
            threading.Event(),
        )

        self.assertTrue(outcome.artifact_id.startswith("art1_"))
        self.assertEqual("quarantined", outcome.validation_state)
        self.assertEqual(
            "VALIDATION_TIMEOUT",
            outcome.attestation["validationErrorCode"],
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    GatewayRuntimeBindingV2,
)
from codex_smart_subagents.child_launch_coordinator_v2 import (  # noqa: E402
    ProcessObservationV2,
    SnapshotObservationV2,
)
from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    GuardExecConfirmationV2,
    GuardExecutionResultV2,
    GuardHelloV2,
)
from codex_smart_subagents.child_launch_v2 import (  # noqa: E402
    cleanup_prepared_child_launch_v2,
)
from codex_smart_subagents.child_runner import (  # noqa: E402
    ChildTelemetryConfig,
)
from codex_smart_subagents.execution_dispatcher_v2 import (  # noqa: E402
    ExecutionDispatcherV2,
)
from codex_smart_subagents.policy_bundle_v2 import (  # noqa: E402
    load_policy_bundle_v2,
)
from codex_smart_subagents.production_dispatcher_v2 import (  # noqa: E402
    ProductionDispatcherDependenciesV2,
    ProductionDispatcherV2Error,
    ProductionLaunchPreparerV2,
    build_production_dispatcher_factory_v2,
)
from codex_smart_subagents.snapshot import (  # noqa: E402
    SnapshotResult,
    SourceManifest,
)
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    AdmissionV2,
    AttemptLaunchIdentityV2,
    CommittedLaunchV2,
    LaunchPermitV2,
    NodePlanV2,
    PlannedNodeV2,
    RequestContextV2,
    StartRequestV2,
)
from codex_smart_subagents.telemetry import RunAttestation  # noqa: E402
from codex_smart_subagents.writer_publication_v2 import (  # noqa: E402
    WriterPublicationCoordinatorV2,
    WriterPublicationResultV2,
)


_CLEAN = hashlib.sha256(b"").hexdigest()


class _AttemptResource:
    def __init__(self, *, close_failures: int = 0) -> None:
        self.closed = False
        self.close_failures = close_failures
        self.close_calls = 0
        self.telemetry_config = ChildTelemetryConfig(
            endpoint="http://127.0.0.1:4318/v1/logs",
            header_name="X-Codex-Token",
            token="test-token-123456",
        )

    def attest(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("attest is outside this preparation test")

    def close(self) -> None:
        self.close_calls += 1
        if self.close_calls <= self.close_failures:
            raise RuntimeError("transient receiver close failure")
        self.closed = True


class _RuntimeArtifactStore:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, object]] = {}
        self.transitions: list[tuple[str, str]] = []

    def reserve_runtime_artifact(self, **arguments: object) -> str:
        artifact_id = "ra2_" + f"{len(self.records) + 1:032x}"
        self.records[artifact_id] = {
            "artifactId": artifact_id,
            "routeId": arguments["route_id"],
            "nodeId": arguments["node_id"],
            "kind": arguments["kind"],
            "path": str(arguments["path"]),
            "allowedRoot": str(arguments["allowed_root"]),
            "state": "RESERVED",
            "device": None,
            "inode": None,
        }
        self.transitions.append((artifact_id, "RESERVED"))
        return artifact_id

    def seal_runtime_artifact(
        self, artifact_id: str, *, terminal: bool
    ) -> dict[str, object]:
        record = self.records[artifact_id]
        path = Path(str(record["path"]))
        if path.exists():
            metadata = path.stat()
            record["state"] = "TERMINAL" if terminal else "ACTIVE"
            record["device"] = metadata.st_dev
            record["inode"] = metadata.st_ino
        else:
            record["state"] = "MISSING"
            record["device"] = None
            record["inode"] = None
        self.transitions.append((artifact_id, str(record["state"])))
        return dict(record)

    def runtime_artifacts(self) -> list[dict[str, object]]:
        return [dict(item) for item in self.records.values()]


class _SnapshotBuilder:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, str, Path]] = []

    def build(
        self,
        *,
        repository: Path,
        base_sha: str,
        destination: Path,
        deadline_at: datetime,
    ) -> SnapshotResult:
        if deadline_at.tzinfo is None:
            raise AssertionError("snapshot deadline must be timezone-aware")
        self.calls.append((repository, base_sha, destination))
        destination.mkdir(mode=0o700)
        source_file = destination / "README.md"
        source_file.write_text("snapshot\n", encoding="utf-8")
        source_file.chmod(0o444)
        destination.chmod(0o555)
        manifest = SourceManifest(
            head_sha=base_sha,
            status_sha256=_CLEAN,
            refs_sha256="1" * 64,
            worktrees_sha256="2" * 64,
            git_control_sha256="3" * 64,
        )
        return SnapshotResult(
            root=destination,
            base_sha=base_sha,
            file_count=1,
            total_bytes=9,
            manifest_sha256="4" * 64,
            source_before=manifest,
            source_after=manifest,
        )


class _WriterCoordinator(WriterPublicationCoordinatorV2):
    def __init__(self, snapshot_builder: _SnapshotBuilder) -> None:
        self.snapshot_builder = snapshot_builder
        self.completed = 0

    def prepare(self, request):
        request.attempt_root.mkdir(mode=0o700)
        snapshot = self.snapshot_builder.build(
            repository=request.repository,
            base_sha=request.base_sha,
            destination=request.attempt_root / "snapshot",
            deadline_at=request.deadline_at,
        )
        workspace = request.attempt_root / "workspace"
        workspace.mkdir(mode=0o700)
        return SimpleNamespace(
            request=request,
            snapshot=snapshot,
            workspace=SimpleNamespace(root=workspace),
        )

    def complete(self, session, *, cancellation):
        del session, cancellation
        self.completed += 1
        return WriterPublicationResultV2(
            state="VERIFIED",
            validation_state="passed",
            error_code=None,
            artifact_id="art2_" + "a" * 43,
            ref="refs/codex-smart/candidates/art2_fixture",
            commit_sha="b" * 40,
            tree_sha="c" * 40,
            base_commit_sha="d" * 40,
            ref_published=True,
            proof_hash="e" * 64,
            validation=None,
        )


class _Provider:
    def __init__(self, binding: GatewayRuntimeBindingV2) -> None:
        self.binding = binding

    def runtime_binding(self) -> GatewayRuntimeBindingV2:
        return self.binding

    def activation_gate(self) -> dict[str, object]:
        return {
            "manifestSemanticFingerprint": "5" * 64,
            "activationReceiptFingerprint": "6" * 64,
            "journalAbsenceProof": {},
            "gateFingerprint": "7" * 64,
        }


class _VerticalAttemptResource(_AttemptResource):
    def attest(
        self,
        prepared: object,
        events: list[dict[str, object]],
        permission_probe_id: str,
    ) -> RunAttestation:
        if events[0]["type"] != "thread.started":
            raise AssertionError("unexpected child event sequence")
        return RunAttestation(
            cli_version=prepared.expected_cli_version,
            requested_model=prepared.model,
            observed_model=prepared.model,
            requested_effort=prepared.reasoning_effort,
            observed_effort=prepared.reasoning_effort,
            conversation_hash="6" * 64,
            argv_fingerprint=prepared.argv_fingerprint,
            permission_probe_id=permission_probe_id,
            run_fingerprint="7" * 64,
        )


class _SharedBarrier:
    def __init__(self) -> None:
        self.depth = 0
        self.trace: list[str] = []

    @contextmanager
    def __call__(self):
        if self.depth != 0:
            raise AssertionError("shared barrier was entered recursively")
        self.depth = 1
        self.trace.append("enter")
        try:
            yield
        finally:
            self.depth = 0
            self.trace.append("exit")


class _VerticalService:
    def __init__(self, *, barrier: _SharedBarrier, start: StartRequestV2) -> None:
        self.barrier = barrier
        self.start = start
        self.calls: list[str] = []

    def process_account_evidence(self, **arguments: object) -> AdmissionV2:
        self.calls.append("evidence")
        if self.barrier.depth != 0:
            raise AssertionError("evidence collection retained the launch barrier")
        admission_barrier = arguments["admission_barrier"]
        with admission_barrier():
            if self.barrier.depth != 1:
                raise AssertionError("admit transition escaped the shared barrier")
            self.calls.append("admit")
        return AdmissionV2(
            admission_id="adm2_" + "0" * 32,
            start_request_id=self.start.start_request_id,
            evidence_job_id=self.start.evidence_job_id,
            route_id=self.start.route_id,
            node_id=self.start.node_id,
            activation_gate_fingerprint="7" * 64,
            state="ADMITTED",
        )


class _VerticalGuardHandle:
    def __init__(
        self,
        *,
        prepared: object,
        permit_id: str,
        token: str,
        barrier: _SharedBarrier,
    ) -> None:
        self.prepared = prepared
        self.permit_id = permit_id
        self.token = token
        self.barrier = barrier
        self.committed = False

    def receive_hello(self, timeout_seconds: float) -> GuardHelloV2:
        del timeout_seconds
        return GuardHelloV2(
            protocol_version=2,
            permit_id=self.permit_id,
            one_time_token=self.token,
            pid=4101,
            process_start_marker="pid-4101-start",
            argv_fingerprint=self.prepared.argv_fingerprint,
            snapshot_identity_fingerprint=(self.prepared.snapshot_identity_fingerprint),
        )

    def authorize_commit(
        self,
        one_time_token: str,
        timeout_seconds: float,
    ) -> GuardExecConfirmationV2:
        del timeout_seconds
        if one_time_token != self.token:
            raise AssertionError("coordinator changed the guard token")
        self.committed = True
        return GuardExecConfirmationV2(
            pid=4101,
            process_start_marker="pid-4101-start",
        )

    def collect(
        self,
        stdin: bytes,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> GuardExecutionResultV2:
        del timeout_seconds, max_output_bytes
        if not self.committed or self.barrier.depth != 0 or not stdin:
            raise AssertionError("mission crossed a forbidden launch boundary")
        return GuardExecutionResultV2(
            exit_code=0,
            stdout=(
                b'{"type":"thread.started","thread_id":"thread-1"}\n'
                b'{"type":"turn.completed","usage":{}}\n'
            ),
            stderr=b"",
        )

    def abort(self) -> None:
        return None


class _VerticalGuardFactory:
    def __init__(self, barrier: _SharedBarrier) -> None:
        self.barrier = barrier

    def start(
        self,
        prepared: object,
        *,
        permit_id: str,
        one_time_token: str,
        snapshot_probe: object,
    ) -> _VerticalGuardHandle:
        del snapshot_probe
        if self.barrier.depth != 1:
            raise AssertionError("guard start escaped the shared barrier")
        return _VerticalGuardHandle(
            prepared=prepared,
            permit_id=permit_id,
            token=one_time_token,
            barrier=self.barrier,
        )


class _VerticalStore(_RuntimeArtifactStore):
    def __init__(
        self,
        *,
        barrier: _SharedBarrier,
        start: StartRequestV2,
        plan: NodePlanV2,
    ) -> None:
        super().__init__()
        self.barrier = barrier
        self.start = start
        self.plan = plan
        self.calls: list[str] = []
        self.commit_arguments: dict[str, object] = {}
        self.terminal_state: str | None = None

    def read_start_request(
        self,
        start_request_id: str,
        request_context: RequestContextV2,
    ) -> StartRequestV2:
        del request_context
        if start_request_id != self.start.start_request_id:
            raise AssertionError("dispatcher changed start request identity")
        self.calls.append("read_start")
        return self.start

    def read_node_plan(
        self,
        route_id: str,
        node_id: str,
        request_context: RequestContextV2,
    ) -> NodePlanV2:
        del request_context
        if (route_id, node_id) != (self.plan.route_id, self.plan.node_id):
            raise AssertionError("execution changed plan identity")
        self.calls.append("read_plan")
        return self.plan

    def abort_admission_before_permit(self, **arguments: object) -> object:
        raise AssertionError(f"unexpected pre-permit abort: {arguments}")

    def _require_barrier(self) -> None:
        if self.barrier.depth != 1:
            raise AssertionError("durable launch transition escaped shared barrier")

    def reserve_launch_permit(self, **arguments: object) -> LaunchPermitV2:
        self._require_barrier()
        self.calls.append("reserve")
        return LaunchPermitV2(
            permit_id="lp2_" + "a" * 32,
            admission_id=str(arguments["admission_id"]),
            route_id=self.plan.route_id,
            node_id=self.plan.node_id,
            reserved_control_epoch=int(arguments["expected_control_epoch"]),
            activation_gate_fingerprint="7" * 64,
            permit_evidence_fingerprint="8" * 64,
            state="RESERVED",
        )

    def record_guard_hello(self, permit_id: str, **arguments: object) -> None:
        del permit_id, arguments
        self._require_barrier()
        self.calls.append("hello")

    def commit_launch_permit(self, **arguments: object) -> CommittedLaunchV2:
        self._require_barrier()
        self.calls.append("commit")
        self.commit_arguments = dict(arguments)
        return CommittedLaunchV2(
            permit_id="lp2_" + "a" * 32,
            attempt_id=self.start.attempt_id,
            route_id=self.plan.route_id,
            node_id=self.plan.node_id,
            permit_state="COMMIT_AUTHORIZED",
        )

    def read_attempt_launch_identity(
        self,
        attempt_id: str,
        request_context: RequestContextV2,
    ) -> AttemptLaunchIdentityV2:
        del request_context
        self._require_barrier()
        self.calls.append("identity")
        return AttemptLaunchIdentityV2(
            attempt_id=attempt_id,
            route_id=self.plan.route_id,
            node_id=self.plan.node_id,
            start_request_id=self.start.start_request_id,
            evidence_job_id=self.start.evidence_job_id,
            admission_id="adm2_" + "0" * 32,
            model=self.plan.node.selected_model,
            reasoning_effort=self.plan.node.reasoning_effort,
            permission_profile_id=self.plan.node.permission_profile_id,
            argv_fingerprint=str(self.commit_arguments["argv_fingerprint"]),
            snapshot_identity_fingerprint=str(
                self.commit_arguments["snapshot_identity_fingerprint"]
            ),
            compatibility_fingerprint=self.plan.compatibility_fingerprint,
            account_context_fingerprint=self.plan.account_context_fingerprint,
            pid=4101,
            process_start_marker="pid-4101-start",
            codex_binary_sha256=str(self.commit_arguments["codex_binary_sha256"]),
            state="STARTING",
        )

    def record_attempt_started(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        self._require_barrier()
        self.calls.append("started")
        return SimpleNamespace(state="RUNNING")

    def record_attempt_terminal(
        self,
        attempt_id: str,
        request_context: RequestContextV2,
        **arguments: object,
    ) -> object:
        del attempt_id, request_context
        if self.barrier.depth != 0:
            raise AssertionError("terminal result retained launch barrier")
        self.calls.append("terminal")
        self.terminal_state = str(arguments["state"])
        return SimpleNamespace(state=self.terminal_state)

    def abort_launch_permit_before_commit(
        self, *args: object, **kwargs: object
    ) -> None:
        raise AssertionError(f"unexpected launch abort: {args!r} {kwargs!r}")


class ProductionDispatcherV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="cspd2-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.state_home = self.root / "state"
        self.state_home.mkdir(mode=0o700)
        self.marketplace = self.root / "marketplace"
        schema_root = self.marketplace / "docs" / "contracts" / "schemas"
        schema_root.mkdir(parents=True, mode=0o700)
        for schema_name in (
            "boundary-result-v1.schema.json",
            "reader-result-v1.schema.json",
            "writer-result-v1.schema.json",
        ):
            source = ROOT / "docs" / "contracts" / "schemas" / schema_name
            target = schema_root / schema_name
            target.write_bytes(source.read_bytes())
            target.chmod(0o600)

        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.codex_home.chmod(0o755)
        auth = self.codex_home / "auth.json"
        auth.write_text('{"token":"private"}\n', encoding="utf-8")
        auth.chmod(0o600)
        self.repository = self.root / "repository"
        self.repository.mkdir(mode=0o700)

        self.executable = self.root / "codex-snapshot"
        self.executable.write_bytes(b"codex-snapshot-v2")
        self.executable.chmod(0o500)
        self.executable_sha = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        activation_fingerprint = "a" * 64
        activation_id = "act2_" + activation_fingerprint
        compatibility = "b" * 64
        self.binding = GatewayRuntimeBindingV2(
            activation_id=activation_id,
            activation_fingerprint=activation_fingerprint,
            compatibility_fingerprint=compatibility,
            control_epoch=9,
            state_home=self.state_home,
            marketplace_path=self.marketplace,
            database_path=self.state_home / "state.sqlite3",
            database_identity_row={
                "activation_id": activation_id,
                "activation_fingerprint": activation_fingerprint,
            },
            controller_row={
                "controller_identity": "c" * 64,
                "controller_pid": os.getpid(),
                "controller_process_start_marker": "controller-start",
                "activation_id": activation_id,
                "activation_fingerprint": activation_fingerprint,
                "compatibility_fingerprint": compatibility,
                "control_epoch": 9,
            },
            interface_evidence={
                "subject": {
                    "snapshotPath": str(self.executable),
                    "snapshotSha256": self.executable_sha,
                    "version": "codex-cli 0.144.6",
                }
            },
            activation_identity={
                "codexSnapshot": {
                    "absolutePath": str(self.executable),
                    "sha256": self.executable_sha,
                }
            },
        )
        self.provider = _Provider(self.binding)
        self.bundle = load_policy_bundle_v2(
            catalog_path=(
                ROOT
                / "plugins"
                / "codex-smart-subagents"
                / "config"
                / "adaptive-subagents.toml"
            ),
            routing_vector_path=ROOT / "docs/contracts/vectors/routing-policy-v2.json",
            delegation_vector_path=(
                ROOT / "docs/contracts/vectors/delegation-policy-v2.json"
            ),
            role_vector_path=ROOT / "docs/contracts/vectors/role-template-v1.json",
            child_profile_vector_path=(
                ROOT / "docs/contracts/vectors/child-profile-v1.json"
            ),
        )
        machine_schemas = {}
        for schema_name in (
            "boundary-result-v1",
            "reader-result-v1",
            "writer-result-v1",
        ):
            path = schema_root / f"{schema_name}.schema.json"
            machine_schemas[schema_name] = {
                "schemaId": schema_name,
                "schemaSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        self.binding = GatewayRuntimeBindingV2(
            **{
                **self.binding.__dict__,
                "interface_evidence": {
                    **dict(self.binding.interface_evidence),
                    "semantic": {
                        "childProfiles": dict(self.bundle.child_profile_fingerprints),
                        "machineSchemas": machine_schemas,
                    },
                },
            }
        )
        self.provider = _Provider(self.binding)
        self.schema_resolution = {
            "virtualRoot": "/private/schemas",
            "repositoryRoot": "docs/contracts/schemas",
        }
        self.snapshot_builder = _SnapshotBuilder()
        self.resources: list[_AttemptResource] = []
        self.resource_close_failures = 0
        self.artifact_store = _RuntimeArtifactStore()

    def _dependencies(self) -> ProductionDispatcherDependenciesV2:
        def resource_factory() -> _AttemptResource:
            resource = _AttemptResource(
                close_failures=self.resource_close_failures,
            )
            self.resources.append(resource)
            return resource

        return ProductionDispatcherDependenciesV2(
            launch_barrier=lambda: _NullContext(),
            fresh_permission_probe=lambda _prepared: "permission-proof-v2",
            codex_snapshot_probe=lambda _path, expected: SnapshotObservationV2(
                snapshot_sha256=expected,
                snapshot_identity_fingerprint="d" * 64,
            ),
            fresh_process_probe=lambda _prepared, _confirmation: (_ for _ in ()).throw(
                AssertionError("process proof is outside preparation tests")
            ),
            result_schema_resolution_provider=lambda _binding, _bundle: dict(
                self.schema_resolution
            ),
            bounded_snapshot_builder_factory=lambda _limits: self.snapshot_builder,
            guard_factory=SimpleNamespace(start=lambda *args, **kwargs: None),
            attempt_resource_factory=resource_factory,
            clock=lambda: datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc),
        )

    def _context(self) -> RequestContextV2:
        return RequestContextV2(
            shell_session_id="cas2_" + "s" * 32,
            session_id="session",
            turn_id="turn",
            codex_home=str(self.codex_home),
            repo_root=str(self.repository),
            base_sha="e" * 40,
            worktree_fingerprint=_CLEAN,
            activation_fingerprint=self.binding.activation_fingerprint,
            compatibility_fingerprint=self.binding.compatibility_fingerprint,
            issued_control_epoch=self.binding.control_epoch,
        )

    def _plan(
        self,
        *,
        role: str = "researcher",
        template_id: str = "researcher-v1",
        model: str = "gpt-5.6-terra",
        effort: str = "high",
        permission_profile_id: str = "codex-smart-reader",
    ) -> NodePlanV2:
        context_content = "Проверить производственный запуск"
        encoded_context = context_content.encode("utf-8")
        source_content = "Файл: production_dispatcher_v2.py"
        encoded_source = source_content.encode("utf-8")
        node = PlannedNodeV2(
            node_id="node2_" + "1" * 32,
            ordinal=0,
            role=role,
            mission="Проверить реализацию",
            dependencies=(),
            context_refs=("request", "source"),
            scope_id="scope",
            artifact_profile_id="artifact",
            validation_profile_id="validation",
            assessment={"q": 1, "p": 2, "v": 3, "o": 4},
            risk_flags=(),
            selected_model=model,
            reasoning_effort=effort,
            permission_profile_id=permission_profile_id,
            disposition="DELEGATE",
        )
        return NodePlanV2(
            route_id="route2_" + "2" * 32,
            node_id=node.node_id,
            plan_output={
                "nodes": [
                    {
                        "clientNodeId": "other_a",
                        "nodeId": "node2_" + "9" * 32,
                        "dependencyNodeIds": [],
                        "routingInput": {"roleTemplateId": "implementer-v1"},
                    },
                    {
                        "clientNodeId": "reader_a",
                        "nodeId": node.node_id,
                        "dependencyNodeIds": [],
                        "routingInput": {
                    "roleTemplateId": template_id,
                    "contextBundle": {
                        "schemaVersion": 1,
                        "contractVersion": "codex-context-bundle-v1",
                        "bundleId": "vertical-bundle",
                        "maxBytes": 4096,
                        "totalBytes": len(encoded_context) + len(encoded_source),
                        "entries": [
                            {
                                "contextRefId": "request",
                                "kind": "task-request",
                                "required": True,
                                "sourceEvidenceRefs": [
                                    {
                                        "evidenceRefId": "request",
                                        "evidenceSha256": "a" * 64,
                                    }
                                ],
                                "sha256": hashlib.sha256(encoded_context).hexdigest(),
                                "byteLength": len(encoded_context),
                                "content": context_content,
                            },
                            {
                                "contextRefId": "source",
                                "kind": "source-excerpt",
                                "required": True,
                                "sourceEvidenceRefs": [
                                    {
                                        "evidenceRefId": "source",
                                        "evidenceSha256": "b" * 64,
                                    }
                                ],
                                "sha256": hashlib.sha256(encoded_source).hexdigest(),
                                "byteLength": len(encoded_source),
                                "content": source_content,
                            },
                        ],
                            },
                        },
                    },
                ]
            },
            node=node,
            node_state="PLANNED",
            catalog_generation=self.bundle.bundle_fingerprint,
            algorithm_version=self.bundle.algorithm_version,
            compatibility_fingerprint=self.binding.compatibility_fingerprint,
            account_context_fingerprint="f" * 64,
        )

    def _preparer(self) -> ProductionLaunchPreparerV2:
        return ProductionLaunchPreparerV2(
            store=self.artifact_store,
            provider=self.provider,
            policy_bundle=self.bundle,
            binding=self.binding,
            environment={"CODEX_HOME": str(self.codex_home)},
            dependencies=self._dependencies(),
        )

    def _start(self, plan: NodePlanV2) -> StartRequestV2:
        return StartRequestV2(
            start_request_id="sr2_" + "3" * 32,
            evidence_job_id="aej2_" + "4" * 32,
            attempt_id="att2_" + "5" * 32,
            route_id=plan.route_id,
            node_id=plan.node_id,
            queue_position=0,
            deadline_at=datetime(2099, 7, 19, 12, 3, tzinfo=timezone.utc),
            state="ATTESTING",
        )

    def test_preparer_uses_plan_pair_and_builds_fresh_snapshot_per_request(
        self,
    ) -> None:
        preparer = self._preparer()
        plan = self._plan()

        first = preparer(plan, "Первое задание", self._context(), self._start(plan))
        cleanup_prepared_child_launch_v2(first)
        second_start = StartRequestV2(
            **{
                **self._start(plan).__dict__,
                "attempt_id": "att2_" + "6" * 32,
            }
        )
        second = preparer(plan, "Второе задание", self._context(), second_start)

        self.assertEqual("gpt-5.6-terra", first.model)
        self.assertEqual("high", first.reasoning_effort)
        self.assertEqual("codex-smart-reader", first.permission_profile_id)
        self.assertEqual("reader", first.role)
        self.assertEqual(2, len(self.snapshot_builder.calls))
        self.assertNotEqual(
            self.snapshot_builder.calls[0][2],
            self.snapshot_builder.calls[1][2],
        )
        for repository, base_sha, _destination in self.snapshot_builder.calls:
            self.assertEqual(self.repository, repository)
            self.assertEqual(self._context().base_sha, base_sha)
        self.assertIn("--model", first.argv)
        self.assertEqual(
            "gpt-5.6-terra",
            first.argv[first.argv.index("--model") + 1],
        )
        self.assertTrue(any("model_reasoning_effort" in value for value in first.argv))

        attempt_roots = [path.parent for *_prefix, path in self.snapshot_builder.calls]
        cleanup_prepared_child_launch_v2(second)
        self.assertTrue(all(not path.exists() for path in attempt_roots))
        self.assertTrue(all(resource.closed for resource in self.resources))
        self.assertEqual(
            ["RESERVED", "ACTIVE", "MISSING", "RESERVED", "ACTIVE", "MISSING"],
            [state for _artifact, state in self.artifact_store.transitions],
        )

    def test_preparer_accepts_historical_epoch_for_same_activation_owner(self) -> None:
        plan = self._plan()
        historical = RequestContextV2(
            **{
                **self._context().__dict__,
                "issued_control_epoch": self.binding.control_epoch - 1,
            }
        )

        prepared = self._preparer()(
            plan,
            "Восстановленное задание",
            historical,
            self._start(plan),
        )

        self.assertEqual(self.binding.activation_fingerprint, historical.activation_fingerprint)
        self.assertEqual(
            self.binding.compatibility_fingerprint,
            historical.compatibility_fingerprint,
        )
        cleanup_prepared_child_launch_v2(prepared)

    def test_changed_gateway_binding_is_rejected_before_snapshot(self) -> None:
        preparer = self._preparer()
        changed = GatewayRuntimeBindingV2(
            **{
                **self.binding.__dict__,
                "control_epoch": 10,
                "controller_row": {
                    **dict(self.binding.controller_row),
                    "control_epoch": 10,
                },
            }
        )
        self.provider.binding = changed

        with self.assertRaisesRegex(
            ProductionDispatcherV2Error,
            "ACTIVATION_BINDING_CHANGED",
        ):
            plan = self._plan()
            preparer(plan, "Задание", self._context(), self._start(plan))

        self.assertEqual([], self.snapshot_builder.calls)
        self.assertEqual([], self.resources)

    def test_writer_fails_closed_before_snapshot_without_publication_contract(
        self,
    ) -> None:
        preparer = self._preparer()
        writer_plan = self._plan(
            role="implementer",
            template_id="implementer-v1",
            permission_profile_id="codex-smart-writer",
        )

        with self.assertRaisesRegex(
            ProductionDispatcherV2Error,
            "WRITER_PUBLICATION_UNAVAILABLE",
        ):
            preparer(
                writer_plan,
                "Изменить файл",
                self._context(),
                self._start(writer_plan),
            )

        self.assertEqual([], self.snapshot_builder.calls)
        self.assertEqual([], self.resources)

    def test_writer_publication_factory_is_lazy_and_reader_does_not_call_it(
        self,
    ) -> None:
        factory_calls = 0

        def unavailable_factory(**_arguments: object) -> WriterPublicationCoordinatorV2:
            nonlocal factory_calls
            factory_calls += 1
            raise RuntimeError("managed configuration is unavailable")

        dependencies = self._dependencies()
        dependencies = ProductionDispatcherDependenciesV2(
            **{
                **dependencies.__dict__,
                "writer_publication_coordinator_factory": unavailable_factory,
                "writer_validation_commands_provider": (
                    lambda _plan, _bundle: (("/usr/bin/true",),)
                ),
            }
        )
        preparer = ProductionLaunchPreparerV2(
            store=self.artifact_store,
            provider=self.provider,
            policy_bundle=self.bundle,
            binding=self.binding,
            environment={"CODEX_HOME": str(self.codex_home)},
            dependencies=dependencies,
        )
        self.assertEqual(0, factory_calls)

        reader_plan = self._plan()
        prepared = preparer(
            reader_plan,
            "Прочитать файлы",
            self._context(),
            self._start(reader_plan),
        )
        self.assertEqual(0, factory_calls)
        cleanup_prepared_child_launch_v2(prepared)
        snapshot_calls = len(self.snapshot_builder.calls)
        resource_count = len(self.resources)

        writer_plan = self._plan(
            role="implementer",
            template_id="implementer-v1",
            permission_profile_id="codex-smart-writer",
        )
        with self.assertRaisesRegex(
            ProductionDispatcherV2Error,
            "WRITER_PUBLICATION_UNAVAILABLE",
        ):
            preparer(
                writer_plan,
                "Изменить файл",
                self._context(),
                self._start(writer_plan),
            )

        self.assertEqual(1, factory_calls)
        self.assertEqual(snapshot_calls, len(self.snapshot_builder.calls))
        self.assertEqual(resource_count, len(self.resources))
        self.assertTrue(all(resource.closed for resource in self.resources))

    def test_writer_uses_isolated_workspace_and_completion_owner(self) -> None:
        coordinator = _WriterCoordinator(self.snapshot_builder)
        factory_calls = 0

        def coordinator_factory(**_arguments: object) -> WriterPublicationCoordinatorV2:
            nonlocal factory_calls
            factory_calls += 1
            return coordinator

        dependencies = self._dependencies()
        dependencies = ProductionDispatcherDependenciesV2(
            **{
                **dependencies.__dict__,
                "writer_publication_coordinator_factory": coordinator_factory,
                "writer_validation_commands_provider": (
                    lambda _plan, _bundle: (("/usr/bin/true",),)
                ),
            }
        )
        preparer = ProductionLaunchPreparerV2(
            store=self.artifact_store,
            provider=self.provider,
            policy_bundle=self.bundle,
            binding=self.binding,
            environment={"CODEX_HOME": str(self.codex_home)},
            dependencies=dependencies,
        )
        self.assertEqual(0, factory_calls)
        plan = self._plan(
            role="implementer",
            template_id="implementer-v1",
            permission_profile_id="codex-smart-writer",
        )

        prepared = preparer(
            plan,
            "Изменить файл",
            self._context(),
            self._start(plan),
        )

        workspace = Path(prepared.environment["CODEX_ADAPTIVE_WORKSPACE_ROOT"])
        self.assertTrue(workspace.is_dir())
        self.assertEqual("writer", prepared.role)
        self.assertIsNotNone(prepared.completion)
        publication = prepared.completion.complete({"events": []})
        self.assertEqual("VERIFIED", publication["state"])
        self.assertEqual(1, coordinator.completed)
        self.assertEqual(1, factory_calls)
        cleanup_prepared_child_launch_v2(prepared)
        self.assertFalse(workspace.exists())

        repeated_start = StartRequestV2(
            **{
                **self._start(plan).__dict__,
                "attempt_id": "att2_" + "6" * 32,
            }
        )
        repeated = preparer(
            plan,
            "Изменить второй файл",
            self._context(),
            repeated_start,
        )
        self.assertEqual(1, factory_calls)
        cleanup_prepared_child_launch_v2(repeated)

    def test_context_mismatch_is_rejected_before_snapshot(self) -> None:
        preparer = self._preparer()
        context = RequestContextV2(
            **{
                **self._context().__dict__,
                "worktree_fingerprint": "9" * 64,
            }
        )

        with self.assertRaisesRegex(
            ProductionDispatcherV2Error,
            "WORKTREE_NOT_CLEAN",
        ):
            plan = self._plan()
            preparer(plan, "Задание", context, self._start(plan))

        self.assertEqual([], self.snapshot_builder.calls)

    def test_snapshot_failure_removes_only_new_attempt_tree(self) -> None:
        preparer = self._preparer()
        original_build = self.snapshot_builder.build

        def fail_after_materialization(**kwargs: object) -> SnapshotResult:
            original_build(**kwargs)
            raise RuntimeError("snapshot failed after materialization")

        self.snapshot_builder.build = fail_after_materialization  # type: ignore[method-assign]

        with self.assertRaisesRegex(RuntimeError, "snapshot failed"):
            plan = self._plan()
            preparer(plan, "Задание", self._context(), self._start(plan))

        attempts_root = self.state_home / "attempt-runtimes-v2"
        self.assertEqual([], list(attempts_root.iterdir()))
        self.assertEqual([], self.resources)

    def test_profile_and_schema_are_bound_to_interface_evidence(self) -> None:
        preparer = self._preparer()
        semantic = self.binding.interface_evidence["semantic"]
        semantic["childProfiles"]["reader"] = "9" * 64
        plan = self._plan()

        with self.assertRaisesRegex(
            ProductionDispatcherV2Error,
            "INTERFACE_CHILD_PROFILE_MISMATCH",
        ):
            preparer(plan, "Задание", self._context(), self._start(plan))

        self.assertEqual([], self.snapshot_builder.calls)

    def test_changed_schema_bytes_are_rejected_before_snapshot(self) -> None:
        preparer = self._preparer()
        schema = (
            self.marketplace / "docs/contracts/schemas/reader-result-v1.schema.json"
        )
        schema.write_bytes(schema.read_bytes() + b"\n")
        schema.chmod(0o600)
        plan = self._plan()

        with self.assertRaisesRegex(
            ProductionDispatcherV2Error,
            "RESULT_SCHEMA_FINGERPRINT_MISMATCH",
        ):
            preparer(plan, "Задание", self._context(), self._start(plan))

        self.assertEqual([], self.snapshot_builder.calls)

    def test_changed_machine_schema_fingerprint_is_rejected(self) -> None:
        preparer = self._preparer()
        machine_schemas = self.binding.interface_evidence["semantic"]["machineSchemas"]
        machine_schemas["reader-result-v1"]["schemaSha256"] = "8" * 64
        plan = self._plan()

        with self.assertRaisesRegex(
            ProductionDispatcherV2Error,
            "RESULT_SCHEMA_FINGERPRINT_MISMATCH",
        ):
            preparer(plan, "Задание", self._context(), self._start(plan))

    def test_changed_schema_resolution_is_rejected(self) -> None:
        preparer = self._preparer()
        self.schema_resolution["repositoryRoot"] = "another/schema/root"
        plan = self._plan()

        with self.assertRaisesRegex(
            ProductionDispatcherV2Error,
            "RESULT_SCHEMA_RESOLUTION_CHANGED",
        ):
            preparer(plan, "Задание", self._context(), self._start(plan))

        self.assertEqual([], self.snapshot_builder.calls)

    def test_other_policy_generation_is_rejected(self) -> None:
        preparer = self._preparer()
        plan = NodePlanV2(
            **{
                **self._plan().__dict__,
                "catalog_generation": "0" * 64,
            }
        )

        with self.assertRaisesRegex(
            ProductionDispatcherV2Error,
            "NODE_PLAN_BINDING_MISMATCH",
        ):
            preparer(plan, "Задание", self._context(), self._start(plan))

    def test_expired_request_is_rejected_before_snapshot(self) -> None:
        preparer = self._preparer()
        plan = self._plan()
        expired = StartRequestV2(
            **{
                **self._start(plan).__dict__,
                "deadline_at": datetime(
                    2026,
                    7,
                    19,
                    11,
                    59,
                    tzinfo=timezone.utc,
                ),
            }
        )

        with self.assertRaisesRegex(
            ProductionDispatcherV2Error,
            "REQUEST_DEADLINE_EXCEEDED",
        ):
            preparer(plan, "Задание", self._context(), expired)

        self.assertEqual([], self.snapshot_builder.calls)

    def test_cleanup_retries_only_unfinished_steps(self) -> None:
        self.resource_close_failures = 1
        preparer = self._preparer()
        plan = self._plan()
        prepared = preparer(plan, "Задание", self._context(), self._start(plan))
        attempt_root = self.snapshot_builder.calls[0][2].parent

        with self.assertRaisesRegex(Exception, "transient receiver close failure"):
            cleanup_prepared_child_launch_v2(prepared)
        self.assertFalse(attempt_root.exists())
        self.assertFalse(self.resources[0].closed)

        cleanup_prepared_child_launch_v2(prepared)
        self.assertTrue(self.resources[0].closed)
        self.assertEqual(2, self.resources[0].close_calls)

    def test_unknown_crash_leftover_fails_closed(self) -> None:
        attempts_root = self.state_home / "attempt-runtimes-v2"
        attempts_root.mkdir(mode=0o700)
        leftover = attempts_root / ("attempt-att2_" + "a" * 32)
        leftover.mkdir(mode=0o700)

        with self.assertRaisesRegex(
            ProductionDispatcherV2Error,
            "ATTEMPT_RECOVERY_REQUIRED",
        ):
            self._preparer()

        self.assertTrue(leftover.exists())

    def test_every_policy_pair_reaches_exact_child_arguments(self) -> None:
        preparer = self._preparer()
        for index, pair in enumerate(self.bundle.policy_pairs, start=1):
            with self.subTest(pair=pair):
                plan = self._plan(
                    model=pair["model"],
                    effort=pair["reasoningEffort"],
                )
                start = StartRequestV2(
                    **{
                        **self._start(plan).__dict__,
                        "attempt_id": f"att2_{index:x}" + f"{index:x}" * 31,
                    }
                )
                prepared = preparer(plan, "Задание", self._context(), start)
                self.assertEqual(pair["model"], prepared.model)
                self.assertEqual(
                    pair["reasoningEffort"],
                    prepared.reasoning_effort,
                )
                cleanup_prepared_child_launch_v2(prepared)

    def test_factory_returns_bounded_dispatcher_and_requires_real_proofs(
        self,
    ) -> None:
        dependencies = self._dependencies()
        factory = build_production_dispatcher_factory_v2(dependencies)
        service = SimpleNamespace(process_account_evidence=lambda **_kwargs: None)
        store = SimpleNamespace(
            read_start_request=lambda *_args: None,
            read_node_plan=lambda *_args: None,
            abort_admission_before_permit=lambda **_kwargs: None,
            reserve_runtime_artifact=self.artifact_store.reserve_runtime_artifact,
            seal_runtime_artifact=self.artifact_store.seal_runtime_artifact,
            runtime_artifacts=self.artifact_store.runtime_artifacts,
        )

        dispatcher = factory(
            service,
            store,
            self.provider,
            self.bundle,
            self.binding,
            {"CODEX_HOME": str(self.codex_home)},
        )
        self.addCleanup(dispatcher.close)

        self.assertIsInstance(dispatcher, ExecutionDispatcherV2)
        with self.assertRaises(TypeError):
            ProductionDispatcherDependenciesV2()  # type: ignore[call-arg]

    def test_dispatcher_runs_one_complete_attested_vertical_launch(self) -> None:
        barrier = _SharedBarrier()
        plan = self._plan()
        start = self._start(plan)
        store = _VerticalStore(barrier=barrier, start=start, plan=plan)
        service = _VerticalService(barrier=barrier, start=start)
        resources: list[_VerticalAttemptResource] = []
        asynchronous_errors: list[BaseException] = []

        def resource_factory() -> _VerticalAttemptResource:
            resource = _VerticalAttemptResource()
            resources.append(resource)
            return resource

        def process_probe(prepared: object, confirmation: object):
            return ProcessObservationV2(
                model=prepared.model,
                reasoning_effort=prepared.reasoning_effort,
                permission_profile_id=prepared.permission_profile_id,
                argv_fingerprint=prepared.argv_fingerprint,
                snapshot_identity_fingerprint=(prepared.snapshot_identity_fingerprint),
                compatibility_fingerprint=prepared.compatibility_fingerprint,
                account_context_fingerprint=(prepared.account_context_fingerprint),
                pid=confirmation.pid,
                process_start_marker=confirmation.process_start_marker,
                codex_binary_sha256=prepared.snapshot_sha256,
            )

        dependencies = ProductionDispatcherDependenciesV2(
            launch_barrier=barrier,
            fresh_permission_probe=lambda _prepared: "pc2_" + "a" * 32,
            codex_snapshot_probe=lambda _path, expected: SnapshotObservationV2(
                snapshot_sha256=expected,
                snapshot_identity_fingerprint="d" * 64,
            ),
            fresh_process_probe=process_probe,
            result_schema_resolution_provider=lambda _binding, _bundle: dict(
                self.schema_resolution
            ),
            bounded_snapshot_builder_factory=lambda _limits: self.snapshot_builder,
            guard_factory=_VerticalGuardFactory(barrier),
            attempt_resource_factory=resource_factory,
            clock=lambda: datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc),
            error_sink=lambda _identifier, error: asynchronous_errors.append(error),
            max_workers=1,
            max_pending=1,
        )
        dispatcher = build_production_dispatcher_factory_v2(dependencies)(
            service,
            store,
            self.provider,
            self.bundle,
            self.binding,
            {"CODEX_HOME": str(self.codex_home)},
        )
        self.addCleanup(dispatcher.close)

        self.assertTrue(dispatcher.submit(start.start_request_id, self._context()))
        self.assertTrue(dispatcher.wait_idle(10))

        self.assertEqual([], asynchronous_errors)
        self.assertEqual("SUCCEEDED", store.terminal_state)
        self.assertEqual(["evidence", "admit"], service.calls)
        self.assertEqual(
            [
                "read_start",
                "read_plan",
                "reserve",
                "hello",
                "commit",
                "identity",
                "started",
                "terminal",
            ],
            store.calls,
        )
        self.assertEqual(["enter", "exit", "enter", "exit"], barrier.trace)
        self.assertTrue(resources[0].closed)
        self.assertEqual([], list((self.state_home / "attempt-runtimes-v2").iterdir()))


class _NullContext:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *args: object) -> None:
        del args


if __name__ == "__main__":
    unittest.main()

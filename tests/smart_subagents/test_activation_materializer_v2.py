from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    ActivationResolver,
    GatewayLayout,
    GatewayState,
)
from codex_smart_subagents.activation_materializer_v2 import (  # noqa: E402
    ActivationMaterializationV2Error,
    ControllerCandidateV2,
    _CONFIG_CONTRACT_VECTOR_FILES,
    _MCP_RUNTIME_SCHEMA_FILES,
    _RUNTIME_SCHEMA_FILES,
    _RUNTIME_VECTOR_FILES,
    activate_materialized_v2,
    materialize_activation_v2,
)
from codex_smart_subagents import activation_materializer_v2  # noqa: E402
from codex_smart_subagents.canonical_json import domain_fingerprint  # noqa: E402
from codex_smart_subagents.codex_binary_snapshot import (  # noqa: E402
    SnapshotCommand,
    SnapshotCommandResult,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
)
from codex_smart_subagents.policy_bundle_v2 import load_policy_bundle_v2  # noqa: E402


class _Snapshotter:
    def __init__(self, snapshot_root: Path) -> None:
        self.snapshot_root = snapshot_root
        self.calls: list[str] = []

    def materialize(self, source_locator: str | os.PathLike[str]) -> dict[str, object]:
        source = Path(source_locator).absolute()
        self.calls.append(str(source))
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        destination = self.snapshot_root / digest / "codex"
        destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.snapshot_root.chmod(0o700)
        destination.parent.chmod(0o700)
        if not destination.exists():
            shutil.copyfile(source, destination)
            destination.chmod(0o500)
            os.utime(destination, ns=(1_000_000_000_000, 1_000_000_000_000))
        info = destination.stat()
        return {
            "snapshotSha256": digest,
            "snapshotPath": str(destination),
            "size": info.st_size,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "device": info.st_dev,
            "inode": info.st_ino,
            "mtimeNs": str(info.st_mtime_ns),
            "version": "codex-cli 0.144.6",
            "platform": "darwin",
            "architecture": "arm64",
            "signatureIdentifier": "codex",
            "teamIdentifier": "2DC432GLL2",
            "cdHash": "5" * 40,
            "sourceLocator": str(source),
            "sourceObservedSha256": digest,
        }


class _CoordinatorInspector:
    def inspect(self):
        return {"gpt-5.6-sol": frozenset({"medium"})}


class _InterfaceExecutor:
    def __init__(self) -> None:
        self.commands: list[SnapshotCommand] = []

    def run(self, command: SnapshotCommand) -> SnapshotCommandResult:
        self.commands.append(command)
        arguments = command.argv[1:]
        if arguments == ("debug", "models", "--bundled"):
            value = {
                "models": [
                    {
                        "slug": "gpt-5.6-sol",
                        "supported_reasoning_levels": [
                            {"effort": "max"},
                            {"effort": "xhigh"},
                            {"effort": "high"},
                        ],
                    },
                    {
                        "slug": "gpt-5.6-luna",
                        "supported_reasoning_levels": [
                            {"effort": "medium"},
                            {"effort": "low"},
                        ],
                    },
                    {
                        "slug": "gpt-5.6-terra",
                        "supported_reasoning_levels": [
                            {"effort": "xhigh"},
                            {"effort": "high"},
                            {"effort": "medium"},
                        ],
                    },
                ]
            }
            return SnapshotCommandResult(0, json.dumps(value).encode("utf-8"), b"")
        if arguments == ("app-server", "--help"):
            return SnapshotCommandResult(0, b"--strict-config --listen\n", b"")
        if arguments == ("exec", "--help"):
            return SnapshotCommandResult(
                0,
                (
                    b"--strict-config --model --skip-git-repo-check --ephemeral "
                    b"--ignore-user-config --ignore-rules --output-schema --json\n"
                ),
                b"",
            )
        raise AssertionError(f"unexpected probe command: {command.argv!r}")


class ActivationMaterializerV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="csam2-")
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.codex_binary = self.root / "codex-source"
        self.codex_binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.codex_binary.chmod(0o500)
        self.layout = GatewayLayout.for_codex_home(self.codex_home)
        self.state_home = self.codex_home / "state" / "codex-smart-subagents-v2"
        (self.codex_home / "state").mkdir(mode=0o700)
        self.state_home.mkdir(mode=0o700)
        self.socket_path = self.state_home / "controller.sock"
        self.controller_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.controller_socket.bind(str(self.socket_path))
        self.socket_path.chmod(0o600)
        self.wrapper = self.root / "codex-smart"
        self.wrapper.write_bytes(b"#!/bin/sh\n")
        self.wrapper.chmod(0o500)
        vectors = ROOT / "docs" / "contracts" / "vectors"
        self.policy = load_policy_bundle_v2(
            catalog_path=ROOT / ".codex" / "adaptive-subagents.toml",
            routing_vector_path=vectors / "routing-policy-v2.json",
            delegation_vector_path=vectors / "delegation-policy-v2.json",
            role_vector_path=vectors / "role-template-v1.json",
            child_profile_vector_path=vectors / "child-profile-v1.json",
        )
        self.snapshotter = _Snapshotter(self.layout.managed_root / "codex-snapshots")
        self.interface_executor = _InterfaceExecutor()
        self.candidate = ControllerCandidateV2(
            instance_id="ci2_" + "6" * 32,
            controller_start_id="cs2_" + "7" * 32,
            pid=os.getpid(),
            process_start_marker="materializer-test-process",
            process_group_id=os.getpgrp(),
            control_epoch=1,
            socket_path=self.socket_path,
            updated_at=datetime(2026, 7, 18, tzinfo=timezone.utc),
        )

    def test_private_file_copy_checks_shared_deadline_between_blocks(self) -> None:
        source = self.root / "large-source"
        target = self.root / "large-target"
        source.write_bytes(b"x" * (2 * 1024 * 1024 + 17))

        with mock.patch.object(
            activation_materializer_v2,
            "checkpoint_current_operation_deadline_if_scoped_v2",
            return_value=None,
        ) as checkpoint:
            activation_materializer_v2._copy_regular_file_with_deadline(
                source,
                target,
            )

        self.assertEqual(source.read_bytes(), target.read_bytes())
        self.assertGreaterEqual(checkpoint.call_count, 3)

    def test_snapshot_deadline_is_not_reclassified(self) -> None:
        original = OperationDeadlineExceededV2(
            code="ROOT_OPERATION_EXPIRED",
            operation="apply",
            phase="snapshot",
            deadline_kind="operation",
            configured_timeout_nanoseconds=1,
            elapsed_monotonic_nanoseconds=2,
        )
        with mock.patch.object(
            self.snapshotter,
            "materialize",
            side_effect=original,
        ):
            with self.assertRaises(OperationDeadlineExceededV2) as caught:
                self._materialize()

        self.assertIs(original, caught.exception)

    def test_interface_probe_deadline_is_not_reclassified(self) -> None:
        original = OperationDeadlineExceededV2(
            code="ROOT_OPERATION_EXPIRED",
            operation="apply",
            phase="interface-probe",
            deadline_kind="operation",
            configured_timeout_nanoseconds=1,
            elapsed_monotonic_nanoseconds=2,
        )
        with mock.patch.object(
            self.interface_executor,
            "run",
            side_effect=original,
        ):
            with self.assertRaises(OperationDeadlineExceededV2) as caught:
                self._materialize()

        self.assertIs(original, caught.exception)

    def tearDown(self) -> None:
        self.controller_socket.close()
        for path in sorted(
            self.root.rglob("*"),
            key=lambda item: len(item.parts),
        ):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)
        self.temporary.cleanup()

    def _materialize(self, *, source_root: Path = ROOT):
        return materialize_activation_v2(
            source_root=source_root,
            codex_home=self.codex_home,
            state_home=self.state_home,
            codex_binary=self.codex_binary,
            controller_candidate=self.candidate,
            policy_bundle=self.policy,
            coordinator_inspector_factory=lambda **_arguments: (
                _CoordinatorInspector()
            ),
            snapshotter=self.snapshotter,
            interface_executor=self.interface_executor,
            completed_at=datetime(2026, 7, 18, 0, 0, 1, tzinfo=timezone.utc),
        )

    def test_divergent_catalog_copies_fail_before_any_materialization(self) -> None:
        source_root = self.root / "divergent-source"
        catalog = source_root / ".codex" / "adaptive-subagents.toml"
        bundled = (
            source_root
            / "plugins"
            / "codex-smart-subagents"
            / "config"
            / "adaptive-subagents.toml"
        )
        catalog.parent.mkdir(parents=True)
        bundled.parent.mkdir(parents=True)
        catalog.write_bytes(b"canonical\n")
        bundled.write_bytes(b"divergent\n")

        with self.assertRaises(ActivationMaterializationV2Error) as captured:
            self._materialize(source_root=source_root)

        self.assertEqual("SOURCE_CATALOG_MISMATCH", captured.exception.code)
        self.assertFalse(self.layout.managed_root.exists())

    def test_generated_catalog_paths_fail_before_any_materialization(self) -> None:
        for reserved in (
            Path("config/contracts/extra.txt"),
            Path("config/bundled-catalog-v1.json"),
            Path("config/runtime-schemas/extra.schema.json"),
        ):
            with self.subTest(reserved=reserved):
                source_root = self.root / ("source-" + reserved.name)
                catalog = source_root / ".codex" / "adaptive-subagents.toml"
                bundled = (
                    source_root
                    / "plugins"
                    / "codex-smart-subagents"
                    / "config"
                    / "adaptive-subagents.toml"
                )
                catalog.parent.mkdir(parents=True)
                bundled.parent.mkdir(parents=True)
                catalog.write_bytes(b"canonical\n")
                bundled.write_bytes(catalog.read_bytes())
                generated = (
                    source_root / "plugins" / "codex-smart-subagents" / reserved
                )
                generated.parent.mkdir(parents=True, exist_ok=True)
                generated.write_bytes(b"not recoverable\n")

                with self.assertRaises(ActivationMaterializationV2Error) as captured:
                    self._materialize(source_root=source_root)

                self.assertEqual(
                    "SOURCE_GENERATED_PATH_CONFLICT", captured.exception.code
                )
                self.assertFalse(self.layout.managed_root.exists())

    def test_clean_materialization_reaches_only_the_live_health_boundary(self) -> None:
        result = self._materialize()

        self.assertEqual("CANDIDATE_MATERIALIZED", result.status)
        self.assertEqual("AWAITING_CONTROLLER_HEALTH", result.readiness)
        self.assertFalse((self.codex_home / "config.toml").exists())
        self.assertFalse(self.layout.journal_path.exists())
        for name in ("databases", "backups", "quarantine"):
            with self.subTest(retained_root=name):
                path = self.state_home / name
                self.assertTrue(path.is_dir())
                self.assertEqual(0o700, stat.S_IMODE(path.stat().st_mode))
        catalog_projection = json.loads(
            result.bundled_catalog_path.read_text(encoding="utf-8")
        )
        self.assertEqual(result.bundled_catalog, catalog_projection)
        self.assertEqual(0o500, stat.S_IMODE(result.activation_dir.stat().st_mode))
        for path in result.activation_dir.rglob("*"):
            with self.subTest(sealed_path=path.relative_to(result.activation_dir)):
                mode = stat.S_IMODE(path.lstat().st_mode)
                if path.is_dir():
                    self.assertEqual(0o500, mode)
                elif path.is_file():
                    self.assertIn(mode, {0o400, 0o500})
        helper = (
            result.activation_dir
            / "marketplace"
            / "plugins"
            / "codex-smart-subagents"
            / "scripts"
            / "prepare_smart_plan.py"
        )
        before = activation_materializer_v2._tree_sha256(result.activation_dir)
        completed = subprocess.run(
            [sys.executable, str(helper), "--help"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                key: value
                for key, value in os.environ.items()
                if key != "PYTHONDONTWRITEBYTECODE"
            },
        )
        self.assertEqual(0, completed.returncode, completed.stderr.decode())
        self.assertEqual(before, activation_materializer_v2._tree_sha256(result.activation_dir))
        self.assertFalse(any(result.activation_dir.rglob("__pycache__")))
        self.assertEqual(
            {
                "model": "gpt-5.6-sol",
                "reasoningEffort": "medium",
            },
            result.expected_health_payload["coordinatorSelection"][
                "selectedPair"
            ],
        )
        installed_routing_input = (
            result.activation_dir
            / "marketplace"
            / "plugins"
            / "codex-smart-subagents"
            / "config"
            / "contracts"
            / "routing-input-v2.json"
        )
        self.assertEqual(
            (
                ROOT / "docs" / "contracts" / "vectors" / "routing-input-v2.json"
            ).read_bytes(),
            installed_routing_input.read_bytes(),
        )
        self.assertEqual(3, len(self.interface_executor.commands))
        self.assertTrue(
            all(
                command.argv[0] == str(result.snapshot_path)
                for command in self.interface_executor.commands
            )
        )

        ordinary = ActivationResolver(
            layout=self.layout,
            wrapper=self.wrapper,
            snapshot_verifier=lambda _subject: None,
            controller_probe=lambda _path, _request: (_ for _ in ()).throw(
                RuntimeError("controller is not serving health")
            ),
        ).resolve()
        self.assertEqual(GatewayState.ORDINARY, ordinary.state)
        self.assertEqual(self.codex_binary, ordinary.executable)

        ready = activate_materialized_v2(
            materialization=result,
            wrapper=self.wrapper,
            snapshot_verifier=lambda _subject: None,
            controller_probe=lambda _path, request: self._health_response(
                result,
                request,
            ),
        )
        self.assertEqual(GatewayState.READY, ready.state)
        self.assertEqual(result.activation_id, ready.activation_id)

    def test_repeat_is_semantically_unchanged(self) -> None:
        first = self._materialize()
        manifest_before = self.layout.manifest_path.read_bytes()
        receipt_before = first.receipt_path.read_bytes()

        second = self._materialize()

        self.assertEqual("UNCHANGED", second.status)
        self.assertEqual(first.activation_id, second.activation_id)
        self.assertEqual(first.operation_id, second.operation_id)
        self.assertEqual(manifest_before, self.layout.manifest_path.read_bytes())
        self.assertEqual(receipt_before, second.receipt_path.read_bytes())

    def test_existing_materialization_preserves_exact_deadline_error(self) -> None:
        self._materialize()
        original = OperationDeadlineExceededV2(
            code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            operation="apply",
            phase="existing-materialization",
            deadline_kind="operation",
            configured_timeout_nanoseconds=1,
            elapsed_monotonic_nanoseconds=2,
        )

        with mock.patch.object(
            activation_materializer_v2,
            "connect_sqlite_with_deadline_v2",
            side_effect=original,
        ):
            with self.assertRaises(OperationDeadlineExceededV2) as caught:
                self._materialize()

        self.assertIs(original, caught.exception)

    def test_existing_manifest_does_not_hide_a_foreign_activation_link(self) -> None:
        self._materialize()
        self.layout.marketplace_link.symlink_to("activations/other/marketplace")

        with self.assertRaises(ActivationMaterializationV2Error) as captured:
            self._materialize()

        self.assertEqual("EXISTING_ACTIVATION_CONFLICT", captured.exception.code)

    def test_python_entrypoint_binding_rejects_interpreter_path_with_spaces(
        self,
    ) -> None:
        spaced_directory = Path(self.temporary.name) / "python runtime"
        spaced_directory.mkdir()
        interpreter = spaced_directory / "python3"
        interpreter.write_bytes(b"not executed\n")
        interpreter.chmod(0o700)
        bin_root = Path(self.temporary.name) / "bin"
        bin_root.mkdir()
        entrypoint = bin_root / "tool"
        entrypoint.write_bytes(b"#!/usr/bin/env python3\nprint('ok')\n")
        entrypoint.chmod(0o700)

        with (
            mock.patch.object(
                activation_materializer_v2.sys,
                "executable",
                str(interpreter),
            ),
            self.assertRaises(ActivationMaterializationV2Error) as captured,
        ):
            activation_materializer_v2._bind_python_entrypoints(bin_root)

        self.assertEqual("PYTHON_RUNTIME_INVALID", captured.exception.code)

    def test_runtime_schemas_are_exact_and_installed_mcp_is_self_contained(
        self,
    ) -> None:
        result = self._materialize()
        installed_marketplace = result.activation_dir / "marketplace"
        self.assertEqual(
            (ROOT / ".claude-plugin" / "marketplace.json").read_bytes(),
            (
                installed_marketplace / ".claude-plugin" / "marketplace.json"
            ).read_bytes(),
        )
        expected_shebang = f"#!{Path(sys.executable).resolve(strict=True)} -B\n".encode(
            "utf-8"
        )
        installed_bin = (
            installed_marketplace / "plugins" / "codex-smart-subagents" / "bin"
        )
        for entrypoint in sorted(installed_bin.iterdir()):
            if entrypoint.is_file() and entrypoint.stat().st_mode & stat.S_IXUSR:
                with self.subTest(entrypoint=entrypoint.name):
                    self.assertTrue(
                        entrypoint.read_bytes().startswith(expected_shebang),
                        entrypoint.name,
                    )
        names = set(_RUNTIME_SCHEMA_FILES)
        installed = installed_marketplace / "docs" / "contracts" / "schemas"
        cached = (
            installed_marketplace
            / "plugins"
            / "codex-smart-subagents"
            / "config"
            / "runtime-schemas"
        )

        self.assertEqual(names, {path.name for path in installed.iterdir()})
        for name in names:
            self.assertEqual(
                (ROOT / "docs" / "contracts" / "schemas" / name).read_bytes(),
                (installed / name).read_bytes(),
            )
        self.assertEqual(
            set(_MCP_RUNTIME_SCHEMA_FILES),
            {path.name for path in cached.iterdir()},
        )
        for name in _MCP_RUNTIME_SCHEMA_FILES:
            self.assertEqual(
                (ROOT / "docs" / "contracts" / "schemas" / name).read_bytes(),
                (cached / name).read_bytes(),
            )
        installed_vectors = installed_marketplace / "docs" / "contracts" / "vectors"
        self.assertEqual(
            set(_RUNTIME_VECTOR_FILES) | set(_CONFIG_CONTRACT_VECTOR_FILES),
            {path.name for path in installed_vectors.iterdir()},
        )
        for name in set(_RUNTIME_VECTOR_FILES) | set(_CONFIG_CONTRACT_VECTOR_FILES):
            self.assertEqual(
                (ROOT / "docs" / "contracts" / "vectors" / name).read_bytes(),
                (installed_vectors / name).read_bytes(),
            )

        definitions = self._installed_tool_definitions(result)
        self.assertEqual(
            ["smart_plan", "route_start", "smart_wait", "smart_cancel"],
            [item["name"] for item in definitions],
        )
        references: list[str] = []

        def collect(value):
            if type(value) is dict:
                if type(value.get("$ref")) is str:
                    references.append(value["$ref"])
                for child in value.values():
                    collect(child)
            elif type(value) is list:
                for child in value:
                    collect(child)

        collect(definitions)
        self.assertTrue(references)
        self.assertTrue(all(reference.startswith("#") for reference in references))
        routing = definitions[0]["inputSchema"]["properties"]["nodes"]["items"][
            "properties"
        ]["routingInput"]
        self.assertFalse(routing["additionalProperties"])
        plan_definitions = definitions[0]["inputSchema"]["$defs"]
        self.assertIn("external_context_bundle_v1_schema_json", plan_definitions)
        self.assertIn("smartPlanTaskFacts", plan_definitions)
        self.assertNotIn("external_task_facts_v1_schema_json", plan_definitions)
        self.assertEqual(
            [],
            list(
                (
                    installed_marketplace / "plugins" / "codex-smart-subagents" / "src"
                ).rglob("__pycache__")
            ),
        )

        with self.assertRaises(PermissionError):
            (installed / "context-bundle-v1.schema.json").unlink()
        self._installed_tool_definitions(result)
        mutable_activation = self.root / "mutable-activation-copy"
        shutil.copytree(result.activation_dir, mutable_activation)
        for path in mutable_activation.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
            elif path.is_file():
                path.chmod(0o500 if path.stat().st_mode & stat.S_IXUSR else 0o600)
        mutable_activation.chmod(0o700)
        (
            mutable_activation
            / "marketplace"
            / "plugins"
            / "codex-smart-subagents"
            / "config"
            / "runtime-schemas"
            / "context-bundle-v1.schema.json"
        ).unlink()
        failed = self._installed_tool_definitions(
            result,
            check=False,
            activation_dir=mutable_activation,
        )
        self.assertNotEqual(0, failed.returncode)
        self.assertIn("SCHEMA_DEPENDENCY_MISSING", failed.stderr)

    def test_materialized_marketplace_is_a_self_contained_installer_source(
        self,
    ) -> None:
        result = self._materialize()
        source_root = result.activation_dir / "marketplace"

        canonical_catalog = ROOT / ".codex" / "adaptive-subagents.toml"
        self.assertEqual(
            canonical_catalog.read_bytes(),
            (source_root / ".codex" / "adaptive-subagents.toml").read_bytes(),
        )
        self.assertEqual(
            canonical_catalog.read_bytes(),
            (
                source_root
                / "plugins"
                / "codex-smart-subagents"
                / "config"
                / "adaptive-subagents.toml"
            ).read_bytes(),
        )
        installer = source_root / "scripts" / "install_adaptive_subagents.py"
        self.assertEqual(
            (ROOT / "scripts" / "install_adaptive_subagents.py").read_bytes(),
            installer.read_bytes(),
        )
        self.assertEqual(0o500, stat.S_IMODE(installer.stat().st_mode))

    def test_materialized_capsule_source_rejects_runtime_schema_drift(
        self,
    ) -> None:
        result = self._materialize()
        source_root = result.activation_dir / "marketplace"
        cached = (
            source_root
            / "plugins"
            / "codex-smart-subagents"
            / "config"
            / "runtime-schemas"
        )
        schema = cached / _MCP_RUNTIME_SCHEMA_FILES[0]
        original = schema.read_bytes()
        extra = cached / "extra.schema.json"

        mutations = (
            (
                "changed",
                lambda: schema.write_bytes(original + b"\n"),
            ),
            (
                "extra",
                lambda: extra.write_bytes(b"{}\n"),
            ),
        )
        before = activation_materializer_v2._tree_sha256(result.activation_dir)
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                with self.assertRaises(PermissionError):
                    mutate()
                self.assertEqual(
                    before,
                    activation_materializer_v2._tree_sha256(result.activation_dir),
                )

    def test_manifest_tracks_immutable_artifacts_and_preserves_user_config(
        self,
    ) -> None:
        config = self.codex_home / "config.toml"
        config.write_bytes(b'model = "user-choice"\n')
        config.chmod(0o600)
        before = (config.read_bytes(), config.stat().st_mode)

        result = self._materialize()

        manifest = json.loads(self.layout.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(
            {
                str(result.activation_dir.relative_to(self.codex_home)),
                str(result.snapshot_path.relative_to(self.codex_home)),
                str(self.layout.fallback_path.relative_to(self.codex_home)),
                str(self.layout.lock_path.relative_to(self.codex_home)),
            },
            {item["relativePath"] for item in manifest["artifacts"]},
        )
        self.assertEqual(before, (config.read_bytes(), config.stat().st_mode))

    def test_missing_live_candidate_never_publishes_the_activation_gate(self) -> None:
        self.controller_socket.close()
        self.socket_path.unlink()

        with self.assertRaises(ActivationMaterializationV2Error) as captured:
            self._materialize()

        self.assertEqual("CONTROLLER_CANDIDATE_INVALID", captured.exception.code)
        self.assertFalse(self.layout.manifest_path.exists())
        self.assertFalse(self.layout.marketplace_link.exists())
        self.assertFalse(self.layout.receipts_root.exists())

    def _health_response(self, result, request: dict[str, object]):
        payload = copy.deepcopy(result.expected_health_payload)
        response = {
            "messageType": "response",
            "protocolVersion": 2,
            "release": "0.2.0",
            "method": "health",
            "responseKind": "HEALTH",
            "commandId": None,
            "requestFingerprint": request["requestFingerprint"],
            "controlEpoch": self.candidate.control_epoch,
            "payload": payload,
            "extensions": {},
        }
        response["responseFingerprint"] = domain_fingerprint(
            "codex-smart/controller-response/v2",
            {key: value for key, value in response.items() if key != "extensions"},
        )
        return response

    def _installed_tool_definitions(
        self,
        result,
        *,
        check: bool = True,
        activation_dir: Path | None = None,
    ):
        source = (
            (activation_dir or result.activation_dir)
            / "marketplace"
            / "plugins"
            / "codex-smart-subagents"
            / "src"
        )
        program = (
            "import json,sys;"
            "sys.path.insert(0,sys.argv[1]);"
            "from codex_smart_subagents.mcp_contracts_v2 import get_tool_definitions_v2;"
            "print(json.dumps(get_tool_definitions_v2(),sort_keys=True))"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-c", program, str(source)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if not check:
            return completed
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)


if __name__ == "__main__":
    unittest.main()

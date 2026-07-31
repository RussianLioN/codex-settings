from __future__ import annotations

import os
import copy
import fcntl
import hashlib
import io
import json
import shutil
import socket
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing, redirect_stderr
from pathlib import Path
from typing import Mapping, Sequence
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
PLUGIN_SCRIPTS = ROOT / "plugins" / "codex-smart-subagents" / "scripts"
sys.path.insert(0, str(PLUGIN_SRC))
sys.path.insert(0, str(PLUGIN_SCRIPTS))

from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    ActivationResolver,
    GatewayDecision,
    GatewayLayout,
    GatewayState,
    GatewayUnavailable,
    ManagedLaunchUnavailable,
    _ProofError,
    _read_owned_json,
    _refresh_absence_proof,
    _validate_original_backup,
    clean_ordinary_environment,
    refresh_activation_journal_absence_v2,
    require_pinned_controller_health_v2,
    run_permanent_gateway,
    v2_gateway_state_present,
)
from codex_smart_subagents import (  # noqa: E402
    activation_gateway_v2 as gateway_module,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.coordinator_selection_v2 import (  # noqa: E402
    CoordinatorSelectionV2,
    collect_coordinator_selection_v2,
)
from codex_smart_subagents.evidence import build_interface_evidence  # noqa: E402
from codex_smart_subagents.schema_projection import (  # noqa: E402
    APPLICATION_ID,
    database_schema_fingerprint,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    scoped_current_deadline_v2,
)
from integration_runtime_v2 import (  # noqa: E402
    HookTurnContextV2,
    IntegrationConfigV2,
    IntegrationV2Error,
    durable_smart_plan_exists_v2,
)


LIFECYCLE_SCHEMA_SHA256 = hashlib.sha256(
    (ROOT / "docs/contracts/schemas/lifecycle-projection-v2.schema.json").read_bytes()
).hexdigest()


class _GatewayDeadlineClock:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> int:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += int(seconds * 1_000_000_000)


class _StatOverride:
    def __init__(self, original: os.stat_result, **overrides: int) -> None:
        self._original = original
        self._overrides = overrides

    def __getattr__(self, name: str):
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._original, name)


def _write_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.write_bytes(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    path.chmod(mode)


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_sha256(root: Path) -> str:
    entries: list[dict[str, object]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        children = sorted(
            directory.iterdir(),
            key=lambda path: path.name.encode("utf-8"),
            reverse=True,
        )
        for child in children:
            info = child.lstat()
            relative = child.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                entries.append(
                    {
                        "path": relative,
                        "type": "symlink",
                        "mode": stat.S_IMODE(info.st_mode),
                        "target": os.readlink(child),
                    }
                )
            elif stat.S_ISDIR(info.st_mode):
                entries.append(
                    {
                        "path": relative,
                        "type": "directory",
                        "mode": stat.S_IMODE(info.st_mode),
                    }
                )
                pending.append(child)
            elif stat.S_ISREG(info.st_mode):
                entries.append(
                    {
                        "path": relative,
                        "type": "regular",
                        "mode": stat.S_IMODE(info.st_mode),
                        "size": info.st_size,
                        "sha256": _file_sha256(child),
                    }
                )
            else:
                raise AssertionError(f"unexpected fixture object: {child}")
    entries.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    return hashlib.sha256(canonical_json_bytes(entries)).hexdigest()


def _file_projection(path: Path) -> dict[str, object]:
    info = path.lstat()
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "linkCount": info.st_nlink,
        "size": info.st_size,
        "sha256": _file_sha256(path),
    }


def _tree_projection(path: Path) -> dict[str, object]:
    info = path.lstat()
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "entryCount": sum(1 for item in path.rglob("*") if not item.is_symlink()),
        "treeSha256": _tree_sha256(path),
    }


def _manifest_semantic_fingerprint(manifest: dict[str, object]) -> str:
    projection = {key: value for key, value in manifest.items() if key != "extensions"}
    return domain_fingerprint("codex-smart/manifest-semantic/v2", projection)


def _journal_projection(
    schema_id: str,
    value: dict[str, object],
) -> dict[str, object]:
    result = {
        "schemaId": schema_id,
        "schemaSha256": LIFECYCLE_SCHEMA_SHA256,
        "value": value,
    }
    result["valueFingerprint"] = domain_fingerprint(
        "codex-smart/journal-state/v2", result
    )
    return result


class _StaticResolver:
    def __init__(self, decision: GatewayDecision) -> None:
        self.decision = decision
        self.calls = 0

    def resolve(self) -> GatewayDecision:
        self.calls += 1
        return self.decision


class PermanentGatewayExecutionTests(unittest.TestCase):
    ADAPTIVE_DISABLED_FEATURE_ARGUMENTS = (
        "--disable",
        "multi_agent",
        "--disable",
        "multi_agent_v2",
        "--disable",
        "enable_fanout",
    )

    ADAPTIVE_DIRECT_TOOL_ARGUMENTS = (
        "-c",
        'code_mode.direct_only_tool_namespaces=["mcp__codex_smart_subagents"]',
    )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.wrapper = self.root / "codex-smart"
        self.wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
        self.wrapper.chmod(0o500)
        self.real = self.root / "codex"
        self.real.write_text("#!/bin/sh\n", encoding="utf-8")
        self.real.chmod(0o500)
        self.config_path = self.root / "config.toml"
        self.config_path.write_text(
            '[plugins."codex-smart-subagents@codex-settings-adaptive"]\n'
            "enabled = true\n",
            encoding="utf-8",
        )
        self.config_path.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _execute(
        self,
        decision: GatewayDecision,
        arguments: Sequence[str],
        environment: Mapping[str, str],
        *,
        managed_required: bool | None = None,
    ) -> tuple[str, tuple[str, ...], dict[str, str]]:
        observed: list[tuple[str, tuple[str, ...], dict[str, str]]] = []

        def expected_exec(
            path: str,
            argv: Sequence[str],
            environ: Mapping[str, str],
        ) -> object:
            observed.append((path, tuple(argv), dict(environ)))
            raise RuntimeError("expected exec")

        source_environment = dict(environment)
        source_environment.setdefault("CODEX_HOME", str(self.root))
        source_environment.setdefault("CODEX_REAL_BIN", str(self.real))
        gateway_options: dict[str, object] = {}
        if managed_required is not None:
            gateway_options["managed_required"] = managed_required
        resolver = _StaticResolver(decision)
        with self.assertRaisesRegex(RuntimeError, "expected exec"):
            run_permanent_gateway(
                arguments,
                resolver=resolver,
                wrapper=self.wrapper,
                environment=source_environment,
                execve=expected_exec,
                **gateway_options,
            )
        self._last_resolver_calls = resolver.calls
        self.assertEqual(1, len(observed))
        return observed[0]

    def _v2_decision(
        self,
        selection: CoordinatorSelectionV2,
    ) -> GatewayDecision:
        return GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.real,
            coordinator=(
                None
                if selection.selected_pair is None
                else {
                    "model": selection.selected_pair["model"],
                    "reasoning_effort": selection.selected_pair[
                        "reasoningEffort"
                    ],
                }
            ),
            coordinator_selection=selection.to_document(),
            catalog_schema_version=2,
            activation_id="act2_" + "a" * 64,
            gate_fingerprint="b" * 64,
            activation_gate={"gateFingerprint": "b" * 64},
            catalog_path=self.root / "adaptive-subagents.toml",
        )

    def test_automatic_unavailable_pair_is_always_managed_unavailable(self) -> None:
        decision = self._v2_decision(
            CoordinatorSelectionV2(
                selection="first-verified-available",
                status="UNAVAILABLE",
                reason_code="COORDINATOR_PAIR_UNAVAILABLE",
                selected_pair=None,
                candidate_index=None,
                account_catalog_fingerprint="5" * 64,
                account_context_fingerprint="6" * 64,
            )
        )
        executions: list[object] = []

        with self.assertRaises(ManagedLaunchUnavailable) as caught:
            run_permanent_gateway(
                ["проверь"],
                resolver=_StaticResolver(decision),
                wrapper=self.wrapper,
                environment={
                    "PATH": "/usr/bin",
                    "CODEX_HOME": str(self.root),
                },
                execve=lambda *_arguments: executions.append(object()),
            )

        self.assertEqual("COORDINATOR_PAIR_UNAVAILABLE", caught.exception.code)
        self.assertEqual([], executions)

    def test_explicit_root_controls_bypass_unavailable_automatic_pair(self) -> None:
        decision = self._v2_decision(
            CoordinatorSelectionV2(
                selection="first-verified-available",
                status="UNAVAILABLE",
                reason_code="COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
                selected_pair=None,
                candidate_index=None,
                account_catalog_fingerprint=None,
                account_context_fingerprint="6" * 64,
            )
        )
        original = [
            "--model",
            "gpt-user",
            "-c",
            'model_reasoning_effort="high"',
            "проверь",
        ]

        _path, argv, _environment = self._execute(
            decision,
            original,
            {"PATH": "/usr/bin"},
        )

        self.assertEqual(
            (
                str(self.real),
                *original,
                *self.ADAPTIVE_DIRECT_TOOL_ARGUMENTS,
                *self.ADAPTIVE_DISABLED_FEATURE_ARGUMENTS,
            ),
            argv,
        )

    def test_terra_fallback_warning_is_exact_and_printed_once_before_exec(
        self,
    ) -> None:
        decision = self._v2_decision(
            CoordinatorSelectionV2(
                selection="first-verified-available",
                status="SELECTED",
                reason_code="COORDINATOR_PAIR_SELECTED",
                selected_pair={
                    "model": "gpt-5.6-terra",
                    "reasoningEffort": "medium",
                },
                candidate_index=1,
                account_catalog_fingerprint="5" * 64,
                account_context_fingerprint="6" * 64,
            )
        )
        error = io.StringIO()

        with redirect_stderr(error):
            _path, _argv, _environment = self._execute(
                decision,
                ["проверь"],
                {"PATH": "/usr/bin"},
            )

        self.assertEqual(
            "codex-smart: COORDINATOR_PAIR_FALLBACK; "
            "gpt-5.6-sol+medium недоступен, "
            "используется gpt-5.6-terra+medium\n",
            error.getvalue(),
        )

    def test_ordinary_fallback_preserves_argv_and_removes_service_environment(self) -> None:
        decision = GatewayDecision(
            state=GatewayState.ORDINARY,
            reason_code="MANIFEST_INVALID",
            executable=self.real,
        )
        original = ["--model", "user-model", "проверь"]
        path, argv, environment = self._execute(
            decision,
            original,
            {
                "PATH": "/usr/bin",
                "CODEX_HOME": str(self.root),
                "CODEX_ADAPTIVE_SESSION_ID": "old",
                "CODEX_SMART_GATE_FINGERPRINT": "bad",
                "CODEX_SMART_REQUIRED": "1",
                "CODEX_REAL_BIN": "/wrong/codex",
                "CODEX_COORDINATOR_MODEL": "wrong",
            },
        )

        self.assertEqual(str(self.real), path)
        self.assertEqual((str(self.real), *original), argv)
        self.assertEqual("/usr/bin", environment["PATH"])
        self.assertEqual(str(self.root), environment["CODEX_HOME"])
        self.assertFalse(
            any(
                name.startswith("CODEX_SMART_")
                or name.startswith("CODEX_ADAPTIVE_")
                or name.startswith("CODEX_COORDINATOR_")
                or name == "CODEX_REAL_BIN"
                for name in environment
            )
        )

    def test_native_invocation_bypasses_damaged_gateway_state(self) -> None:
        layout = GatewayLayout.for_codex_home(self.root)
        layout.manifest_root.mkdir(mode=0o700)
        layout.managed_root.mkdir(mode=0o700)
        delegate = ActivationResolver(layout=layout, wrapper=self.wrapper)

        class TrackingResolver:
            def __init__(self) -> None:
                self.calls = 0

            def resolve(self) -> GatewayDecision:
                self.calls += 1
                return delegate.resolve()

        resolver = TrackingResolver()
        original = ["help", "--"]
        observed: list[tuple[str, tuple[str, ...], dict[str, str]]] = []

        def expected_exec(
            path: str,
            argv: Sequence[str],
            environ: Mapping[str, str],
        ) -> object:
            observed.append((path, tuple(argv), dict(environ)))
            raise RuntimeError("expected exec")

        with self.assertRaisesRegex(RuntimeError, "expected exec"):
            run_permanent_gateway(
                original,
                resolver=resolver,
                wrapper=self.wrapper,
                environment={
                    "PATH": "/usr/bin",
                    "CODEX_HOME": str(self.root),
                    "CODEX_REAL_BIN": str(self.real),
                    "CODEX_SMART_REQUIRED": "invalid",
                    "CODEX_ADAPTIVE_SESSION_ID": "stale",
                    "CODEX_COORDINATOR_MODEL": "stale",
                },
                execve=expected_exec,
            )

        self.assertEqual(0, resolver.calls)
        self.assertEqual(
            [
                (
                    str(self.real),
                    (str(self.real), *original),
                    {
                        "PATH": "/usr/bin",
                        "CODEX_HOME": str(self.root),
                    },
                )
            ],
            observed,
        )

        observed.clear()
        with (
            patch.object(
                gateway_module,
                "validate_real_binary",
                return_value=self.real,
            ) as validate,
            self.assertRaisesRegex(RuntimeError, "expected exec"),
        ):
            run_permanent_gateway(
                ["update"],
                resolver=resolver,
                wrapper=self.wrapper,
                environment={
                    "PATH": "/usr/bin",
                    "CODEX_HOME": str(self.root),
                    "CODEX_SMART_REQUIRED": "invalid",
                },
                execve=expected_exec,
            )

        validate.assert_called_once_with(
            Path("/opt/homebrew/bin/codex"),
            self.wrapper,
        )
        self.assertEqual(0, resolver.calls)
        self.assertEqual(
            [
                (
                    str(self.real),
                    (str(self.real), "update"),
                    {
                        "PATH": "/usr/bin",
                        "CODEX_HOME": str(self.root),
                    },
                )
            ],
            observed,
        )

        observed.clear()
        with self.assertRaisesRegex(RuntimeError, "REAL_CODEX_NOT_ABSOLUTE"):
            run_permanent_gateway(
                ["help"],
                resolver=resolver,
                wrapper=self.wrapper,
                environment={
                    "PATH": "/usr/bin",
                    "CODEX_HOME": str(self.root),
                    "CODEX_REAL_BIN": "relative/codex",
                },
                execve=expected_exec,
            )
        self.assertEqual(0, resolver.calls)
        self.assertEqual([], observed)

    def test_ultra_bypasses_gateway_without_a_resolver(self) -> None:
        original = [
            '-cmodel_reasoning_effort="ultra"',
            "--model",
            "user-model",
            "проверь",
        ]
        observed: list[tuple[str, tuple[str, ...], dict[str, str]]] = []

        def expected_exec(
            path: str,
            argv: Sequence[str],
            environ: Mapping[str, str],
        ) -> object:
            observed.append((path, tuple(argv), dict(environ)))
            raise RuntimeError("expected exec")

        with self.assertRaisesRegex(RuntimeError, "expected exec"):
            run_permanent_gateway(
                original,
                resolver=None,
                wrapper=self.wrapper,
                environment={
                    "PATH": "/usr/bin",
                    "CODEX_HOME": str(self.root),
                    "CODEX_REAL_BIN": str(self.real),
                    "CODEX_SMART_REQUIRED": "1",
                    "CODEX_SMART_GATE_FINGERPRINT": "stale",
                    "CODEX_ADAPTIVE_SESSION_ID": "stale",
                    "CODEX_COORDINATOR_MODEL": "stale",
                },
                managed_required=False,
                execve=expected_exec,
            )

        self.assertEqual(
            [
                (
                    str(self.real),
                    (str(self.real), *original),
                    {"PATH": "/usr/bin", "CODEX_HOME": str(self.root)},
                )
            ],
            observed,
        )

    def test_managed_invocation_without_resolver_fails_closed(self) -> None:
        with self.assertRaises(ManagedLaunchUnavailable) as raised:
            run_permanent_gateway(
                ["проверь"],
                resolver=None,
                wrapper=self.wrapper,
                environment={
                    "PATH": "/usr/bin",
                    "CODEX_HOME": str(self.root),
                    "CODEX_REAL_BIN": str(self.real),
                },
                execve=lambda *_arguments: self.fail("выполнен управляемый запуск"),
            )

        self.assertEqual("MANAGED_RESOLVER_UNAVAILABLE", raised.exception.code)

    def test_required_managed_ordinary_decision_fails_without_exec(self) -> None:
        decision = GatewayDecision(
            state=GatewayState.ORDINARY,
            reason_code="MANIFEST_INVALID",
            executable=self.real,
        )
        executions: list[object] = []

        with self.assertRaisesRegex(RuntimeError, "MANIFEST_INVALID"):
            run_permanent_gateway(
                ["проверь"],
                resolver=_StaticResolver(decision),
                wrapper=self.wrapper,
                environment={
                    "PATH": "/usr/bin",
                    "CODEX_HOME": str(self.root),
                    "CODEX_SMART_REQUIRED": "1",
                },
                managed_required=True,
                execve=lambda *_arguments: executions.append(object()),
            )

        self.assertEqual([], executions)

    def test_required_ordinary_reason_code_is_normalized(self) -> None:
        decision = GatewayDecision(
            state=GatewayState.ORDINARY,
            reason_code="invalid\nprivate diagnostic",
            executable=self.real,
        )

        with self.assertRaises(ManagedLaunchUnavailable) as raised:
            run_permanent_gateway(
                ["проверь"],
                resolver=_StaticResolver(decision),
                wrapper=self.wrapper,
                environment={
                    "PATH": "/usr/bin",
                    "CODEX_HOME": str(self.root),
                },
                managed_required=True,
                execve=lambda *_arguments: self.fail("ordinary Codex executed"),
            )

        self.assertEqual(
            "MANAGED_ACTIVATION_UNAVAILABLE",
            raised.exception.code,
        )
        self.assertNotIn("private diagnostic", str(raised.exception))

    def test_required_resolver_failure_becomes_managed_unavailable(self) -> None:
        class UnavailableResolver:
            def resolve(self):
                raise GatewayUnavailable(
                    "FALLBACK_UNAVAILABLE",
                    "private resolver details",
                )

        executions: list[object] = []
        with self.assertRaises(ManagedLaunchUnavailable) as raised:
            run_permanent_gateway(
                ["проверь"],
                resolver=UnavailableResolver(),
                wrapper=self.wrapper,
                environment={
                    "PATH": "/usr/bin",
                    "CODEX_HOME": str(self.root),
                    "CODEX_SMART_REQUIRED": "1",
                },
                managed_required=True,
                execve=lambda *_arguments: executions.append(object()),
            )

        self.assertEqual("FALLBACK_UNAVAILABLE", raised.exception.code)
        self.assertEqual([], executions)

    def test_ready_adds_atomic_coordinator_pair_only_without_explicit_choice(self) -> None:
        decision = GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.real,
            coordinator={
                "model": "gpt-5.6-terra",
                "reasoning_effort": "medium",
            },
            activation_id="act2_" + "a" * 64,
            gate_fingerprint="b" * 64,
            activation_gate={
                "manifestSemanticFingerprint": "c" * 64,
                "activationReceiptFingerprint": "d" * 64,
                "journalAbsenceProof": {},
                "gateFingerprint": "b" * 64,
            },
            catalog_path=self.root / "adaptive-subagents.toml",
        )

        _path, argv, environment = self._execute(
            decision,
            ["проверь"],
            {"PATH": "/usr/bin", "CODEX_SMART_LAUNCHER_ACTIVE": "stale"},
        )
        self.assertEqual(1, self._last_resolver_calls)
        self.assertEqual(
            (
                str(self.real),
                "проверь",
                "--model",
                "gpt-5.6-terra",
                "-c",
                'model_reasoning_effort="medium"',
                *self.ADAPTIVE_DIRECT_TOOL_ARGUMENTS,
                *self.ADAPTIVE_DISABLED_FEATURE_ARGUMENTS,
            ),
            argv,
        )
        self.assertEqual("1", environment["CODEX_SMART_LAUNCHER_ACTIVE"])
        self.assertEqual(str(self.wrapper), environment["CODEX_SMART_GATEWAY_PATH"])
        self.assertEqual(decision.activation_id, environment["CODEX_SMART_ACTIVATION_ID"])
        self.assertEqual(decision.gate_fingerprint, environment["CODEX_SMART_GATE_FINGERPRINT"])
        self.assertEqual(
            decision.activation_gate,
            json.loads(environment["CODEX_SMART_ACTIVATION_GATE"]),
        )
        self.assertIn("CODEX_SMART_MCP_SESSION_NONCE", environment)
        self.assertRegex(
            environment["CODEX_SMART_MCP_SESSION_NONCE"],
            r"^mcpn2_[0-9a-f]{64}$",
        )
        self.assertIn("CODEX_SMART_USER_MCP_POLICY_PROOF", environment)
        policy_proof = json.loads(
            environment["CODEX_SMART_USER_MCP_POLICY_PROOF"]
        )
        self.assertEqual(
            "codex-user-mcp-policy-v2",
            policy_proof["proofKind"],
        )
        self.assertEqual(
            "approve",
            policy_proof["policy"]["defaultToolsApprovalMode"],
        )

        explicit_cases = (
            ["--model", "gpt-user", "проверь"],
            ["--model=gpt-user", "проверь"],
            ["-m", "gpt-user", "проверь"],
            ["-mgpt-user", "проверь"],
            ["-c", 'model_reasoning_effort="high"', "проверь"],
            ["-cmodel=gpt-user", "проверь"],
        )
        for original in explicit_cases:
            with self.subTest(original=original):
                _path, explicit_argv, explicit_environment = self._execute(
                    decision,
                    original,
                    {"PATH": "/usr/bin"},
                )
                self.assertEqual(
                    (
                        str(self.real),
                        *original,
                        *self.ADAPTIVE_DIRECT_TOOL_ARGUMENTS,
                        *self.ADAPTIVE_DISABLED_FEATURE_ARGUMENTS,
                    ),
                    explicit_argv,
                )
                self.assertEqual(
                    tuple(original),
                    explicit_argv[1 : 1 + len(original)],
                )
                self.assertEqual(
                    decision.gate_fingerprint,
                    explicit_environment["CODEX_SMART_GATE_FINGERPRINT"],
                )

    def test_managed_controls_are_inserted_before_separator(self) -> None:
        decision = GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.real,
            coordinator={
                "model": "gpt-5.6-terra",
                "reasoning_effort": "medium",
            },
            activation_id="act2_" + "a" * 64,
            gate_fingerprint="b" * 64,
            activation_gate={
                "manifestSemanticFingerprint": "c" * 64,
                "activationReceiptFingerprint": "d" * 64,
                "journalAbsenceProof": {},
                "gateFingerprint": "b" * 64,
            },
            catalog_path=self.root / "adaptive-subagents.toml",
        )
        defaults = (
            "--model",
            "gpt-5.6-terra",
            "-c",
            'model_reasoning_effort="medium"',
            *self.ADAPTIVE_DIRECT_TOOL_ARGUMENTS,
            *self.ADAPTIVE_DISABLED_FEATURE_ARGUMENTS,
        )
        cases = (
            (
                ["--", "help"],
                (*defaults, "--", "help"),
            ),
            (
                ["--", "--model"],
                (*defaults, "--", "--model"),
            ),
            (
                ["--", "-c", 'model="prompt text"'],
                (*defaults, "--", "-c", 'model="prompt text"'),
            ),
            (
                [
                    "--model",
                    "gpt-user",
                    "-c",
                    'model_reasoning_effort="high"',
                    "--",
                    "help",
                ],
                (
                    "--model",
                    "gpt-user",
                    "-c",
                    'model_reasoning_effort="high"',
                    *self.ADAPTIVE_DIRECT_TOOL_ARGUMENTS,
                    *self.ADAPTIVE_DISABLED_FEATURE_ARGUMENTS,
                    "--",
                    "help",
                ),
            ),
        )
        for original, expected in cases:
            with self.subTest(original=original):
                _path, argv, _environment = self._execute(
                    decision,
                    original,
                    {"PATH": "/usr/bin"},
                )
                self.assertEqual((str(self.real), *expected), argv)
                separator = argv.index("--")
                self.assertEqual(
                    tuple(original[original.index("--") :]),
                    argv[separator:],
                )

    def test_user_agent_feature_controls_bypass_managed_rewrite(self) -> None:
        decision = GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.real,
            coordinator={
                "model": "gpt-5.6-terra",
                "reasoning_effort": "medium",
            },
            activation_id="act2_" + "a" * 64,
            gate_fingerprint="b" * 64,
            activation_gate={
                "manifestSemanticFingerprint": "c" * 64,
                "activationReceiptFingerprint": "d" * 64,
                "journalAbsenceProof": {},
                "gateFingerprint": "b" * 64,
            },
            catalog_path=self.root / "adaptive-subagents.toml",
        )

        _path, argv, environment = self._execute(
            decision,
            ["--enable", "multi_agent", "проверь"],
            {
                "PATH": "/usr/bin",
                "CODEX_SMART_GATE_FINGERPRINT": "stale",
            },
        )

        self.assertEqual(
            (str(self.real), "--enable", "multi_agent", "проверь"),
            argv,
        )
        self.assertNotIn("CODEX_SMART_GATE_FINGERPRINT", environment)

    def test_unproved_user_mcp_policy_falls_back_without_smart_environment(
        self,
    ) -> None:
        self.config_path.write_text(
            '[plugins."codex-smart-subagents@codex-settings-adaptive"]\n'
            "enabled = false\n",
            encoding="utf-8",
        )
        self.config_path.chmod(0o600)
        decision = GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.real,
            coordinator={"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
            activation_id="act2_" + "a" * 64,
            gate_fingerprint="b" * 64,
            activation_gate={"gateFingerprint": "b" * 64},
            catalog_path=self.root / "adaptive-subagents.toml",
        )

        _path, argv, environment = self._execute(
            decision,
            ["проверь"],
            {
                "PATH": "/usr/bin",
                "CODEX_SMART_USER_MCP_POLICY_PROOF": "stale",
                "CODEX_SMART_MCP_SESSION_NONCE": "stale",
            },
        )

        self.assertEqual((str(self.real), "проверь"), argv)
        self.assertFalse(
            any(name.startswith("CODEX_SMART_") for name in environment)
        )

    def test_required_policy_proof_failure_fails_without_exec(self) -> None:
        self.config_path.write_text(
            '[plugins."codex-smart-subagents@codex-settings-adaptive"]\n'
            "enabled = false\n",
            encoding="utf-8",
        )
        self.config_path.chmod(0o600)
        decision = GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.real,
            coordinator={"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
            activation_id="act2_" + "a" * 64,
            gate_fingerprint="b" * 64,
            activation_gate={"gateFingerprint": "b" * 64},
            catalog_path=self.root / "adaptive-subagents.toml",
        )
        executions: list[object] = []

        with self.assertRaisesRegex(RuntimeError, "USER_MCP_POLICY_UNPROVED"):
            run_permanent_gateway(
                ["проверь"],
                resolver=_StaticResolver(decision),
                wrapper=self.wrapper,
                environment={
                    "PATH": "/usr/bin",
                    "CODEX_HOME": str(self.root),
                    "CODEX_SMART_REQUIRED": "1",
                },
                managed_required=True,
                execve=lambda *_arguments: executions.append(object()),
            )

        self.assertEqual([], executions)

    def test_user_profile_or_arbitrary_config_never_exports_proofs(self) -> None:
        decision = GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.real,
            coordinator={"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
            activation_id="act2_" + "a" * 64,
            gate_fingerprint="b" * 64,
            activation_gate={"gateFingerprint": "b" * 64},
            catalog_path=self.root / "adaptive-subagents.toml",
        )
        for original in (
            ["-p", "custom", "проверь"],
            ["-c", "approval_policy=\"never\"", "проверь"],
        ):
            with self.subTest(original=original):
                _path, argv, environment = self._execute(
                    decision,
                    original,
                    {"PATH": "/usr/bin"},
                )
                self.assertEqual((str(self.real), *original), argv)
                self.assertNotIn(
                    "CODEX_SMART_USER_MCP_POLICY_PROOF",
                    environment,
                )
                self.assertNotIn("CODEX_SMART_MCP_SESSION_NONCE", environment)

    def test_ready_activation_still_bypasses_noninteractive_subcommands(self) -> None:
        decision = GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.real,
            coordinator={"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
            activation_id="act2_" + "a" * 64,
            gate_fingerprint="b" * 64,
            activation_gate={
                "manifestSemanticFingerprint": "c" * 64,
                "activationReceiptFingerprint": "d" * 64,
                "journalAbsenceProof": {},
                "gateFingerprint": "b" * 64,
            },
            catalog_path=self.root / "adaptive-subagents.toml",
        )
        original = ["exec", "проверь"]
        _path, argv, environment = self._execute(
            decision,
            original,
            {"PATH": "/usr/bin", "CODEX_SMART_GATE_FINGERPRINT": "stale"},
        )
        self.assertEqual((str(self.real), *original), argv)
        self.assertNotIn("CODEX_SMART_GATE_FINGERPRINT", environment)

    def test_cleaner_does_not_mutate_input(self) -> None:
        source = {"PATH": "/usr/bin", "CODEX_ADAPTIVE_SESSION_ID": "old"}
        result = clean_ordinary_environment(source)
        self.assertIn("CODEX_ADAPTIVE_SESSION_ID", source)
        self.assertNotIn("CODEX_ADAPTIVE_SESSION_ID", result)

    def test_any_v2_lifecycle_artifact_prevents_silent_legacy_fallback(self) -> None:
        layout = GatewayLayout.for_codex_home(self.root)
        self.assertFalse(v2_gateway_state_present(layout))
        layout.manifest_root.mkdir(mode=0o700)
        layout.fallback_path.symlink_to(self.root / "missing-target")
        self.assertTrue(v2_gateway_state_present(layout))


class FallbackCapsuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.codex_home = Path(self.temporary.name).resolve() / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.layout = GatewayLayout.for_codex_home(self.codex_home)
        self.layout.manifest_root.mkdir(mode=0o700)
        self.wrapper = Path(self.temporary.name).resolve() / "codex-smart"
        self.wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
        self.wrapper.chmod(0o500)
        self.source = Path(self.temporary.name).resolve() / "codex-source"
        self.source.write_text("#!/bin/sh\n", encoding="utf-8")
        self.source.chmod(0o500)
        self.backup = Path(self.temporary.name).resolve() / "codex-backup"
        self.backup.write_bytes(self.source.read_bytes())
        self.backup.chmod(0o500)
        self._write_capsule()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_capsule(self) -> None:
        capsule = {
            "schemaVersion": 2,
            "sourceLocator": {
                "lexicalPath": str(self.source),
                "resolvedPathAtCapture": str(self.source),
                "argv0Policy": "lexical",
                "sourceObservedSha256": hashlib.sha256(
                    self.source.read_bytes()
                ).hexdigest(),
            },
            "backupSnapshot": {
                "absolutePath": str(self.backup),
                "sha256": hashlib.sha256(self.backup.read_bytes()).hexdigest(),
            },
            "extensions": {},
        }
        self.layout.fallback_path.write_text(
            json.dumps(capsule, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        self.layout.fallback_path.chmod(0o600)

    def _resolver(self) -> ActivationResolver:
        return ActivationResolver(
            layout=self.layout,
            wrapper=self.wrapper,
            snapshot_verifier=lambda _subject: None,
            controller_probe=lambda _socket, _request: {},
        )

    def test_missing_manifest_uses_independent_lexical_source(self) -> None:
        decision = self._resolver().resolve()
        self.assertEqual(GatewayState.ORDINARY, decision.state)
        self.assertEqual("MANIFEST_UNAVAILABLE", decision.reason_code)
        self.assertEqual(self.source, decision.executable)

    def test_missing_lexical_source_uses_verified_capsule_snapshot(self) -> None:
        self.source.unlink()
        decision = self._resolver().resolve()
        self.assertEqual(GatewayState.ORDINARY, decision.state)
        self.assertEqual(self.backup, decision.executable)

    def test_corrupt_capsule_with_no_ordinary_source_is_explicit_error(self) -> None:
        self.source.unlink()
        self.backup.chmod(0o700)
        self.backup.write_bytes(b"corrupt")
        self.backup.chmod(0o500)
        with self.assertRaisesRegex(GatewayUnavailable, "FALLBACK_UNAVAILABLE"):
            self._resolver().resolve()

    def test_capsule_rejects_values_outside_canonical_json_model(self) -> None:
        unsafe = self.layout.manifest_root / "unsafe.json"
        _write_json(unsafe, {"unsafeInteger": 9_007_199_254_740_992})

        with self.assertRaisesRegex(_ProofError, "invalid strict JSON"):
            _read_owned_json(
                unsafe,
                expected_mode=0o600,
                code="FALLBACK_INVALID",
            )


class _ActivationFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="csgw-")
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.layout = GatewayLayout.for_codex_home(self.codex_home)
        self.layout.manifest_root.mkdir(mode=0o700)
        self.layout.managed_root.mkdir(mode=0o700)
        self.state_home = self.codex_home / "state" / "codex-smart-subagents-v2"
        self.state_home.mkdir(parents=True, mode=0o700)
        self.wrapper = self.root / "codex-smart"
        self.wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
        self.wrapper.chmod(0o500)
        self.source = self.root / "codex-source"
        self.source.write_text("#!/bin/sh\n", encoding="utf-8")
        self.source.chmod(0o500)
        self.source_sha256 = _file_sha256(self.source)

        snapshot_dir = (
            self.layout.managed_root / "codex-snapshots" / self.source_sha256
        )
        snapshot_dir.mkdir(parents=True, mode=0o700)
        (self.layout.managed_root / "codex-snapshots").chmod(0o700)
        self.snapshot = snapshot_dir / "codex"
        shutil.copyfile(self.source, self.snapshot)
        self.snapshot.chmod(0o500)
        os.utime(self.snapshot, ns=(1_000_000_000_000, 1_000_000_000_000))

        self.installation_id = "ins2_" + "1" * 32
        self.operation_id = "op2_" + "2" * 32
        self.database_id = "db2_" + "3" * 32
        self.activation_nonce = "4" * 64
        self.database_path = (
            self.state_home
            / "databases"
            / self.database_id
            / "smart-subagents.sqlite3"
        )
        self.database_path.parent.mkdir(parents=True, mode=0o700)
        (self.state_home / "databases").chmod(0o700)
        self.schema_artifact = (
            ROOT
            / "plugins/codex-smart-subagents/src/codex_smart_subagents/schema/state-v2.sql"
        )
        connection = sqlite3.connect(self.database_path)
        connection.executescript(self.schema_artifact.read_text(encoding="utf-8"))
        connection.execute(f"pragma application_id={APPLICATION_ID}")
        connection.execute("pragma user_version=2")
        self.schema_fingerprint = database_schema_fingerprint(
            connection,
            version=2,
        ).fingerprint
        connection.commit()
        connection.close()
        self.database_path.chmod(0o600)

        activation_seed = self.layout.managed_root / "activations" / "seed"
        self.marketplace = activation_seed / "marketplace"
        plugin_root = self.marketplace / "plugins" / "codex-smart-subagents"
        self.catalog_path = plugin_root / "config" / "adaptive-subagents.toml"
        self.catalog_path.parent.mkdir(parents=True, mode=0o700)
        shutil.copyfile(ROOT / ".codex/adaptive-subagents.toml", self.catalog_path)
        self.catalog_path.chmod(0o600)
        installed_schema = plugin_root / "src/codex_smart_subagents/schema/state-v2.sql"
        installed_schema.parent.mkdir(parents=True, mode=0o700)
        shutil.copyfile(self.schema_artifact, installed_schema)
        installed_schema.chmod(0o600)
        for directory in (
            self.layout.managed_root / "activations",
            activation_seed,
            self.marketplace,
            self.marketplace / "plugins",
            plugin_root,
            plugin_root / "config",
            plugin_root / "src",
            plugin_root / "src/codex_smart_subagents",
            plugin_root / "src/codex_smart_subagents/schema",
        ):
            directory.chmod(0o700)

        marketplace_sha = _tree_sha256(self.marketplace)
        generation_sha = _tree_sha256(plugin_root)
        semantic_vector = json.loads(
            (ROOT / "docs/contracts/vectors/interface-evidence-v1.json").read_text(
                encoding="utf-8"
            )
        )["base"]["semantic"]
        semantic = copy.deepcopy(semantic_vector)
        semantic["extensionRelease"] = "0.2.0"
        self.routing_fingerprint = semantic["routingPolicyFingerprint"]
        self.catalog_fingerprint = semantic["bundledCatalogFingerprint"]

        subject_info = self.snapshot.stat()
        subject = {
            "snapshotSha256": self.source_sha256,
            "snapshotPath": str(self.snapshot),
            "size": subject_info.st_size,
            "mode": stat.S_IMODE(subject_info.st_mode),
            "uid": subject_info.st_uid,
            "device": subject_info.st_dev,
            "inode": subject_info.st_ino,
            "mtimeNs": str(subject_info.st_mtime_ns),
            "version": "codex-cli 0.144.6",
            "platform": "darwin",
            "architecture": "arm64",
            "signatureIdentifier": "codex",
            "teamIdentifier": "2DC432GLL2",
            "cdHash": "5" * 40,
            "sourceLocator": str(self.source),
            "sourceObservedSha256": self.source_sha256,
        }
        self.interface_evidence = build_interface_evidence(
            subject=subject,
            semantic=semantic,
        )

        identity = {
            "schemaVersion": 2,
            "generationId": "gen2_" + generation_sha,
            "release": "0.2.0",
            "pluginId": "codex-smart-subagents",
            "marketplaceTreeSha256": marketplace_sha,
            "generationTreeSha256": generation_sha,
            "database": {
                "databaseId": self.database_id,
                "absolutePath": str(self.database_path),
                "schemaVersion": 2,
                "schemaFingerprint": self.schema_fingerprint,
                "schemaArtifactSha256": _file_sha256(self.schema_artifact),
                "activationBindingNonce": self.activation_nonce,
            },
            "codexSnapshot": {
                "absolutePath": str(self.snapshot),
                "sha256": self.source_sha256,
            },
            "compatibilityFingerprint": self.interface_evidence[
                "compatibilityFingerprint"
            ],
            "routingPolicyFingerprint": self.routing_fingerprint,
            "bundledCatalogFingerprint": self.catalog_fingerprint,
            "minimumGatewayVersion": "0.2.0",
        }
        self.activation_fingerprint = domain_fingerprint(
            "codex-smart/activation/v2", identity
        )
        self.activation_id = "act2_" + self.activation_fingerprint
        self.activation_dir = (
            self.layout.managed_root / "activations" / self.activation_id
        )
        activation_seed.rename(self.activation_dir)
        self.marketplace = self.activation_dir / "marketplace"
        self.catalog_path = (
            self.marketplace
            / "plugins/codex-smart-subagents/config/adaptive-subagents.toml"
        )
        self.activation_path = self.activation_dir / "activation.json"
        self.activation_document = {
            "schemaVersion": 2,
            "activationId": self.activation_id,
            "activationFingerprint": self.activation_fingerprint,
            "identity": identity,
        }
        _write_json(self.activation_path, self.activation_document)
        self.layout.marketplace_link.symlink_to(
            f"activations/{self.activation_id}/marketplace"
        )

        self.socket_path = self.state_home / "controller.sock"
        self.controller_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.controller_socket.bind(str(self.socket_path))
        self.socket_path.chmod(0o600)
        socket_info = self.socket_path.lstat()
        self.controller_start_marker = "fixture-controller-start"
        controller_projection = {
            "protocolVersion": 2,
            "release": "0.2.0",
            "namespace": "codex-smart-subagents-v2",
            "codexHomeHash": hashlib.sha256(
                str(self.codex_home.resolve()).encode("utf-8")
            ).hexdigest(),
            "stateHome": str(self.state_home),
            "activationFingerprint": self.activation_fingerprint,
            "compatibilityFingerprint": self.interface_evidence[
                "compatibilityFingerprint"
            ],
            "routingPolicyFingerprint": self.routing_fingerprint,
            "bundledCatalogFingerprint": self.catalog_fingerprint,
            "databaseId": self.database_id,
            "databaseSchemaVersion": 2,
        }
        self.controller_identity = domain_fingerprint(
            "codex-smart/controller-identity/v2", controller_projection
        )
        self.instance_id = "ci2_" + "6" * 32
        self.controller_start_id = "cs2_" + "7" * 32

        database_identity = {
            "databaseId": self.database_id,
            "activationBindingNonce": self.activation_nonce,
            "activationId": self.activation_id,
            "activationFingerprint": self.activation_fingerprint,
        }
        self.database_identity_fingerprint = domain_fingerprint(
            "codex-smart/database-identity/v2", database_identity
        )
        connection = sqlite3.connect(self.database_path)
        connection.execute(
            """
            insert into database_identity(
              singleton,database_id,schema_version,schema_fingerprint,
              schema_artifact_sha256,activation_binding_nonce,activation_id,
              activation_fingerprint,source_shape,source_schema_fingerprint,
              source_backup_sha256,created_operation_id,created_at
            ) values(1,?,?,?,?,?,?,?,'fresh-v2',null,null,?,?)
            """,
            (
                self.database_id,
                2,
                self.schema_fingerprint,
                _file_sha256(self.schema_artifact),
                self.activation_nonce,
                self.activation_id,
                self.activation_fingerprint,
                self.operation_id,
                "2026-07-18T00:00:00.000000Z",
            ),
        )
        connection.execute(
            """
            insert into controller_state(
              singleton,database_id,protocol_version,release,controller_identity,
              instance_id,controller_start_id,controller_pid,
              controller_process_start_marker,controller_process_group_id,
              control_epoch,state,maintenance_mode,reason_code,operation_id,
              activation_id,activation_fingerprint,compatibility_fingerprint,
              routing_policy_fingerprint,bundled_catalog_fingerprint,
              socket_path,socket_device,socket_inode,socket_owner_uid,
              socket_owner_gid,socket_mode,lock_held,accepting_new_routes,
              quiescent,updated_at
            ) values(1,?,?,?,?,?,?,?,?,?,1,'ACCEPTING','NONE','NONE',null,
                     ?,?,?,?,?,?,?,?,?,?,'0600',1,1,1,?)
            """,
            (
                self.database_id,
                2,
                "0.2.0",
                self.controller_identity,
                self.instance_id,
                self.controller_start_id,
                os.getpid(),
                self.controller_start_marker,
                os.getpgrp(),
                self.activation_id,
                self.activation_fingerprint,
                self.interface_evidence["compatibilityFingerprint"],
                self.routing_fingerprint,
                self.catalog_fingerprint,
                str(self.socket_path),
                socket_info.st_dev,
                socket_info.st_ino,
                socket_info.st_uid,
                socket_info.st_gid,
                "2026-07-18T00:00:00.000000Z",
            ),
        )
        connection.commit()
        connection.close()
        self.database_path.chmod(0o600)

        source_locator = {
            "lexicalPath": str(self.source),
            "resolvedPathAtCapture": str(self.source),
            "argv0Policy": "lexical",
            "sourceObservedSha256": self.source_sha256,
        }
        fallback = {
            "schemaVersion": 2,
            "sourceLocator": source_locator,
            "backupSnapshot": {
                "absolutePath": str(self.snapshot),
                "sha256": self.source_sha256,
            },
            "extensions": {},
        }
        _write_json(self.layout.fallback_path, fallback)
        self.layout.lock_path.write_bytes(b"")
        self.layout.lock_path.chmod(0o600)

        self.manifest = {
            "schemaVersion": 2,
            "installationId": self.installation_id,
            "release": "0.2.0",
            "pluginId": "codex-smart-subagents",
            "marketplaceName": "codex-settings-adaptive",
            "stateHome": str(self.state_home),
            "sourceLocator": source_locator,
            "codexSnapshot": {
                "absolutePath": str(self.snapshot),
                "sha256": self.source_sha256,
            },
            "activeActivation": {
                "activationId": self.activation_id,
                "activationFingerprint": self.activation_fingerprint,
                "symlinkTarget": f"activations/{self.activation_id}/marketplace",
                "generationId": identity["generationId"],
                "databaseId": self.database_id,
            },
            "previousActivation": None,
            "interfaceEvidence": self.interface_evidence,
            "routingPolicyFingerprint": self.routing_fingerprint,
            "bundledCatalogFingerprint": self.catalog_fingerprint,
            "artifacts": [],
            "originalBackup": {
                "type": "absent",
                "path": str(self.codex_home / "original-codex-backup"),
                "parentPath": str(self.codex_home),
                "name": "original-codex-backup",
            },
            "lastCommittedOperation": self.operation_id,
            "databaseSchemaVersion": 2,
            "extensions": {},
        }
        _write_json(self.layout.manifest_path, self.manifest)

        manifest_value = {
            "file": _file_projection(self.layout.manifest_path),
            "schemaVersion": 2,
            "installationId": self.installation_id,
            "release": "0.2.0",
            "pluginId": "codex-smart-subagents",
            "stateHome": str(self.state_home),
            "activeActivationId": self.activation_id,
            "previousActivationId": None,
            "lastCommittedOperation": self.operation_id,
            "sourceLocatorFingerprint": hashlib.sha256(
                canonical_json_bytes(source_locator)
            ).hexdigest(),
            "artifactsFingerprint": hashlib.sha256(
                canonical_json_bytes([])
            ).hexdigest(),
            "semanticFingerprint": _manifest_semantic_fingerprint(self.manifest),
        }
        manifest_projection = _journal_projection("manifest-v2", manifest_value)
        activation_value = {
            "directory": _tree_projection(self.activation_dir),
            "activationFile": _file_projection(self.activation_path),
            "activationId": self.activation_id,
            "activationFingerprint": self.activation_fingerprint,
            "generationId": identity["generationId"],
            "release": "0.2.0",
            "databaseId": self.database_id,
            "databaseIdentityFingerprint": self.database_identity_fingerprint,
            "marketplaceTreeSha256": identity["marketplaceTreeSha256"],
            "generationTreeSha256": identity["generationTreeSha256"],
        }
        activation_projection = _journal_projection(
            "activation-v2", activation_value
        )
        database_info = self.database_path.lstat()
        database_binding_value = {
            "path": str(self.database_path),
            "device": database_info.st_dev,
            "inode": database_info.st_ino,
            "ownerUid": database_info.st_uid,
            "ownerGid": database_info.st_gid,
            "mode": "0600",
            "linkCount": 1,
            "databaseId": self.database_id,
            "databaseIdentity": database_identity,
            "databaseIdentityFingerprint": self.database_identity_fingerprint,
            "activationIdentity": {
                "activationId": self.activation_id,
                "activationFingerprint": self.activation_fingerprint,
            },
            "databaseVersion": "0.2.0",
            "schemaVersion": 2,
            "userVersion": 2,
            "schemaFingerprint": self.schema_fingerprint,
            "schemaArtifactSha256": _file_sha256(self.schema_artifact),
        }
        database_binding = {
            "schemaId": "database-binding-v2",
            "schemaSha256": LIFECYCLE_SCHEMA_SHA256,
            "value": database_binding_value,
        }
        database_binding["valueFingerprint"] = domain_fingerprint(
            "codex-smart/database-binding/v2", database_binding
        )
        manifest_root_info = self.layout.manifest_root.lstat()
        absence_value = {
            "proofId": "ap2_" + "8" * 32,
            "installationId": self.installation_id,
            "operationId": self.operation_id,
            "entries": [
                {
                    "path": str(self.layout.journal_path),
                    "basename": self.layout.journal_path.name,
                    "parentDevice": manifest_root_info.st_dev,
                    "parentInode": manifest_root_info.st_ino,
                    "absent": True,
                }
            ],
            "directorySyncCompleted": True,
        }
        absence_value["proofFingerprint"] = domain_fingerprint(
            "codex-smart/absence-proof/v2", absence_value
        )
        absence_projection = {
            "schemaId": "absence-proof-v2",
            "schemaSha256": LIFECYCLE_SCHEMA_SHA256,
            "value": absence_value,
        }
        absence_projection["valueFingerprint"] = domain_fingerprint(
            "codex-smart/absence-proof-projection/v2", absence_projection
        )
        self.receipt = {
            "schemaVersion": 2,
            "receiptKind": "activation-commit",
            "installationId": self.installation_id,
            "operationId": self.operation_id,
            "frozenJournalFingerprint": "9" * 64,
            "manifest": manifest_projection,
            "manifestDocument": copy.deepcopy(self.manifest),
            "transitionLineage": {
                "transitionKind": "initial",
                "sourceReceipt": None,
                "activationProofFingerprint": None,
                "shutdownCommandIds": None,
                "stoppedController": None,
            },
            "activation": activation_projection,
            "databaseBinding": database_binding,
            "journalAbsenceTarget": absence_projection,
            "controllerIdentity": self.controller_identity,
            "completedStepIds": ["st2_" + "a" * 32],
            "completedAt": "2026-07-18T00:00:01Z",
        }
        self.receipt["transitionLineage"]["lineageFingerprint"] = (
            domain_fingerprint(
                "codex-smart/activation-transition-lineage/v2",
                self.receipt["transitionLineage"],
            )
        )
        self.receipt["receiptFingerprint"] = domain_fingerprint(
            "codex-smart/activation-commit-receipt/v2", self.receipt
        )
        self.receipt_path = (
            self.layout.receipts_root
            / self.installation_id
            / f"{self.operation_id}.commit.json"
        )
        self.receipt_path.parent.mkdir(parents=True, mode=0o700)
        self.layout.receipts_root.chmod(0o700)
        _write_json(self.receipt_path, self.receipt)

        zero_counts = {
            "nonterminalRoutes": 0,
            "nonterminalNodes": 0,
            "activeAttempts": 0,
            "activeLeases": 0,
            "openIntents": 0,
            "inflightLaunchPermits": 0,
            "activeRuntimeArtifacts": 0,
            "pendingCandidatePublications": 0,
            "activeEvidenceJobs": 0,
            "queuedEvidenceJobs": 0,
        }
        coordinator_selection = collect_coordinator_selection_v2(
            selection="first-verified-available",
            candidates=(
                {
                    "model": "gpt-5.6-sol",
                    "reasoningEffort": "medium",
                },
                {
                    "model": "gpt-5.6-terra",
                    "reasoningEffort": "medium",
                },
            ),
            inspector=type(
                "_CoordinatorInspector",
                (),
                {
                    "inspect": lambda _self: {
                        "gpt-5.6-terra": frozenset({"medium"})
                    }
                },
            )(),
            active_context_fingerprint=self.activation_fingerprint,
        )
        self.health_payload = {
            "namespace": "codex-smart-subagents-v2",
            "controllerIdentity": self.controller_identity,
            "instanceId": self.instance_id,
            "controllerStartId": self.controller_start_id,
            "pid": os.getpid(),
            "processStartMarker": self.controller_start_marker,
            "processGroupId": os.getpgrp(),
            "state": "ACCEPTING",
            "maintenanceMode": None,
            "operationId": None,
            "acceptingNewRoutes": True,
            "quiescent": True,
            "activationFingerprint": self.activation_fingerprint,
            "compatibilityFingerprint": self.interface_evidence[
                "compatibilityFingerprint"
            ],
            "routingPolicyFingerprint": self.routing_fingerprint,
            "bundledCatalogFingerprint": self.catalog_fingerprint,
            "coordinatorSelection": coordinator_selection.to_document(),
            "databaseId": self.database_id,
            "databaseSchemaVersion": 2,
            "workCounts": zero_counts,
        }

    def close(self) -> None:
        self.controller_socket.close()
        self.temporary.cleanup()

    @property
    def live_codex(self) -> Path:
        return self.source

    @property
    def snapshot_path(self) -> Path:
        return self.snapshot

    def replace_live_codex(self, contents: bytes) -> None:
        self.source.chmod(0o700)
        self.source.write_bytes(contents)
        self.source.chmod(0o500)

    def mutate_interface_subject(self, name: str, value: object) -> None:
        self.interface_evidence["subject"][name] = value
        _write_json(self.layout.manifest_path, self.manifest)

    def mutate_interface_evidence(self, name: str, value: object) -> None:
        self.interface_evidence[name] = value
        _write_json(self.layout.manifest_path, self.manifest)

    def controller_probe(self, _socket_path: Path, request: dict[str, object]):
        response = {
            "messageType": "response",
            "protocolVersion": 2,
            "release": "0.2.0",
            "method": "health",
            "responseKind": "HEALTH",
            "commandId": None,
            "requestFingerprint": request["requestFingerprint"],
            "controlEpoch": 1,
            "payload": copy.deepcopy(self.health_payload),
            "extensions": {},
        }
        response["responseFingerprint"] = domain_fingerprint(
            "codex-smart/controller-response/v2",
            {key: value for key, value in response.items() if key != "extensions"},
        )
        return response

    def resolver(self, *, controller_probe=None) -> ActivationResolver:
        return ActivationResolver(
            layout=self.layout,
            wrapper=self.wrapper,
            snapshot_verifier=lambda subject: (
                None
                if subject["snapshotPath"] == str(self.snapshot)
                else (_ for _ in ()).throw(AssertionError("wrong snapshot"))
            ),
            controller_probe=controller_probe or self.controller_probe,
        )


class ActivationResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _ActivationFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_full_bound_activation_is_the_only_ready_state(self) -> None:
        decision = self.fixture.resolver().resolve()

        self.assertEqual(GatewayState.READY, decision.state, decision.reason_code)
        self.assertEqual(self.fixture.source, decision.executable)
        self.assertEqual(self.fixture.activation_id, decision.activation_id)
        self.assertEqual(self.fixture.catalog_path, decision.catalog_path)
        self.assertEqual(
            {"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
            decision.coordinator,
        )
        self.assertRegex(decision.gate_fingerprint or "", r"^[0-9a-f]{64}$")
        self.assertEqual(
            decision.gate_fingerprint,
            decision.activation_gate["gateFingerprint"],
        )
        self.assertEqual(
            self.fixture.receipt["journalAbsenceTarget"],
            decision.activation_gate["journalAbsenceProof"],
        )
        binding = decision.runtime_binding
        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(self.fixture.activation_id, binding.activation_id)
        self.assertEqual(
            self.fixture.activation_fingerprint,
            binding.activation_fingerprint,
        )
        self.assertEqual(
            self.fixture.interface_evidence["compatibilityFingerprint"],
            binding.compatibility_fingerprint,
        )
        self.assertEqual(1, binding.control_epoch)
        self.assertEqual(self.fixture.state_home, binding.state_home)
        self.assertEqual(self.fixture.marketplace, binding.marketplace_path)
        self.assertEqual(self.fixture.database_path, binding.database_path)
        self.assertEqual(
            self.fixture.database_id,
            binding.database_identity_row["database_id"],
        )
        self.assertEqual(
            self.fixture.controller_identity,
            binding.controller_row["controller_identity"],
        )

    def test_source_change_keeps_valid_activation_ready_on_snapshot(self) -> None:
        self.fixture.replace_live_codex(b"compatible-new-codex")

        decision = self.fixture.resolver().resolve_persisted_activation()

        self.assertIs(GatewayState.READY, decision.state)
        self.assertEqual(self.fixture.snapshot_path, decision.executable)
        self.assertIsNotNone(decision.source_drift)
        assert decision.source_drift is not None
        self.assertEqual(self.fixture.live_codex, decision.source_drift.lexical_path)
        self.assertEqual(
            hashlib.sha256(b"compatible-new-codex").hexdigest(),
            decision.source_drift.observed_sha256,
        )

    def test_source_change_does_not_hide_corrupt_snapshot(self) -> None:
        self.fixture.replace_live_codex(b"new-codex")
        self.fixture.snapshot_path.chmod(0o700)

        decision = self.fixture.resolver().resolve()

        self.assertIs(GatewayState.ORDINARY, decision.state)
        self.assertEqual("ACTIVATION_PROOF_INVALID", decision.reason_code)
        self.assertIsNone(decision.source_drift)

    def test_unchanged_source_has_no_drift_marker(self) -> None:
        decision = self.fixture.resolver().resolve_persisted_activation()

        self.assertIs(GatewayState.READY, decision.state)
        self.assertIsNone(decision.source_drift)

    def test_source_change_rejects_tampered_snapshot_interface_evidence(self) -> None:
        self.fixture.replace_live_codex(b"new-codex")
        self.fixture.mutate_interface_subject("architecture", "x86_64")

        decision = self.fixture.resolver().resolve()

        self.assertIs(GatewayState.ORDINARY, decision.state)
        self.assertEqual("ACTIVATION_PROOF_INVALID", decision.reason_code)
        self.assertIsNone(decision.source_drift)

    def test_source_change_rejects_foreign_interface_fingerprint(self) -> None:
        self.fixture.replace_live_codex(b"new-codex")
        self.fixture.mutate_interface_evidence("compatibilityFingerprint", "f" * 64)

        decision = self.fixture.resolver().resolve()

        self.assertIs(GatewayState.ORDINARY, decision.state)
        self.assertEqual("ACTIVATION_PROOF_INVALID", decision.reason_code)
        self.assertIsNone(decision.source_drift)

    def test_fast_pinned_health_check_reuses_the_proven_controller_protocol(
        self,
    ) -> None:
        observed: list[tuple[Path, dict[str, object]]] = []

        def probe(
            socket_path: Path,
            request: dict[str, object],
        ) -> dict[str, object]:
            observed.append((socket_path, copy.deepcopy(request)))
            return self.fixture.controller_probe(socket_path, request)

        require_pinned_controller_health_v2(
            codex_home=self.fixture.codex_home,
            state_home=self.fixture.state_home,
            activation_id=self.fixture.activation_id,
            controller_probe=probe,
        )

        self.assertEqual(1, len(observed))
        self.assertEqual(self.fixture.socket_path, observed[0][0])
        self.assertEqual("health", observed[0][1]["method"])
        self.assertEqual(
            self.fixture.receipt["journalAbsenceTarget"],
            refresh_activation_journal_absence_v2(
                self.fixture.receipt["journalAbsenceTarget"],
                expected_journal=self.fixture.layout.journal_path,
            ),
        )

    def test_fast_pinned_health_check_rejects_another_activation(self) -> None:
        def mismatched(
            socket_path: Path,
            request: dict[str, object],
        ) -> dict[str, object]:
            response = self.fixture.controller_probe(socket_path, request)
            response["payload"]["activationFingerprint"] = "f" * 64
            response["responseFingerprint"] = domain_fingerprint(
                "codex-smart/controller-response/v2",
                {
                    key: value
                    for key, value in response.items()
                    if key not in {"responseFingerprint", "extensions"}
                },
            )
            return response

        with self.assertRaisesRegex(_ProofError, "activation"):
            require_pinned_controller_health_v2(
                codex_home=self.fixture.codex_home,
                state_home=self.fixture.state_home,
                activation_id=self.fixture.activation_id,
                controller_probe=mismatched,
            )

    def test_fast_pinned_health_check_rejects_maintenance(self) -> None:
        def maintenance(
            socket_path: Path,
            request: dict[str, object],
        ) -> dict[str, object]:
            response = self.fixture.controller_probe(socket_path, request)
            response["payload"]["state"] = "MAINTENANCE"
            response["payload"]["maintenanceMode"] = "PREPARE"
            response["payload"]["acceptingNewRoutes"] = False
            response["responseFingerprint"] = domain_fingerprint(
                "codex-smart/controller-response/v2",
                {
                    key: value
                    for key, value in response.items()
                    if key not in {"responseFingerprint", "extensions"}
                },
            )
            return response

        with self.assertRaisesRegex(_ProofError, "accepting"):
            require_pinned_controller_health_v2(
                codex_home=self.fixture.codex_home,
                state_home=self.fixture.state_home,
                activation_id=self.fixture.activation_id,
                controller_probe=maintenance,
            )

    def test_snapshot_device_drift_after_reboot_is_accepted(self) -> None:
        original_verify = gateway_module._verify_private_file

        def verify_with_device_drift(path, **kwargs):
            info = original_verify(path, **kwargs)
            if path == self.fixture.snapshot:
                return _StatOverride(info, st_dev=info.st_dev + 1)
            return info

        with patch.object(
            gateway_module,
            "_verify_private_file",
            side_effect=verify_with_device_drift,
        ):
            interface = self.fixture.resolver()._validate_interface(
                self.fixture.interface_evidence,
                identity=self.fixture.activation_document["identity"],
                manifest=self.fixture.manifest,
            )

        self.assertEqual(self.fixture.interface_evidence, interface)

    def test_snapshot_device_drift_does_not_hide_inode_change(self) -> None:
        original_verify = gateway_module._verify_private_file

        def verify_with_identity_change(path, **kwargs):
            info = original_verify(path, **kwargs)
            if path == self.fixture.snapshot:
                return _StatOverride(
                    info,
                    st_dev=info.st_dev + 1,
                    st_ino=info.st_ino + 1,
                )
            return info

        with patch.object(
            gateway_module,
            "_verify_private_file",
            side_effect=verify_with_identity_change,
        ):
            with self.assertRaisesRegex(_ProofError, "SNAPSHOT_MISMATCH"):
                self.fixture.resolver()._validate_interface(
                    self.fixture.interface_evidence,
                    identity=self.fixture.activation_document["identity"],
                    manifest=self.fixture.manifest,
                )

    def test_database_device_drift_after_reboot_is_accepted(self) -> None:
        original_lstat = os.lstat

        def lstat_with_device_drift(path, *args, **kwargs):
            info = original_lstat(path, *args, **kwargs)
            if Path(path) == self.fixture.database_path:
                return _StatOverride(info, st_dev=info.st_dev + 1)
            return info

        with patch.object(
            gateway_module.os,
            "lstat",
            side_effect=lstat_with_device_drift,
        ):
            binding, _, _ = self.fixture.resolver()._validate_database(
                self.fixture.receipt["databaseBinding"],
                identity=self.fixture.activation_document["identity"],
                interface=self.fixture.interface_evidence,
                state_home=self.fixture.state_home,
                marketplace=self.fixture.marketplace,
            )

        self.assertEqual(self.fixture.receipt["databaseBinding"], binding)

    def test_receipt_projection_device_drift_after_reboot_is_accepted(self) -> None:
        original_lstat = os.lstat
        durable_paths = {
            self.fixture.layout.manifest_path,
            self.fixture.activation_dir,
            self.fixture.activation_path,
        }

        def lstat_with_device_drift(path, *args, **kwargs):
            info = original_lstat(path, *args, **kwargs)
            if Path(path) in durable_paths:
                return _StatOverride(info, st_dev=info.st_dev + 1)
            return info

        with patch.object(
            gateway_module.os,
            "lstat",
            side_effect=lstat_with_device_drift,
        ):
            self.fixture.resolver()._validate_receipt_projections(
                self.fixture.receipt,
                manifest=self.fixture.manifest,
                activation=self.fixture.activation_document,
                activation_dir=self.fixture.activation_dir,
                database_binding=self.fixture.receipt["databaseBinding"],
            )

    def test_absence_parent_device_drift_after_reboot_is_accepted(self) -> None:
        original_fstat = os.fstat

        def fstat_with_device_drift(descriptor):
            info = original_fstat(descriptor)
            return _StatOverride(info, st_dev=info.st_dev + 1)

        with patch.object(
            gateway_module.os,
            "fstat",
            side_effect=fstat_with_device_drift,
        ):
            observed = _refresh_absence_proof(
                self.fixture.receipt["journalAbsenceTarget"],
                expected_journal=self.fixture.layout.journal_path,
            )

        self.assertEqual(self.fixture.receipt["journalAbsenceTarget"], observed)

    def test_each_binding_mismatch_closes_to_ordinary_mode(self) -> None:
        cases = {
            "journal": self._add_journal,
            "manifest": self._corrupt_manifest,
            "receipt": self._corrupt_receipt,
            "activation": self._corrupt_activation,
            "marketplace-link": self._replace_marketplace_link,
            "snapshot": self._corrupt_snapshot,
            "database": self._corrupt_database_identity,
            "receipt-root-symlink": self._replace_receipt_root_with_symlink,
        }
        for name, mutation in cases.items():
            with self.subTest(name=name):
                mutation()
                decision = self.fixture.resolver().resolve()
                self.assertEqual(GatewayState.ORDINARY, decision.state)
                self.assertEqual(self.fixture.source, decision.executable)
                self.tearDown()
                self.setUp()

    def test_controller_health_must_match_immutable_database_identity(self) -> None:
        def mismatched(_socket_path, request):
            response = self.fixture.controller_probe(_socket_path, request)
            response["payload"]["controllerIdentity"] = "f" * 64
            response["responseFingerprint"] = domain_fingerprint(
                "codex-smart/controller-response/v2",
                {
                    key: value
                    for key, value in response.items()
                    if key not in {"responseFingerprint", "extensions"}
                },
            )
            return response

        decision = self.fixture.resolver(controller_probe=mismatched).resolve()
        self.assertEqual(GatewayState.ORDINARY, decision.state)
        self.assertEqual("CONTROLLER_BINDING_MISMATCH", decision.reason_code)

    def test_controller_health_epoch_must_match_database_epoch(self) -> None:
        def mismatched(_socket_path, request):
            response = self.fixture.controller_probe(_socket_path, request)
            response["controlEpoch"] += 1
            response["responseFingerprint"] = domain_fingerprint(
                "codex-smart/controller-response/v2",
                {
                    key: value
                    for key, value in response.items()
                    if key not in {"responseFingerprint", "extensions"}
                },
            )
            return response

        decision = self.fixture.resolver(controller_probe=mismatched).resolve()
        self.assertEqual(GatewayState.ORDINARY, decision.state)
        self.assertEqual("CONTROLLER_BINDING_MISMATCH", decision.reason_code)

    def test_manifest_semantic_fingerprint_is_recomputed_from_live_manifest(self) -> None:
        receipt = copy.deepcopy(self.fixture.receipt)
        receipt["manifest"]["value"]["semanticFingerprint"] = "0" * 64
        projection = {
            key: value
            for key, value in receipt["manifest"].items()
            if key != "valueFingerprint"
        }
        receipt["manifest"]["valueFingerprint"] = domain_fingerprint(
            "codex-smart/journal-state/v2", projection
        )
        receipt_projection = {
            key: value
            for key, value in receipt.items()
            if key != "receiptFingerprint"
        }
        receipt["receiptFingerprint"] = domain_fingerprint(
            "codex-smart/activation-commit-receipt/v2", receipt_projection
        )
        _write_json(self.fixture.receipt_path, receipt)

        decision = self.fixture.resolver().resolve()
        self.assertEqual(GatewayState.ORDINARY, decision.state)
        self.assertEqual("MANIFEST_BINDING_MISMATCH", decision.reason_code)

    def test_damaged_database_shape_falls_back_instead_of_leaking_key_error(self) -> None:
        with closing(sqlite3.connect(self.fixture.database_path)) as connection, connection:
            connection.execute(
                "alter table database_identity rename column activation_binding_nonce "
                "to damaged_binding_nonce"
            )

        decision = self.fixture.resolver().resolve()
        self.assertEqual(GatewayState.ORDINARY, decision.state)
        self.assertEqual("ACTIVATION_PROOF_INVALID", decision.reason_code)

    def test_controller_health_rejects_type_confusion_and_noncanonical_extensions(
        self,
    ) -> None:
        def boolean_as_integer(_socket_path, request):
            response = self.fixture.controller_probe(_socket_path, request)
            response["payload"]["acceptingNewRoutes"] = 1
            response["responseFingerprint"] = domain_fingerprint(
                "codex-smart/controller-response/v2",
                {
                    key: value
                    for key, value in response.items()
                    if key not in {"responseFingerprint", "extensions"}
                },
            )
            return response

        confused = self.fixture.resolver(
            controller_probe=boolean_as_integer
        ).resolve()
        self.assertEqual(GatewayState.ORDINARY, confused.state)
        self.assertEqual("CONTROLLER_BINDING_MISMATCH", confused.reason_code)

        def unsafe_extension(_socket_path, request):
            response = self.fixture.controller_probe(_socket_path, request)
            response["extensions"] = {"unsafeInteger": 9_007_199_254_740_992}
            return response

        noncanonical = self.fixture.resolver(
            controller_probe=unsafe_extension
        ).resolve()
        self.assertEqual(GatewayState.ORDINARY, noncanonical.state)
        self.assertEqual("CONTROLLER_BINDING_MISMATCH", noncanonical.reason_code)

    def test_busy_installation_lock_and_unavailable_controller_fail_closed(self) -> None:
        descriptor = os.open(self.fixture.layout.lock_path, os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = self.fixture.resolver().resolve()
            self.assertEqual(GatewayState.ORDINARY, locked.state)
            self.assertEqual("LOCK_BUSY", locked.reason_code)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

        def unavailable(_socket_path, _request):
            raise OSError("offline")

        offline = self.fixture.resolver(controller_probe=unavailable).resolve()
        self.assertEqual(GatewayState.ORDINARY, offline.state)
        self.assertEqual("CONTROLLER_UNAVAILABLE", offline.reason_code)

    def test_default_probe_recomputes_one_deadline_before_each_socket_block(
        self,
    ) -> None:
        clock = _GatewayDeadlineClock()

        class TimedSocket:
            def __init__(self) -> None:
                self.timeouts: list[float] = []
                self.responses = iter((b"{}", b"\n"))

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def settimeout(self, timeout: float) -> None:
                self.timeouts.append(timeout)

            def connect(self, _path: str) -> None:
                clock.advance(0.4)

            def sendall(self, _payload: bytes) -> None:
                clock.advance(0.4)

            def recv(self, _maximum: int) -> bytes:
                clock.advance(0.05)
                return next(self.responses)

        connection = TimedSocket()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1.0,
            timeout_code="ROOT_OPERATION_EXPIRED",
            monotonic_ns=clock,
        )
        with (
            scoped_current_deadline_v2(deadline),
            patch.object(
                gateway_module.socket,
                "socket",
                return_value=connection,
            ),
        ):
            self.assertEqual(
                {},
                gateway_module._unix_controller_probe(
                    self.fixture.socket_path,
                    {"request": "health"},
                ),
            )

        self.assertGreaterEqual(len(connection.timeouts), 4)
        self.assertAlmostEqual(1.0, connection.timeouts[0], places=6)
        self.assertLessEqual(connection.timeouts[1], 0.600001)
        self.assertLessEqual(connection.timeouts[2], 0.200001)
        self.assertLessEqual(connection.timeouts[3], 0.150001)

    def test_resolver_does_not_convert_root_deadline_to_ordinary_fallback(
        self,
    ) -> None:
        clock = _GatewayDeadlineClock()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1.0,
            timeout_code="ROOT_OPERATION_EXPIRED",
            monotonic_ns=clock,
        )

        def expired_probe(_socket_path, _request):
            clock.advance(1.0)
            deadline.checkpoint()

        with scoped_current_deadline_v2(deadline):
            with self.assertRaises(OperationDeadlineExceededV2) as caught:
                self.fixture.resolver(controller_probe=expired_probe).resolve()

        self.assertEqual("ROOT_OPERATION_EXPIRED", caught.exception.code)

    def test_stop_plan_reader_bounds_real_slow_gateway_probe(self) -> None:
        ready = self.fixture.resolver().resolve()
        self.assertEqual(GatewayState.READY, ready.state, ready.reason_code)
        assert ready.activation_id is not None
        assert ready.gate_fingerprint is not None
        assert ready.catalog_path is not None
        config = IntegrationConfigV2(
            shell_session_id="cas2_" + "s" * 32,
            codex_home=self.fixture.codex_home,
            state_home=self.fixture.state_home,
            gateway_path=self.fixture.wrapper,
            launch_activation_id=ready.activation_id,
            launch_gate_fingerprint=ready.gate_fingerprint,
            catalog_path=ready.catalog_path,
        )
        record = HookTurnContextV2(
            shell_session_id=config.shell_session_id,
            session_id="session-real-probe",
            turn_id="turn-real-probe",
            codex_home=str(config.codex_home),
            repo_root=str(self.fixture.root),
            base_sha="d" * 40,
            worktree_fingerprint="e" * 64,
        )
        accepted = threading.Event()
        release = threading.Event()
        self.fixture.controller_socket.listen(1)

        def hold_health_response() -> None:
            connection, _address = self.fixture.controller_socket.accept()
            with connection:
                connection.recv(64 * 1024)
                accepted.set()
                release.wait(timeout=1)

        server = threading.Thread(target=hold_health_response, daemon=True)
        server.start()

        def real_resolver(_config: IntegrationConfigV2) -> ActivationResolver:
            resolver = self.fixture.resolver()
            resolver.controller_probe = None
            return resolver

        started = time.monotonic()
        try:
            with self.assertRaises(IntegrationV2Error):
                durable_smart_plan_exists_v2(
                    config,
                    record,
                    resolver_factory=real_resolver,
                    deadline=time.monotonic() + 0.50,
                )
        finally:
            elapsed = time.monotonic() - started
            release.set()
            server.join(timeout=1)

        self.assertTrue(accepted.is_set())
        self.assertFalse(server.is_alive())
        self.assertLess(elapsed, 0.80)

    def test_snapshot_verifier_preserves_the_exact_root_deadline(self) -> None:
        original = OperationDeadlineExceededV2(
            code="ROOT_OPERATION_EXPIRED",
            operation="apply",
            phase="snapshot-verification",
            deadline_kind="operation",
            configured_timeout_nanoseconds=1,
            elapsed_monotonic_nanoseconds=2,
        )
        resolver = ActivationResolver(
            layout=self.fixture.layout,
            wrapper=self.fixture.wrapper,
            snapshot_verifier=lambda _subject: (_ for _ in ()).throw(original),
            controller_probe=self.fixture.controller_probe,
        )

        with self.assertRaises(OperationDeadlineExceededV2) as caught:
            resolver.resolve()

        self.assertIs(original, caught.exception)

    def test_standalone_probe_keeps_local_timeout_in_transport_category(
        self,
    ) -> None:
        clock = _GatewayDeadlineClock()
        local_deadline = OperationDeadlineV2.start(
            operation="activation-controller-health-probe",
            timeout_seconds=1.0,
            timeout_code="CONTROLLER_HEALTH_PROBE_TIMEOUT",
            monotonic_ns=clock,
        )

        class TimedOutSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def settimeout(self, _timeout: float) -> None:
                return None

            def connect(self, _path: str) -> None:
                clock.advance(0.6)

            def sendall(self, _payload: bytes) -> None:
                clock.advance(0.5)

        with (
            patch.object(
                gateway_module.operation_deadline_v2.OperationDeadlineV2,
                "start",
                return_value=local_deadline,
            ),
            patch.object(
                gateway_module.socket,
                "socket",
                return_value=TimedOutSocket(),
            ),
            self.assertRaises(TimeoutError) as caught,
        ):
            gateway_module._unix_controller_probe(
                self.fixture.socket_path,
                {"request": "health"},
            )

        self.assertNotIsInstance(
            caught.exception,
            OperationDeadlineExceededV2,
        )

    def test_default_controller_probe_uses_strict_v2_health_exchange(self) -> None:
        self.fixture.controller_socket.listen(1)
        server_errors: list[BaseException] = []

        def serve_once() -> None:
            try:
                connection, _address = self.fixture.controller_socket.accept()
                with connection:
                    raw = b""
                    while b"\n" not in raw:
                        raw += connection.recv(65536)
                    request = json.loads(raw.split(b"\n", 1)[0])
                    response = self.fixture.controller_probe(
                        self.fixture.socket_path, request
                    )
                    connection.sendall(canonical_json_bytes(response) + b"\n")
            except BaseException as exc:  # pragma: no cover - reported below
                server_errors.append(exc)

        thread = threading.Thread(target=serve_once)
        thread.start()
        try:
            resolver = ActivationResolver(
                layout=self.fixture.layout,
                wrapper=self.fixture.wrapper,
                snapshot_verifier=lambda _subject: None,
            )
            decision = resolver.resolve()
        finally:
            thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual([], server_errors)
        self.assertEqual(GatewayState.READY, decision.state, decision.reason_code)

    def test_snapshot_must_use_managed_content_addressed_path(self) -> None:
        misplaced = self.fixture.root / "misplaced-codex"
        shutil.copyfile(self.fixture.snapshot, misplaced)
        misplaced.chmod(0o500)
        os.utime(misplaced, ns=(1_000_000_000_000, 1_000_000_000_000))
        subject = copy.deepcopy(self.fixture.interface_evidence["subject"])
        info = misplaced.lstat()
        subject.update(
            {
                "snapshotPath": str(misplaced),
                "size": info.st_size,
                "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "device": info.st_dev,
                "inode": info.st_ino,
                "mtimeNs": str(info.st_mtime_ns),
            }
        )
        interface = build_interface_evidence(
            subject=subject,
            semantic=copy.deepcopy(self.fixture.interface_evidence["semantic"]),
        )
        identity = copy.deepcopy(self.fixture.activation_document["identity"])
        identity["codexSnapshot"]["absolutePath"] = str(misplaced)
        identity["compatibilityFingerprint"] = interface["compatibilityFingerprint"]

        with self.assertRaisesRegex(_ProofError, "content-addressed snapshot path"):
            self.fixture.resolver()._validate_interface(
                interface,
                identity=identity,
                manifest=self.fixture.manifest,
            )

    def test_database_must_use_database_identity_path(self) -> None:
        misplaced = self.fixture.database_path.with_name("other.sqlite3")
        shutil.copyfile(self.fixture.database_path, misplaced)
        misplaced.chmod(0o600)
        identity = copy.deepcopy(self.fixture.activation_document["identity"])
        identity["database"]["absolutePath"] = str(misplaced)

        with self.assertRaisesRegex(_ProofError, "canonical database path"):
            self.fixture.resolver()._validate_database(
                self.fixture.receipt["databaseBinding"],
                identity=identity,
                interface=self.fixture.interface_evidence,
                state_home=self.fixture.state_home,
                marketplace=self.fixture.marketplace,
            )

    def test_original_backup_accepts_and_verifies_regular_variant(self) -> None:
        backup = self.fixture.root / "original-backup"
        backup.write_bytes(b"original")
        backup.chmod(0o500)
        value = {"type": "regular", **_file_projection(backup)}

        _validate_original_backup(value, "MANIFEST_INVALID")

    def test_original_backup_accepts_directory_and_symlink_variants(self) -> None:
        directory = self.fixture.root / "original-directory"
        directory.mkdir(mode=0o700)
        child = directory / "child"
        child.write_bytes(b"original")
        child.chmod(0o600)
        _validate_original_backup(
            {"type": "directory", **_tree_projection(directory)},
            "MANIFEST_INVALID",
        )

        link = self.fixture.root / "original-link"
        link.symlink_to("relative-target")
        link_info = link.lstat()
        parent_info = link.parent.lstat()
        _validate_original_backup(
            {
                "type": "symlink",
                "path": str(link),
                "parentDevice": parent_info.st_dev,
                "parentInode": parent_info.st_ino,
                "ownerUid": link_info.st_uid,
                "ownerGid": link_info.st_gid,
                "mode": f"0{stat.S_IMODE(link_info.st_mode):03o}",
                "target": "relative-target",
                "targetFingerprint": "f" * 64,
            },
            "MANIFEST_INVALID",
        )

    def _add_journal(self) -> None:
        _write_json(self.fixture.layout.journal_path, {"open": True})

    def _corrupt_manifest(self) -> None:
        value = copy.deepcopy(self.fixture.manifest)
        value["unexpected"] = True
        _write_json(self.fixture.layout.manifest_path, value)

    def _corrupt_receipt(self) -> None:
        value = copy.deepcopy(self.fixture.receipt)
        value["receiptFingerprint"] = "0" * 64
        _write_json(self.fixture.receipt_path, value)

    def _corrupt_activation(self) -> None:
        value = copy.deepcopy(self.fixture.activation_document)
        value["activationFingerprint"] = "0" * 64
        _write_json(self.fixture.activation_path, value)

    def _replace_marketplace_link(self) -> None:
        self.fixture.layout.marketplace_link.unlink()
        self.fixture.layout.marketplace_link.symlink_to("activations/other/marketplace")

    def _corrupt_snapshot(self) -> None:
        self.fixture.snapshot.chmod(0o700)
        self.fixture.snapshot.write_bytes(b"corrupt")
        self.fixture.snapshot.chmod(0o500)

    def _corrupt_database_identity(self) -> None:
        connection = sqlite3.connect(self.fixture.database_path)
        connection.execute(
            "update database_identity set activation_binding_nonce=? where singleton=1",
            ("f" * 64,),
        )
        connection.commit()
        connection.close()

    def _replace_receipt_root_with_symlink(self) -> None:
        moved = self.fixture.layout.receipts_root.with_name("receipts-moved")
        self.fixture.layout.receipts_root.rename(moved)
        self.fixture.layout.receipts_root.symlink_to(moved.name)


if __name__ == "__main__":
    unittest.main()

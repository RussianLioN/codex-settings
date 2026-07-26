from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.account_evidence_executor_v2 import (  # noqa: E402
    AppServerAccountEvidenceExecutorV2,
)
from codex_smart_subagents.evidence import ACCOUNT_ARGV, EvidenceError, FIXED_PATH  # noqa: E402


class AccountEvidenceExecutorV2Tests(unittest.TestCase):
    def test_five_stages_use_five_processes_and_catalog_pages_share_process(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            executable = root / "codex-snapshot"
            executable.write_text(
                """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

marker = Path(os.environ["HOME"]).parent / "processes"
with marker.open("a", encoding="utf-8") as stream:
    stream.write("sqlite=" + str("CODEX_SQLITE_HOME" in os.environ) + "\\n")
for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        result = {
            "userAgent": "fake-codex",
            "codexHome": os.environ["CODEX_HOME"],
            "platformFamily": "unix",
            "platformOs": "test",
        }
    elif method == "initialized":
        continue
    elif method == "configRequirements/read":
        result = {"requirements": {"allowedSandboxModes": ["read-only"]}, "future": 1}
    elif method == "model/list":
        cursor = request["params"].get("cursor")
        if cursor is None:
            result = {
                "data": [{
                    "model": "model-b",
                    "supportedReasoningEfforts": [{"reasoningEffort": "high"}],
                    "future": True,
                }],
                "nextCursor": "second",
                "future": True,
            }
        else:
            result = {
                "data": [{
                    "model": "model-a",
                    "supportedReasoningEfforts": [
                        {"reasoningEffort": "medium"},
                        {"reasoningEffort": "low"},
                    ],
                }],
                "nextCursor": None,
            }
    else:
        raise SystemExit(7)
    print(json.dumps({"id": request["id"], "result": result}), flush=True)
""",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            environment = self._environment(root)
            executor = AppServerAccountEvidenceExecutorV2()

            observed = [
                executor.execute(
                    stage,
                    executable_path=str(executable),
                    argv=ACCOUNT_ARGV,
                    environment=environment,
                    timeout_seconds=30,
                )
                for stage in (
                    "requirements-a",
                    "catalog-a",
                    "requirements-b",
                    "catalog-b",
                    "requirements-c",
                )
            ]

            self.assertEqual(
                {"allowedSandboxModes": ["read-only"]}, observed[0]
            )
            self.assertEqual(observed[0], observed[2])
            self.assertEqual(observed[2], observed[4])
            expected_pairs = [
                {"model": "model-a", "reasoningEffort": "low"},
                {"model": "model-a", "reasoningEffort": "medium"},
                {"model": "model-b", "reasoningEffort": "high"},
            ]
            self.assertEqual(expected_pairs, observed[1])
            self.assertEqual(observed[1], observed[3])
            self.assertEqual(
                ["sqlite=False"] * 5,
                (root / "processes").read_text(encoding="utf-8").splitlines(),
            )

    def test_rejects_changed_argv_environment_and_stage_before_spawn(self) -> None:
        calls: list[dict[str, object]] = []

        def factory(**kwargs: object) -> object:
            calls.append(kwargs)
            raise AssertionError("must not spawn")

        executor = AppServerAccountEvidenceExecutorV2(client_factory=factory)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            executable = root / "codex"
            executable.write_text("x", encoding="utf-8")
            environment = self._environment(root)
            invalid = (
                ("future", ACCOUNT_ARGV, environment),
                ("requirements-a", ("app-server",), environment),
                (
                    "requirements-a",
                    ACCOUNT_ARGV,
                    {**environment, "EXTRA": "1"},
                ),
            )
            for stage, argv, candidate_environment in invalid:
                with self.subTest(stage=stage, argv=argv):
                    with self.assertRaises(EvidenceError):
                        executor.execute(
                            stage,
                            executable_path=str(executable),
                            argv=argv,
                            environment=candidate_environment,
                            timeout_seconds=30,
                        )
        self.assertEqual([], calls)

    def test_rejects_noncanonical_paths_before_spawn(self) -> None:
        calls: list[dict[str, object]] = []

        def factory(**kwargs: object) -> object:
            calls.append(kwargs)
            raise AssertionError("must not spawn")

        executor = AppServerAccountEvidenceExecutorV2(client_factory=factory)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            executable = root / "codex"
            executable.write_text("x", encoding="utf-8")
            environment = self._environment(root)
            with self.assertRaisesRegex(EvidenceError, "ACCOUNT_EXECUTABLE_INVALID"):
                executor.execute(
                    "requirements-a",
                    executable_path=str(root / "." / "missing" / ".." / "codex"),
                    argv=ACCOUNT_ARGV,
                    environment=environment,
                    timeout_seconds=30,
                )
            changed = dict(environment)
            changed["HOME"] = str(root / "home" / ".." / "home")
            with self.assertRaisesRegex(EvidenceError, "ACCOUNT_ENVIRONMENT_INVALID"):
                executor.execute(
                    "requirements-a",
                    executable_path=str(executable),
                    argv=ACCOUNT_ARGV,
                    environment=changed,
                    timeout_seconds=30,
                )
        self.assertEqual([], calls)

    def test_accepts_owned_non_writable_account_home_with_group_access(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            executable = root / "codex-snapshot"
            executable.write_text(
                """#!/usr/bin/env python3
import json
import os
import sys

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        result = {
            "userAgent": "fake-codex",
            "codexHome": os.environ["CODEX_HOME"],
            "platformFamily": "unix",
            "platformOs": "test",
        }
    elif method == "initialized":
        continue
    elif method == "configRequirements/read":
        result = {"requirements": None}
    else:
        raise SystemExit(7)
    print(json.dumps({"id": request["id"], "result": result}), flush=True)
""",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            environment = self._environment(root)
            Path(environment["HOME"]).chmod(0o750)

            observed = AppServerAccountEvidenceExecutorV2().execute(
                "requirements-a",
                executable_path=str(executable),
                argv=ACCOUNT_ARGV,
                environment=environment,
                timeout_seconds=30,
            )

            self.assertIsNone(observed)

    def test_rejects_group_writable_account_home(self) -> None:
        for mode in (0o770, 0o777):
            with self.subTest(mode=oct(mode)), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                executable = root / "codex-snapshot"
                executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                executable.chmod(0o700)
                environment = self._environment(root)
                Path(environment["HOME"]).chmod(mode)

                with self.assertRaisesRegex(
                    ValueError,
                    "owned non-writable directory",
                ):
                    AppServerAccountEvidenceExecutorV2().execute(
                        "requirements-a",
                        executable_path=str(executable),
                        argv=ACCOUNT_ARGV,
                        environment=environment,
                        timeout_seconds=30,
                    )

    def test_rejects_oversized_or_too_deep_raw_requirements_envelope(self) -> None:
        class Client:
            def __init__(self, result: object) -> None:
                self.result = result

            def call(self, _method: str, _params: object) -> object:
                return self.result

        oversized = {"requirements": None, "future": "x" * (1024 * 1024)}
        with self.assertRaisesRegex(EvidenceError, "MANAGED_REQUIREMENT_MALFORMED"):
            AppServerAccountEvidenceExecutorV2._requirements(Client(oversized))

        deep: object = None
        for _ in range(17):
            deep = {"value": deep}
        with self.assertRaisesRegex(EvidenceError, "MANAGED_REQUIREMENT_MALFORMED"):
            AppServerAccountEvidenceExecutorV2._requirements(
                Client({"requirements": None, "future": deep})
            )

    @staticmethod
    def _environment(root: Path) -> dict[str, str]:
        paths = {}
        for name in ("codex-home", "home", "tmp"):
            path = root / name
            path.mkdir(mode=0o700)
            paths[name] = str(path)
        return {
            "CODEX_HOME": paths["codex-home"],
            "HOME": paths["home"],
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": FIXED_PATH,
            "TMPDIR": paths["tmp"],
        }


if __name__ == "__main__":
    unittest.main()

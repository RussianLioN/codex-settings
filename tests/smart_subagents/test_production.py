from __future__ import annotations

import json
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
PLUGIN_SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.daemon import (  # noqa: E402
    ControllerProcessConfig,
)
from codex_smart_subagents.production import (  # noqa: E402
    build_production_runtime,
    materialize_reader_schema,
)
from codex_smart_subagents.catalog import Catalog  # noqa: E402
from codex_smart_subagents.identity import RequestContext  # noqa: E402
from codex_smart_subagents.service import SmartService  # noqa: E402
from codex_smart_subagents.state import RouteState  # noqa: E402
from tests.smart_subagents.fixtures import valid_plan  # noqa: E402


FAKE_CODEX = Path(__file__).with_name("test_production_fake_codex.py")


def git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repository), *arguments],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout.strip()
from codex_smart_subagents.runtime_executor import (  # noqa: E402
    READER_RESULT_SCHEMA,
)


class ProductionCompositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        auth = self.codex_home / "auth.json"
        auth.write_text('{"test":"credential"}\n', encoding="utf-8")
        auth.chmod(0o600)
        self.state_home = self.root / "state"
        self.controller = self.root / "controller"
        self.controller.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.controller.chmod(0o700)
        self.codex = self.root / "codex"
        self.codex.write_text(
            "#!/bin/sh\n"
            'if [ "${1:-}" = "--version" ]; then\n'
            "  echo 'codex-cli 0.144.4'\n"
            "  exit 0\n"
            "fi\n"
            "exit 7\n",
            encoding="utf-8",
        )
        self.codex.chmod(0o700)
        self.config = ControllerProcessConfig(
            codex_home=self.codex_home,
            state_home=self.state_home,
            catalog_path=PLUGIN_ROOT / "config" / "adaptive-subagents.toml",
            controller_executable=self.controller,
            real_codex=self.codex,
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_materializes_private_canonical_reader_schema_idempotently(self) -> None:
        parent = self.root / "contracts"
        parent.mkdir(mode=0o700)
        schema = parent / "reader.schema.json"

        materialize_reader_schema(schema)
        first_identity = (schema.stat().st_dev, schema.stat().st_ino)
        materialize_reader_schema(schema)

        self.assertEqual(first_identity, (schema.stat().st_dev, schema.stat().st_ino))
        self.assertEqual(0o400, stat.S_IMODE(schema.stat().st_mode))
        self.assertEqual(
            READER_RESULT_SCHEMA,
            json.loads(schema.read_text(encoding="utf-8")),
        )

        schema.chmod(0o600)
        schema.write_text('{"type":"null"}\n', encoding="utf-8")
        materialize_reader_schema(schema)
        self.assertEqual(READER_RESULT_SCHEMA, json.loads(schema.read_text()))
        self.assertEqual(0o400, stat.S_IMODE(schema.stat().st_mode))

    def test_builds_controller_executor_and_closes_owned_socket(self) -> None:
        runtime = build_production_runtime(self.config)
        socket_path = self.config.paths.socket_path
        try:
            self.assertEqual(3, runtime.route_workers)
            self.assertEqual("ok", runtime.store.integrity_check())
            self.assertTrue(socket_path.exists())
            schema = (
                self.config.paths.namespace_dir
                / "contracts"
                / "reader-result.schema.json"
            )
            self.assertTrue(schema.is_file())
            self.assertEqual(0o400, stat.S_IMODE(schema.stat().st_mode))
            self.assertEqual(
                0o700,
                stat.S_IMODE(
                    (self.config.paths.base_dir / "ns").stat().st_mode
                ),
            )
        finally:
            runtime.close()
        self.assertFalse(os.path.lexists(socket_path))

    def test_reader_route_runs_end_to_end_with_protocol_fake(self) -> None:
        repository = self.root / "repository"
        repository.mkdir()
        git(repository, "init", "-q")
        git(repository, "config", "user.name", "Codex Test")
        git(repository, "config", "user.email", "codex@example.invalid")
        (repository / "source.txt").write_text("source\n", encoding="utf-8")
        git(repository, "add", "source.txt")
        git(repository, "commit", "-qm", "initial")
        self.codex = FAKE_CODEX
        self.config = ControllerProcessConfig(
            codex_home=self.codex_home,
            state_home=self.state_home,
            catalog_path=PLUGIN_ROOT / "config" / "adaptive-subagents.toml",
            controller_executable=self.controller,
            real_codex=FAKE_CODEX,
        )
        runtime = build_production_runtime(self.config)
        catalog = Catalog.load(self.config.catalog_path)
        service = SmartService(runtime.store, catalog)
        status = subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(repository),
                "status",
                "--porcelain=v2",
                "-z",
                "--untracked-files=all",
            ],
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
        context = RequestContext(
            shell_session_id="cas1_" + "A" * 43,
            session_id="session-1",
            turn_id="turn-1",
            codex_home=str(self.codex_home.resolve()),
            repo_root=str(repository.resolve()),
            base_sha=git(repository, "rev-parse", "HEAD"),
            worktree_fingerprint=hashlib.sha256(status).hexdigest(),
        )
        payload = valid_plan()
        payload["turnBinding"] = runtime.store.issue_turn_binding(context)
        payload["catalogGeneration"] = catalog.generation
        try:
            plan = service.smart_plan(payload, context)
            service.smart_start(
                {"schemaVersion": "1", "routeId": plan["routeId"]},
                context,
            )

            self.assertTrue(runtime.engine.run_once())

            bundle = runtime.store.execution_bundle(plan["routeId"])
            diagnostics = {
                "terminal": bundle.route.terminal_result,
                "attempts": runtime.store.attempts_for_route(plan["routeId"]),
                "events": runtime.store.events_after(
                    plan["routeId"],
                    context,
                    0,
                    limit=100,
                ),
            }
            self.assertEqual(
                RouteState.SUCCEEDED,
                bundle.route.state,
                diagnostics,
            )
            self.assertEqual(
                "passed",
                bundle.route.terminal_result["validationState"],
            )
            self.assertEqual(
                "Снимок проверен сквозным испытанием.",
                bundle.nodes[0].result["summary"],
            )
            attempts = runtime.store.attempts_for_route(plan["routeId"])
            self.assertEqual("SUCCEEDED", attempts[0]["state"])
            self.assertEqual(
                bundle.nodes[0].selected_model,
                attempts[0]["attestation"]["observedModel"],
            )
            artifacts = runtime.store.runtime_artifacts(plan["routeId"])
            self.assertEqual("TERMINAL", artifacts[0]["state"])
            self.assertFalse(
                (Path(artifacts[0]["path"]) / "codex-home" / "auth.json").exists()
            )
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()

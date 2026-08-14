from __future__ import annotations

import json
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
PLUGIN_SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.daemon import (  # noqa: E402
    ControllerProcessConfig,
)
from codex_smart_subagents.production import (  # noqa: E402
    build_production_runtime,
    materialize_boundary_permission_snapshot,
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
        self.codex = FAKE_CODEX
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

    def test_boundary_snapshot_keeps_source_private_until_replace_failure_cleanup(
        self,
    ) -> None:
        parent = self.root / "contracts"
        parent.mkdir(mode=0o700)
        snapshot = parent / "boundary-permission-snapshot"
        observed_modes: list[int] = []

        class ReplaceFailure(RuntimeError):
            pass

        def fail_replace(
            source: str | os.PathLike[str],
            target: str | os.PathLike[str],
        ) -> None:
            del target
            observed_modes.append(stat.S_IMODE(Path(source).stat().st_mode))
            raise ReplaceFailure("forced replace failure")

        with mock.patch(
            "codex_smart_subagents.production.os.replace",
            side_effect=fail_replace,
        ):
            with self.assertRaises(ReplaceFailure):
                materialize_boundary_permission_snapshot(snapshot)

        self.assertEqual([0o700], observed_modes)
        self.assertFalse(os.path.lexists(snapshot))
        self.assertEqual(
            [],
            [
                item.name
                for item in parent.iterdir()
                if item.name.startswith(".boundary-")
            ],
        )

    def test_boundary_snapshot_final_modes_and_idempotency(self) -> None:
        parent = self.root / "contracts"
        parent.mkdir(mode=0o700)
        snapshot = parent / "boundary-permission-snapshot"

        first = materialize_boundary_permission_snapshot(snapshot)
        first_identity = (snapshot.stat().st_dev, snapshot.stat().st_ino)
        second = materialize_boundary_permission_snapshot(snapshot)

        self.assertEqual(first, second)
        self.assertEqual(
            first_identity,
            (snapshot.stat().st_dev, snapshot.stat().st_ino),
        )
        self.assertEqual(0o500, stat.S_IMODE(snapshot.stat().st_mode))
        self.assertEqual(
            0o400,
            stat.S_IMODE((snapshot / "read-probe.txt").stat().st_mode),
        )

    def test_boundary_snapshot_final_chmod_failure_removes_owned_publication(
        self,
    ) -> None:
        parent = self.root / "contracts"
        parent.mkdir(mode=0o700)
        snapshot = parent / "boundary-permission-snapshot"
        original_chmod = os.chmod

        class ChmodFailure(RuntimeError):
            pass

        def fail_final_chmod(
            target: str | os.PathLike[str],
            mode: int,
            *args: object,
            **kwargs: object,
        ) -> None:
            if Path(target) == snapshot and mode == 0o500:
                raise ChmodFailure("forced final chmod failure")
            original_chmod(target, mode, *args, **kwargs)

        with mock.patch(
            "codex_smart_subagents.production.os.chmod",
            side_effect=fail_final_chmod,
        ):
            with self.assertRaises(ChmodFailure):
                materialize_boundary_permission_snapshot(snapshot)

        self.assertFalse(os.path.lexists(snapshot))

    def test_boundary_snapshot_uses_valid_concurrent_publication_and_cleans_temp(
        self,
    ) -> None:
        parent = self.root / "contracts"
        parent.mkdir(mode=0o700)
        snapshot = parent / "boundary-permission-snapshot"
        expected = b"adaptive boundary classifier read probe\n"
        temporary_names: list[str] = []

        def publish_competing_snapshot(
            source: str | os.PathLike[str],
            target: str | os.PathLike[str],
        ) -> None:
            temporary_names.append(Path(source).name)
            competing = Path(target)
            competing.mkdir(mode=0o700)
            probe = competing / "read-probe.txt"
            probe.write_bytes(expected)
            probe.chmod(0o400)
            competing.chmod(0o500)
            raise FileExistsError("competing snapshot already exists")

        with mock.patch(
            "codex_smart_subagents.production.os.replace",
            side_effect=publish_competing_snapshot,
        ):
            result = materialize_boundary_permission_snapshot(snapshot)

        self.assertEqual(snapshot.resolve(strict=True), result)
        self.assertEqual(0o500, stat.S_IMODE(snapshot.stat().st_mode))
        self.assertEqual(
            0o400,
            stat.S_IMODE((snapshot / "read-probe.txt").stat().st_mode),
        )
        self.assertEqual(
            [],
            [
                parent / name
                for name in temporary_names
                if (parent / name).exists()
            ],
        )

    def test_builds_controller_executor_and_closes_owned_socket(self) -> None:
        runtime = build_production_runtime(self.config)
        socket_path = self.config.paths.socket_path
        try:
            self.assertEqual(2, runtime.route_workers)
            self.assertEqual(20, runtime.process_limiter.limit)
            self.assertEqual("ok", runtime.store.integrity_check())
            self.assertEqual([], runtime.recovery_report.to_wire()["errors"])
            self.assertIsNone(runtime.recovery_report.backup_path)
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
            boundary_snapshot = (
                self.config.paths.namespace_dir
                / "contracts"
                / "boundary-permission-snapshot"
            )
            self.assertEqual(
                0o500,
                stat.S_IMODE(boundary_snapshot.stat().st_mode),
            )
            self.assertEqual(
                0o400,
                stat.S_IMODE(
                    (boundary_snapshot / "read-probe.txt").stat().st_mode
                ),
            )
            self.assertIsNotNone(runtime.server.service.reclassifier)
        finally:
            runtime.close()
        self.assertFalse(os.path.lexists(socket_path))

    def test_boundary_plan_runs_one_production_reclassification(self) -> None:
        runtime = build_production_runtime(self.config)
        catalog = Catalog.load(self.config.catalog_path)
        context = RequestContext(
            shell_session_id="cas1_" + "C" * 43,
            session_id="session-boundary",
            turn_id="turn-boundary",
            codex_home=str(self.codex_home.resolve()),
            repo_root=str(REPO.resolve()),
            base_sha="a" * 40,
            worktree_fingerprint="b" * 64,
        )
        payload = valid_plan(catalog)
        payload["catalogGeneration"] = catalog.generation
        payload["turnBinding"] = runtime.store.issue_turn_binding(context)
        payload["nodes"][0]["assessment"]["delegation"] = {
            "q": {"min": 0, "max": 2},
            "p": {"min": 0, "max": 1},
            "v": {"min": 1, "max": 2},
            "o": {"min": 0, "max": 1},
        }
        try:
            plan = runtime.server.service.smart_plan(payload, context)
            self.assertEqual("delegate", plan["overallDisposition"])
            self.assertEqual(
                "certain_gain",
                plan["nodeDecisions"][0]["reasonCode"],
            )
        finally:
            runtime.close()

    def test_missing_boundary_model_degrades_only_boundary_nodes(self) -> None:
        visible = {
            "gpt-5.6-luna": frozenset({"low", "medium"}),
            "gpt-5.6-sol": frozenset({"high", "xhigh", "max"}),
        }
        with mock.patch(
            "codex_smart_subagents.production."
            "AppServerModelCatalogInspector.inspect",
            return_value=visible,
        ):
            runtime = build_production_runtime(self.config)
        catalog = Catalog.load(self.config.catalog_path)
        context = RequestContext(
            shell_session_id="cas1_" + "D" * 43,
            session_id="session-no-boundary-model",
            turn_id="turn-no-boundary-model",
            codex_home=str(self.codex_home.resolve()),
            repo_root=str(REPO.resolve()),
            base_sha="a" * 40,
            worktree_fingerprint="b" * 64,
        )
        payload = valid_plan(catalog)
        payload["catalogGeneration"] = catalog.generation
        payload["turnBinding"] = runtime.store.issue_turn_binding(context)
        payload["nodes"][0]["assessment"]["delegation"] = {
            "q": {"min": 0, "max": 2},
            "p": {"min": 0, "max": 1},
            "v": {"min": 1, "max": 2},
            "o": {"min": 0, "max": 1},
        }
        try:
            self.assertIsNone(runtime.server.service.reclassifier)
            self.assertEqual(3, runtime.route_workers)
            plan = runtime.server.service.smart_plan(payload, context)
            self.assertEqual("direct", plan["overallDisposition"])
            self.assertEqual(
                "reclassification_failed",
                plan["nodeDecisions"][0]["reasonCode"],
            )
        finally:
            runtime.close()

    def test_two_clean_starts_do_not_create_recovery_backups(self) -> None:
        backup_root = (
            self.config.paths.namespace_dir
            / "state"
            / "recovery-backups"
        )

        first = build_production_runtime(self.config)
        first.close()
        second = build_production_runtime(self.config)
        second.close()

        self.assertFalse(backup_root.exists())

    def test_build_queries_effective_requirements_through_app_server(self) -> None:
        marker = self.root / "app-server-called"
        traced_codex = self.root / "traced-codex"
        traced_codex.write_text(
            """#!/usr/bin/python3
import os
import sys
from pathlib import Path

if len(sys.argv) > 1 and sys.argv[1] == "app-server":
    Path(%r).write_text("called\\n", encoding="utf-8")
os.execv(%r, [%r, *sys.argv[1:]])
"""
            % (str(marker), str(FAKE_CODEX), str(FAKE_CODEX)),
            encoding="utf-8",
        )
        traced_codex.chmod(0o700)
        config = ControllerProcessConfig(
            codex_home=self.codex_home,
            state_home=self.state_home,
            catalog_path=PLUGIN_ROOT / "config" / "adaptive-subagents.toml",
            controller_executable=self.controller,
            real_codex=traced_codex,
        )

        runtime = build_production_runtime(config)
        try:
            self.assertEqual("called\n", marker.read_text(encoding="utf-8"))
        finally:
            runtime.close()

    def test_restart_with_controller_lock_proof_requeues_unexpired_lease(
        self,
    ) -> None:
        first = build_production_runtime(self.config)
        catalog = Catalog.load(self.config.catalog_path)
        service = SmartService(first.store, catalog)
        context = RequestContext(
            shell_session_id="shell-restart",
            session_id="session-restart",
            turn_id="turn-restart",
            codex_home=str(self.codex_home.resolve()),
            repo_root=str(REPO.resolve()),
            base_sha="a" * 40,
            worktree_fingerprint="b" * 64,
        )
        payload = valid_plan(catalog)
        payload["turnBinding"] = first.store.issue_turn_binding(context)
        payload["catalogGeneration"] = catalog.generation
        plan = service.smart_plan(payload, context)
        service.smart_start(
            {"schemaVersion": "1", "routeId": plan["routeId"]},
            context,
        )
        claim = first.store.claim_next_route(
            owner_id="controller-before-restart",
            pid=123,
            start_marker="before-restart",
            now=datetime.now(timezone.utc),
            lease_seconds=300,
        )
        self.assertIsNotNone(claim)
        first.close()

        second = build_production_runtime(self.config)
        try:
            self.assertEqual(1, second.recovery_report.requeued_routes)
            self.assertIsNotNone(second.recovery_report.backup_path)
            self.assertTrue(Path(second.recovery_report.backup_path).is_file())
            self.assertEqual(
                RouteState.QUEUED,
                second.store.execution_bundle(plan["routeId"]).route.state,
            )
        finally:
            second.close()

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
        payload = valid_plan(catalog)
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

    def test_writer_route_builds_quarantined_candidate_end_to_end(self) -> None:
        repository = self.root / "writer-repository"
        repository.mkdir()
        git(repository, "init", "-q")
        git(repository, "config", "user.name", "Codex Test")
        git(repository, "config", "user.email", "codex@example.invalid")
        (repository / "source.txt").write_text("source\n", encoding="utf-8")
        git(repository, "add", "source.txt")
        git(repository, "commit", "-qm", "initial")
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
            shell_session_id="cas1_" + "B" * 43,
            session_id="session-writer",
            turn_id="turn-writer",
            codex_home=str(self.codex_home.resolve()),
            repo_root=str(repository.resolve()),
            base_sha=git(repository, "rev-parse", "HEAD"),
            worktree_fingerprint=hashlib.sha256(status).hexdigest(),
        )
        payload = valid_plan(catalog)
        reader = payload["nodes"][0]
        reader["clientNodeId"] = "reader"
        writer = {
            **reader,
            "clientNodeId": "writer",
            "mission": "Измени source.txt в отдельном кандидате.",
            "role": "implementer",
            "dependencyIds": ["reader"],
            "artifactProfileId": catalog.opaque_id(
                "artifact",
                "candidate",
            ),
            "validationProfileId": catalog.opaque_id(
                "validation",
                "none",
            ),
            "riskFlags": ["writer_final_validation"],
        }
        payload["nodes"] = [reader, writer]
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
                "attempts": runtime.store.attempts_for_route(plan["routeId"]),
                "candidates": runtime.store.candidate_records(),
                "intents": runtime.store.pending_candidate_publications(),
            }
            self.assertEqual(
                RouteState.QUARANTINED,
                bundle.route.state,
                diagnostics,
            )
            self.assertTrue(
                bundle.route.terminal_result["artifactId"].startswith("art1_")
            )
            self.assertEqual(
                "not_applicable",
                bundle.route.terminal_result["validationState"],
            )
            self.assertEqual(
                "source\n",
                (repository / "source.txt").read_text(encoding="utf-8"),
            )
            writer_result = next(
                node.result for node in bundle.nodes if node.role == "implementer"
            )
            self.assertEqual(
                "Кандидат подготовлен сквозным испытанием.",
                writer_result["summary"],
            )
            self.assertEqual(4, len(runtime.store.runtime_artifacts(plan["routeId"])))
            candidates = runtime.store.candidate_records()
            self.assertEqual(1, len(candidates))
            self.assertEqual(
                bundle.route.terminal_result["artifactId"],
                candidates[0]["artifactId"],
            )
            self.assertEqual("not_applicable", candidates[0]["validationState"])
            self.assertEqual(
                "VALIDATION_QUARANTINED",
                candidates[0]["state"],
            )
            self.assertFalse(candidates[0]["trusted"])
            self.assertEqual([], runtime.store.pending_candidate_publications())
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()

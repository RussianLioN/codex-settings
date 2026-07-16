from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
PLUGIN_SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.admin import main  # noqa: E402
from codex_smart_subagents.controller import RuntimePaths  # noqa: E402
from codex_smart_subagents.identity import RequestContext  # noqa: E402
from codex_smart_subagents.installation_rollback import (  # noqa: E402
    RollbackError,
    RollbackPreflight,
)
from codex_smart_subagents.state import RouteState  # noqa: E402
from codex_smart_subagents.store import SmartStore  # noqa: E402


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def node() -> dict[str, object]:
    return {
        "clientNodeId": "reader_1",
        "role": "researcher",
        "mission": "Секретная миссия с абсолютным /private/source/path",
        "dependencyIds": [],
        "contextRefs": [],
        "scopeId": "scope_0123456789abcdef",
        "artifactProfileId": "artifact_0123456789abcdef",
        "validationProfileId": "validation_0123456789abcdef",
        "assessment": {"q": 1},
        "riskFlags": [],
        "selectedModel": "gpt-5.6-luna",
        "reasoningEffort": "low",
        "permissionProfileId": "permission_0123456789abcdef",
        "disposition": "delegate",
    }


class AdminTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.state_home = self.root / "state-home"
        self.environ = {
            "CODEX_HOME": str(self.codex_home),
            "XDG_STATE_HOME": str(self.state_home),
            "CODEX_ADAPTIVE_CATALOG": str(
                PLUGIN_ROOT / "config" / "adaptive-subagents.toml"
            ),
        }
        self.paths = RuntimePaths.for_codex_home(
            str(self.codex_home),
            state_home=self.state_home,
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def invoke(
        self,
        *arguments: str,
        now: datetime = NOW,
        environ: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, object], str]:
        output = io.StringIO()
        code = main(
            list(arguments),
            environ=self.environ if environ is None else environ,
            stdout=output,
            now=now,
        )
        raw = output.getvalue()
        self.assertEqual(1, len(raw.splitlines()))
        return code, json.loads(raw), raw

    def create_route(
        self,
        *,
        state: RouteState = RouteState.PLANNED,
        updated_at: datetime | None = None,
    ) -> str:
        for directory in (
            self.paths.base_dir,
            self.paths.base_dir / "ns",
            self.paths.namespace_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)
        store = SmartStore(self.paths.namespace_dir / "state")
        context = RequestContext(
            shell_session_id="shell-1",
            session_id="session-1",
            turn_id="turn-1",
            codex_home=str(self.codex_home.resolve()),
            repo_root="/private/source/path",
            base_sha="a" * 40,
            worktree_fingerprint="b" * 64,
        )
        route_id = store.create_route(
            request_context=context,
            request_key="request-1",
            request_hash="c" * 64,
            catalog_generation="cg1_0123456789abcdef",
            algorithm_version="route-v1",
            disposition="delegate",
            startable=True,
            expires_at=NOW + timedelta(days=1),
            plan_output={"secret": "token-value"},
            nodes=[node()],
        )
        if state is not RouteState.PLANNED:
            store.transition_route(
                route_id,
                context,
                state,
                event="test_transition",
                code="TEST",
                message="/private/source/path token-value",
            )
        store.close()
        if updated_at is not None:
            import sqlite3

            with closing(
                sqlite3.connect(
                    self.paths.namespace_dir
                    / "state"
                    / "smart-subagents.sqlite3"
                )
            ) as connection:
                connection.execute(
                    "update routes set updated_at = ? where route_id = ?",
                    (updated_at.isoformat(), route_id),
                )
                connection.commit()
        return route_id

    def create_coordination_record(
        self,
        route_id: str,
        *,
        shell_session_id: str = "shell-cleanup",
    ) -> tuple[Path, Path]:
        coordination = self.paths.namespace_dir / "coordination"
        coordination.mkdir(mode=0o700)
        token = hashlib.sha256(
            shell_session_id.encode()
        ).hexdigest()[:32]
        record = coordination / f"{token}.json"
        lock = coordination / f"{token}.lock"
        record.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "shellSessionId": shell_session_id,
                    "sessionId": "session",
                    "turnId": "turn",
                    "turnBinding": "tb1_" + "A" * 43,
                    "catalogGeneration": "cg1_0123456789abcdef",
                    "planCalled": True,
                    "routeId": route_id,
                    "disposition": "delegate",
                    "routeState": "CANCELLED",
                    "afterSequence": 0,
                    "continuationCount": 0,
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        lock.touch(mode=0o600)
        record.chmod(0o600)
        old = (NOW - timedelta(days=100)).timestamp()
        os.utime(record, (old, old))
        os.utime(lock, (old, old))
        return record, lock

    def test_invalid_environment_is_json_and_exit_two(self) -> None:
        code, envelope, _raw = self.invoke(
            "status",
            environ={"CODEX_HOME": "relative"},
        )

        self.assertEqual(2, code)
        self.assertEqual(
            {
                "schemaVersion",
                "ok",
                "command",
                "code",
                "message",
                "data",
            },
            set(envelope),
        )
        self.assertEqual("1", envelope["schemaVersion"])
        self.assertFalse(envelope["ok"])
        self.assertEqual("INVALID_ENVIRONMENT", envelope["code"])

    def test_status_missing_database_does_not_create_any_path(self) -> None:
        code, envelope, _raw = self.invoke("status")

        self.assertEqual(0, code)
        self.assertTrue(envelope["ok"])
        self.assertEqual("NOT_INITIALIZED", envelope["code"])
        self.assertFalse(self.state_home.exists())

    def test_symbolic_or_group_writable_codex_home_is_rejected(self) -> None:
        symbolic = self.root / "codex-home-link"
        symbolic.symlink_to(self.codex_home, target_is_directory=True)
        symbolic_code, symbolic_result, _raw = self.invoke(
            "status",
            environ={
                **self.environ,
                "CODEX_HOME": str(symbolic),
            },
        )
        self.codex_home.chmod(0o770)
        writable_code, writable_result, _raw = self.invoke("status")

        self.assertEqual(4, symbolic_code)
        self.assertEqual("UNSAFE_CODEX_HOME", symbolic_result["code"])
        self.assertEqual(4, writable_code)
        self.assertEqual("UNSAFE_CODEX_HOME", writable_result["code"])

    def test_codex_home_owned_by_another_user_is_rejected(self) -> None:
        with patch(
            "codex_smart_subagents.admin.os.getuid",
            return_value=os.getuid() + 1,
        ):
            code, envelope, _raw = self.invoke("status")

        self.assertEqual(4, code)
        self.assertEqual("UNSAFE_CODEX_HOME", envelope["code"])

    def test_status_reports_only_bounded_aggregates(self) -> None:
        self.create_route()

        code, envelope, raw = self.invoke("status")

        self.assertIn(code, {0, 1})
        self.assertEqual(1, envelope["data"]["routes"]["active"])
        self.assertEqual(
            {"gpt-5.6-luna": 1},
            envelope["data"]["nodes"]["byModel"],
        )
        self.assertNotIn("/private/source/path", raw)
        self.assertNotIn("token-value", raw)
        self.assertNotIn(str(self.codex_home), raw)

    def test_inspect_hashes_mission_and_omits_arbitrary_text(self) -> None:
        route_id = self.create_route()

        code, envelope, raw = self.invoke("inspect", route_id, "--limit", "10")

        self.assertEqual(0, code)
        self.assertEqual(route_id, envelope["data"]["route"]["routeId"])
        mission = envelope["data"]["nodes"][0]["mission"]
        self.assertGreater(mission["bytes"], 0)
        self.assertRegex(mission["sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("/private/source/path", raw)
        self.assertNotIn("Секретная миссия", raw)
        self.assertNotIn("token-value", raw)

    def test_explain_reports_bounded_routing_factors_without_task_text(
        self,
    ) -> None:
        route_id = self.create_route()

        code, envelope, raw = self.invoke("explain", route_id)

        self.assertEqual(0, code)
        self.assertEqual("OK", envelope["code"])
        self.assertEqual(route_id, envelope["data"]["routeId"])
        explained = envelope["data"]["nodes"][0]
        self.assertEqual("gpt-5.6-luna", explained["model"])
        self.assertEqual("low", explained["reasoningEffort"])
        self.assertEqual({"q": 1}, explained["assessment"])
        self.assertNotIn("/private/source/path", raw)
        self.assertNotIn("Секретная миссия", raw)
        self.assertNotIn("token-value", raw)

    def test_report_includes_bounded_evidence_and_omits_runtime_paths(
        self,
    ) -> None:
        route_id = self.create_route()
        runtime_root = self.paths.namespace_dir / "runtime"
        runtime_root.mkdir(mode=0o700)
        runtime = runtime_root / "private-runtime-name"
        store = SmartStore(self.paths.namespace_dir / "state")
        artifact_id = store.reserve_runtime_artifact(
            route_id=route_id,
            node_id="reader_1",
            kind="reader_runtime",
            path=runtime,
            allowed_root=runtime_root,
        )
        runtime.mkdir(mode=0o700)
        store.seal_runtime_artifact(artifact_id, terminal=True)
        store.close()

        code, envelope, raw = self.invoke("report", route_id, "--limit", "10")

        self.assertEqual(0, code)
        self.assertEqual(route_id, envelope["data"]["route"]["routeId"])
        self.assertEqual(artifact_id, envelope["data"]["artifacts"][0]["artifactId"])
        self.assertNotIn(str(runtime_root), raw)
        self.assertNotIn("private-runtime-name", raw)
        self.assertNotIn("/private/source/path", raw)

    def test_metrics_are_low_cardinality_and_have_no_route_identifiers(
        self,
    ) -> None:
        route_id = self.create_route()
        store = SmartStore(self.paths.namespace_dir / "state")
        attempt_id = store.begin_attempt(
            route_id=route_id,
            node_id="reader_1",
            model="gpt-5.6-luna",
            reasoning_effort="low",
            permission_profile_id="permission_0123456789abcdef",
            pid=0,
            argv_fingerprint="d" * 64,
            permission_probe_id="pc1_" + "A" * 43,
        )
        store.complete_attempt(
            attempt_id,
            state="SUCCEEDED",
            result={
                "summary": "/private/source/path token-value",
                "fingerprint": "e" * 64,
                "validationState": "passed",
                "artifactId": "",
                "usage": {
                    "inputTokens": 120,
                    "cachedInputTokens": 20,
                    "outputTokens": 30,
                    "reasoningOutputTokens": 5,
                },
            },
            attestation={},
        )
        store.close()

        code, envelope, raw = self.invoke("metrics")

        self.assertEqual(0, code)
        self.assertEqual(1, envelope["data"]["routes"]["total"])
        self.assertEqual(
            {"researcher": 1},
            envelope["data"]["nodes"]["byRole"],
        )
        self.assertEqual(
            {"gpt-5.6-luna": 1},
            envelope["data"]["nodes"]["byModel"],
        )
        self.assertEqual(
            {
                "reportedAttempts": 1,
                "inputTokens": 120,
                "cachedInputTokens": 20,
                "outputTokens": 30,
                "reasoningOutputTokens": 5,
            },
            envelope["data"]["attempts"]["usage"],
        )
        self.assertNotIn(route_id, raw)
        self.assertNotIn("/private/source/path", raw)
        self.assertNotIn("token-value", raw)

        inspect_code, inspected, inspect_raw = self.invoke(
            "inspect",
            route_id,
        )
        self.assertEqual(0, inspect_code)
        self.assertEqual(
            {
                "inputTokens": 120,
                "cachedInputTokens": 20,
                "outputTokens": 30,
                "reasoningOutputTokens": 5,
            },
            inspected["data"]["attempts"][0]["usage"],
        )
        self.assertNotIn("/private/source/path", inspect_raw)
        self.assertNotIn("token-value", inspect_raw)

    def test_cancel_uses_store_transition_and_is_idempotent(self) -> None:
        route_id = self.create_route()

        first_code, first, _raw = self.invoke("cancel", route_id)
        second_code, second, _raw = self.invoke("cancel", route_id)

        self.assertEqual(0, first_code)
        self.assertEqual("CANCEL_REQUESTED", first["code"])
        self.assertEqual("CANCELLED", first["data"]["newState"])
        self.assertEqual(0, second_code)
        self.assertEqual("ALREADY_TERMINAL", second["code"])

    def test_recover_supports_read_only_plan_and_backed_up_apply(self) -> None:
        route_id = self.create_route()
        backup_root = (
            self.paths.namespace_dir
            / "state"
            / "recovery-backups"
        )

        plan_code, plan, _raw = self.invoke("recover", "--dry-run")

        self.assertEqual(0, plan_code)
        self.assertEqual("dry-run", plan["data"]["mode"])
        self.assertTrue(plan["data"]["ready"])
        self.assertFalse(plan["data"]["recovery"]["backupCreated"])
        self.assertFalse(backup_root.exists())

        apply_code, applied, raw = self.invoke("recover", "--apply")

        self.assertEqual(0, apply_code)
        self.assertEqual("apply", applied["data"]["mode"])
        self.assertFalse(applied["data"]["recovery"]["backupCreated"])
        self.assertFalse(backup_root.exists())
        self.assertNotIn(str(backup_root), raw)

        store = SmartStore(self.paths.namespace_dir / "state")
        store.begin_attempt(
            route_id=route_id,
            node_id="reader_1",
            model="gpt-5.6-luna",
            reasoning_effort="low",
            permission_profile_id="permission_0123456789abcdef",
            pid=0,
            argv_fingerprint="f" * 64,
            permission_probe_id="pending",
        )
        store.close()

        changed_code, changed, changed_raw = self.invoke(
            "recover",
            "--apply",
        )

        self.assertEqual(0, changed_code)
        self.assertTrue(changed["data"]["recovery"]["backupCreated"])
        self.assertEqual(1, changed["data"]["recovery"]["closedAttempts"])
        self.assertEqual(1, len(list(backup_root.glob("*.sqlite3"))))
        self.assertNotIn(str(backup_root), changed_raw)

    def test_recover_apply_is_blocked_by_controller_lock(self) -> None:
        self.create_route()
        self.paths.run_dir.mkdir(mode=0o700)
        descriptor = os.open(
            self.paths.lock_path,
            os.O_RDWR | os.O_CREAT,
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            code, envelope, _raw = self.invoke("recover", "--apply")
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

        self.assertEqual(4, code)
        self.assertEqual("CONTROLLER_ACTIVE", envelope["code"])

    def test_rollback_dry_run_and_apply_are_bounded_and_path_free(self) -> None:
        secret = self.root / "secret-installation-path"
        context = SimpleNamespace(
            database_path=secret / "database.sqlite3",
            quarantine_path=secret / "quarantine",
            backups_path=secret / "backups",
        )
        preflight = RollbackPreflight(
            smart_mode_disabled=True,
            controller_stopped=True,
            active_routes=0,
            active_attempts=0,
        )
        manifest = {"codexBinary": str(self.root / "bin" / "codex")}
        with (
            patch(
                "codex_smart_subagents.admin.load_manifest",
                return_value=manifest,
            ),
            patch(
                "codex_smart_subagents.admin.RollbackContext.from_installation",
                return_value=context,
            ),
            patch(
                "codex_smart_subagents.admin.probe_rollback_preflight",
                return_value=preflight,
            ),
            patch(
                "codex_smart_subagents.admin.plan_rollback",
                return_value={"status": "planned"},
            ) as planned,
            patch(
                "codex_smart_subagents.admin.apply_rollback",
                return_value={"status": "rolled_back"},
            ) as applied,
        ):
            dry_code, dry, dry_raw = self.invoke(
                "rollback",
                "--dry-run",
            )
            apply_code, result, apply_raw = self.invoke(
                "rollback",
                "--apply",
            )

        self.assertEqual(0, dry_code)
        self.assertEqual("dry-run", dry["data"]["mode"])
        self.assertTrue(dry["data"]["ready"])
        self.assertEqual(5, len(dry["data"]["actions"]))
        self.assertEqual(0, apply_code)
        self.assertEqual("apply", result["data"]["mode"])
        planned.assert_called_once()
        applied.assert_called_once()
        self.assertNotIn(str(secret), dry_raw)
        self.assertNotIn(str(secret), apply_raw)
        self.assertNotIn(manifest["codexBinary"], dry_raw)

    def test_rollback_error_does_not_expose_manifest_path(self) -> None:
        leaked = str(self.codex_home / "private-manifest")
        with patch(
            "codex_smart_subagents.admin.load_manifest",
            side_effect=RollbackError(
                "ROLLBACK_MANIFEST_MISSING",
                leaked,
            ),
        ):
            code, envelope, raw = self.invoke(
                "rollback",
                "--dry-run",
            )

        self.assertEqual(3, code)
        self.assertEqual("ROLLBACK_MANIFEST_MISSING", envelope["code"])
        self.assertNotIn(leaked, raw)

    def test_route_identifier_is_strict_and_not_found_is_exit_three(self) -> None:
        invalid_code, invalid, _raw = self.invoke("inspect", "rt1_bad")
        missing = "rt1_" + "A" * 43
        missing_code, missing_result, _raw = self.invoke("inspect", missing)

        self.assertEqual(2, invalid_code)
        self.assertEqual("INVALID_ROUTE_ID", invalid["code"])
        self.assertEqual(3, missing_code)
        self.assertEqual("ROUTE_NOT_FOUND", missing_result["code"])

    def test_doctor_blocks_unsafe_database_permissions(self) -> None:
        self.create_route()
        database = (
            self.paths.namespace_dir / "state" / "smart-subagents.sqlite3"
        )
        database.chmod(0o644)

        code, envelope, raw = self.invoke("doctor")

        self.assertEqual(4, code)
        self.assertEqual("BLOCKED", envelope["code"])
        self.assertIn("UNSAFE_DATABASE", raw)
        self.assertNotIn(str(database), raw)

    def test_cleanup_removes_only_registered_old_terminal_runtime(self) -> None:
        route_id = self.create_route(
            state=RouteState.CANCELLED,
            updated_at=NOW - timedelta(days=100),
        )
        runtime_root = self.paths.namespace_dir / "runtime"
        runtime_root.mkdir(mode=0o700)
        candidate = runtime_root / "registered-runtime"
        unknown = runtime_root / "unknown-runtime"
        quarantine = runtime_root / "quarantine-runtime"
        for directory in (candidate, unknown, quarantine):
            directory.mkdir(mode=0o700)
            (directory / "result.json").write_text(
                "private",
                encoding="utf-8",
            )
            (directory / "result.json").chmod(0o600)

        store = SmartStore(self.paths.namespace_dir / "state")
        registered = store.reserve_runtime_artifact(
            route_id=route_id,
            node_id="reader_1",
            kind="reader_runtime",
            path=runtime_root / "fresh-placeholder",
            allowed_root=runtime_root,
        )
        import sqlite3

        with closing(sqlite3.connect(store.path)) as connection:
            info = candidate.stat()
            connection.execute(
                """
                update runtime_artifacts
                set path = ?, state = 'TERMINAL', device = ?, inode = ?,
                    updated_at = ?
                where artifact_id = ?
                """,
                (
                    str(candidate),
                    info.st_dev,
                    info.st_ino,
                    (NOW - timedelta(days=100)).isoformat(),
                    registered,
                ),
            )
            connection.execute(
                """
                insert into runtime_artifacts (
                  artifact_id, route_id, node_id, kind, path, allowed_root,
                  state, device, inode, created_at, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "ra1_" + "Q" * 43,
                    route_id,
                    "reader_1",
                    "quarantine",
                    str(quarantine),
                    str(runtime_root),
                    "TERMINAL",
                    quarantine.stat().st_dev,
                    quarantine.stat().st_ino,
                    (NOW - timedelta(days=100)).isoformat(),
                    (NOW - timedelta(days=100)).isoformat(),
                ),
            )
            connection.commit()
        store.close()

        dry_code, dry, _raw = self.invoke("cleanup", "--dry-run")
        self.assertEqual(1, dry_code)
        self.assertEqual(1, dry["data"]["runtime"]["eligible"])
        self.assertTrue(candidate.exists())

        apply_code, applied, _raw = self.invoke("cleanup", "--apply")
        self.assertEqual(1, apply_code)
        self.assertEqual(1, applied["data"]["runtime"]["removed"])
        self.assertFalse(candidate.exists())
        self.assertTrue(unknown.exists())
        self.assertTrue(quarantine.exists())

        import sqlite3

        database = (
            self.paths.namespace_dir / "state" / "smart-subagents.sqlite3"
        )
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                """
                update runtime_artifacts
                set state = 'TERMINAL', device = 1, inode = 1
                where artifact_id = ?
                """,
                (registered,),
            )
            connection.commit()
        missing_code, missing, _raw = self.invoke("cleanup", "--dry-run")
        self.assertEqual(1, missing_code)
        self.assertGreaterEqual(missing["data"]["runtime"]["skipped"], 1)

    def test_cleanup_removes_registered_validation_runtime(self) -> None:
        route_id = self.create_route(
            state=RouteState.CANCELLED,
            updated_at=NOW - timedelta(days=100),
        )
        validation_root = self.paths.namespace_dir / "validation"
        validation_root.mkdir(mode=0o700)
        validation = validation_root / "registered-validation"

        store = SmartStore(self.paths.namespace_dir / "state")
        artifact_id = store.reserve_runtime_artifact(
            route_id=route_id,
            node_id="reader_1",
            kind="validation_runtime",
            path=validation,
            allowed_root=validation_root,
        )
        validation.mkdir(mode=0o700)
        proof = validation / "proof.json"
        proof.write_text("private", encoding="utf-8")
        proof.chmod(0o600)
        sealed = store.seal_runtime_artifact(
            artifact_id,
            terminal=True,
        )
        self.assertEqual("TERMINAL", sealed["state"])
        store.close()

        code, envelope, _raw = self.invoke("cleanup", "--apply")

        self.assertEqual(0, code)
        self.assertEqual(1, envelope["data"]["runtime"]["eligible"])
        self.assertEqual(1, envelope["data"]["runtime"]["removed"])
        self.assertFalse(validation.exists())

    def test_cleanup_removes_strict_old_coordination_record(self) -> None:
        route_id = self.create_route(
            state=RouteState.CANCELLED,
            updated_at=NOW - timedelta(days=100),
        )
        record, lock = self.create_coordination_record(route_id)

        code, envelope, _raw = self.invoke("cleanup", "--apply")

        self.assertEqual(0, code)
        self.assertEqual(1, envelope["data"]["coordination"]["removed"])
        self.assertFalse(record.exists())
        self.assertTrue(lock.exists())

        repeated_code, repeated, _raw = self.invoke("cleanup", "--apply")
        self.assertEqual(0, repeated_code)
        self.assertEqual(0, repeated["data"]["coordination"]["removed"])
        self.assertTrue(lock.exists())

    def test_cleanup_skips_coordination_record_while_lock_is_busy(self) -> None:
        route_id = self.create_route(
            state=RouteState.CANCELLED,
            updated_at=NOW - timedelta(days=100),
        )
        record, lock = self.create_coordination_record(
            route_id,
            shell_session_id="shell-busy",
        )
        descriptor = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code, envelope, _raw = self.invoke("cleanup", "--apply")
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

        self.assertEqual(1, code)
        self.assertGreaterEqual(
            envelope["data"]["coordination"]["skipped"],
            1,
        )
        self.assertTrue(record.exists())

    def test_executable_runs_from_unrelated_working_directory(self) -> None:
        executable = (
            PLUGIN_ROOT / "bin" / "codex-smart-subagents-admin"
        )
        completed = subprocess.run(
            [str(executable), "status"],
            cwd=self.root,
            env={**os.environ, **self.environ},
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(0, completed.returncode)
        self.assertEqual(1, len(completed.stdout.splitlines()))
        self.assertEqual(
            "NOT_INITIALIZED",
            json.loads(completed.stdout)["code"],
        )
        self.assertEqual("", completed.stderr)


if __name__ == "__main__":
    unittest.main()

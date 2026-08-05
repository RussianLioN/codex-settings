from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    GatewayRuntimeBindingV2,
)
from codex_smart_subagents.production_runtime_v2 import (  # noqa: E402
    ProductionRuntimeV2,
    build_production_runtime_v2,
    ProductionRuntimeV2Error,
    accepting_controller_from_binding_v2,
    database_identity_from_binding_v2,
)
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    QueuedStartDispatchV2,
    RequestContextV2,
)


class ProductionRuntimeV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="cspr2-")
        root = Path(self.temporary.name).resolve()
        self.state_home = root / "state"
        self.state_home.mkdir(mode=0o700)
        self.marketplace = root / "marketplace"
        self.marketplace.mkdir(mode=0o700)
        self.database = root / "smart-subagents.sqlite3"
        activation_fingerprint = "a" * 64
        activation_id = "act2_" + activation_fingerprint
        compatibility = "b" * 64
        self.database_row = {
            "database_id": "db2_" + "c" * 32,
            "activation_binding_nonce": "d" * 64,
            "activation_id": activation_id,
            "activation_fingerprint": activation_fingerprint,
            "created_operation_id": "op2_" + "e" * 32,
            "created_at": "2026-07-18T12:00:00.000000Z",
        }
        self.controller_row = {
            "controller_identity": "f" * 64,
            "instance_id": "ci2_" + "1" * 32,
            "controller_start_id": "cs2_" + "2" * 32,
            "controller_pid": os.getpid(),
            "controller_process_start_marker": "process-start",
            "controller_process_group_id": os.getpgrp(),
            "control_epoch": 9,
            "activation_id": activation_id,
            "activation_fingerprint": activation_fingerprint,
            "compatibility_fingerprint": compatibility,
            "routing_policy_fingerprint": "3" * 64,
            "bundled_catalog_fingerprint": "4" * 64,
            "socket_path": str(root / "controller.sock"),
            "socket_device": 1,
            "socket_inode": 2,
            "socket_owner_uid": os.getuid(),
            "socket_owner_gid": os.getgid(),
            "socket_mode": "0600",
            "updated_at": "2026-07-18T12:00:01+00:00",
        }
        self.binding = GatewayRuntimeBindingV2(
            activation_id=activation_id,
            activation_fingerprint=activation_fingerprint,
            compatibility_fingerprint=compatibility,
            control_epoch=9,
            state_home=self.state_home,
            marketplace_path=self.marketplace,
            database_path=self.database,
            database_identity_row=self.database_row,
            controller_row=self.controller_row,
            interface_evidence={"subject": {}},
            activation_identity={"bundledCatalogFingerprint": "4" * 64},
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_binding_projects_exact_store_identity_and_controller(self) -> None:
        identity = database_identity_from_binding_v2(self.binding)
        controller = accepting_controller_from_binding_v2(self.binding)

        self.assertEqual(self.database_row["database_id"], identity.database_id)
        self.assertEqual(
            self.database_row["created_operation_id"],
            identity.created_operation_id,
        )
        self.assertEqual(
            self.controller_row["controller_identity"],
            controller.controller_identity,
        )
        self.assertEqual(9, controller.control_epoch)
        self.assertEqual("0600", controller.socket_mode)

    def test_close_is_idempotent_and_closes_store_after_dispatcher_error(self) -> None:
        events: list[str] = []

        class Dispatcher:
            def close(self) -> None:
                events.append("dispatcher")
                raise RuntimeError("dispatcher close failed")

        class Store:
            def close(self) -> None:
                events.append("store")

        runtime = ProductionRuntimeV2(
            provider=object(),
            binding=self.binding,
            policy_bundle=object(),
            store=Store(),
            service=object(),
            runtime=object(),
            server=object(),
            dispatcher=Dispatcher(),
        )

        with self.assertRaisesRegex(RuntimeError, "dispatcher close failed"):
            runtime.close()
        runtime.close()

        self.assertEqual(["dispatcher", "store"], events)

    def test_build_preserves_original_error_and_completes_cleanup_cascade(self) -> None:
        events: list[str] = []

        class Store:
            def queued_start_dispatches(self):
                return ()

            def record_account_evidence_terminal(
                self, *_args: object, **_kwargs: object
            ) -> None:
                raise AssertionError("пустая очередь не терминализируется")

            def close(self) -> None:
                events.append("store")

        class Dispatcher:
            def submit(self, *_args: object) -> bool:
                return True

            def close(self) -> None:
                events.append("dispatcher")
                raise RuntimeError("dispatcher close failed")

        class Provider:
            def runtime_binding(self):
                return self_binding

            def activation_gate(self):
                return {"gateFingerprint": "7" * 64}

            def request_context(self):
                raise AssertionError("сервер не построен")

        self_binding = self.binding
        store = Store()
        dispatcher = Dispatcher()
        policy = SimpleNamespace(router=SimpleNamespace(evaluate=lambda value: value))
        recovery = SimpleNamespace(
            run=lambda *, apply: SimpleNamespace(ok=True, blockers=())
        )
        original = LookupError("server construction failed")
        module = sys.modules[build_production_runtime_v2.__module__]
        with (
            patch.object(module, "load_policy_bundle_v2", return_value=policy),
            patch.object(module, "_read_bundled_catalog", return_value={}),
            patch.object(module, "SmartStoreV2", return_value=store),
            patch.object(module, "RecoverySuiteV2", return_value=recovery),
            patch.object(module, "SmartServiceV2", return_value=object()),
            patch.object(module, "SmartTurnRuntimeV2", return_value=object()),
            patch.object(module, "MCPServerV2", side_effect=original),
        ):
            with self.assertRaises(LookupError) as captured:
                build_production_runtime_v2(
                    provider=Provider(),
                    environment={
                        "HOME": str(Path(self.temporary.name).resolve()),
                        "TMPDIR": str(Path(self.temporary.name).resolve()),
                    },
                    dispatcher_factory=lambda *_args: dispatcher,
                )

        self.assertIs(original, captured.exception)
        self.assertEqual(["dispatcher", "store"], events)
        self.assertTrue(
            any("dispatcher close failed" in note for note in original.__notes__)
        )

    def test_binding_projection_rejects_missing_or_naive_time(self) -> None:
        row = dict(self.database_row)
        row["created_at"] = "2026-07-18T12:00:00"
        malformed = GatewayRuntimeBindingV2(
            **{**self.binding.__dict__, "database_identity_row": row}
        )
        with self.assertRaises(ProductionRuntimeV2Error):
            database_identity_from_binding_v2(malformed)

    def test_managed_resume_rejects_invalid_root_identity(self) -> None:
        class Provider:
            def runtime_binding(self):
                return self_binding

        self_binding = self.binding
        policy = SimpleNamespace(router=SimpleNamespace(evaluate=lambda value: value))
        module = sys.modules[build_production_runtime_v2.__module__]
        with (
            patch.object(module, "load_policy_bundle_v2", return_value=policy),
            patch.object(module, "_read_bundled_catalog", return_value={}),
            self.assertRaisesRegex(
                ProductionRuntimeV2Error,
                "MANAGED_ROOT_IDENTITY_UNAVAILABLE",
            ),
        ):
            build_production_runtime_v2(
                provider=Provider(),
                environment={
                    "HOME": str(Path(self.temporary.name).resolve()),
                    "TMPDIR": str(Path(self.temporary.name).resolve()),
                    "CODEX_SMART_LAUNCH_KIND": "resume",
                    "CODEX_SMART_ROOT_PID": "not-a-pid",
                    "CODEX_SMART_ROOT_START_MARKER": "process-start",
                },
                dispatcher_factory=lambda *_args: object(),
            )

    def test_build_recovers_queued_starts_before_server_becomes_ready(self) -> None:
        events: list[object] = []
        context = RequestContextV2(
            shell_session_id="shell",
            session_id="session",
            turn_id="turn",
            codex_home=str(Path(self.temporary.name).resolve()),
            repo_root=str(Path(self.temporary.name).resolve()),
            base_sha="1" * 64,
            worktree_fingerprint="2" * 64,
            activation_fingerprint="a" * 64,
            compatibility_fingerprint="b" * 64,
            issued_control_epoch=8,
        )
        start_request_id = "sr2_" + "d" * 32
        queued = QueuedStartDispatchV2(
            start_request_id=start_request_id,
            evidence_job_id="aej2_" + "e" * 32,
            deadline_at=datetime.now(timezone.utc) + timedelta(seconds=60),
            request_context=context,
        )

        class Store:
            def queued_start_dispatches(self):
                events.append("queued")
                return (queued,)

            def record_account_evidence_terminal(
                self, *args: object, **kwargs: object
            ) -> None:
                raise AssertionError((args, kwargs))

            def close(self) -> None:
                events.append("store-close")

        class Dispatcher:
            def submit(
                self,
                identifier: str,
                request_context: RequestContextV2,
            ) -> bool:
                events.append(("submit", identifier, request_context))
                return True

            def close(self) -> None:
                events.append("dispatcher-close")

        class Provider:
            def runtime_binding(self):
                return self_binding

            def activation_gate(self):
                return {"gateFingerprint": "7" * 64}

            def request_context(self):
                return context

        self_binding = self.binding
        store = Store()
        dispatcher = Dispatcher()
        server_arguments: dict[str, object] = {}
        policy = SimpleNamespace(
            router=SimpleNamespace(evaluate=lambda value: value),
        )
        recovery = SimpleNamespace(
            run=lambda *, apply: SimpleNamespace(ok=True, blockers=())
        )

        def dispatcher_factory(*_args: object) -> Dispatcher:
            events.append("dispatcher")
            return dispatcher

        def server_factory(**kwargs: object) -> object:
            server_arguments.update(kwargs)
            events.append("server")
            return object()

        module = sys.modules[build_production_runtime_v2.__module__]
        with (
            patch.object(module, "load_policy_bundle_v2", return_value=policy),
            patch.object(module, "_read_bundled_catalog", return_value={}),
            patch.object(module, "SmartStoreV2", return_value=store),
            patch.object(module, "RecoverySuiteV2", return_value=recovery),
            patch.object(module, "SmartServiceV2", return_value=object()),
            patch.object(module, "SmartTurnRuntimeV2", return_value=object()),
            patch.object(module, "MCPServerV2", side_effect=server_factory),
        ):
            production = build_production_runtime_v2(
                provider=Provider(),
                environment={
                    "HOME": str(Path(self.temporary.name).resolve()),
                    "TMPDIR": str(Path(self.temporary.name).resolve()),
                },
                dispatcher_factory=dispatcher_factory,
            )

        self.assertEqual("dispatcher", events[0])
        self.assertEqual("queued", events[1])
        self.assertEqual(("submit", start_request_id, context), events[2])
        self.assertEqual(8, context.issued_control_epoch)
        self.assertEqual(9, self.binding.control_epoch)
        self.assertEqual("server", events[3])
        self.assertNotIn("routing_input_validator", server_arguments)
        production.close()

    def test_expired_queued_start_is_failed_without_dispatch(self) -> None:
        context = RequestContextV2(
            shell_session_id="shell",
            session_id="session",
            turn_id="turn",
            codex_home="/private/codex-home",
            repo_root="/private/repo",
            base_sha="1" * 64,
            worktree_fingerprint="2" * 64,
            activation_fingerprint="a" * 64,
            compatibility_fingerprint="b" * 64,
            issued_control_epoch=9,
        )
        now = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
        queued = QueuedStartDispatchV2(
            start_request_id="sr2_" + "d" * 32,
            evidence_job_id="aej2_" + "e" * 32,
            deadline_at=now,
            request_context=context,
        )
        terminalized: list[tuple[object, ...]] = []

        class Store:
            def queued_start_dispatches(self):
                return (queued,)

            def record_account_evidence_terminal(self, *args: object, **kwargs: object):
                terminalized.append((args, kwargs))

        class Dispatcher:
            def submit(self, *_args: object) -> None:
                raise AssertionError("истёкшая заявка не должна подаваться")

        module = sys.modules[build_production_runtime_v2.__module__]
        restored = module.restore_queued_start_requests_v2(
            store=Store(),
            dispatcher=Dispatcher(),
            now=now,
        )

        self.assertEqual(0, restored)
        self.assertEqual(
            "REQUEST_DEADLINE_EXCEEDED", terminalized[0][1]["failure_code"]
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.candidate_controller_v2 import (  # noqa: E402
    CandidateControllerV2Error,
    load_candidate_controller_config_v2,
    serve_candidate_controller_v2,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.candidate_ready_channel_v2 import (  # noqa: E402
    CandidateDispatchIntentReceiptV2,
    CandidateReadyBootstrapV2,
    CandidateSpawnActionV2,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
)


class _FakeServer:
    def __init__(self, **arguments) -> None:
        self.arguments = arguments
        self.handler = None
        self.observer = None
        self.closed = False
        self.database_path = None
        self.accept_ready = True

    def bind_lifecycle_handler(self, handler, *, response_observer=None) -> None:
        if self.handler is not None and self.handler is not handler:
            raise AssertionError("candidate handler was replaced")
        self.handler = handler
        self.observer = response_observer

    def start_candidate(self, *, database_path: Path):
        self.database_path = database_path
        return object()

    def serve_forever(self) -> None:
        return None

    def wait_until_ready(self, timeout: float) -> bool:
        return self.accept_ready and timeout > 0

    def close(self) -> None:
        self.closed = True


class _Protocol:
    def __init__(self, **arguments) -> None:
        self.arguments = arguments

    def handle(self, request):
        return {"request": request}


class _Application:
    def __init__(self, health) -> None:
        self.health = health
        self.waited = False
        self.closed = False

    def wait(self) -> None:
        self.waited = True

    def close(self) -> None:
        self.closed = True
        self.health.close()


class _DeadlineInspector:
    def __init__(self) -> None:
        self.calls = 0

    def inspect(self):
        self.calls += 1
        raise OperationDeadlineExceededV2(
            code="ROOT_OPERATION_EXPIRED",
            operation="candidate-controller",
            phase="model-list-cleanup",
            deadline_kind="root",
            configured_timeout_nanoseconds=5_000_000_000,
            elapsed_monotonic_nanoseconds=5_000_000_001,
        )


class _FakeReadyChannel:
    def __init__(
        self,
        events: list[str],
        *,
        registered: bool = True,
        fail_after_registration: bool = False,
    ) -> None:
        self.events = events
        self.registered = registered
        self.closed = False
        self.accepted = False
        self.state = "LISTENING"
        self.fail_after_registration = fail_after_registration

    def wait_until_registered(self, timeout: float) -> bool:
        self.events.append("ready-wait")
        if self.fail_after_registration:
            self.state = "FAILED"
        return self.registered and timeout > 0

    def remaining_seconds(self) -> float:
        return 12.0

    def mark_accepted(self) -> None:
        self.events.append("ready-accepted")
        self.accepted = True
        self.state = "ACCEPTED"
        self.close()

    def close(self) -> None:
        if not self.closed:
            self.events.append("ready-close")
            self.closed = True


class CandidateControllerV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="cscv2-")
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.state_home = self.root / "state"
        self.state_home.mkdir(mode=0o700)
        self.database_id = "db2_" + "1" * 32
        database_parent = self.state_home / "databases" / self.database_id
        database_parent.mkdir(parents=True, mode=0o700)
        (self.state_home / "databases").chmod(0o700)
        self.database_path = database_parent / "smart-subagents.sqlite3"
        self.database_path.write_bytes(b"prepared")
        self.database_path.chmod(0o600)
        self.activation_id = "act2_" + "2" * 64
        self.activation_dir = (
            self.codex_home
            / "managed"
            / "codex-smart-subagents-v2"
            / "activations"
            / self.activation_id
        )
        self.plugin_root = (
            self.activation_dir / "marketplace" / "plugins" / "codex-smart-subagents"
        )
        self.plugin_root.mkdir(parents=True, mode=0o700)
        for parent in (
            self.codex_home / "managed",
            self.codex_home / "managed" / "codex-smart-subagents-v2",
            self.codex_home / "managed" / "codex-smart-subagents-v2" / "activations",
            self.activation_dir,
            self.activation_dir / "marketplace",
            self.activation_dir / "marketplace" / "plugins",
        ):
            parent.chmod(0o700)
        self.snapshot = self.root / "snapshot-codex"
        self.snapshot.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.snapshot.chmod(0o500)
        self.wrapper = self.root / "codex-smart"
        self.wrapper.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.wrapper.chmod(0o500)
        self.operation_id = "op2_" + "3" * 32
        self.controller_start_id = "cs2_" + "4" * 32
        self.identity = {
            "schemaVersion": 2,
            "release": "0.2.0",
            "database": {
                "databaseId": self.database_id,
                "absolutePath": str(self.database_path),
                "schemaVersion": 2,
                "activationBindingNonce": "5" * 64,
            },
            "codexSnapshot": {
                "absolutePath": str(self.snapshot),
                "sha256": hashlib.sha256(self.snapshot.read_bytes()).hexdigest(),
            },
            "compatibilityFingerprint": "6" * 64,
            "routingPolicyFingerprint": "7" * 64,
            "bundledCatalogFingerprint": "8" * 64,
        }
        computed_activation_id = "act2_" + domain_fingerprint(
            "codex-smart/activation/v2", self.identity
        )
        if computed_activation_id != self.activation_id:
            computed_dir = self.activation_dir.parent / computed_activation_id
            self.activation_dir.rename(computed_dir)
            self.activation_id = computed_activation_id
            self.activation_dir = computed_dir
            self.plugin_root = (
                self.activation_dir
                / "marketplace"
                / "plugins"
                / "codex-smart-subagents"
            )
        document = {
            "schemaVersion": 2,
            "activationId": self.activation_id,
            "activationFingerprint": self.activation_id.removeprefix("act2_"),
            "identity": self.identity,
        }
        (self.activation_dir / "activation.json").write_bytes(
            canonical_json_bytes(document)
        )
        (self.activation_dir / "activation.json").chmod(0o600)
        self.environment = {
            "CODEX_HOME": str(self.codex_home),
            "CODEX_V2_STATE_HOME": str(self.state_home),
            "CODEX_V2_WRAPPER_PATH": str(self.wrapper),
            "CODEX_V2_CANDIDATE_OPERATION_ID": self.operation_id,
            "CODEX_V2_CANDIDATE_CONTROLLER_START_ID": self.controller_start_id,
        }

    def _ready_bootstrap(self, config) -> CandidateReadyBootstrapV2:
        token = "candidate-ready-" + "9" * 48
        argv = [
            str(Path(sys.executable).resolve()),
            str((config.plugin_root / "controller" / "server.py").resolve()),
            "--serve-candidate-v2",
        ]
        action = CandidateSpawnActionV2.from_mapping(
            {
                "actionKind": "controller-candidate-spawn",
                "candidateId": "cand2_" + "a" * 32,
                "controllerIdentity": config.controller_identity,
                "controllerStartId": config.controller_start_id,
                "operationId": config.operation_id,
                "activationId": config.activation_id,
                "activationFingerprint": config.activation_fingerprint,
                "databaseId": config.database_id,
                "argv": argv,
                "argvFingerprint": domain_fingerprint(
                    "codex-smart/controller-candidate-argv/v2",
                    {"argv": argv},
                ),
                "snapshotFingerprint": self.identity["codexSnapshot"]["sha256"],
                "privateReadyChannelPath": str(config.state_home / "candidate.ready"),
                "readinessTokenHash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
                "readinessWindowMs": 30_000,
                "processGroupPolicy": "NEW_PRIVATE_GROUP",
            }
        )
        dispatch_intent = CandidateDispatchIntentReceiptV2.create(
            action=action,
            created_at_monotonic_ms=1_000_000,
        )
        return CandidateReadyBootstrapV2(
            action=action,
            dispatch_intent=dispatch_intent,
            readiness_token=token,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _policy(self):
        return SimpleNamespace(
            coordinator_selection="first-verified-available",
            coordinator_candidates=(
                {
                    "model": "gpt-5.6-sol",
                    "reasoningEffort": "medium",
                },
                {
                    "model": "gpt-5.6-terra",
                    "reasoningEffort": "medium",
                },
            ),
        )

    def _coordinator_inspector_factory(self, **_arguments):
        return SimpleNamespace(
            inspect=lambda: {
                "gpt-5.6-sol": frozenset({"medium"}),
            }
        )

    def test_loader_binds_candidate_to_its_activation_and_prepared_database(
        self,
    ) -> None:
        config = load_candidate_controller_config_v2(
            plugin_root=self.plugin_root,
            environment=self.environment,
        )

        self.assertEqual(self.activation_dir, config.activation_dir)
        self.assertEqual(self.database_path, config.database_path)
        self.assertEqual(self.activation_id, config.activation_id)
        self.assertEqual(self.controller_start_id, config.controller_start_id)
        expected_controller_identity = domain_fingerprint(
            "codex-smart/controller-identity/v2",
            {
                "protocolVersion": 2,
                "release": "0.2.0",
                "namespace": "codex-smart-subagents-v2",
                "codexHomeHash": hashlib.sha256(
                    str(self.codex_home.resolve()).encode("utf-8")
                ).hexdigest(),
                "stateHome": str(self.state_home),
                "activationFingerprint": self.activation_id.removeprefix("act2_"),
                "compatibilityFingerprint": "6" * 64,
                "routingPolicyFingerprint": "7" * 64,
                "bundledCatalogFingerprint": "8" * 64,
                "databaseId": self.database_id,
                "databaseSchemaVersion": 2,
            },
        )
        self.assertEqual(expected_controller_identity, config.controller_identity)

    def test_loader_accepts_owned_readable_codex_home(self) -> None:
        self.codex_home.chmod(0o755)

        config = load_candidate_controller_config_v2(
            plugin_root=self.plugin_root,
            environment=self.environment,
        )

        self.assertEqual(self.codex_home, config.codex_home)

    def test_loader_still_requires_private_state_home(self) -> None:
        self.state_home.chmod(0o755)

        with self.assertRaises(CandidateControllerV2Error) as caught:
            load_candidate_controller_config_v2(
                plugin_root=self.plugin_root,
                environment=self.environment,
            )

        self.assertEqual("STATE_HOME_INVALID", caught.exception.code)

    def test_loader_rejects_an_environment_database_alias(self) -> None:
        changed = dict(self.environment)
        changed["CODEX_V2_CANDIDATE_DATABASE"] = str(self.root / "other.sqlite3")

        with self.assertRaises(CandidateControllerV2Error) as caught:
            load_candidate_controller_config_v2(
                plugin_root=self.plugin_root,
                environment=changed,
            )

        self.assertEqual("CANDIDATE_ENVIRONMENT_FORBIDDEN", caught.exception.code)

    def test_candidate_is_accepted_before_the_same_health_owner_starts_full_runtime(
        self,
    ) -> None:
        config = load_candidate_controller_config_v2(
            plugin_root=self.plugin_root,
            environment=self.environment,
        )
        captured = {}
        server = _FakeServer()
        inspector = type(
            "Inspector",
            (),
            {
                "calls": 0,
                "inspect": lambda self: (
                    setattr(self, "calls", self.calls + 1)
                    or {"gpt-5.6-sol": frozenset({"medium"})}
                ),
            },
        )()
        factories = []
        decision = type(
            "Decision",
            (),
            {
                "runtime_binding": type(
                    "Binding",
                    (),
                    {
                        "state_home": self.state_home,
                        "database_path": self.database_path,
                    },
                )(),
            },
        )()

        def starter(entrypoint_config, **arguments):
            health = arguments["bootstrapper"]()
            captured["entrypoint_config"] = entrypoint_config
            captured["health"] = health
            # The full starter binds its observer through the same proxy rather
            # than replacing the handler that accepted the candidate.
            health.bind_lifecycle_handler(
                lambda _request: {}, response_observer=lambda *_: None
            )
            return _Application(health)

        application = serve_candidate_controller_v2(
            config,
            policy_loader=lambda **_arguments: self._policy(),
            coordinator_inspector_factory=lambda **arguments: (
                factories.append(arguments) or inspector
            ),
            server_factory=lambda **arguments: (
                server.arguments.update(arguments) or server
            ),
            protocol_factory=_Protocol,
            decision_provider=lambda: decision,
            full_controller_starter=starter,
            signal_installer=lambda _application: None,
            ready_timeout_seconds=12.0,
        )

        self.assertTrue(application.waited)
        self.assertTrue(application.closed)
        self.assertTrue(server.closed)
        self.assertEqual(self.database_path, server.database_path)
        self.assertEqual(
            self.controller_start_id, server.arguments["controller_start_id"]
        )
        self.assertEqual(1, len(factories))
        self.assertEqual(1, inspector.calls)
        self.assertEqual(
            {
                "model": "gpt-5.6-sol",
                "reasoningEffort": "medium",
            },
            server.arguments[
                "coordinator_selection"
            ].to_document()["selectedPair"],
        )
        self.assertEqual(self.state_home, captured["entrypoint_config"].state_home)

    def test_candidate_deadline_becomes_saved_health_unavailable(self) -> None:
        config = load_candidate_controller_config_v2(
            plugin_root=self.plugin_root,
            environment=self.environment,
        )
        server = _FakeServer()
        inspector = _DeadlineInspector()
        decision = type(
            "Decision",
            (),
            {
                "runtime_binding": type(
                    "Binding",
                    (),
                    {
                        "state_home": self.state_home,
                        "database_path": self.database_path,
                    },
                )(),
            },
        )()

        serve_candidate_controller_v2(
            config,
            policy_loader=lambda **_arguments: self._policy(),
            coordinator_inspector_factory=lambda **_arguments: inspector,
            server_factory=lambda **arguments: (
                server.arguments.update(arguments) or server
            ),
            protocol_factory=_Protocol,
            decision_provider=lambda: decision,
            full_controller_starter=lambda _config, **arguments: _Application(
                arguments["bootstrapper"]()
            ),
            signal_installer=lambda _application: None,
            ready_timeout_seconds=12.0,
        )

        selection = server.arguments["coordinator_selection"].to_document()
        self.assertEqual(1, inspector.calls)
        self.assertEqual("UNAVAILABLE", selection["status"])
        self.assertEqual(
            "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
            selection["reasonCode"],
        )
        self.assertIsNone(selection["accountCatalogFingerprint"])
        self.assertRegex(
            selection["accountContextFingerprint"],
            r"^[0-9a-f]{64}$",
        )

    def test_ready_channel_bridges_start_candidate_to_controller_accept(self) -> None:
        config = load_candidate_controller_config_v2(
            plugin_root=self.plugin_root,
            environment=self.environment,
        )
        bootstrap = self._ready_bootstrap(config)
        expected_readiness_token = bootstrap.readiness_token
        events: list[str] = []
        server = _FakeServer()
        original_start = server.start_candidate
        original_wait = server.wait_until_ready

        def start_candidate(*, database_path):
            events.append("health-start")
            return original_start(database_path=database_path)

        def wait_until_ready(timeout):
            events.append("controller-accept")
            return original_wait(timeout)

        server.start_candidate = start_candidate
        server.wait_until_ready = wait_until_ready
        ready = _FakeReadyChannel(events)
        captured = {}
        decision = type(
            "Decision",
            (),
            {
                "runtime_binding": type(
                    "Binding",
                    (),
                    {
                        "state_home": self.state_home,
                        "database_path": self.database_path,
                    },
                )(),
            },
        )()

        def ready_starter(**arguments):
            events.append("ready-start")
            captured.update(arguments)
            return ready

        def full_starter(_config, **arguments):
            events.append("full-start")
            return _Application(arguments["bootstrapper"]())

        serve_candidate_controller_v2(
            config,
            ready_bootstrap=bootstrap,
            ready_channel_starter=ready_starter,
            policy_loader=lambda **_arguments: self._policy(),
            coordinator_inspector_factory=self._coordinator_inspector_factory,
            server_factory=lambda **arguments: (
                server.arguments.update(arguments) or server
            ),
            protocol_factory=_Protocol,
            decision_provider=lambda: decision,
            full_controller_starter=full_starter,
            signal_installer=lambda _application: None,
            ready_timeout_seconds=12.0,
        )

        self.assertEqual(
            [
                "health-start",
                "ready-start",
                "ready-wait",
                "controller-accept",
                "ready-accepted",
                "ready-close",
                "full-start",
            ],
            events,
        )
        self.assertIs(bootstrap.action, captured["action"])
        self.assertEqual(expected_readiness_token, captured["readiness_token"])
        self.assertEqual("", bootstrap.readiness_token)
        self.assertEqual(self.database_path, captured["database_path"])

    def test_registration_deadline_closes_both_channels_before_accept(self) -> None:
        config = load_candidate_controller_config_v2(
            plugin_root=self.plugin_root,
            environment=self.environment,
        )
        events: list[str] = []
        server = _FakeServer()
        ready = _FakeReadyChannel(events, registered=False)

        with self.assertRaises(CandidateControllerV2Error) as caught:
            serve_candidate_controller_v2(
                config,
                ready_bootstrap=self._ready_bootstrap(config),
                ready_channel_starter=lambda **_arguments: ready,
                policy_loader=lambda **_arguments: self._policy(),
                coordinator_inspector_factory=self._coordinator_inspector_factory,
                server_factory=lambda **arguments: (
                    server.arguments.update(arguments) or server
                ),
                protocol_factory=_Protocol,
                full_controller_starter=lambda *_args, **_kwargs: self.fail(
                    "full controller must not start"
                ),
                ready_timeout_seconds=12.0,
            )

        self.assertEqual("CANDIDATE_REGISTRATION_TIMEOUT", caught.exception.code)
        self.assertTrue(ready.closed)
        self.assertTrue(server.closed)

    def test_ready_channel_failure_after_registration_aborts_before_accept(
        self,
    ) -> None:
        config = load_candidate_controller_config_v2(
            plugin_root=self.plugin_root,
            environment=self.environment,
        )
        events: list[str] = []
        server = _FakeServer()
        server.accept_ready = False
        ready = _FakeReadyChannel(events, fail_after_registration=True)

        with self.assertRaises(CandidateControllerV2Error) as caught:
            serve_candidate_controller_v2(
                config,
                ready_bootstrap=self._ready_bootstrap(config),
                ready_channel_starter=lambda **_arguments: ready,
                policy_loader=lambda **_arguments: self._policy(),
                coordinator_inspector_factory=self._coordinator_inspector_factory,
                server_factory=lambda **arguments: (
                    server.arguments.update(arguments) or server
                ),
                protocol_factory=_Protocol,
                full_controller_starter=lambda *_args, **_kwargs: self.fail(
                    "full controller must not start"
                ),
                ready_timeout_seconds=12.0,
            )

        self.assertEqual("CANDIDATE_READY_CHANNEL_FAILED", caught.exception.code)
        self.assertTrue(ready.closed)
        self.assertTrue(server.closed)


if __name__ == "__main__":
    unittest.main()

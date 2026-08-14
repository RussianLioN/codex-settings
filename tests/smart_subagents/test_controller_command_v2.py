from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))
SHELL_SESSION_ID = "cas2_" + "A" * 32

from codex_smart_subagents.controller_command_v2 import (  # noqa: E402
    MAX_MESSAGE_BYTES,
    ControllerCommandClientV2,
    ControllerCommandServerV2,
    ControllerCommandV2Error,
    get_private_command_schemas_v2,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.smart_turn_runtime_v2 import (  # noqa: E402
    _response,
    owner_for_context_v2,
)
from codex_smart_subagents.state_store_v2 import RequestContextV2  # noqa: E402


def _arguments(method: str) -> dict[str, object]:
    return {
        "smart_plan": {
            "nodes": [
                {
                    "clientNodeId": "reader_a",
                    "dependencyIds": [],
                    "routingInput": _public_routing_input(),
                }
            ]
        },
        "route_start": {
            "routeId": "route2_" + "a" * 32,
            "nodeId": "node2_" + "b" * 32,
        },
        "smart_wait": {
            "startRequestId": "sr2_" + "c" * 32,
            "cursor": None,
            "pageSize": 20,
            "waitSeconds": 0,
        },
        "smart_cancel": {
            "startRequestId": "sr2_" + "c" * 32,
            "reasonCode": "USER_REQUESTED",
        },
    }[method]


def _public_routing_input() -> dict[str, object]:
    internal = json.loads(
        (ROOT / "docs/contracts/vectors/routing-input-v2.json").read_text(
            encoding="utf-8"
        )
    )["baseInput"]
    facts = internal["taskFacts"]
    return {
        "taskFacts": {
            "taskText": facts["taskText"],
            "evidence": facts["evidence"],
            "workShape": facts["workShape"],
            "factorClaims": facts["factorClaims"],
            "delegation": {
                "objectivelyVerifiable": facts["delegation"]["objectivelyVerifiable"],
                "independentWorkUnits": facts["delegation"]["independentWorkUnits"],
            },
            "hardFloorReasons": facts["hardFloorReasons"],
            "hardBanReasons": facts["hardBanReasons"],
        },
        "contextBundle": internal["contextBundle"],
        "roleTemplateId": internal["roleTemplateId"],
    }


def _public_response(
    method: str,
    *,
    shell_session_id: str = SHELL_SESSION_ID,
) -> dict[str, object]:
    context = RequestContextV2(
        shell_session_id=shell_session_id,
        session_id="session-1",
        turn_id="turn-1",
        codex_home="/Users/test/.codex",
        repo_root="/Users/test/repo",
        base_sha="1" * 64,
        worktree_fingerprint="2" * 64,
        activation_fingerprint="3" * 64,
        compatibility_fingerprint="4" * 64,
        issued_control_epoch=7,
    )
    owner = owner_for_context_v2(context)

    def effect(result_kind: str, result_id: str) -> dict[str, object]:
        return {
            "operation": "READ",
            "transactionMode": "READ_ONLY",
            "transitions": [],
            "completedAt": "2026-07-19T12:00:00Z",
            "result": {
                "resultKind": result_kind,
                "resultId": result_id,
                "resultFingerprint": "5" * 64,
            },
        }

    payloads: dict[str, dict[str, object]] = {
        "smart_plan": {
            "status": "PLANNED",
            "routeId": "route2_" + "a" * 32,
            "disposition": "DELEGATE",
            "nodeDecisions": [
                {
                    "clientNodeId": "reader_a",
                    "nodeId": "node2_" + "b" * 32,
                    "dependencyNodeIds": [],
                    "disposition": "DELEGATE",
                    "selectedPair": {
                        "model": "model-luna",
                        "reasoningEffort": "medium",
                    },
                    "score": 2,
                    "factors": {"q": 1, "p": 1, "v": 0, "o": 0},
                }
            ],
            "clarification": None,
            "planFingerprint": "6" * 64,
            "effect": effect("ROUTE_PLAN", "route2_" + "a" * 32),
        },
        "route_start": {
            "status": "ATTESTING",
            "routeId": "route2_" + "a" * 32,
            "nodeId": "node2_" + "b" * 32,
            "startRequestId": "sr2_" + "c" * 32,
            "evidenceJob": {
                "evidenceJobId": "aej2_" + "d" * 32,
                "state": "QUEUED",
                "owner": owner,
                "queuePosition": 1,
                "deadlineAt": "2026-07-19T12:03:00Z",
                "stage": None,
            },
            "admissionId": None,
            "effect": effect("START_REQUEST", "sr2_" + "c" * 32),
        },
        "smart_wait": {
            "startRequestId": "sr2_" + "c" * 32,
            "state": "ATTESTING",
            "evidenceJobState": "QUEUED",
            "admissionId": None,
            "terminal": False,
            "terminalResult": None,
            "page": {"cursor": None, "nextCursor": None, "items": []},
            "effect": effect("WAIT_PAGE", "sr2_" + "c" * 32),
        },
        "smart_cancel": {
            "status": "CANCELLED",
            "startRequestId": "sr2_" + "c" * 32,
            "state": "CANCELLED",
            "terminal": True,
            "idempotencyKey": "idem2_" + "e" * 32,
            "idempotencyStatus": "COMMITTED",
            "effect": effect("CANCELLATION", "sr2_" + "c" * 32),
        },
    }
    return _response(
        {
            "requestId": "strq2_" + "f" * 32,
            "owner": owner,
            "method": method,
            "requestFingerprint": "7" * 64,
        },
        "SUCCESS",
        payloads[method],
    )


class ControllerCommandV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.runtime_dir = Path(self.temporary.name) / "runtime"
        self.runtime_dir.mkdir(mode=0o700)
        self.socket_path = self.runtime_dir / "smart-command-v2.sock"
        self.lock_path = self.runtime_dir / "smart-command-v2.lock"
        self.calls: list[tuple[str, str, dict[str, object]]] = []
        self.server: ControllerCommandServerV2 | None = None
        self.thread: threading.Thread | None = None

    def tearDown(self) -> None:
        if self.server is not None:
            self.server.close()
        if self.thread is not None:
            self.thread.join(timeout=2)
        self.temporary.cleanup()

    def _handler(
        self,
        shell_session_id: str,
        method: str,
        arguments: dict[str, object],
    ):
        self.calls.append((shell_session_id, method, arguments))
        return _public_response(method)

    def _start(self, *, handler=None) -> ControllerCommandClientV2:
        self.server = ControllerCommandServerV2(
            socket_path=self.socket_path,
            lock_path=self.lock_path,
            handler=handler or self._handler,
        )
        self.server.start()
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.assertTrue(self.server.wait_until_ready(0.2))
        return ControllerCommandClientV2(
            socket_path=self.socket_path,
            shell_session_id=SHELL_SESSION_ID,
        )

    def test_schemas_are_closed_and_exact_for_all_four_methods(self) -> None:
        schemas = get_private_command_schemas_v2()

        self.assertEqual(
            ["smart_plan", "route_start", "smart_wait", "smart_cancel"],
            list(schemas["requestByMethod"]),
        )
        for direction in ("requestByMethod", "successResponseByMethod"):
            for schema in schemas[direction].values():
                Draft202012Validator.check_schema(schema)
                self.assertFalse(schema["additionalProperties"])
        Draft202012Validator.check_schema(schemas["errorResponse"])
        self.assertFalse(schemas["errorResponse"]["additionalProperties"])

        request_projection = {
            "messageType": "request",
            "protocolVersion": 2,
            "release": "0.2.0",
            "commandId": "csc2_" + "a" * 32,
            "shellSessionId": SHELL_SESSION_ID,
            "method": "route_start",
            "params": _arguments("route_start"),
        }
        request = {
            **request_projection,
            "requestFingerprint": domain_fingerprint(
                "codex-smart/private-command-request/v2", request_projection
            ),
        }
        Draft202012Validator(schemas["requestByMethod"]["route_start"]).validate(
            request
        )

        for method in ("smart_plan", "route_start", "smart_wait", "smart_cancel"):
            response_projection = {
                "messageType": "response",
                "protocolVersion": 2,
                "release": "0.2.0",
                "commandId": request["commandId"],
                "method": method,
                "responseKind": "SUCCESS",
                "requestFingerprint": request["requestFingerprint"],
                "payload": _public_response(method),
            }
            response = {
                **response_projection,
                "responseFingerprint": domain_fingerprint(
                    "codex-smart/private-command-response/v2", response_projection
                ),
            }
            Draft202012Validator(schemas["successResponseByMethod"][method]).validate(
                response
            )

    def test_real_round_trip_supports_only_the_four_tool_commands(self) -> None:
        client = self._start()

        for method in ("smart_plan", "route_start", "smart_wait", "smart_cancel"):
            self.assertEqual(method, client.call(method, _arguments(method))["method"])

        self.assertEqual(
            ["smart_plan", "route_start", "smart_wait", "smart_cancel"],
            [method for _shell, method, _arguments_value in self.calls],
        )
        self.assertEqual(
            [SHELL_SESSION_ID] * 4,
            [shell for shell, _method, _arguments_value in self.calls],
        )
        self.assertEqual(0o600, self.socket_path.stat().st_mode & 0o777)
        self.assertEqual(0o600, self.lock_path.stat().st_mode & 0o777)

        with self.assertRaisesRegex(ControllerCommandV2Error, "UNKNOWN_METHOD"):
            client.call("health", {})

    def test_shell_session_is_constructor_only_and_must_match_cas2_contract(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            ControllerCommandV2Error,
            "INVALID_SHELL_SESSION",
        ):
            ControllerCommandClientV2(
                socket_path=self.socket_path,
                shell_session_id="shell-1",
            )

        client = self._start()
        response = client.call("smart_plan", _arguments("smart_plan"))
        self.assertEqual(SHELL_SESSION_ID, response["owner"]["shellSessionId"])

    def test_response_owned_by_another_shell_is_rejected(self) -> None:
        client = self._start(
            handler=lambda _shell, method, _arguments_value: _public_response(
                method,
                shell_session_id="cas2_" + "B" * 32,
            )
        )

        with self.assertRaises(ControllerCommandV2Error) as caught:
            client.call("smart_plan", _arguments("smart_plan"))
        self.assertEqual("INVALID_RESULT", caught.exception.code)

    def test_invalid_input_is_rejected_before_handler_and_paths_are_not_enveloped(
        self,
    ) -> None:
        client = self._start()

        with self.assertRaisesRegex(ControllerCommandV2Error, "INVALID_PARAMS"):
            client.call(
                "route_start",
                {
                    **_arguments("route_start"),
                    "stateHome": "/tmp/подмена",
                },
            )
        with self.assertRaisesRegex(ControllerCommandV2Error, "INVALID_PARAMS"):
            client.call(
                "route_start",
                {
                    **_arguments("route_start"),
                    "shellSessionId": "cas2_" + "B" * 32,
                },
            )

        self.assertEqual([], self.calls)
        request_schema = get_private_command_schemas_v2()["requestByMethod"][
            "route_start"
        ]
        self.assertEqual(
            {
                "messageType",
                "protocolVersion",
                "release",
                "commandId",
                "shellSessionId",
                "method",
                "params",
                "requestFingerprint",
            },
            set(request_schema["properties"]),
        )

    def test_handler_failure_and_invalid_result_have_stable_non_leaking_errors(
        self,
    ) -> None:
        def failure(
            _shell: str,
            _method: str,
            _arguments_value: dict[str, object],
        ):
            raise RuntimeError("секретный путь /Users/private и ключ")

        client = self._start(handler=failure)
        with self.assertRaises(ControllerCommandV2Error) as caught:
            client.call("smart_plan", _arguments("smart_plan"))
        self.assertEqual("HANDLER_FAILED", caught.exception.code)
        self.assertNotIn("секрет", str(caught.exception))

        self.server.close()
        self.thread.join(timeout=2)
        self.server = None
        self.thread = None

        client = self._start(
            handler=lambda _shell, _method, _arguments_value: {"ok": True}
        )
        with self.assertRaises(ControllerCommandV2Error) as caught:
            client.call("smart_plan", _arguments("smart_plan"))
        self.assertEqual("INVALID_RESULT", caught.exception.code)

    def test_server_rejects_other_uid_before_reading_or_dispatching(self) -> None:
        with mock.patch(
            "codex_smart_subagents.controller_command_v2._peer_uid",
            return_value=os.getuid() + 1,
        ):
            client = self._start()
            with self.assertRaises(ControllerCommandV2Error) as caught:
                client.call("smart_plan", _arguments("smart_plan"))

        self.assertEqual("TRANSPORT_FAILURE", caught.exception.code)
        self.assertEqual([], self.calls)

    def test_message_size_and_io_time_are_bounded(self) -> None:
        client = self._start()

        with self.assertRaisesRegex(ControllerCommandV2Error, "MESSAGE_TOO_LARGE"):
            client.call(
                "smart_plan",
                {
                    "nodes": [
                        {
                            "clientNodeId": "reader_a",
                            "dependencyIds": [],
                            "routingInput": {
                                **_public_routing_input(),
                                "contextBundle": {
                                    **_public_routing_input()["contextBundle"],
                                    "entries": [
                                        {
                                            **_public_routing_input()["contextBundle"][
                                                "entries"
                                            ][0],
                                            "content": "x" * MAX_MESSAGE_BYTES,
                                        }
                                    ],
                                },
                            },
                        }
                    ]
                },
            )

        self.server.close()
        self.thread.join(timeout=2)
        self.server = None
        self.thread = None

        def delayed(
            _shell: str,
            method: str,
            _arguments_value: dict[str, object],
        ):
            time.sleep(0.2)
            return _public_response(method)

        client = self._start(handler=delayed)
        client = ControllerCommandClientV2(
            socket_path=self.socket_path,
            shell_session_id=SHELL_SESSION_ID,
            call_timeout_seconds=0.05,
        )
        started = time.monotonic()
        with self.assertRaisesRegex(ControllerCommandV2Error, "TRANSPORT_TIMEOUT"):
            client.call("smart_plan", _arguments("smart_plan"))
        self.assertLess(time.monotonic() - started, 0.2)

    def test_lock_excludes_second_owner_and_cleanup_preserves_replacement(self) -> None:
        self._start()
        second = ControllerCommandServerV2(
            socket_path=self.socket_path,
            lock_path=self.lock_path,
            handler=self._handler,
        )
        with self.assertRaisesRegex(ControllerCommandV2Error, "ALREADY_RUNNING"):
            second.start()
        second.close()

        os.unlink(self.socket_path)
        self.socket_path.write_text("не сокет", encoding="utf-8")
        self.server.close()
        self.thread.join(timeout=2)
        self.server = None
        self.thread = None
        self.assertEqual("не сокет", self.socket_path.read_text(encoding="utf-8"))

    def test_existing_non_socket_and_shared_runtime_directory_are_rejected(
        self,
    ) -> None:
        self.socket_path.write_text("не сокет", encoding="utf-8")
        server = ControllerCommandServerV2(
            socket_path=self.socket_path,
            lock_path=self.lock_path,
            handler=self._handler,
        )
        with self.assertRaisesRegex(ControllerCommandV2Error, "UNSAFE_EXISTING_SOCKET"):
            server.start()
        server.close()

        self.socket_path.unlink()
        self.runtime_dir.chmod(0o755)
        with self.assertRaisesRegex(ControllerCommandV2Error, "INVALID_CONFIGURATION"):
            ControllerCommandServerV2(
                socket_path=self.socket_path,
                lock_path=self.lock_path,
                handler=self._handler,
            )


class ControllerCommandRawProtocolV2Tests(unittest.TestCase):
    def test_shell_session_tampering_and_invalid_form_are_rejected(self) -> None:
        calls: list[object] = []
        with tempfile.TemporaryDirectory() as temporary:
            runtime_dir = Path(temporary) / "runtime"
            runtime_dir.mkdir(mode=0o700)
            socket_path = runtime_dir / "command.sock"
            server = ControllerCommandServerV2(
                socket_path=socket_path,
                lock_path=runtime_dir / "command.lock",
                handler=lambda shell, method, arguments: calls.append(
                    (shell, method, arguments)
                ),
            )
            server.start()
            thread = threading.Thread(target=server.serve_forever)
            thread.start()

            def exchange(request: dict[str, object]) -> bytes:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(1)
                    connection.connect(str(socket_path))
                    connection.sendall(canonical_json_bytes(request) + b"\n")
                    return connection.recv(1024)

            projection = {
                "messageType": "request",
                "protocolVersion": 2,
                "release": "0.2.0",
                "commandId": "csc2_" + "a" * 32,
                "shellSessionId": SHELL_SESSION_ID,
                "method": "smart_plan",
                "params": _arguments("smart_plan"),
            }
            request = {
                **projection,
                "requestFingerprint": domain_fingerprint(
                    "codex-smart/private-command-request/v2", projection
                ),
            }
            tampered = {**request, "shellSessionId": "cas2_" + "B" * 32}

            invalid_projection = {**projection, "shellSessionId": "shell-1"}
            invalid = {
                **invalid_projection,
                "requestFingerprint": domain_fingerprint(
                    "codex-smart/private-command-request/v2", invalid_projection
                ),
            }
            try:
                self.assertEqual(b"", exchange(tampered))
                self.assertEqual(b"", exchange(invalid))
            finally:
                server.close()
                thread.join(timeout=2)

        self.assertEqual([], calls)

    def test_valid_envelope_with_invalid_params_returns_exact_error(self) -> None:
        calls: list[object] = []
        with tempfile.TemporaryDirectory() as temporary:
            runtime_dir = Path(temporary) / "runtime"
            runtime_dir.mkdir(mode=0o700)
            socket_path = runtime_dir / "command.sock"
            server = ControllerCommandServerV2(
                socket_path=socket_path,
                lock_path=runtime_dir / "command.lock",
                handler=lambda shell, method, arguments: calls.append(
                    (shell, method, arguments)
                ),
            )
            server.start()
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            projection = {
                "messageType": "request",
                "protocolVersion": 2,
                "release": "0.2.0",
                "commandId": "csc2_" + "a" * 32,
                "shellSessionId": SHELL_SESSION_ID,
                "method": "route_start",
                "params": {
                    **_arguments("route_start"),
                    "stateHome": "/tmp/подмена",
                },
            }
            request = {
                **projection,
                "requestFingerprint": domain_fingerprint(
                    "codex-smart/private-command-request/v2", projection
                ),
            }
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(1)
                    connection.connect(str(socket_path))
                    connection.sendall(canonical_json_bytes(request) + b"\n")
                    response = json.loads(connection.recv(65536))
            finally:
                server.close()
                thread.join(timeout=2)

        self.assertEqual("ERROR", response["responseKind"])
        self.assertEqual(
            {
                "code": "INVALID_PARAMS",
                "message": "Параметры команды отклонены.",
            },
            response["payload"],
        )
        self.assertEqual([], calls)

    def test_duplicate_json_keys_are_not_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime_dir = Path(temporary) / "runtime"
            runtime_dir.mkdir(mode=0o700)
            socket_path = runtime_dir / "command.sock"
            server = ControllerCommandServerV2(
                socket_path=socket_path,
                lock_path=runtime_dir / "command.lock",
                handler=lambda _shell, method, _arguments_value: _public_response(
                    method
                ),
            )
            server.start()
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(1)
                    connection.connect(str(socket_path))
                    connection.sendall(
                        b'{"messageType":"request","messageType":"request"}\n'
                    )
                    self.assertEqual(b"", connection.recv(1024))
            finally:
                server.close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()

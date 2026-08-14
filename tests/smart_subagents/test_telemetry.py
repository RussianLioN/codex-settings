from __future__ import annotations

import http.client
import json
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.telemetry import (  # noqa: E402
    AttestationError,
    OTelReceiver,
    attest_run,
)


def otlp_payload(
    *,
    model: str = "gpt-5.6-terra",
    effort: str = "high",
    conversation_id: str = "thread-123",
) -> dict[str, object]:
    values = [
        {
            "key": "event.name",
            "value": {"stringValue": "codex.conversation_starts"},
        },
        {"key": "model", "value": {"stringValue": model}},
        {
            "key": "reasoning_effort",
            "value": {"stringValue": effort},
        },
        {
            "key": "conversation.id",
            "value": {"stringValue": conversation_id},
        },
        {
            "key": "app.version",
            "value": {"stringValue": "0.144.4"},
        },
        {
            "key": "account.email",
            "value": {"stringValue": "secret@example.invalid"},
        },
        {
            "key": "user_prompt",
            "value": {"stringValue": "sensitive prompt"},
        },
        {
            "key": "CODEX_V2_SOURCE_ROOT",
            "value": {"stringValue": "/private/bootstrap/source"},
        },
        {
            "key": "CODEX_V2_CODEX_BIN",
            "value": {"stringValue": "/private/bootstrap/codex"},
        },
        {
            "key": "CODEX_V2_WRAPPER_PATH",
            "value": {"stringValue": "/private/bootstrap/wrapper"},
        },
    ]
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "service.version",
                            "value": {"stringValue": "0.144.4"},
                        }
                    ]
                },
                "scopeLogs": [
                    {"logRecords": [{"body": {"kvlistValue": {"values": values}}}]}
                ],
            }
        ]
    }


class OTelReceiverTests(unittest.TestCase):
    def test_receiver_requires_path_token_json_and_redacts_sensitive_fields(
        self,
    ) -> None:
        with OTelReceiver(max_request_bytes=32_000, max_requests=2) as receiver:
            body = json.dumps(otlp_payload()).encode()
            connection = http.client.HTTPConnection(
                receiver.host,
                receiver.port,
                timeout=2,
            )
            connection.request(
                "POST",
                receiver.path,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    receiver.header_name: receiver.token,
                },
            )
            response = connection.getresponse()
            response.read()
            self.assertEqual(200, response.status)

            connection.request(
                "POST",
                receiver.path,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    receiver.header_name: "wrong",
                },
            )
            rejected = connection.getresponse()
            rejected.read()
            self.assertEqual(403, rejected.status)

            stored = json.dumps(receiver.events, sort_keys=True)
            self.assertIn("gpt-5.6-terra", stored)
            self.assertNotIn("secret@example.invalid", stored)
            self.assertNotIn("sensitive prompt", stored)
            self.assertNotIn("/private/bootstrap/source", stored)
            self.assertNotIn("/private/bootstrap/codex", stored)
            self.assertNotIn("/private/bootstrap/wrapper", stored)

    def test_receiver_enforces_request_limit(self) -> None:
        with OTelReceiver(max_request_bytes=32_000, max_requests=1) as receiver:
            body = json.dumps(otlp_payload()).encode()
            for expected in (200, 429):
                connection = http.client.HTTPConnection(
                    receiver.host,
                    receiver.port,
                    timeout=2,
                )
                connection.request(
                    "POST",
                    receiver.path,
                    body=body,
                    headers={
                        "Content-Type": "application/json",
                        receiver.header_name: receiver.token,
                    },
                )
                response = connection.getresponse()
                response.read()
                self.assertEqual(expected, response.status)


class AttestationTests(unittest.TestCase):
    def test_attestation_matches_requested_values_and_jsonl_thread(self) -> None:
        result = attest_run(
            events=[
                {
                    "event.name": "codex.conversation_starts",
                    "app.version": "0.144.4",
                    "service.version": "0.144.4",
                    "model": "gpt-5.6-terra",
                    "reasoning_effort": "high",
                    "conversation.id": "thread-123",
                }
            ],
            jsonl_events=[
                {"type": "thread.started", "thread_id": "thread-123"},
                {"type": "turn.completed"},
            ],
            requested_model="gpt-5.6-terra",
            requested_effort="high",
            expected_cli_version="0.144.4",
            permission_probe_id="probe-7",
            argv_fingerprint="a" * 64,
        )
        self.assertEqual("gpt-5.6-terra", result.observed_model)
        self.assertEqual("high", result.observed_effort)
        self.assertEqual(64, len(result.conversation_hash))
        self.assertEqual("probe-7", result.permission_probe_id)

    def test_attestation_fails_closed_on_missing_or_mismatched_fields(
        self,
    ) -> None:
        base = {
            "event.name": "codex.conversation_starts",
            "app.version": "0.144.4",
            "service.version": "0.144.4",
            "model": "gpt-5.6-terra",
            "reasoning_effort": "high",
            "conversation.id": "thread-123",
        }
        cases = [
            (
                {key: value for key, value in base.items() if key != "model"},
                "FIELD_MISSING",
            ),
            ({**base, "model": "gpt-5.6-luna"}, "MODEL_MISMATCH"),
            ({**base, "reasoning_effort": "medium"}, "EFFORT_MISMATCH"),
            ({**base, "conversation.id": "other"}, "CONVERSATION_MISMATCH"),
            (
                {**base, "service.version": "0.144.3"},
                "AMBIGUOUS_ATTESTATION",
            ),
        ]
        for event, code in cases:
            with self.subTest(code=code), self.assertRaises(AttestationError) as caught:
                attest_run(
                    events=[event],
                    jsonl_events=[
                        {"type": "thread.started", "thread_id": "thread-123"}
                    ],
                    requested_model="gpt-5.6-terra",
                    requested_effort="high",
                    expected_cli_version="0.144.4",
                    permission_probe_id="probe-7",
                    argv_fingerprint="a" * 64,
                )
            self.assertEqual(code, caught.exception.code)


if __name__ == "__main__":
    unittest.main()

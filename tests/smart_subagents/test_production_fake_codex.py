#!/usr/bin/env python3
"""Protocol-complete fake Codex for the local production integration test."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request


SANDBOX_CHECKS = (
    "snapshot_read_allowed",
    "snapshot_write_denied",
    "secret_read_denied",
    "source_git_read_denied",
    "controller_database_read_denied",
    "source_worktree_write_denied",
    "external_network_denied",
    "dns_denied",
    "udp_denied",
    "loopback_denied",
    "controller_socket_denied",
)


def option_value(name: str) -> str:
    index = sys.argv.index(name)
    return sys.argv[index + 1]


def config_value(prefix: str) -> str:
    for index, value in enumerate(sys.argv[:-1]):
        if value == "-c" and sys.argv[index + 1].startswith(prefix):
            return sys.argv[index + 1][len(prefix) :]
    raise RuntimeError(f"missing config prefix: {prefix}")


def emit(event: dict[str, object]) -> None:
    print(json.dumps(event, ensure_ascii=False, separators=(",", ":")), flush=True)


def send_otel(model: str, effort: str, thread_id: str) -> None:
    exporter = next(
        value
        for value in sys.argv
        if value.startswith("otel.exporter={ otlp-http")
    )
    endpoint_match = re.search(r'endpoint="([^"]+)"', exporter)
    if endpoint_match is None:
        raise RuntimeError("OTel endpoint is missing")
    payload = {
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
                    {
                        "logRecords": [
                            {
                                "attributes": [
                                    {
                                        "key": "event.name",
                                        "value": {
                                            "stringValue": "codex.conversation_starts"
                                        },
                                    },
                                    {
                                        "key": "model",
                                        "value": {"stringValue": model},
                                    },
                                    {
                                        "key": "model_reasoning_effort",
                                        "value": {"stringValue": effort},
                                    },
                                    {
                                        "key": "conversation_id",
                                        "value": {"stringValue": thread_id},
                                    },
                                ]
                            }
                        ]
                    }
                ],
            }
        ]
    }
    request = urllib.request.Request(
        endpoint_match.group(1),
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Codex-Attestation-Token": os.environ[
                "CODEX_ADAPTIVE_OTEL_TOKEN"
            ],
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        if response.status != 200:
            raise RuntimeError("OTel receiver rejected evidence")


def main() -> int:
    if sys.argv[1:] == ["--version"]:
        print("codex-cli 0.144.4")
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "sandbox":
        print(
            "CODEX_PERMISSION_CANARY_V1:"
            + json.dumps(
                {name: True for name in SANDBOX_CHECKS},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    if len(sys.argv) <= 1 or sys.argv[1] != "exec":
        return 2

    prompt = sys.stdin.read()
    nonce = re.search(r"\bce1_[A-Za-z0-9_-]{43}\b", prompt)
    if nonce is not None:
        command = (
            prompt.split("Команда:\n", 1)[1]
            .split("\nПосле завершения", 1)[0]
        )
        emit({"type": "thread.started", "thread_id": "canary-thread"})
        emit(
            {
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "command": command,
                    "aggregated_output": (
                        "CODEX_EXEC_PERMISSION_CANARY_V1:"
                        f"{nonce.group(0)}:DENIED\n"
                    ),
                    "exit_code": 0,
                    "status": "completed",
                },
            }
        )
        emit({"type": "turn.completed"})
        return 0

    model = option_value("--model")
    effort = json.loads(config_value("model_reasoning_effort="))
    thread_id = "reader-thread-123"
    send_otel(model, effort, thread_id)
    emit({"type": "thread.started", "thread_id": thread_id})
    emit(
        {
            "type": "item.completed",
            "item": {
                "id": "message-1",
                "type": "agent_message",
                "text": json.dumps(
                    {
                        "summary": "Снимок проверен сквозным испытанием.",
                        "validationState": "passed",
                        "artifactId": "",
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            },
        }
    )
    emit(
        {
            "type": "turn.completed",
            "model": model,
            "reasoning_effort": effort,
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

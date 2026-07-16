#!/usr/bin/env python3
"""Protocol-complete fake Codex for the local production integration test."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import unquote


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
                                        "key": "app.version",
                                        "value": {"stringValue": "0.144.4"},
                                    },
                                    {
                                        "key": "model",
                                        "value": {"stringValue": model},
                                    },
                                    {
                                        "key": "reasoning_effort",
                                        "value": {"stringValue": effort},
                                    },
                                    {
                                        "key": "conversation.id",
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
            "X-Codex-Attestation-Token": _otel_token(),
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        if response.status != 200:
            raise RuntimeError("OTel receiver rejected evidence")


def _otel_token() -> str:
    raw = os.environ["OTEL_EXPORTER_OTLP_LOGS_HEADERS"]
    name, separator, encoded = raw.partition("=")
    if name != "X-Codex-Attestation-Token" or not separator or not encoded:
        raise RuntimeError("OTel header environment is malformed")
    return unquote(encoded)


def main() -> int:
    if sys.argv[1:] == ["--version"]:
        print("codex-cli 0.144.4")
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "app-server":
        initialize = json.loads(sys.stdin.readline())
        if initialize.get("method") != "initialize":
            return 3
        emit(
            {
                "id": initialize["id"],
                "result": {
                    "userAgent": "codex_smart_subagents/0.144.4",
                    "codexHome": os.environ["CODEX_HOME"],
                    "platformFamily": "unix",
                    "platformOs": "macos",
                },
            }
        )
        initialized = json.loads(sys.stdin.readline())
        request = json.loads(sys.stdin.readline())
        if initialized.get("method") != "initialized":
            return 4
        method = request.get("method")
        if method == "configRequirements/read":
            result = {"requirements": None}
        elif method == "model/list":
            result = {
                "data": [
                    {
                        "model": slug,
                        "supportedReasoningEfforts": [
                            {"reasoningEffort": effort}
                            for effort in (
                                "low",
                                "medium",
                                "high",
                                "xhigh",
                                "max",
                            )
                        ],
                    }
                    for slug in (
                        "gpt-5.6-luna",
                        "gpt-5.6-terra",
                        "gpt-5.6-sol",
                    )
                ],
                "nextCursor": None,
            }
        else:
            return 5
        emit({"id": request["id"], "result": result})
        return 0
    if sys.argv[1:] == ["debug", "models", "--bundled"]:
        print(
            json.dumps(
                [
                    {
                        "slug": slug,
                        "supported_reasoning_levels": [
                            {"effort": effort}
                            for effort in (
                                "low",
                                "medium",
                                "high",
                                "xhigh",
                                "max",
                                "ultra",
                            )
                        ],
                    }
                    for slug in (
                        "gpt-5.6-luna",
                        "gpt-5.6-terra",
                        "gpt-5.6-sol",
                    )
                ],
                separators=(",", ":"),
            )
        )
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "sandbox":
        if "--" in sys.argv:
            command = sys.argv[sys.argv.index("--") + 1 :]
            if (
                command
                and Path(command[0]).name
                == "codex-smart-subagents-validate"
            ):
                os.execve(command[0], command, dict(os.environ))
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

    prompt_text = sys.stdin.read()
    nonce = re.search(r"\bce1_[A-Za-z0-9_-]{43}\b", prompt_text)
    if nonce is not None:
        command = (
            prompt_text.split("Команда:\n", 1)[1]
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
    prompt = json.loads(prompt_text)
    boundary = (
        prompt.get("contractVersion")
        == "boundary-reclassification-v1"
    )
    if boundary:
        sqlite_home = Path(os.environ["CODEX_SQLITE_HOME"])
        (sqlite_home / "state_5.sqlite").write_bytes(b"sqlite-state")
        (sqlite_home / "state_5.sqlite").chmod(0o600)
        codex_home = Path(os.environ["CODEX_HOME"])
        (codex_home / "models_cache.json").write_text(
            '{"models":[]}\n',
            encoding="utf-8",
        )
        (codex_home / "models_cache.json").chmod(0o600)
        thread_id = "boundary-thread-123"
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
                            "q": {"min": 1, "max": 2},
                            "p": {"min": 0, "max": 1},
                            "v": {"min": 2, "max": 2},
                            "o": {"min": 0, "max": 1},
                            "hardBan": "none",
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
                "usage": {
                    "input_tokens": 10,
                    "cached_input_tokens": 0,
                    "output_tokens": 5,
                    "reasoning_output_tokens": 1,
                },
            }
        )
        return 0

    writer = prompt.get("contractVersion") == "writer-result-v1"
    if writer:
        candidate = (
            Path(os.environ["CODEX_ADAPTIVE_WORKSPACE_ROOT"])
            / "source.txt"
        )
        candidate.write_text("candidate\n", encoding="utf-8")
    thread_id = "writer-thread-123" if writer else "reader-thread-123"
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
                        "summary": (
                            "Кандидат подготовлен сквозным испытанием."
                            if writer
                            else "Снимок проверен сквозным испытанием."
                        ),
                        "validationState": (
                            "not_applicable" if writer else "passed"
                        ),
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

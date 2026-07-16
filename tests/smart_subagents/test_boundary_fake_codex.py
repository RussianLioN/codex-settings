#!/usr/bin/env python3
"""Protocol-complete fake Codex for boundary reclassifier tests."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import unquote


REQUIRED_DISABLED = {
    "enable_fanout",
    "multi_agent",
    "multi_agent_v2",
    "shell_tool",
    "unified_exec",
}


def _option(name: str) -> str:
    index = sys.argv.index(name)
    return sys.argv[index + 1]


def _config(prefix: str) -> str:
    for index, value in enumerate(sys.argv[:-1]):
        if value == "-c" and sys.argv[index + 1].startswith(prefix):
            return sys.argv[index + 1][len(prefix) :]
    raise RuntimeError(f"missing config prefix: {prefix}")


def _disabled_features() -> set[str]:
    return {
        sys.argv[index + 1]
        for index, value in enumerate(sys.argv[:-1])
        if value == "--disable"
    }


def _emit(event: dict[str, object]) -> None:
    print(
        json.dumps(event, ensure_ascii=False, separators=(",", ":")),
        flush=True,
    )


def _send_otel(model: str, effort: str, thread_id: str) -> None:
    exporter = next(
        value
        for value in sys.argv
        if value.startswith("otel.exporter={ otlp-http")
    )
    endpoint = re.search(r'endpoint="([^"]+)"', exporter)
    if endpoint is None:
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
                                            "stringValue": (
                                                "codex.conversation_starts"
                                            )
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
        endpoint.group(1),
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
    prompt = json.loads(sys.stdin.read())
    work = Path.cwd()
    codex_home = Path(os.environ["CODEX_HOME"])
    sqlite_home = Path(os.environ["CODEX_SQLITE_HOME"])
    auth_file = codex_home / "auth.json"
    api_key = os.environ.get("OPENAI_API_KEY")
    entries = {path.name for path in codex_home.iterdir()}
    auth_is_valid = (
        (
            entries == {"auth.json"}
            and auth_file.is_file()
            and api_key is None
        )
        or (not entries and api_key == "synthetic-openai-key")
    )
    profile = next(
        value
        for value in sys.argv
        if value.startswith(
            "permissions.adaptive_boundary_classifier.filesystem="
        )
    )
    schema = json.loads(
        Path(_option("--output-schema")).read_text(encoding="utf-8")
    )
    invariants = (
        not any(work.iterdir())
        and auth_is_valid
        and sqlite_home != codex_home
        and sqlite_home.is_dir()
        and not any(sqlite_home.iterdir())
        and _option("--model") == "gpt-5.6-terra"
        and json.loads(_config("model_reasoning_effort=")) == "high"
        and json.loads(_config("approval_policy=")) == "never"
        and _config("agents.max_depth=") == "1"
        and REQUIRED_DISABLED.issubset(_disabled_features())
        and '":workspace_roots"={"."="read"}' in profile
        and '"."="write"' not in profile
        and prompt.get("contractVersion") == "boundary-reclassification-v1"
        and "assessment" not in prompt.get("task", {})
        and schema.get("additionalProperties") is False
    )
    if not invariants:
        _emit({"type": "thread.started", "thread_id": "boundary-thread-123"})
        _emit({"type": "turn.failed"})
        return 9

    (sqlite_home / "state_5.sqlite").write_bytes(b"sqlite-state")
    (sqlite_home / "state_5.sqlite").chmod(0o600)
    (codex_home / "models_cache.json").write_text(
        '{"models":[]}\n',
        encoding="utf-8",
    )
    (codex_home / "models_cache.json").chmod(0o600)
    thread_id = "boundary-thread-123"
    _send_otel("gpt-5.6-terra", "high", thread_id)
    _emit({"type": "thread.started", "thread_id": thread_id})
    _emit(
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
                    separators=(",", ":"),
                ),
            },
        }
    )
    _emit(
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


if __name__ == "__main__":
    raise SystemExit(main())

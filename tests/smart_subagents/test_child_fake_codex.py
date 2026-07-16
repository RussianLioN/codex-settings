#!/usr/bin/python3
"""Executable test double for the child Codex process."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    prompt = sys.stdin.read()
    sqlite_home = Path(os.environ["CODEX_SQLITE_HOME"])
    (sqlite_home / "state_5.sqlite").write_bytes(b"sqlite-state")
    (sqlite_home / "state_5.sqlite").chmod(0o600)
    probe = Path.cwd() / "umask-probe"
    probe.write_text("private\n", encoding="utf-8")
    auth_file = Path(os.environ["CODEX_HOME"]) / "auth.json"
    invocation = {
        "argv": sys.argv[1:],
        "environment": dict(os.environ),
        "prompt": prompt,
        "pid": os.getpid(),
        "processGroup": os.getpgrp(),
        "session": os.getsid(0),
        "umaskProbeMode": probe.stat().st_mode & 0o777,
        "authContents": (
            auth_file.read_text(encoding="utf-8")
            if auth_file.is_file()
            else None
        ),
        "authMode": (
            auth_file.stat().st_mode & 0o777
            if auth_file.is_file()
            else None
        ),
    }
    (Path.cwd() / "fake-codex-invocation.json").write_text(
        json.dumps(invocation, sort_keys=True),
        encoding="utf-8",
    )

    if prompt == "FAKE_SLEEP":
        child = subprocess.Popen(["/bin/sleep", "30"])
        (Path.cwd() / "fake-grandchild.pid").write_text(
            str(child.pid),
            encoding="ascii",
        )
        time.sleep(30)
        return 0
    if prompt == "FAKE_SLEEP_IGNORE_TERM":
        child = subprocess.Popen(
            ["/bin/sh", "-c", 'trap "" TERM; exec /bin/sleep 30']
        )
        (Path.cwd() / "fake-grandchild.pid").write_text(
            str(child.pid),
            encoding="ascii",
        )
        time.sleep(30)
        return 0
    if prompt == "FAKE_FLOOD":
        sys.stdout.write("x" * (2 * 1024 * 1024))
        sys.stdout.flush()
        return 0
    if prompt == "FAKE_GROWTH":
        (Path(os.environ["TMPDIR"]) / "growth.bin").write_bytes(
            b"x" * (2 * 1024 * 1024)
        )
        time.sleep(30)
        return 0
    if prompt == "FAKE_PROCESSES":
        children = [
            subprocess.Popen(["/bin/sleep", "30"])
            for _ in range(8)
        ]
        time.sleep(30)
        return 0 if all(child.poll() is None for child in children) else 1
    if prompt == "FAKE_MEMORY":
        allocation = bytearray(128 * 1024 * 1024)
        allocation[0] = 1
        time.sleep(30)
        return allocation[0] - 1
    if prompt.startswith("FAKE_ARG0"):
        session_name = (
            "codex-arg0ABC12"
            if prompt == "FAKE_ARG0_WRONG_SESSION"
            else "codex-arg0ABC123"
        )
        arg0 = (
            Path(os.environ["CODEX_HOME"])
            / "tmp"
            / "arg0"
            / session_name
        )
        arg0.mkdir(parents=True, mode=0o700)
        (arg0 / ".lock").write_bytes(b"")
        target = (
            Path("/bin/true")
            if prompt == "FAKE_ARG0_WRONG_TARGET"
            else Path(sys.argv[0]).resolve()
        )
        link_target: Path | str = target
        if prompt == "FAKE_ARG0_RELATIVE_TARGET":
            link_target = os.path.relpath(target, arg0)
        for name in ("apply_patch", "applypatch", "codex-execve-wrapper"):
            (arg0 / name).symlink_to(link_target)
        if prompt == "FAKE_ARG0_UNEXPECTED_NAME":
            (arg0 / "unexpected").symlink_to(target)
        if prompt == "FAKE_ARG0_PUBLIC_PARENT":
            arg0.parent.chmod(0o755)
        time.sleep(0.4)
    if prompt == "FAKE_INVALID_JSON":
        print("not-json", flush=True)
        return 0
    if prompt == "FAKE_EXIT_7":
        print(
            json.dumps(
                {
                    "type": "thread.started",
                    "thread_id": "019f-test-child-thread",
                }
            ),
            flush=True,
        )
        print(json.dumps({"type": "turn.failed"}), flush=True)
        return 7
    if prompt.startswith("FAKE_MUTATE_RELATIVE:"):
        target = Path(prompt.partition(":")[2])
        target.write_text("mutated by fake child\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "type": "thread.started",
                "thread_id": "019f-test-child-thread",
            }
        ),
        flush=True,
    )
    print(
        json.dumps(
            {
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 10,
                    "cached_input_tokens": 0,
                    "output_tokens": 5,
                    "reasoning_output_tokens": 1,
                },
            }
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

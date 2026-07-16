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
    probe = Path.cwd() / "umask-probe"
    probe.write_text("private\n", encoding="utf-8")
    invocation = {
        "argv": sys.argv[1:],
        "environment": dict(os.environ),
        "prompt": prompt,
        "pid": os.getpid(),
        "processGroup": os.getpgrp(),
        "session": os.getsid(0),
        "umaskProbeMode": probe.stat().st_mode & 0o777,
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

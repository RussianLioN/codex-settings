#!/usr/bin/env python3
"""Снять один обезличенный снимок процессов и классифицировать помощники Codex."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Callable


PROTOCOL_VERSION = 1
ORPHAN_CONFIRM_SECONDS = 300.0
NODE_REPL_PATTERN = re.compile(r"(?:^|/)node_repl(?:\s|$)")
NODE_REPL_STATES = (
    "attached",
    "orphan_candidate",
    "confirmed_orphan",
    "external",
    "stale_path",
    "unknown",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot-json", type=Path)
    parser.add_argument("--caller-pid", type=int, default=os.getppid())
    parser.add_argument("--now-epoch", type=float, default=time.time())
    parser.add_argument("--format", choices=("json", "shell"), default="json")
    return parser.parse_args()


def take_snapshot() -> list[dict[str, object]]:
    completed = subprocess.run(
        [
            "ps",
            "-axo",
            "pid=,ppid=,uid=,user=,lstart=,command=",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"ps failed with status {completed.returncode}: {completed.stderr.strip()}"
        )
    return parse_ps_snapshot(completed.stdout)


def parse_ps_snapshot(text: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split(None, 9)
        if len(parts) != 10:
            raise ValueError(f"malformed ps row {line_number}")
        pid_text, ppid_text, uid_text, user = parts[:4]
        started_text = " ".join(parts[4:9])
        command = parts[9]
        try:
            started_epoch = datetime.strptime(
                started_text,
                "%a %b %d %H:%M:%S %Y",
            ).timestamp()
            executable = command_executable(command)
            rows.append(
                {
                    "pid": int(pid_text),
                    "ppid": int(ppid_text),
                    "uid": int(uid_text),
                    "user": user,
                    "started_epoch": started_epoch,
                    "executable": executable,
                    "command": command,
                }
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"malformed ps row {line_number}: {exc}") from exc
    if not rows:
        raise ValueError("process snapshot is empty")
    return rows


def command_executable(command: str) -> str:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    return tokens[0] if tokens else ""


def normalized_process(row: dict[str, object]) -> dict[str, object]:
    required = ("pid", "ppid", "uid", "user", "started_epoch", "command")
    missing = [key for key in required if key not in row]
    if missing:
        raise ValueError(f"process row missing fields: {','.join(missing)}")
    command = str(row["command"])
    return {
        "pid": int(row["pid"]),
        "ppid": int(row["ppid"]),
        "uid": int(row["uid"]),
        "user": str(row["user"]),
        "started_epoch": float(row["started_epoch"]),
        "executable": str(row.get("executable") or command_executable(command)),
        "command": command,
    }


def process_kind(process: dict[str, object]) -> str:
    executable = str(process["executable"])
    command = str(process["command"])
    basename = os.path.basename(executable).lower()
    lowered = command.lower()
    if "chatgpt.app/contents/macos/chatgpt" in lowered or basename == "chatgpt":
        return "chatgpt"
    if (
        basename in {"codex-app-server", "codex_app_server"}
        or re.search(r"(?:^|/)codex(?:\s+|.*\s+)app-server(?:\s|$)", lowered)
    ):
        return "app_server"
    if basename == "codex" or re.match(r"^(?:\S*/)?codex(?:\s|$)", command):
        return "codex_cli"
    return "unknown"


def is_node_repl(process: dict[str, object]) -> bool:
    executable = str(process["executable"])
    command = str(process["command"])
    return os.path.basename(executable) == "node_repl" or bool(
        NODE_REPL_PATTERN.search(command)
    )


def valid_parent(
    child: dict[str, object],
    parent: dict[str, object] | None,
) -> bool:
    if parent is None:
        return False
    return float(parent["started_epoch"]) <= float(child["started_epoch"]) + 0.001


def ancestor_chain(
    process: dict[str, object],
    by_pid: dict[int, dict[str, object]],
) -> tuple[list[dict[str, object]], bool]:
    ancestors: list[dict[str, object]] = []
    visited = {int(process["pid"])}
    child = process
    while int(child["ppid"]) > 1:
        parent_pid = int(child["ppid"])
        if parent_pid in visited:
            return ancestors, True
        parent = by_pid.get(parent_pid)
        if not valid_parent(child, parent):
            return ancestors, True
        assert parent is not None
        ancestors.append(parent)
        visited.add(parent_pid)
        child = parent
    return ancestors, False


def classified_roots(
    processes: list[dict[str, object]],
    by_pid: dict[int, dict[str, object]],
) -> list[tuple[dict[str, object], str]]:
    roots: list[tuple[dict[str, object], str]] = []
    for process in processes:
        kind = process_kind(process)
        if kind == "unknown":
            continue
        ancestors, _broken = ancestor_chain(process, by_pid)
        if any(process_kind(ancestor) != "unknown" for ancestor in ancestors):
            continue
        roots.append((process, kind))
    return roots


def nearest_owner(
    process: dict[str, object],
    by_pid: dict[int, dict[str, object]],
) -> tuple[dict[str, object] | None, str, bool]:
    ancestors, broken = ancestor_chain(process, by_pid)
    for ancestor in ancestors:
        kind = process_kind(ancestor)
        if kind != "unknown":
            return ancestor, kind, broken
    return None, "unknown", broken


def current_codex_root(
    caller_pid: int,
    by_pid: dict[int, dict[str, object]],
) -> int | None:
    caller = by_pid.get(caller_pid)
    if caller is None:
        return None
    candidates = [caller]
    ancestors, _broken = ancestor_chain(caller, by_pid)
    candidates.extend(ancestors)
    for process in candidates:
        if process_kind(process) == "codex_cli":
            return int(process["pid"])
    return None


def classify_snapshot(
    rows: list[dict[str, object]],
    *,
    caller_pid: int,
    now_epoch: float,
    executable_exists: Callable[[str], bool] | None = None,
) -> dict[str, object]:
    exists = executable_exists or (
        lambda path: os.path.isfile(path) and os.access(path, os.X_OK)
    )
    processes = [normalized_process(row) for row in rows]
    by_pid = {int(process["pid"]): process for process in processes}
    if len(by_pid) != len(processes):
        raise ValueError("process snapshot contains duplicate pid")
    roots = classified_roots(processes, by_pid)
    managed_root = current_codex_root(caller_pid, by_pid)
    root_counts = {
        "codex_cli": sum(1 for _process, kind in roots if kind == "codex_cli"),
        "managed_codex_cli": int(managed_root is not None),
        "unmanaged_codex_cli": sum(
            1
            for process, kind in roots
            if kind == "codex_cli" and int(process["pid"]) != managed_root
        ),
        "app_server": sum(1 for _process, kind in roots if kind == "app_server"),
        "chatgpt": sum(1 for _process, kind in roots if kind == "chatgpt"),
        "unknown": 0,
    }
    states = {state: 0 for state in NODE_REPL_STATES}
    node_repl_total = 0
    for process in processes:
        if not is_node_repl(process):
            continue
        node_repl_total += 1
        executable = str(process["executable"])
        if executable.startswith("/") and not exists(executable):
            states["stale_path"] += 1
            continue
        _owner, owner_kind, broken = nearest_owner(process, by_pid)
        if owner_kind == "codex_cli":
            states["attached"] += 1
        elif owner_kind in {"app_server", "chatgpt"}:
            states["external"] += 1
        elif broken or int(process["ppid"]) <= 1:
            age = max(0.0, now_epoch - float(process["started_epoch"]))
            state = (
                "confirmed_orphan"
                if age >= ORPHAN_CONFIRM_SECONDS
                else "orphan_candidate"
            )
            states[state] += 1
        else:
            states["unknown"] += 1
    root_counts["unknown"] = max(
        0,
        node_repl_total - sum(states[state] for state in NODE_REPL_STATES),
    )
    return {
        "protocol_version": PROTOCOL_VERSION,
        "snapshot_status": "ok",
        "process_count": len(processes),
        "user_process_count": sum(
            1 for process in processes if int(process["uid"]) == os.getuid()
        ),
        "current_codex_pid": managed_root,
        "root_counts": root_counts,
        "node_repl_total": node_repl_total,
        "node_repl_states": states,
        "max_expected_node_repl_processes": "unknown",
    }


def load_snapshot(path: Path | None) -> list[dict[str, object]]:
    if path is None:
        return take_snapshot()
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("processes") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError("snapshot JSON must contain a process list")
    return rows


def render_shell(summary: dict[str, object]) -> str:
    roots = summary["root_counts"]
    states = summary["node_repl_states"]
    assert isinstance(roots, dict)
    assert isinstance(states, dict)
    values = {
        "inventory_protocol_version": summary["protocol_version"],
        "inventory_status": summary["snapshot_status"],
        "inventory_process_count": summary["process_count"],
        "inventory_user_process_count": summary["user_process_count"],
        "inventory_current_codex_pid": summary["current_codex_pid"] or "none",
        "inventory_codex_roots": roots["codex_cli"],
        "inventory_managed_codex_roots": roots["managed_codex_cli"],
        "inventory_unmanaged_codex_roots": roots["unmanaged_codex_cli"],
        "inventory_app_server_roots": roots["app_server"],
        "inventory_chatgpt_roots": roots["chatgpt"],
        "inventory_node_repl_total": summary["node_repl_total"],
        "inventory_node_repl_attached": states["attached"],
        "inventory_node_repl_orphan_candidate": states["orphan_candidate"],
        "inventory_node_repl_confirmed_orphan": states["confirmed_orphan"],
        "inventory_node_repl_external": states["external"],
        "inventory_node_repl_stale_path": states["stale_path"],
        "inventory_node_repl_unknown": states["unknown"],
        "max_expected_node_repl_processes": summary[
            "max_expected_node_repl_processes"
        ],
    }
    return "".join(f"{key}={value}\n" for key, value in values.items())


def main() -> int:
    args = parse_args()
    try:
        summary = classify_snapshot(
            load_snapshot(args.snapshot_json),
            caller_pid=args.caller_pid,
            now_epoch=args.now_epoch,
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"codex_process_inventory: {exc}", file=sys.stderr)
        return 2
    if args.format == "shell":
        sys.stdout.write(render_shell(summary))
    else:
        json.dump(summary, sys.stdout, ensure_ascii=False, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

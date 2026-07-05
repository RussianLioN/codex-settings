#!/usr/bin/env python3
"""SQLite-backed control plane for isolated Codex batch-worker attempts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import textwrap
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_FIELDS = {
    "repo",
    "base_sha",
    "goal",
    "constraints",
    "validation_profile",
    "validation_commands",
    "risk_level",
    "output_schema",
    "owned_write_scope",
    "allowed_read_scope",
    "do_not_touch",
    "done_criteria",
    "expected_artifact",
    "stop_condition",
}
VALID_STATES = {"queued", "leased", "succeeded", "failed", "retryable"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=".codex-batch/tasks.sqlite3", help="SQLite queue path.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Create or migrate the queue database.")

    enqueue = sub.add_parser("enqueue", help="Add an immutable task spec to the queue.")
    enqueue.add_argument("spec", type=Path)

    list_cmd = sub.add_parser("list", help="List tasks.")
    list_cmd.add_argument("--state", choices=sorted(VALID_STATES))

    show = sub.add_parser("show", help="Show one task spec and state.")
    show.add_argument("task_id")

    run_once = sub.add_parser("run-once", help="Lease and run one queued task.")
    run_once.add_argument("--attempt-root", default=".codex-batch/worktrees")
    run_once.add_argument("--artifact-root", default=".codex-batch/artifacts")
    run_once.add_argument("--codex-bin", default="codex")
    run_once.add_argument("--lease-seconds", type=int, default=7200)
    run_once.add_argument("--timeout-seconds", type=int, default=7200)
    run_once.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()
    db_path = Path(args.db)
    if args.command == "init-db":
        init_db(db_path)
        print(db_path)
        return 0
    if args.command == "enqueue":
        init_db(db_path)
        task_id = enqueue_task(db_path, args.spec)
        print(task_id)
        return 0
    if args.command == "list":
        init_db(db_path)
        list_tasks(db_path, args.state)
        return 0
    if args.command == "show":
        init_db(db_path)
        show_task(db_path, args.task_id)
        return 0
    if args.command == "run-once":
        init_db(db_path)
        return run_once_task(
            db_path=db_path,
            attempt_root=Path(args.attempt_root),
            artifact_root=Path(args.artifact_root),
            codex_bin=args.codex_bin,
            lease_seconds=args.lease_seconds,
            timeout_seconds=args.timeout_seconds,
            dry_run=args.dry_run,
        )
    raise AssertionError(args.command)


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            create table if not exists tasks (
              id text primary key,
              spec_sha256 text not null unique,
              spec_json text not null,
              state text not null,
              attempts integer not null default 0,
              created_at text not null,
              updated_at text not null,
              leased_until text,
              last_error text
            );
            create table if not exists attempts (
              id text primary key,
              task_id text not null references tasks(id),
              attempt_no integer not null,
              state text not null,
              worktree text not null,
              artifact_dir text not null,
              branch text not null,
              base_sha text not null,
              started_at text not null,
              completed_at text,
              codex_exit_code integer,
              validation_exit_code integer,
              error text
            );
            """
        )


def enqueue_task(db_path: Path, spec_path: Path) -> str:
    spec = load_spec(spec_path)
    spec_sha = stable_sha(spec)
    task_id = str(spec.get("id") or f"task-{spec_sha[:16]}")
    now = utc_now()
    with sqlite3.connect(db_path) as conn:
        try:
            conn.execute(
                """
                insert into tasks (id, spec_sha256, spec_json, state, created_at, updated_at)
                values (?, ?, ?, 'queued', ?, ?)
                """,
                (task_id, spec_sha, canonical_json(spec), now, now),
            )
        except sqlite3.IntegrityError as exc:
            raise SystemExit(f"task already exists or spec duplicated: {exc}") from exc
    return task_id


def list_tasks(db_path: Path, state: str | None) -> None:
    query = "select id, state, attempts, updated_at, last_error from tasks"
    params: tuple[Any, ...] = ()
    if state:
        query += " where state = ?"
        params = (state,)
    query += " order by created_at"
    with sqlite3.connect(db_path) as conn:
        for row in conn.execute(query, params):
            print("\t".join("" if value is None else str(value) for value in row))


def show_task(db_path: Path, task_id: str) -> None:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "select id, state, attempts, spec_sha256, spec_json, last_error from tasks where id = ?",
            (task_id,),
        ).fetchone()
    if not row:
        raise SystemExit(f"no such task: {task_id}")
    task = {
        "id": row[0],
        "state": row[1],
        "attempts": row[2],
        "spec_sha256": row[3],
        "spec": json.loads(row[4]),
        "last_error": row[5],
    }
    print(json.dumps(task, indent=2, sort_keys=True))


def run_once_task(
    db_path: Path,
    attempt_root: Path,
    artifact_root: Path,
    codex_bin: str,
    lease_seconds: int,
    timeout_seconds: int,
    dry_run: bool,
) -> int:
    leased = lease_next_task(db_path, lease_seconds)
    if leased is None:
        print("no queued task")
        return 0

    task_id, attempt_no, spec = leased
    attempt_id = f"{task_id}-attempt-{attempt_no}"
    branch = f"codex-batch/{task_id[:40]}-{attempt_no}"
    worktree = (attempt_root / attempt_id).resolve()
    artifact_dir = (artifact_root / attempt_id).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            insert into attempts
              (id, task_id, attempt_no, state, worktree, artifact_dir, branch, base_sha, started_at)
            values (?, ?, ?, 'leased', ?, ?, ?, ?, ?)
            """,
            (attempt_id, task_id, attempt_no, str(worktree), str(artifact_dir), branch, spec["base_sha"], started_at),
        )

    try:
        if dry_run:
            write_text(artifact_dir / "dry-run-prompt.md", build_prompt(spec))
            mark_attempt(db_path, task_id, attempt_id, "succeeded", 0, 0, None)
            return 0

        create_worktree(spec["repo"], spec["base_sha"], branch, worktree)
        prompt = build_prompt(spec)
        write_text(artifact_dir / "prompt.md", prompt)
        codex_exit = run_codex(codex_bin, worktree, artifact_dir, prompt, timeout_seconds)
        validation_exit = run_validation(worktree, artifact_dir, spec.get("validation_commands", []), timeout_seconds)
        collect_git_artifacts(worktree, artifact_dir)
        state = "succeeded" if codex_exit == 0 and validation_exit == 0 else "failed"
        mark_attempt(db_path, task_id, attempt_id, state, codex_exit, validation_exit, None)
        return 0 if state == "succeeded" else 1
    except Exception as exc:
        collect_best_effort(worktree, artifact_dir)
        mark_attempt(db_path, task_id, attempt_id, "retryable", None, None, str(exc))
        print(str(exc), file=sys.stderr)
        return 2


def lease_next_task(db_path: Path, lease_seconds: int) -> tuple[str, int, dict[str, Any]] | None:
    now = utc_now()
    leased_until = datetime.fromtimestamp(time.time() + lease_seconds, timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.isolation_level = "EXCLUSIVE"
        conn.execute("begin exclusive")
        row = conn.execute(
            "select id, attempts, spec_json from tasks where state = 'queued' order by created_at limit 1"
        ).fetchone()
        if not row:
            conn.commit()
            return None
        task_id, attempts, spec_json = row
        attempt_no = int(attempts) + 1
        conn.execute(
            """
            update tasks
            set state = 'leased', attempts = ?, leased_until = ?, updated_at = ?, last_error = null
            where id = ?
            """,
            (attempt_no, leased_until, now, task_id),
        )
        conn.commit()
    return task_id, attempt_no, json.loads(spec_json)


def load_spec(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        spec = json.load(handle)
    if not isinstance(spec, dict):
        raise SystemExit("task spec must be a JSON object")
    missing = sorted(REQUIRED_FIELDS - set(spec))
    if missing:
        raise SystemExit(f"task spec missing required fields: {', '.join(missing)}")
    if not isinstance(spec["validation_commands"], list) or not all(
        isinstance(item, str) and item.strip() for item in spec["validation_commands"]
    ):
        raise SystemExit("validation_commands must be a non-empty string array")
    repo = Path(str(spec["repo"])).expanduser()
    if not repo.exists():
        raise SystemExit(f"repo does not exist: {repo}")
    return spec


def create_worktree(repo: str, base_sha: str, branch: str, worktree: Path) -> None:
    if worktree.exists():
        raise RuntimeError(f"worktree path already exists: {worktree}")
    run(["git", "-C", repo, "rev-parse", "--verify", base_sha], stdout=subprocess.PIPE)
    run(["git", "-C", repo, "worktree", "add", "-b", branch, str(worktree), base_sha])


def run_codex(codex_bin: str, worktree: Path, artifact_dir: Path, prompt: str, timeout_seconds: int) -> int:
    events = artifact_dir / "events.jsonl"
    stderr_path = artifact_dir / "stderr.log"
    result = artifact_dir / "result.md"
    command = [
        codex_bin,
        "exec",
        "--profile",
        "batch-workers",
        "--json",
        "--cd",
        str(worktree),
        "-o",
        str(result),
        prompt,
    ]
    write_text(artifact_dir / "codex-command.json", json.dumps(command, indent=2))
    with events.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
        proc = subprocess.run(command, cwd=worktree, stdout=stdout, stderr=stderr, text=True, timeout=timeout_seconds)
    return proc.returncode


def run_validation(worktree: Path, artifact_dir: Path, commands: list[str], timeout_seconds: int) -> int:
    log_path = artifact_dir / "validation.log"
    overall = 0
    with log_path.open("w", encoding="utf-8") as log:
        for index, command in enumerate(commands, start=1):
            log.write(f"$ {command}\n")
            proc = subprocess.run(
                command,
                cwd=worktree,
                shell=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout_seconds,
            )
            log.write(proc.stdout)
            log.write(f"\n[exit {proc.returncode}]\n")
            if proc.returncode != 0:
                overall = proc.returncode or 1
                break
            write_text(artifact_dir / f"validation-{index}.ok", command)
    return overall


def collect_git_artifacts(worktree: Path, artifact_dir: Path) -> None:
    status = run(["git", "status", "--short"], cwd=worktree, stdout=subprocess.PIPE).stdout
    run(["git", "add", "-N", "."], cwd=worktree, stdout=subprocess.PIPE)
    diff = run(["git", "diff", "--binary", "HEAD"], cwd=worktree, stdout=subprocess.PIPE).stdout
    write_bytes(artifact_dir / "git-status.txt", status)
    write_bytes(artifact_dir / "git-diff.patch", diff)


def collect_best_effort(worktree: Path, artifact_dir: Path) -> None:
    try:
        if worktree.exists():
            collect_git_artifacts(worktree, artifact_dir)
    except Exception as exc:
        write_text(artifact_dir / "artifact-collection-error.txt", str(exc))


def mark_attempt(
    db_path: Path,
    task_id: str,
    attempt_id: str,
    state: str,
    codex_exit: int | None,
    validation_exit: int | None,
    error: str | None,
) -> None:
    now = utc_now()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            update attempts
            set state = ?, completed_at = ?, codex_exit_code = ?, validation_exit_code = ?, error = ?
            where id = ?
            """,
            (state, now, codex_exit, validation_exit, error, attempt_id),
        )
        conn.execute(
            "update tasks set state = ?, updated_at = ?, last_error = ? where id = ?",
            (state, now, error, task_id),
        )


def build_prompt(spec: dict[str, Any]) -> str:
    fields = {
        "mission": spec["goal"],
        "owned write scope": spec["owned_write_scope"],
        "allowed read scope": spec["allowed_read_scope"],
        "do not touch": spec["do_not_touch"],
        "validation commands": spec["validation_commands"],
        "done criteria": spec["done_criteria"],
        "expected artifact": spec["expected_artifact"],
        "stop condition": spec["stop_condition"],
    }
    body = "\n".join(f"{key}:\n{format_value(value)}\n" for key, value in fields.items())
    constraints = format_value(spec["constraints"])
    output_schema = format_value(spec["output_schema"])
    return textwrap.dedent(
        f"""
        Use the batch-worker role.

        This is one queued attempt in one isolated worktree. Do not push, merge,
        open pull requests, publish results, delete worktrees, or edit outside
        the owned write scope.

        constraints:
        {constraints}

        validation_profile:
        {spec["validation_profile"]}

        risk_level:
        {spec["risk_level"]}

        output_schema:
        {output_schema}

        {body}
        """
    ).strip()


def format_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, sort_keys=True)


def run(command: list[str], cwd: Path | str | None = None, stdout: Any = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, cwd=cwd, check=True, stdout=stdout)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def stable_sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())

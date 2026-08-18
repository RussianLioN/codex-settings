#!/usr/bin/env python3
"""Временно отключить локальные хуки Codex с точным обратимым снимком."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path


POLICY_START = "<!-- codex-runtime-fd-guardrails:start -->"
POLICY_END = "<!-- codex-runtime-fd-guardrails:end -->"
STATE_NAME = "temporary-guardrails-override.json"
STATE_VERSION = 1
DISABLE_CONFIRMATION = "disable-all-local-guardrails"
RESTORE_CONFIRMATION = "restore-local-guardrails"
TARGET_NAMES = ("config.toml", "hooks.json", "AGENTS.md")


class OverrideError(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("enable", "status", "restore"):
        command = subparsers.add_parser(name)
        command.add_argument("--codex-home", type=Path, default=Path.home() / ".codex")
        command.add_argument("--timestamp")
        if name != "status":
            command.add_argument("--confirm")
    return parser.parse_args()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_file(path: Path, *, required: bool = True) -> tuple[bytes, int]:
    if path.is_symlink():
        raise OverrideError(f"target_is_symlink:{path.name}")
    if not path.exists():
        if required:
            raise OverrideError(f"target_missing:{path.name}")
        return b"", 0o600
    if not path.is_file():
        raise OverrideError(f"target_invalid_type:{path.name}")
    file_stat = path.stat()
    if file_stat.st_uid != os.getuid() or file_stat.st_nlink != 1:
        raise OverrideError(f"target_ownership_unsafe:{path.name}")
    return path.read_bytes(), stat.S_IMODE(file_stat.st_mode)


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    if path.is_symlink():
        raise OverrideError(f"target_is_symlink:{path.name}")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def disabled_config(data: bytes) -> bytes:
    text = data.decode("utf-8")
    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise OverrideError("config_invalid_toml") from exc
    lines = text.splitlines()
    final_newline = text.endswith("\n")
    header = re.compile(r"^\s*\[features\](?:\s*#.*)?$")
    headers = [index for index, line in enumerate(lines) if header.fullmatch(line)]
    if len(headers) > 1:
        raise OverrideError("config_features_table_duplicate")
    if not headers:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend(("[features]", "hooks = false"))
    else:
        start = headers[0]
        end = next((index for index in range(start + 1, len(lines)) if lines[index].lstrip().startswith("[")), len(lines))
        hook = re.compile(r"^(?P<indent>\s*)hooks\s*=")
        matches = [index for index in range(start + 1, end) if hook.match(lines[index])]
        if len(matches) > 1:
            raise OverrideError("config_features_hooks_duplicate")
        if matches:
            match = hook.match(lines[matches[0]])
            assert match is not None
            lines[matches[0]] = f"{match.group('indent')}hooks = false"
        else:
            lines.insert(start + 1, "hooks = false")
    rendered = "\n".join(lines) + ("\n" if final_newline else "")
    return rendered.encode("utf-8")


def disabled_agents(data: bytes) -> bytes:
    text = data.decode("utf-8")
    start = text.find(POLICY_START)
    end = text.find(POLICY_END)
    if start < 0 or end < 0 or text.find(POLICY_START, start + len(POLICY_START)) >= 0 or text.find(POLICY_END, end + len(POLICY_END)) >= 0:
        raise OverrideError("agents_policy_block_invalid")
    if end < start:
        raise OverrideError("agents_policy_block_invalid")
    end_line = text.find("\n", end)
    if end_line < 0:
        end_line = len(text)
    else:
        end_line += 1
    return (text[:start] + text[end_line:]).encode("utf-8")


def targets(codex_home: Path) -> dict[str, Path]:
    root = codex_home.expanduser().resolve(strict=False)
    return {
        "config.toml": root / "config.toml",
        "hooks.json": root / "hooks.json",
        "AGENTS.md": root / "AGENTS.md",
    }


def state_path(codex_home: Path) -> Path:
    return codex_home.expanduser().resolve(strict=False) / "state" / STATE_NAME


def load_state(codex_home: Path) -> dict[str, object]:
    path = state_path(codex_home)
    data, mode = checked_file(path)
    if mode != 0o600:
        raise OverrideError("state_mode_unsafe")
    try:
        payload = json.loads(data)
    except json.JSONDecodeError as exc:
        raise OverrideError("state_invalid_json") from exc
    if not isinstance(payload, dict) or payload.get("version") != STATE_VERSION or payload.get("status") != "enabled":
        raise OverrideError("state_invalid")
    targets_payload = payload.get("targets")
    if not isinstance(targets_payload, list) or {entry.get("name") for entry in targets_payload if isinstance(entry, dict)} != set(TARGET_NAMES):
        raise OverrideError("state_targets_invalid")
    return payload


def target_entries(codex_home: Path, originals: dict[str, tuple[bytes, int]], disabled: dict[str, bytes], backup: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for name in TARGET_NAMES:
        data, mode = originals[name]
        backup_name = f"{name}.backup"
        atomic_write(backup / backup_name, data, 0o600)
        entries.append(
            {
                "name": name,
                "backup": backup_name,
                "original_sha256": sha256(data),
                "original_mode": mode,
                "disabled_sha256": sha256(disabled[name]),
            }
        )
    return entries


def enable(codex_home: Path, timestamp: str | None) -> None:
    if state_path(codex_home).exists():
        raise OverrideError("override_already_enabled")
    paths = targets(codex_home)
    originals = {name: checked_file(path) for name, path in paths.items()}
    disabled = {
        "config.toml": disabled_config(originals["config.toml"][0]),
        "hooks.json": b'{"hooks":{}}\n',
        "AGENTS.md": disabled_agents(originals["AGENTS.md"][0]),
    }
    suffix = timestamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    if not re.fullmatch(r"[0-9]{8}-[0-9]{6}", suffix):
        raise OverrideError("timestamp_invalid")
    backup = codex_home.expanduser().resolve(strict=False) / "backups" / f"temporary-guardrails-override-{suffix}"
    if backup.exists():
        raise OverrideError("backup_already_exists")
    backup.mkdir(parents=True, mode=0o700)
    backup.chmod(0o700)
    entries = target_entries(codex_home, originals, disabled, backup)
    try:
        for name in TARGET_NAMES:
            atomic_write(paths[name], disabled[name], originals[name][1])
        payload = {
            "version": STATE_VERSION,
            "status": "enabled",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "backup": backup.name,
            "targets": entries,
        }
        atomic_write(state_path(codex_home), (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"), 0o600)
    except BaseException:
        for name in TARGET_NAMES:
            original, mode = originals[name]
            atomic_write(paths[name], original, mode)
        raise
    print("status=ENABLED")
    print("local_hooks=disabled")
    print("restore_command=temporary_guardrails_override.py restore --confirm restore-local-guardrails")


def restore(codex_home: Path) -> None:
    payload = load_state(codex_home)
    paths = targets(codex_home)
    entries = {str(entry["name"]): entry for entry in payload["targets"] if isinstance(entry, dict)}
    disabled_snapshot: dict[str, tuple[bytes, int]] = {}
    backup_name = payload.get("backup")
    if not isinstance(backup_name, str) or not re.fullmatch(r"temporary-guardrails-override-[0-9]{8}-[0-9]{6}", backup_name):
        raise OverrideError("state_backup_invalid")
    backup = codex_home.expanduser().resolve(strict=False) / "backups" / backup_name
    for name in TARGET_NAMES:
        entry = entries[name]
        current, mode = checked_file(paths[name])
        if sha256(current) != entry.get("disabled_sha256"):
            raise OverrideError(f"disabled_target_drifted:{name}")
        disabled_snapshot[name] = (current, mode)
        backup_file = backup / str(entry.get("backup"))
        original, _backup_mode = checked_file(backup_file)
        if sha256(original) != entry.get("original_sha256"):
            raise OverrideError(f"backup_target_drifted:{name}")
    try:
        for name in TARGET_NAMES:
            entry = entries[name]
            original = (backup / str(entry["backup"])).read_bytes()
            atomic_write(paths[name], original, int(entry["original_mode"]))
    except BaseException:
        for name in reversed(TARGET_NAMES):
            disabled, mode = disabled_snapshot[name]
            atomic_write(paths[name], disabled, mode)
        raise
    state_path(codex_home).unlink()
    print("status=RESTORED")
    print("local_hooks=restored")


def status(codex_home: Path) -> int:
    try:
        payload = load_state(codex_home)
    except OverrideError as exc:
        if str(exc) == f"target_missing:{STATE_NAME}":
            print("status=DISABLED")
            return 0
        print("status=BLOCK")
        print(f"reason={exc}")
        return 2
    paths = targets(codex_home)
    for entry in payload["targets"]:
        assert isinstance(entry, dict)
        current, _mode = checked_file(paths[str(entry["name"])])
        if sha256(current) != entry.get("disabled_sha256"):
            print("status=BLOCK")
            print(f"reason=disabled_target_drifted:{entry['name']}")
            return 2
    print("status=ENABLED")
    return 0


def main() -> int:
    args = parse_args()
    try:
        if args.command == "enable":
            if args.confirm != DISABLE_CONFIRMATION:
                raise OverrideError("confirmation_required:disable-all-local-guardrails")
            enable(args.codex_home, args.timestamp)
        elif args.command == "restore":
            if args.confirm != RESTORE_CONFIRMATION:
                raise OverrideError("confirmation_required:restore-local-guardrails")
            restore(args.codex_home)
        else:
            return status(args.codex_home)
    except OverrideError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
